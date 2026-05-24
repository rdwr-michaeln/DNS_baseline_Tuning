#!/usr/bin/env python3
"""
DNS Baseline Monitor

Polls every DP in sites.json every 10 minutes:
- All DPs alive  → refresh dns_baseline.json
- Any DP down    → freeze the file; on first detection delegate QPS
                   redistribution to DpFailoverManager
"""

import json
import os
import time
import urllib3
from datetime import datetime
from cc_connector import CcConnector
from dp_failover_manager import DpFailoverManager
import configParser
import if_status_monitor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASELINE_FILE    = "dns_baseline.json"
INTERVAL_SECONDS = configParser.pull_interval * 60  # pull_interval is in minutes


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def load_sites():
    return configParser.sites_config


def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_baseline(data):
    # Merge into the existing file so keys written by other components
    # (e.g. interface_snapshot from if_status_monitor) are preserved.
    existing = {}
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r") as f:
                existing = json.load(f)
        except Exception:
            pass
    existing.update(data)   # timestamp + sites overwrite; interface_snapshot kept
    with open(BASELINE_FILE, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"💾 dns_baseline.json updated at {data['timestamp']}")


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

def query_all_dps(cc, failover_manager, sites):
    """
    Query every device in sites.json.
    Returns:
        alive_data  – { dp_ip: {"name": str, "pos": [po dicts]} }
        failed_devs – [ {"name": str, "ip": str}, ... ]
    """
    alive_data  = {}
    failed_devs = []

    for site in sites:
        for device in site.get("devices", []):
            dp_name = device.get("name", "unknown")
            dp_ip   = device.get("ip", "")

            if not failover_manager.is_dp_alive(dp_ip):
                print(f"❌  {dp_name} ({dp_ip}) is unreachable")
                failed_devs.append({"name": dp_name, "ip": dp_ip})
                continue

            dns_data = cc.get_po_dns_per_dp(dp_ip)
            po_list  = dns_data.get(dp_ip, [])
            alive_data[dp_ip] = {"name": dp_name, "pos": po_list}
            print(f"✅  {dp_name} ({dp_ip}): {len(po_list)} PO(s)")

    return alive_data, failed_devs


def build_snapshot(alive_data, sites, orm_map, failed_site_ips=None):
    """Build the full baseline dict from currently alive sites.
    Sites that contain any IP in failed_site_ips are skipped entirely.
    """
    if failed_site_ips is None:
        failed_site_ips = set()

    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "sites": []
    }
    for site in sites:
        site_ips = {d.get("ip") for d in site.get("devices", [])}
        if site_ips & failed_site_ips:
            print(f"⏭️   Skipping site '{site.get('site-name')}' — site is in failover state")
            continue
    for site in sites:
        site_entry = {"site_name": site.get("site-name", "unknown"), "devices": []}
        for device in site.get("devices", []):
            dp_name = device.get("name", "unknown")
            dp_ip   = device.get("ip", "")
            entry   = {
                "dp_name": dp_name,
                "ip": dp_ip,
                "ormId": orm_map.get(dp_ip, ""),
                "protection_objects": []
            }

            if dp_ip in alive_data:
                for po in alive_data[dp_ip]["pos"]:
                    if po.get("po_name"):
                        entry["protection_objects"].append({
                            "po_name": po["po_name"],
                            "rsDnsProtProfileExpectedQps": po["expected_qps"],
                            "rsDnsProtProfileMaxAllowQps": po["max_allow_qps"],
                        })

            site_entry["devices"].append(entry)
        snapshot["sites"].append(site_entry)
    return snapshot


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(failover_manager=None):
    sites = load_sites()
    if not sites:
        print("No sites configured in config.ini.")
        return

    cc    = CcConnector(configParser.username, configParser.password)
    if failover_manager is None:
        failover_manager = DpFailoverManager()
    orm_map        = cc.get_device_orm_map()
    already_failed = set()   # local optimisation: avoids calling redistribute on every poll tick
    first_poll     = True    # failures seen on startup are pre-existing — do NOT redistribute

    print(f"🚀 DNS Baseline Monitor started — interval: {INTERVAL_SECONDS // 60} min")

    # -----------------------------------------------------------------------
    # Startup: snapshot interface operational status for all DPs
    # -----------------------------------------------------------------------
    print("\n📡 Fetching initial interface status for all DPs...")
    iface_snapshot = if_status_monitor.snapshot_all_interfaces(cc, sites)
    if_status_monitor.save_interface_devices(BASELINE_FILE, iface_snapshot)
    print(f"💾 Interface snapshot saved to {BASELINE_FILE}\n")

    while True:
        print(f"\n⏰  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Polling DPs...")

        alive_data, failed_devs = query_all_dps(cc, failover_manager, sites)

        # Always refresh interface snapshot for reachable devices regardless of
        # failover state.  Devices that are down retain their last-known entry
        # so LINK_UP traps can still compare against the pre-failure state.
        if alive_data:
            if_status_monitor.update_interface_devices(
                cc, list(alive_data.keys()),
                monitored_indexes_map=configParser.device_monitored_if_indexes
            )

        if failed_devs:
            print(f"🚨  {len(failed_devs)} DP(s) down — baseline will NOT be updated")

            failed_ips = {dev["ip"] for dev in failed_devs}
            # Merge in any IPs flagged as failed by other monitors (e.g. traffic drop)
            all_known_failed = failed_ips | failover_manager._known_failed_ips

            # Remove management-plane failure flag for any device that recovered
            # this poll (was in already_failed but is now alive)
            recovered_mgmt_ips = already_failed - failed_ips
            for recovered_ip in recovered_mgmt_ips:
                failover_manager._known_failed_ips.discard(recovered_ip)
                # If partner sites are still fully down, apply late redistribution
                # instead of a full restore (which would overwrite alive peers' redistributed QPS)
                if failover_manager._redistributed_ips:
                    rec_info = alive_data.get(recovered_ip, {})
                    print(f"♻️   {rec_info.get('name', recovered_ip)} ({recovered_ip}) recovered — applying late redistribution")
                    baseline = load_baseline()
                    failover_manager.apply_late_redistribution_to_device(recovered_ip, alive_data, baseline)
            already_failed &= failed_ips  # drop recovered devices from tracking

            for dev in failed_devs:
                dp_ip = dev["ip"]
                # Register management-plane failure into shared set
                failover_manager._known_failed_ips.add(dp_ip)

                # Check if the entire site this device belongs to is down
                # (combining management-plane failures AND traffic failures).
                site_of_dev = next(
                    (s for s in sites if any(d.get("ip") == dp_ip for d in s.get("devices", []))),
                    None
                )
                if site_of_dev:
                    site_ips = {d.get("ip") for d in site_of_dev.get("devices", [])}
                    site_fully_down = site_ips.issubset(all_known_failed)
                else:
                    site_fully_down = True  # can't determine — fall back to per-device behaviour

                if dp_ip not in already_failed:
                    if first_poll:
                        # Device was already down when we started — treat as pre-existing.
                        # Do NOT redistribute; just wait for recovery and restore from JSON.
                        print(f"⏸️   {dev['name']} ({dp_ip}) was already down at startup — waiting for recovery")
                        already_failed.add(dp_ip)
                    elif not site_fully_down:
                        # Only part of the site is down — do not redistribute yet.
                        site_name = site_of_dev.get("site-name", "unknown") if site_of_dev else "unknown"
                        print(f"⚠️   {dev['name']} ({dp_ip}) down but site '{site_name}' is NOT fully down — skipping redistribution")
                        already_failed.add(dp_ip)
                    else:
                        print(f"🆕  New failure detected: {dev['name']} ({dp_ip})")
                        baseline = load_baseline()
                        failover_manager.redistribute_qps_from_baseline(dp_ip, baseline, alive_data)
                        already_failed.add(dp_ip)
                else:
                    # Device was already tracked — check if the site became fully down
                    # since the last poll (it was only partially down before).
                    if site_fully_down and dp_ip not in failover_manager._redistributed_ips:
                        print(f"🆕  Site now fully down — triggering redistribution for {dev['name']} ({dp_ip})")
                        baseline = load_baseline()
                        failover_manager.redistribute_qps_from_baseline(dp_ip, baseline, alive_data)
                    elif not site_fully_down:
                        site_name = site_of_dev.get("site-name", "unknown") if site_of_dev else "unknown"
                        print(f"⏸️   {dev['name']} ({dp_ip}) still down — site '{site_name}' not fully down yet, waiting")
                    else:
                        print(f"⏭️   {dev['name']} ({dp_ip}) still down — redistribution already applied")
        else:
            # Only clear the management-plane failure flags that THIS loop added.
            # Traffic-drop failures in _known_failed_ips are owned by BaselineTuning
            # and must NOT be removed here.
            for ip in list(already_failed):
                failover_manager._known_failed_ips.discard(ip)
            if already_failed:
                print("✅  All DPs recovered — restoring baseline QPS values...")
                baseline = load_baseline()
                failover_manager.restore_qps_from_baseline(baseline, alive_data)
                already_failed.clear()
                # Re-poll immediately so the snapshot reflects the just-restored
                # QPS values, not the redistributed ones captured before restore.
                print("🔄  Re-polling devices to capture restored values...")
                alive_data, _ = query_all_dps(cc, failover_manager, sites)

            # Block baseline updates while any failover is still active (e.g.
            # triggered by an SNMP trap while the DP management plane is up).
            if failover_manager._redistributed_ips:
                frozen = ", ".join(failover_manager._redistributed_ips)
                print(f"⏸️   Baseline update frozen — active failover(s): {frozen}")
            else:
                snapshot = build_snapshot(alive_data, sites, orm_map,
                                           failed_site_ips=failover_manager._redistributed_ips)
                save_baseline(snapshot)

        print(f"💤  Sleeping {INTERVAL_SECONDS // 60} min...")
        first_poll = False
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    run()


