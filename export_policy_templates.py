#!/usr/bin/env python3
"""
export_policy_templates.py

Reads dp_policies.json, exports a network template for every
DefensePro / policy combination via the CC REST API, post-processes
the content, and saves each result as a separate file under the
policy_templates/ directory.

File naming: dns_baselines/{device_name}_{policy_name}.cfg

Post-processing rules applied to each exported template:
  1. Remove lines that start with  "classes modify network create"
  2. Remove lines that start with  "dp policies-config table create"
  3. In lines that start with      "dp dns-protection global advanced profiles create"
     replace "profiles create " → "profiles set "
"""

import json
import os
import sys
import time

import urllib3

import configParser
from cc_connector import CcConnector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POLICIES_FILE    = "dp_policies.json"
OUTPUT_DIR       = "dns_baselines"


def _safe_filename_part(value):
    return value.replace("/", "_").replace(" ", "_")


def _load_policies_json():
    with open(POLICIES_FILE, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Template post-processing
# ---------------------------------------------------------------------------

def process_template(content):
    """
    Apply the three post-processing rules and return the cleaned text.
    """
    result = []
    for line in content.splitlines():
        stripped = line.lstrip()

        # Rule 1 – remove network-class definition lines
        if stripped.startswith("classes modify network create"):
            continue

        # Rule 2 – remove policy-table creation lines
        if stripped.startswith("dp policies-config table create"):
            continue

        # Rule 3 – change 'create' to 'set' for DNS-protection profile lines
        if stripped.startswith("dp dns-protection global advanced profiles create"):
            line = line.replace("profiles create ", "profiles set ", 1)

        result.append(line)

    return "\n".join(result)


# ---------------------------------------------------------------------------
# Failover helpers
# ---------------------------------------------------------------------------

def _frozen_ips(failover_manager, sites):
    """
    Return the set of device IPs that must NOT be exported right now.

    Rules:
    - If ANY site is in active failover (_redistributed_ips non-empty), ALL
      devices are frozen.  The surviving sites are carrying redistributed
      (inflated) QPS — saving those values would corrupt the baselines.
    - Otherwise, only devices whose own site is fully down
      (_known_failed_ips covers all site IPs) are frozen.
    """
    if failover_manager is None:
        return set()

    all_ips = {
        d.get("ip")
        for site in sites
        for d in site.get("devices", [])
        if d.get("ip")
    }

    # Any active failover → freeze everything
    if failover_manager._redistributed_ips:
        return all_ips

    # No active failover — only freeze sites that are fully unreachable
    frozen = set()
    for site in sites:
        site_ips = {d.get("ip") for d in site.get("devices", []) if d.get("ip")}
        if site_ips and site_ips.issubset(failover_manager._known_failed_ips):
            frozen |= site_ips
    return frozen


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_all(cc, policies_data, frozen_ips=None):
    """
    Iterate every device/policy in policies_data, fetch the template,
    post-process it and save to OUTPUT_DIR.
    Devices whose IP is in frozen_ips are skipped entirely.

    Args:
        cc (CcConnector): Authenticated CC session.
        policies_data (dict): Content of dp_policies.json["devices"].
        frozen_ips (set | None): IPs belonging to frozen/failed sites.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total = sum(len(v.get("policies", [])) for v in policies_data.values())
    done  = 0

    for dp_ip, device_info in policies_data.items():
        device_name = device_info.get("name", dp_ip)
        policies    = device_info.get("policies", [])

        if frozen_ips and dp_ip in frozen_ips:
            continue

        if not policies:
            continue

        for policy_name in policies:
            raw = cc.get_policy_template(dp_ip, policy_name)
            if raw is None:
                continue

            processed = process_template(raw)

            # Sanitise names for safe file-system usage
            safe_device = _safe_filename_part(device_name)
            safe_policy = _safe_filename_part(policy_name)
            filename    = f"{safe_device}_{safe_policy}.cfg"
            filepath    = os.path.join(OUTPUT_DIR, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(processed)

            done += 1


# ---------------------------------------------------------------------------
# Background run loop
# ---------------------------------------------------------------------------

EXPORT_INTERVAL_SECONDS  = 3600  # 1 hour
RECOVERY_COOLDOWN_SECONDS = 3600  # wait 1 h after full recovery before resuming


def _site_name_for_ip(ip, sites):
    for site in sites:
        if any(d.get("ip") == ip for d in site.get("devices", [])):
            return site.get("site-name", "unknown")
    return None


def run(cc=None, failover_manager=None):
    """
    Long-running function for a background thread.
    Exports/refreshes all policy templates every hour.

    Freeze / cooldown rules:
      - A site is FROZEN while ALL its devices are unreachable OR any device
        is in active failover (_redistributed_ips).
      - After the site fully recovers, a 1-hour cooldown begins.  The files
        are NOT updated during the cooldown window.
      - Normal hour-based exports resume once the cooldown has elapsed.

    Args:
        cc (CcConnector | None):             Reuse an existing CC session if provided.
        failover_manager (DpFailoverManager | None):
                                             Shared failover state. Pass None to
                                             disable freeze logic (standalone use).
    """
    if cc is None:
        cc = CcConnector(configParser.username, configParser.password)

    # { site_name: timestamp when it left the frozen state }
    _site_recovered_at = {}
    # Sites that were frozen on the previous cycle
    _previously_frozen_sites = set()

    while True:
        if not os.path.exists(POLICIES_FILE):
            time.sleep(60)
            continue

        policies_json = _load_policies_json()
        policies_data = policies_json.get("devices", {})
        if not policies_data:
            print("[TemplateExport] No devices in dp_policies.json — skipping.")
            time.sleep(EXPORT_INTERVAL_SECONDS)
            continue

        sites      = configParser.sites_config
        ips_frozen = _frozen_ips(failover_manager, sites)

        # Determine which sites are currently frozen
        currently_frozen_sites = set()
        for ip in ips_frozen:
            sname = _site_name_for_ip(ip, sites)
            if sname:
                currently_frozen_sites.add(sname)

        now = time.monotonic()

        # Detect newly recovered sites (were frozen last cycle, not frozen now)
        for sname in _previously_frozen_sites - currently_frozen_sites:
            _site_recovered_at[sname] = now
            print(f"[TemplateExport] Site '{sname}' recovered — 1-hour cooldown started.")

        # Build the set of IPs that are still blocked (frozen OR in cooldown)
        blocked_ips = set(ips_frozen)
        for sname, recovered_at in list(_site_recovered_at.items()):
            elapsed   = now - recovered_at
            remaining = RECOVERY_COOLDOWN_SECONDS - elapsed
            if remaining > 0:
                print(f"[TemplateExport] Site '{sname}' in post-recovery cooldown — "
                      f"{remaining / 60:.1f} min remaining, skipping.")
                for site in sites:
                    if site.get("site-name") == sname:
                        for dev in site.get("devices", []):
                            if dev.get("ip"):
                                blocked_ips.add(dev["ip"])
            else:
                # Cooldown elapsed — remove tracking entry so it won't print again
                del _site_recovered_at[sname]

        if blocked_ips:
            blocked_names = sorted({
                policies_data[ip]["name"]
                for ip in blocked_ips
                if ip in policies_data
            })
            print(f"[TemplateExport] Blocked devices (frozen/cooldown): {blocked_names}")

        print("[TemplateExport] Starting hourly policy template export...")
        export_all(cc, policies_data, frozen_ips=blocked_ips)

        _previously_frozen_sites = currently_frozen_sites

        print("[TemplateExport] Next export in 1 hour.")
        time.sleep(EXPORT_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if not os.path.exists(POLICIES_FILE):
        print(f"Error: {POLICIES_FILE} not found. Run build_dp_policies.py first.")
        sys.exit(1)

    policies_json = _load_policies_json()
    policies_data = policies_json.get("devices", {})
    if not policies_data:
        print(f"No devices found in {POLICIES_FILE} — nothing to export.")
        sys.exit(0)

    cc = CcConnector(configParser.username, configParser.password)
    export_all(cc, policies_data)


if __name__ == "__main__":
    main()
