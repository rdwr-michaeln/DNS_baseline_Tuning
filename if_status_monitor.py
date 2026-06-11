"""
Interface Status Monitor

Fetches the ifTable from DefensePro devices via the CC REST API and saves
the snapshot to dns_baseline.json under the "interface_snapshot" key.

The snapshot is read every 20 seconds by if_poll_monitor to detect
interface operational-status changes.

ifOperStatus values: "1" = up, "2" = down.
"""

import json
import os
from datetime import datetime

OPER_UP   = "1"
OPER_DOWN = "2"

BASELINE_FILE = "dns_baseline.json"


def _monitored_index_strings(monitored_indexes):
    return {str(index) for index in monitored_indexes}


def _filter_monitored_interfaces(ifaces, monitored_indexes):
    if not monitored_indexes:
        return ifaces
    monitored = _monitored_index_strings(monitored_indexes)
    return [iface for iface in ifaces if iface.get("ifIndex") in monitored]


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch_dp_interfaces(cc, dp_ip):
    """
    Fetch the ifTable for a single DP.
    Returns a list of interface dicts, or [] on error.
    """
    return cc.get_if_table(dp_ip)


def snapshot_all_interfaces(cc, sites, logger=None):
    """
    Fetch interface status for every DP listed in *sites* (sites_config format).

    Returns:
        { dp_ip: [interface_dict, ...] }

    Also prints a one-line summary per device showing interface counts.
    """
    devices = {}
    for site in sites:
        site_name = site.get("site-name", "?")
        for device in site.get("devices", []):
            dp_ip   = device.get("ip", "")
            dp_name = device.get("name", "unknown")
            if not dp_ip:
                continue

            ifaces = fetch_dp_interfaces(cc, dp_ip)
            monitored = device.get("monitored_if_indexes") or set()
            ifaces = _filter_monitored_interfaces(ifaces, monitored)
            devices[dp_ip] = ifaces

            up   = sum(1 for i in ifaces if i.get("ifOperStatus") == OPER_UP)
            down = sum(1 for i in ifaces if i.get("ifOperStatus") == OPER_DOWN)
            msg = (
                f"  [{site_name}] {dp_name} ({dp_ip}): "
                f"{len(ifaces)} interfaces — {up} up / {down} down"
            )
            print(msg)
            if logger:
                logger.info(msg)

    return devices


# ---------------------------------------------------------------------------
# Persist
# ---------------------------------------------------------------------------

def save_interface_devices(baseline_file, devices):
    """
    Write *devices* into dns_baseline.json under interface_snapshot.devices.
    All other top-level keys in the file are preserved.
    """
    data = {}
    if os.path.exists(baseline_file):
        try:
            with open(baseline_file, "r") as f:
                data = json.load(f)
        except Exception:
            pass

    data.setdefault("interface_snapshot", {})
    data["interface_snapshot"]["fetched_at"] = datetime.now().isoformat()
    data["interface_snapshot"]["devices"]    = devices

    with open(baseline_file, "w") as f:
        json.dump(data, f, indent=2)


def load_interface_devices(baseline_file=BASELINE_FILE):
    """
    Load the saved interface devices snapshot from dns_baseline.json.

    Returns:
        { dp_ip: [interface_dict, ...] }  — empty dict if the key is absent.
    """
    if not os.path.exists(baseline_file):
        return {}
    try:
        with open(baseline_file, "r") as f:
            data = json.load(f)
        return data.get("interface_snapshot", {}).get("devices", {})
    except Exception:
        return {}


def update_interface_devices(cc, alive_ips, baseline_file=BASELINE_FILE, logger=None,
                             monitored_indexes_map=None):
    """
    Refresh the interface snapshot for *alive_ips* only.
    Devices not in *alive_ips* (e.g. currently down) retain their last-known
    snapshot entry so LINK_UP checks can still compare against it.

    monitored_indexes_map : optional { ip: set(int) } from configParser.
        When provided, only the listed ifIndex values are stored per device.
        An empty set means all interfaces are stored (no filter).

    Called every poll cycle from build_dns_baseline regardless of failover state.
    Returns the merged devices dict.
    """
    saved = load_interface_devices(baseline_file)
    updated = False
    for dp_ip in alive_ips:
        ifaces = fetch_dp_interfaces(cc, dp_ip)
        if ifaces:
            monitored = (monitored_indexes_map or {}).get(dp_ip) or set()
            ifaces = _filter_monitored_interfaces(ifaces, monitored)
            saved[dp_ip] = ifaces
            updated = True
    if updated:
        save_interface_devices(baseline_file, saved)
        if logger:
            logger.debug(f"[IfSnapshot] Interface snapshot refreshed for: {list(alive_ips)}")
    return saved


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

def check_interface_change(cc, dp_ip, saved_devices, direction, logger=None, monitored_indexes=None):
    """
    Confirm via a live ifTable API call that at least one interface on *dp_ip*
    changed operational status in the expected *direction*.

    Parameters
    ----------
    cc                : CcConnector instance
    dp_ip             : IP of the DefensePro device to check
    saved_devices     : { dp_ip: [if_dict, ...] } as returned by load_interface_devices()
    direction         : "down" → look for up→down transitions
                        "up"   → look for down→up transitions
    logger            : optional logger
    monitored_indexes : optional set of ifIndex ints to restrict the check to.
                        When None or empty, all interfaces are checked.

    Returns
    -------
    (changed: bool, current_ifaces: list)
        changed        – True when a matching transition is found, or when the
                         check cannot be performed (fail-open).
        current_ifaces – live ifTable list; [] if the API call failed.
    """
    saved_ifaces = saved_devices.get(dp_ip, [])

    if not saved_ifaces:
        msg = (
            f"[IfCheck] No saved interface snapshot for {dp_ip} — "
            "skipping check (fail-open)"
        )
        print(msg)
        if logger:
            logger.warning(msg)
        return True, []

    current_ifaces = fetch_dp_interfaces(cc, dp_ip)

    if not current_ifaces:
        msg = (
            f"[IfCheck] ifTable API returned empty for {dp_ip} — "
            "skipping check (fail-open)"
        )
        print(msg)
        if logger:
            logger.warning(msg)
        return True, []

    saved_by_idx   = {str(i.get("ifIndex")): i for i in saved_ifaces}
    current_by_idx = {str(i.get("ifIndex")): i for i in current_ifaces}

    # Restrict to the configured monitored indexes (if any are specified)
    # Normalize to strings because ifIndex may come as int or str from the API.
    if monitored_indexes:
        _monitored_str = _monitored_index_strings(monitored_indexes)
        current_by_idx = {k: v for k, v in current_by_idx.items() if k in _monitored_str}
        if not current_by_idx:
            msg = (
                f"[IfCheck] {dp_ip}: none of the monitored ifIndexes "
                f"{sorted(monitored_indexes)} found in live ifTable — "
                "skipping check (fail-open)"
            )
            print(msg)
            if logger:
                logger.warning(msg)
            return True, current_ifaces

    _label = {OPER_UP: "up", OPER_DOWN: "down"}
    changed = []

    for idx, cur in current_by_idx.items():
        prev = saved_by_idx.get(idx)
        if prev is None:
            continue

        p_status = prev.get("ifOperStatus")
        c_status = cur.get("ifOperStatus")
        if p_status == c_status:
            continue

        descr = cur.get("ifDescr", f"ifIndex={idx}")

        if direction == "down" and p_status == OPER_UP and c_status == OPER_DOWN:
            changed.append((idx, descr, p_status, c_status))
        elif direction == "up" and p_status == OPER_DOWN and c_status == OPER_UP:
            changed.append((idx, descr, p_status, c_status))

    if changed:
        for idx, descr, p_s, c_s in changed:
            msg = (
                f"[IfCheck] ✅ {dp_ip} interface '{descr}' (ifIndex {idx}): "
                f"ifOperStatus {_label.get(p_s, p_s)} → {_label.get(c_s, c_s)} "
                f"— confirmed {direction}"
            )
            print(msg)
            if logger:
                logger.info(msg)
        return True, current_ifaces

    msg = (
        f"[IfCheck] ⚠️  {dp_ip}: no interface confirmed as '{direction}' "
        "by live API — trap may be stale or spurious"
    )
    print(msg)
    if logger:
        logger.warning(msg)
    return False, current_ifaces
