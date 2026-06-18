#!/usr/bin/env python3
"""
build_dp_policies.py

Queries every DefensePro device listed in config.ini and writes a
dp_policies.json file that maps each device IP to its policy names.

Output format:
{
    "timestamp": "2026-06-10T12:00:00",
    "devices": {
        "10.213.50.50": {
            "name": "DefensePro-1",
            "policies": ["policy1", "policy2"]
        },
        ...
    }
}
"""

import json
import time
from datetime import datetime

import urllib3

import configParser
from cc_connector import CcConnector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POLICIES_FILE = "dp_policies.json"


def build_policies(cc, sites):
    """
    Iterate all devices in sites and fetch their policy names.

    Returns:
        dict: { dp_ip: {"name": str, "policies": [str, ...]} }
    """
    result = {}
    for site in sites:
        for device in site.get("devices", []):
            dp_name = device.get("name", "unknown")
            dp_ip   = device.get("ip", "")
            if not dp_ip:
                continue

            policies = cc.get_policies_per_dp(dp_ip)
            result[dp_ip] = {
                "name":     dp_name,
                "policies": policies,
            }

    return result


def save_policies(devices_data):
    output = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "devices":   devices_data,
    }
    with open(POLICIES_FILE, "w") as f:
        json.dump(output, f, indent=2)


REFRESH_INTERVAL_SECONDS = 3600  # refresh every hour


def run(cc=None):
    """
    Long-running function intended to be called from a background thread.

    Behaviour:
    - Fetches immediately on every startup.
    - Refreshes the file every hour.
    - Accepts an optional CcConnector instance (so the caller can share the
      existing session instead of creating a second login).
    """
    sites = configParser.sites_config
    if not sites:
        print("[PoliciesMonitor] No sites/devices found in config.ini — skipping.")
        return

    if cc is None:
        cc = CcConnector()

    while True:
        print("[PoliciesMonitor] Updating dp_policies.json...")
        devices_data = build_policies(cc, sites)
        save_policies(devices_data)

        time.sleep(REFRESH_INTERVAL_SECONDS)


def main():
    sites = configParser.sites_config
    if not sites:
        print("No sites/devices found in config.ini — nothing to do.")
        return

    cc = CcConnector()
    devices_data = build_policies(cc, sites)
    save_policies(devices_data)


if __name__ == "__main__":
    main()
