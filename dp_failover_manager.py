#!/usr/bin/env python3
"""
DefensePro Device Failover Manager

Handles DNS QPS redistribution on device failure and restore on recovery.
All state is kept in dns_baseline.json — no separate backup file.
"""

import configParser
import json
import os
from cc_connector import CcConnector
from logManager import LogManager


class DpFailoverManager:
    def __init__(self):
        self.sites_config = configParser.sites_config
        self.cc_connector = CcConnector()
        self.log_manager = LogManager("DpFailoverManager").get_logger()
        self.baseline_file_path = "dns_baseline.json"
        # Track IPs already redistributed so a concurrent SNMP trap cannot
        # trigger a second redistribution on top of the first.
        self._redistributed_ips = set()
        # Shared set of all IPs currently considered failed from ANY source
        # (traffic drop, management plane unreachable, SNMP trap).
        # Written by BaselineTuning and build_dns_baseline; read by
        # build_dns_baseline for site-fully-down detection.
        self._known_failed_ips = set()
        # Optional callback: called with (failed_ip) whenever a device is added
        # to _redistributed_ips.  BaselineTuning uses this to immediately check
        # whether the full site is now down and trigger remaining devices.
        self.on_redistributed = None

    # ------------------------------------------------------------------
    # Config / baseline helpers
    # ------------------------------------------------------------------

    def _load_baseline(self):
        try:
            if os.path.exists(self.baseline_file_path):
                with open(self.baseline_file_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"❌ Error loading baseline: {e}")
            self.log_manager.error(f"Error loading baseline: {e}")
        return {}

    def _build_alive_data(self, exclude_ip=None):
        """
        Query every DP in sites_config and return alive ones.
        Returns: { dp_ip: {"name": str, "pos": [po dicts]} }
        """
        alive_data = {}
        for site in self.sites_config:
            for device in site.get("devices", []):
                dp_ip   = device.get("ip", "")
                dp_name = device.get("name", "unknown")
                if dp_ip == exclude_ip:
                    continue
                if self.is_dp_alive(dp_ip):
                    dns_data = self.cc_connector.get_po_dns_per_dp(dp_ip)
                    alive_data[dp_ip] = {"name": dp_name, "pos": dns_data.get(dp_ip, [])}
        return alive_data

    # ------------------------------------------------------------------
    # DP health check
    # ------------------------------------------------------------------

    def is_dp_alive(self, dp_ip):
        """Return True if the DP responds to the DNS profile API."""
        try:
            url = f"{self.cc_connector.base_url}/mgmt/device/byip/{dp_ip}/config/rsDnsProtProfileTable?count=1"
            r = self.cc_connector.session.get(url, verify=False, timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Read-back validation
    # ------------------------------------------------------------------

    def _verify_qps_applied(self, dp_ip, po_name, expected_qps, max_allow_qps):
        """
        Re-query the device and confirm the written QPS values are live.
        Returns True if the device reports the expected values, False otherwise.
        """
        try:
            dns_data = self.cc_connector.get_po_dns_per_dp(dp_ip)
            for po in dns_data.get(dp_ip, []):
                if po.get("po_name") == po_name:
                    actual_exp = int(po.get("expected_qps", -1))
                    actual_max = int(po.get("max_allow_qps", -1))
                    if actual_exp == expected_qps and actual_max == max_allow_qps:
                        self.log_manager.info(
                            f"[Verify] ✅ {dp_ip} PO '{po_name}' confirmed: "
                            f"ExpectedQps={actual_exp}, MaxAllowQps={actual_max}"
                        )
                        return True
                    else:
                        self.log_manager.warning(
                            f"[Verify] ⚠️  {dp_ip} PO '{po_name}' MISMATCH — "
                            f"sent ExpectedQps={expected_qps}/MaxAllowQps={max_allow_qps}, "
                            f"device reports ExpectedQps={actual_exp}/MaxAllowQps={actual_max}"
                        )
                        return False
            self.log_manager.warning(
                f"[Verify] ⚠️  PO '{po_name}' not found in read-back for {dp_ip}"
            )
            return False
        except Exception as e:
            self.log_manager.error(f"[Verify] Read-back failed for {dp_ip} PO '{po_name}': {e}")
            return False

    # ------------------------------------------------------------------
    # Redistribution (failure)
    # ------------------------------------------------------------------

    def redistribute_qps_from_baseline(self, failed_dp_ip, baseline, alive_data):
        """
        On DP failure: read the failed DP's POs from dns_baseline.json and
        add those QPS values to the device at the SAME POSITION in every other alive site.

        Position mapping example (2 sites, 2 devices each):
            Haifa   index 0 = DP-3  →  Tel-Aviv index 0 = DP-1
            Haifa   index 1 = DP-4  →  Tel-Aviv index 1 = DP-2
        """
        if failed_dp_ip in self._redistributed_ips:
            msg = f"Redistribution for {failed_dp_ip} already applied — skipping duplicate call"
            print(f"⏭️  {msg}")
            self.log_manager.info(msg)
            return

        # Find the failed DP's site and its index within that site
        failed_site_name = None
        failed_site_ips  = set()
        failed_index     = None
        for site in self.sites_config:
            devices = site.get("devices", [])
            for idx, d in enumerate(devices):
                if d.get("ip") == failed_dp_ip:
                    failed_site_name = site.get("site-name")
                    failed_site_ips  = {dev.get("ip") for dev in devices}
                    failed_index     = idx
                    break
            if failed_index is not None:
                break

        if failed_site_name is None:
            self.log_manager.warning(f"Could not find site for {failed_dp_ip} — falling back to all-alive redistribution")
        else:
            print(f"ℹ️  Failed DP site: '{failed_site_name}' index {failed_index} — redistributing to index {failed_index} in other sites")
            self.log_manager.info(f"Failed DP site: '{failed_site_name}' index {failed_index}")

        # Build set of target IPs: device at the same index in every OTHER site
        target_ips = set()
        if failed_index is not None:
            for site in self.sites_config:
                if site.get("site-name") == failed_site_name:
                    continue  # skip the failed site
                devices = site.get("devices", [])
                if failed_index < len(devices):
                    target_ip = devices[failed_index].get("ip")
                    if target_ip:
                        target_ips.add(target_ip)
                        self.log_manager.info(f"Target: {devices[failed_index].get('name')} ({target_ip}) in site '{site.get('site-name')}'")
                else:
                    self.log_manager.warning(f"Site '{site.get('site-name')}' has no device at index {failed_index} — skipped")
        else:
            # fallback: all alive devices not in the failed site
            target_ips = {ip for ip in alive_data if ip not in failed_site_ips}

        # Read failed DP's baseline POs
        failed_dp_name = failed_dp_ip
        failed_pos = []
        for site in baseline.get("sites", []):
            for device in site.get("devices", []):
                if device.get("ip") == failed_dp_ip:
                    failed_dp_name = device.get("dp_name", failed_dp_ip)
                    failed_pos = device.get("protection_objects", [])
                    break

        if not failed_pos:
            msg = f"No baseline POs for {failed_dp_name} ({failed_dp_ip}) — skipping redistribution"
            print(f"⚠️  {msg}")
            self.log_manager.warning(msg)
            return

        failed_po_map = {
            po["po_name"]: {
                "expected_qps": int(po.get("rsDnsProtProfileExpectedQps", 0)),
                "max_allow_qps": int(po.get("rsDnsProtProfileMaxAllowQps", 0)),
            }
            for po in failed_pos if po.get("po_name")
        }

        print(f"🔄 Redistributing QPS from {failed_dp_name} ({failed_dp_ip}) to position-matched DPs...")
        self.log_manager.info(f"Redistributing QPS from {failed_dp_name} ({failed_dp_ip})")

        # Warn for each position-matched target that is currently down
        for target_ip in target_ips:
            if target_ip not in alive_data:
                # Find its name from sites_config
                target_name = target_ip
                for site in self.sites_config:
                    for d in site.get("devices", []):
                        if d.get("ip") == target_ip:
                            target_name = d.get("name", target_ip)
                            break
                print(f"   ⚠️  Position-matched target {target_name} ({target_ip}) is also down — no alive target at index {failed_index}")
                self.log_manager.warning(f"Position-matched target {target_name} ({target_ip}) is also down — skipping index {failed_index}")

        for alive_ip, alive_info in alive_data.items():
            if alive_ip not in target_ips:
                print(f"   ⏭️  {alive_info['name']} ({alive_ip}) skipped — not the position-matched target")
                self.log_manager.info(f"Skipping non-target device {alive_ip} ({alive_info['name']})")
                continue

            alive_name   = alive_info["name"]
            alive_po_map = {po["po_name"]: po for po in alive_info["pos"]}

            for po_name, failed_vals in failed_po_map.items():
                if po_name not in alive_po_map:
                    print(f"   ⚠️  PO '{po_name}' not on {alive_name} ({alive_ip}), skipping")
                    continue

                current       = alive_po_map[po_name]
                new_expected  = int(current["expected_qps"])  + failed_vals["expected_qps"]
                new_max_allow = int(current["max_allow_qps"]) + failed_vals["max_allow_qps"]

                print(f"   📈 {alive_name} ({alive_ip})  PO '{po_name}':")
                print(f"      ExpectedQps : {current['expected_qps']} + {failed_vals['expected_qps']} = {new_expected}")
                print(f"      MaxAllowQps : {current['max_allow_qps']} + {failed_vals['max_allow_qps']} = {new_max_allow}")

                if self.cc_connector.lock_device(alive_ip):
                    if self.cc_connector.dp_dns_qps_update(alive_ip, po_name, new_expected, new_max_allow):
                        self.cc_connector.update_policy(alive_ip)
                        verified = self._verify_qps_applied(alive_ip, po_name, new_expected, new_max_allow)
                        if verified:
                            print(f"      ✅ Applied & verified")
                        else:
                            print(f"      ⚠️  Applied but verification MISMATCH — check logs")
                        self.log_manager.info(f"Applied QPS redistribution: {alive_ip} PO '{po_name}'")
                    else:
                        print(f"      ❌ dp_dns_qps_update failed")
                        self.log_manager.error(f"dp_dns_qps_update failed: {alive_ip} PO '{po_name}'")
                else:
                    print(f"      ❌ Could not lock {alive_ip}")
                    self.log_manager.error(f"Could not lock device {alive_ip}")


        self._redistributed_ips.add(failed_dp_ip)
        if self.on_redistributed:
            try:
                self.on_redistributed(failed_dp_ip)
            except Exception as _cb_exc:
                self.log_manager.error(f"on_redistributed callback error: {_cb_exc}")

    # ------------------------------------------------------------------
    # Restore (recovery)
    # ------------------------------------------------------------------

    def restore_qps_from_baseline(self, baseline, alive_data):
        """
        After all DPs recover: push the baseline QPS values back to every
        alive DP so the redistributed values are undone.
        """
        print("🔁 Restoring all DPs to baseline QPS values...")
        self.log_manager.info("Restoring all DPs to baseline QPS values")

        baseline_map = {}
        for site in baseline.get("sites", []):
            for device in site.get("devices", []):
                dp_ip = device.get("ip", "")
                baseline_map[dp_ip] = {
                    po["po_name"]: {
                        "expected_qps": int(po.get("rsDnsProtProfileExpectedQps", 0)),
                        "max_allow_qps": int(po.get("rsDnsProtProfileMaxAllowQps", 0)),
                    }
                    for po in device.get("protection_objects", []) if po.get("po_name")
                }

        for dp_ip, dp_info in alive_data.items():
            dp_name    = dp_info["name"]
            po_targets = baseline_map.get(dp_ip, {})
            if not po_targets:
                print(f"   ⚠️  No baseline entry for {dp_name} ({dp_ip}), skipping")
                continue

            print(f"   🔄 Restoring {dp_name} ({dp_ip}): {len(po_targets)} PO(s)...")
            if not self.cc_connector.lock_device(dp_ip):
                print(f"   ❌ Could not lock {dp_ip}")
                self.log_manager.error(f"Could not lock device {dp_ip} during restore")
                continue

            for po_name, vals in po_targets.items():
                expected_qps  = vals["expected_qps"]
                max_allow_qps = vals["max_allow_qps"]
                print(f"      📉 {po_name}: ExpectedQps={expected_qps}, MaxAllowQps={max_allow_qps}")
                if self.cc_connector.dp_dns_qps_update(dp_ip, po_name, expected_qps, max_allow_qps):
                    print(f"         ✅ Restored")
                    self.log_manager.info(f"Restored {dp_ip} PO '{po_name}' to baseline values")
                else:
                    print(f"         ❌ dp_dns_qps_update failed")
                    self.log_manager.error(f"Restore failed: {dp_ip} PO '{po_name}'")

            self.cc_connector.update_policy(dp_ip)
            # Read back every PO on this device to confirm values landed
            for po_name_v, vals_v in po_targets.items():
                verified = self._verify_qps_applied(
                    dp_ip, po_name_v, vals_v["expected_qps"], vals_v["max_allow_qps"]
                )
                if not verified:
                    print(f"   ⚠️  Restore verification MISMATCH for {dp_name} ({dp_ip}) PO '{po_name_v}'")

        print("✅ Restore to baseline complete")
        self.log_manager.info("Restore to baseline complete")
        self._redistributed_ips.clear()

    # ------------------------------------------------------------------
    # SNMP trap entry points
    # ------------------------------------------------------------------

    def handle_device_failover(self, failed_device_ip):
        """Called on M_07630 (DefensePro DOWN) SNMP trap."""
        print(f"🚨 Failover triggered for {failed_device_ip}")
        self.log_manager.warning(f"Failover triggered for {failed_device_ip}")
        try:
            baseline   = self._load_baseline()
            alive_data = self._build_alive_data(exclude_ip=failed_device_ip)
            if not alive_data:
                print("⚠️  No alive devices found — skipping redistribution")
                return
            self.redistribute_qps_from_baseline(failed_device_ip, baseline, alive_data)
            print(f"✅ Failover complete for {failed_device_ip}")
            self.log_manager.info(f"Failover complete for {failed_device_ip}")
        except Exception as e:
            print(f"❌ Error during failover: {e}")
            self.log_manager.error(f"Failover failed for {failed_device_ip}: {e}")

    def handle_device_recovery(self, recovered_device_ip):
        """Called on M_07631 (DefensePro UP) SNMP trap."""
        print(f"✅ Recovery triggered for {recovered_device_ip}")
        self.log_manager.info(f"Recovery triggered for {recovered_device_ip}")
        try:
            baseline   = self._load_baseline()
            alive_data = self._build_alive_data()
            if not alive_data:
                print("⚠️  No alive devices found — skipping restore")
                return
            self.restore_qps_from_baseline(baseline, alive_data)
            print(f"✅ Recovery complete for {recovered_device_ip}")
            self.log_manager.info(f"Recovery complete for {recovered_device_ip}")
        except Exception as e:
            print(f"❌ Error during recovery: {e}")
            self.log_manager.error(f"Recovery failed for {recovered_device_ip}: {e}")

    def apply_late_redistribution_to_device(self, recovered_ip, alive_data, baseline):
        """
        Called when a device comes back online while one or more partner sites are
        still fully down (all their devices in _redistributed_ips).

        Finds the position-matched failed device in each fully-down partner site
        and applies: recovered_own_baseline_QPS + sum(partner_baseline_QPS) to the
        recovered device.  Devices in the same site as the recovered device are
        never touched.
        """
        # Find recovered device's site and position index
        recovered_site_name = None
        recovered_index     = None
        for site in self.sites_config:
            for idx, d in enumerate(site.get("devices", [])):
                if d.get("ip") == recovered_ip:
                    recovered_site_name = site.get("site-name")
                    recovered_index     = idx
                    break
            if recovered_index is not None:
                break

        if recovered_index is None:
            self.log_manager.warning(f"[LateRedistribute] Cannot find site/index for {recovered_ip}")
            return

        # Build baseline PO map: ip → {po_name: {expected_qps, max_allow_qps}}
        baseline_pos_by_ip = {}
        for site in baseline.get("sites", []):
            for device in site.get("devices", []):
                ip = device.get("ip", "")
                baseline_pos_by_ip[ip] = {
                    po["po_name"]: {
                        "expected_qps":  int(po.get("rsDnsProtProfileExpectedQps", 0)),
                        "max_allow_qps": int(po.get("rsDnsProtProfileMaxAllowQps", 0)),
                    }
                    for po in device.get("protection_objects", []) if po.get("po_name")
                }

        recovered_own_pos = baseline_pos_by_ip.get(recovered_ip, {})
        if not recovered_own_pos:
            self.log_manager.warning(f"[LateRedistribute] No baseline POs for {recovered_ip}")
            return

        # Accumulate extra QPS from all fully-failed partner sites
        extra_pos = {}  # po_name → {expected_qps, max_allow_qps} cumulative
        for site in self.sites_config:
            if site.get("site-name") == recovered_site_name:
                continue
            devices  = site.get("devices", [])
            site_ips = [d.get("ip") for d in devices if d.get("ip")]
            if not all(ip in self._redistributed_ips for ip in site_ips):
                continue  # site not fully failed — skip
            if recovered_index >= len(devices):
                continue
            partner_ip   = devices[recovered_index].get("ip")
            partner_name = devices[recovered_index].get("name", partner_ip)
            if not partner_ip:
                continue
            partner_pos = baseline_pos_by_ip.get(partner_ip, {})
            self.log_manager.info(
                f"[LateRedistribute] Site '{site.get('site-name')}' fully down — "
                f"absorbing QPS from {partner_name} ({partner_ip})"
            )
            for po_name, vals in partner_pos.items():
                if po_name not in extra_pos:
                    extra_pos[po_name] = {"expected_qps": 0, "max_allow_qps": 0}
                extra_pos[po_name]["expected_qps"]  += vals["expected_qps"]
                extra_pos[po_name]["max_allow_qps"] += vals["max_allow_qps"]

        recovered_name = alive_data.get(recovered_ip, {}).get("name", recovered_ip)

        if not extra_pos:
            # No fully-failed partner sites — restore to own baseline only
            self.log_manager.info(
                f"[LateRedistribute] No active failovers affect {recovered_ip} — restoring own baseline"
            )
            print(f"   📉 {recovered_name} ({recovered_ip}): no active failovers — restoring own baseline")
            if self.cc_connector.lock_device(recovered_ip):
                for po_name, vals in recovered_own_pos.items():
                    self.cc_connector.dp_dns_qps_update(
                        recovered_ip, po_name, vals["expected_qps"], vals["max_allow_qps"]
                    )
                self.cc_connector.update_policy(recovered_ip)
            return

        # Apply own baseline + accumulated partner QPS
        print(f"   📈 Late redistribution for {recovered_name} ({recovered_ip}):")
        self.log_manager.info(f"[LateRedistribute] Applying to {recovered_ip}")
        if not self.cc_connector.lock_device(recovered_ip):
            print(f"   ❌ Could not lock {recovered_ip}")
            self.log_manager.error(f"[LateRedistribute] Could not lock {recovered_ip}")
            return

        for po_name, own_vals in recovered_own_pos.items():
            extra = extra_pos.get(po_name, {"expected_qps": 0, "max_allow_qps": 0})
            new_expected  = own_vals["expected_qps"]  + extra["expected_qps"]
            new_max_allow = own_vals["max_allow_qps"] + extra["max_allow_qps"]
            print(
                f"      PO '{po_name}': {own_vals['expected_qps']} + {extra['expected_qps']} = {new_expected}"
            )
            if self.cc_connector.dp_dns_qps_update(recovered_ip, po_name, new_expected, new_max_allow):
                self._verify_qps_applied(recovered_ip, po_name, new_expected, new_max_allow)
                print(f"         ✅ Applied")
                self.log_manager.info(
                    f"[LateRedistribute] {recovered_ip} PO '{po_name}': ExpectedQps={new_expected}"
                )
            else:
                print(f"         ❌ Update failed")
                self.log_manager.error(f"[LateRedistribute] Update failed {recovered_ip} PO '{po_name}'")
        self.cc_connector.update_policy(recovered_ip)



def main():
    """
    This module is designed to be integrated with SNMP trap handling.
    It should not be run standalone in production.
    """
    print("❌ This module is not intended for standalone execution.")
    print("💡 The DpFailoverManager is automatically triggered by SNMP traps in baseline_tuning.py")
    print("🚀 To start the automatic failover system, run: python baseline_tuning.py")
    print()
    print("📋 Integration details:")
    print("   - M_07630 SNMP traps (DefensePro DOWN) → Automatic failover")
    print("   - M_07631 SNMP traps (DefensePro UP) → Recovery validation")
    print("   - All DNS QPS redistribution is handled automatically")


if __name__ == "__main__":
    main()