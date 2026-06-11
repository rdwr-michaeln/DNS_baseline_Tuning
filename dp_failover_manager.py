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
        # Track IPs already redistributed so a concurrent trigger cannot
        # fire a second redistribution on top of the first.
        self._redistributed_ips = set()
        # Shared set of all IPs currently considered failed from ANY source
        # (traffic drop, management plane unreachable, interface poll).
        # Written by BaselineTuning and build_dns_baseline; read by
        # build_dns_baseline for site-fully-down detection.
        self._known_failed_ips = set()
        # Optional callback: called with (failed_ip) whenever a device is added
        # to _redistributed_ips.  BaselineTuning uses this to immediately check
        # whether the full site is now down and trigger remaining devices.
        self.on_redistributed = None
        # Optional callback: called with (recovered_ips) after QPS values are
        # fully restored to baseline.  BaselineTuning uses this to trigger the
        # SSH config-paste restore on each recovered device.
        self.on_restored = None

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

    def _find_device_site_and_index(self, dp_ip):
        for site in self.sites_config:
            devices = site.get("devices", [])
            for index, device in enumerate(devices):
                if device.get("ip") == dp_ip:
                    site_name = site.get("site-name")
                    site_ips = {dev.get("ip") for dev in devices}
                    return site_name, site_ips, index
        return None, set(), None

    def _build_baseline_po_map(self, baseline):
        baseline_map = {}
        for site in baseline.get("sites", []):
            for device in site.get("devices", []):
                dp_ip = device.get("ip", "")
                baseline_map[dp_ip] = {
                    po["po_name"]: {
                        "expected_qps": int(po.get("rsDnsProtProfileExpectedQps", 0)),
                        "max_allow_qps": int(po.get("rsDnsProtProfileMaxAllowQps", 0)),
                        "dns_aaaa_quota": str(po["rsDnsProtProfileDnsAaaaQuota"]) if po.get("rsDnsProtProfileDnsAaaaQuota") is not None else None,
                    }
                    for po in device.get("protection_objects", []) if po.get("po_name")
                }
        return baseline_map

    # ------------------------------------------------------------------
    # DP health check
    # ------------------------------------------------------------------

    def is_dp_alive(self, dp_ip, retries=2):
        """Return True if the DP responds to the DNS profile API.
        Uses the _request wrapper so an expired session is renewed automatically.
        Retries up to `retries` times on transient failures before returning False.
        """
        url = f"{self.cc_connector.base_url}/mgmt/device/byip/{dp_ip}/config/rsDnsProtProfileTable?count=1"
        for attempt in range(1, retries + 1):
            try:
                r = self.cc_connector._request('get', url, verify=False, timeout=10)
                if r.status_code == 200:
                    return True
                self.log_manager.debug(
                    f"is_dp_alive {dp_ip}: attempt {attempt} returned HTTP {r.status_code}"
                )
            except Exception as e:
                self.log_manager.debug(
                    f"is_dp_alive {dp_ip}: attempt {attempt} exception: {e}"
                )
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

        failed_site_name, failed_site_ips, failed_index = self._find_device_site_and_index(
            failed_dp_ip
        )

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

            # Build all PO updates first, then lock once, apply all, unlock
            # For dns_aaaa_quota we always use the alive device's own baseline value.
            alive_baseline_map = self._build_baseline_po_map(baseline)
            alive_own_pos = alive_baseline_map.get(alive_ip, {})
            updates = []
            for po_name, failed_vals in failed_po_map.items():
                if po_name not in alive_po_map:
                    print(f"   ⚠️  PO '{po_name}' not on {alive_name} ({alive_ip}), skipping")
                    continue
                current       = alive_po_map[po_name]
                new_expected  = int(current["expected_qps"])  + failed_vals["expected_qps"]
                new_max_allow = int(current["max_allow_qps"]) + failed_vals["max_allow_qps"]
                dns_aaaa_quota = alive_own_pos.get(po_name, {}).get("dns_aaaa_quota")
                print(f"   📈 {alive_name} ({alive_ip})  PO '{po_name}':")
                print(f"      ExpectedQps : {current['expected_qps']} + {failed_vals['expected_qps']} = {new_expected}")
                print(f"      MaxAllowQps : {current['max_allow_qps']} + {failed_vals['max_allow_qps']} = {new_max_allow}")
                updates.append((po_name, new_expected, new_max_allow, dns_aaaa_quota))

            if not updates:
                continue

            if not self.cc_connector.lock_device(alive_ip):
                print(f"      ❌ Could not lock {alive_ip}")
                self.log_manager.error(f"Could not lock device {alive_ip}")
                continue

            try:
                # Step 1: push redistributed QPS values and activate
                for po_name, new_expected, new_max_allow, dns_aaaa_quota in updates:
                    if self.cc_connector.dp_dns_qps_update(alive_ip, po_name, new_expected, new_max_allow):
                        self.log_manager.info(f"Applied QPS redistribution: {alive_ip} PO '{po_name}'")
                    else:
                        print(f"      ❌ dp_dns_qps_update failed for PO '{po_name}'")
                        self.log_manager.error(f"dp_dns_qps_update failed: {alive_ip} PO '{po_name}'")
                self.cc_connector.update_policy(alive_ip)
                # Step 2: push device's own AAAA quota from baseline and activate
                for po_name, new_expected, new_max_allow, dns_aaaa_quota in updates:
                    if dns_aaaa_quota is not None:
                        if not self.cc_connector.dp_dns_aaaa_quota_update(alive_ip, po_name, dns_aaaa_quota):
                            self.log_manager.error(f"AAAA quota update failed: {alive_ip} PO '{po_name}'")
                self.cc_connector.update_policy(alive_ip)
                # Verify final QPS values
                for po_name, new_expected, new_max_allow, dns_aaaa_quota in updates:
                    verified = self._verify_qps_applied(alive_ip, po_name, new_expected, new_max_allow)
                    if verified:
                        print(f"      ✅ PO '{po_name}' applied & verified")
                    else:
                        print(f"      ⚠️  PO '{po_name}' applied but verification MISMATCH — check logs")
            finally:
                self.cc_connector.unlock_device(alive_ip)


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

        baseline_map = self._build_baseline_po_map(baseline)

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

            try:
                # Step 1: restore QPS values and activate
                for po_name, vals in po_targets.items():
                    expected_qps  = vals["expected_qps"]
                    max_allow_qps = vals["max_allow_qps"]
                    print(f"      📉 {po_name}: ExpectedQps={expected_qps}, MaxAllowQps={max_allow_qps}")
                    if self.cc_connector.dp_dns_qps_update(dp_ip, po_name, expected_qps, max_allow_qps):
                        self.log_manager.info(f"Restored {dp_ip} PO '{po_name}' to baseline QPS values")
                    else:
                        print(f"         ❌ dp_dns_qps_update failed")
                        self.log_manager.error(f"Restore QPS failed: {dp_ip} PO '{po_name}'")
                self.cc_connector.update_policy(dp_ip)
                # Step 2: restore AAAA quota and activate
                for po_name, vals in po_targets.items():
                    dns_aaaa_quota = vals.get("dns_aaaa_quota")
                    if dns_aaaa_quota is not None:
                        if self.cc_connector.dp_dns_aaaa_quota_update(dp_ip, po_name, dns_aaaa_quota):
                            print(f"         ✅ Restored")
                            self.log_manager.info(f"Restored {dp_ip} PO '{po_name}' AAAA quota to baseline")
                        else:
                            self.log_manager.error(f"Restore AAAA quota failed: {dp_ip} PO '{po_name}'")
                self.cc_connector.update_policy(dp_ip)
                # Read back every PO on this device to confirm QPS values landed
                for po_name_v, vals_v in po_targets.items():
                    verified = self._verify_qps_applied(
                        dp_ip, po_name_v, vals_v["expected_qps"], vals_v["max_allow_qps"]
                    )
                    if not verified:
                        print(f"   ⚠️  Restore verification MISMATCH for {dp_name} ({dp_ip}) PO '{po_name_v}'")
            finally:
                self.cc_connector.unlock_device(dp_ip)

        print("✅ Restore to baseline complete")
        self.log_manager.info("Restore to baseline complete")
        restored_ips = set(self._redistributed_ips)
        self._redistributed_ips.clear()

        # Notify caller so SSH config-paste can be triggered on recovered devices
        if self.on_restored and restored_ips:
            try:
                self.on_restored(restored_ips)
            except Exception as e:
                self.log_manager.error(f"on_restored callback raised an exception: {e}")

    # ------------------------------------------------------------------
    # Failover / recovery entry points
    # ------------------------------------------------------------------

    def handle_device_failover(self, failed_device_ip):
        """Trigger QPS redistribution when a device is detected as down."""
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
        """Trigger QPS restoration when a device comes back up."""
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
        recovered_site_name, _, recovered_index = self._find_device_site_and_index(recovered_ip)

        if recovered_index is None:
            self.log_manager.warning(f"[LateRedistribute] Cannot find site/index for {recovered_ip}")
            return

        baseline_pos_by_ip = self._build_baseline_po_map(baseline)

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
                try:
                    # Step 1: restore QPS and activate
                    for po_name, vals in recovered_own_pos.items():
                        self.cc_connector.dp_dns_qps_update(
                            recovered_ip, po_name, vals["expected_qps"], vals["max_allow_qps"]
                        )
                    self.cc_connector.update_policy(recovered_ip)
                    # Step 2: restore AAAA quota and activate
                    for po_name, vals in recovered_own_pos.items():
                        if vals.get("dns_aaaa_quota") is not None:
                            self.cc_connector.dp_dns_aaaa_quota_update(
                                recovered_ip, po_name, vals["dns_aaaa_quota"]
                            )
                    self.cc_connector.update_policy(recovered_ip)
                finally:
                    self.cc_connector.unlock_device(recovered_ip)
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
        # Step 2: push device's own AAAA quota and activate
        for po_name, own_vals in recovered_own_pos.items():
            dns_aaaa_quota = own_vals.get("dns_aaaa_quota")
            if dns_aaaa_quota is not None:
                if not self.cc_connector.dp_dns_aaaa_quota_update(recovered_ip, po_name, dns_aaaa_quota):
                    self.log_manager.error(f"[LateRedistribute] AAAA quota update failed {recovered_ip} PO '{po_name}'")
        self.cc_connector.update_policy(recovered_ip)
        self.cc_connector.unlock_device(recovered_ip)



def main():
    print("❌ This module is not intended for standalone execution.")
    print("💡 The DpFailoverManager is automatically triggered by the poll monitors in baseline_tuning.py")
    print("🚀 To start the system, run: python baseline_tuning.py")


if __name__ == "__main__":
    main()
