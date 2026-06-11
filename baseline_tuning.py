import configParser
from cc_connector import CcConnector
from validation import ConfigValidator
from dp_failover_manager import DpFailoverManager
import build_dns_baseline
import build_dp_policies
import export_policy_templates
import dp_config_restore
import if_status_monitor
import if_poll_monitor
import threading
import urllib3
import traceback
from logManager import LogManager
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaselineTuning:
    def __init__(self):
        self.ccc = CcConnector(configParser.username, configParser.password)
        self.lm = LogManager("BaselineTuning").get_logger()
        self.thread_lock = threading.Lock()

        # Initialize configuration validator and failover manager
        self.validator = ConfigValidator()
        self.validator.initialize_configuration()
        self.failover_manager = DpFailoverManager()
        # Register callback: when DNS baseline monitor redistributes a device,
        # immediately check whether the full site is now down and trigger
        # redistribution for the remaining devices without waiting for the next
        # traffic monitor poll cycle.
        self.failover_manager.on_redistributed = self._on_device_redistributed
        # Register SSH config-paste restore: fires after QPS values are restored
        # to baseline. Runs in a daemon thread to avoid blocking the main loop.
        # Push config to ALL DPs (not just the ones that recovered) so every
        # device has a consistent baseline config after a failover cycle.
        def _on_restored(recovered_ips):
            all_ips = [
                dev.get("ip")
                for site in configParser.sites_config
                for dev in site.get("devices", [])
                if dev.get("ip")
            ]
            t = threading.Thread(
                target=dp_config_restore.restore_site,
                args=(all_ips, configParser.sites_config),
                daemon=True,
                name="DpConfigRestore",
            )
            t.start()
        self.failover_manager.on_restored = _on_restored
        
        # Start the DNS baseline monitor in a background thread — pass the shared
        # failover_manager so both paths use the same _redistributed_ips guard.
        baseline_thread = threading.Thread(
            target=build_dns_baseline.run,
            args=(self.failover_manager,),
            daemon=True,
            name="DnsBaselineMonitor"
        )
        baseline_thread.start()
        self.lm.info("DNS Baseline Monitor started in background thread")

        # Start the DP policies monitor — fetches on startup if file is missing,
        # then refreshes once a day at midnight.  Shares the same CC session.
        policies_thread = threading.Thread(
            target=build_dp_policies.run,
            args=(self.ccc,),
            daemon=True,
            name="DpPoliciesMonitor"
        )
        policies_thread.start()
        self.lm.info("DP Policies Monitor started in background thread")

        # Start the policy-template export monitor — exports/refreshes all
        # templates in dns_baselines/ every hour. Shares the same CC session
        # and failover state so frozen sites are skipped automatically.
        templates_thread = threading.Thread(
            target=export_policy_templates.run,
            args=(self.ccc, self.failover_manager),
            daemon=True,
            name="PolicyTemplateExport"
        )
        templates_thread.start()
        self.lm.info("Policy Template Export started in background thread")

        # Per-device traffic state: { ip: "healthy" | "failed" } — used by traffic monitor
        self._traffic_state = {}
        # Per-device interface-poll DOWN state: { ip: "up" | "down" }
        self._if_poll_device_state = {}
        # Per-site traffic failover state: { site_name: "healthy" | "failed" }
        self._site_traffic_state = {}
        # Pending traffic failover timers: { site_name: threading.Timer }
        self._traffic_pending_timers = {}
        # Pending DNS-baseline failover timers: { site_name: threading.Timer }
        self._dns_baseline_pending_timers = {}

        # Start the traffic utilization monitor (polls every 3 minutes)
        traffic_thread = threading.Thread(target=self._traffic_monitor_loop, daemon=True, name="TrafficMonitor")
        traffic_thread.start()
        self.lm.info("Traffic Monitor started in background thread")

        # Start the interface-poll monitor — reads dns_baseline.json every 20 s
        # and fires failover/recovery callbacks on interface state transitions.
        if_poll_thread = threading.Thread(
            target=if_poll_monitor.run,
            args=(self._on_interface_down, self._on_interface_up),
            kwargs={"logger": self.lm},
            daemon=True,
            name="IfPollMonitor",
        )
        if_poll_thread.start()
        self.lm.info("Interface Poll Monitor started in background thread")

    # ------------------------------------------------------------------
    # Interface poll monitor callbacks
    # ------------------------------------------------------------------

    def _on_interface_down(self, dp_ip):
        """
        Called by if_poll_monitor after the configured down_delay_minutes
        have elapsed and the interface is confirmed still down.
        Uses the same site-wide failover logic as the traffic path.
        """
        if not configParser.trigger_interface_down:
            self.lm.info(f"interface_down trigger is disabled — ignoring poll DOWN for {dp_ip}")
            return

        self._if_poll_device_state[dp_ip] = "down"
        self.failover_manager._known_failed_ips.add(dp_ip)

        site = self._get_site_for_ip(dp_ip)
        if site is None:
            self.lm.warning(f"[IfPoll] No site found for {dp_ip} — skipping failover")
            return

        site_name = site.get("site-name", dp_ip)
        site_ips  = [d.get("ip") for d in site.get("devices", []) if d.get("ip")]
        all_down  = all(self._is_device_failed(ip) for ip in site_ips)

        if not all_down:
            down_count = sum(1 for ip in site_ips if self._is_device_failed(ip))
            self.lm.warning(
                f"[IfPoll] {dp_ip} confirmed DOWN but site '{site_name}' not fully down "
                f"({down_count}/{len(site_ips)}) — waiting for remaining devices"
            )
            return

        self.lm.warning(f"[IfPoll] All devices in site '{site_name}' are down — triggering failover")
        try:
            for sip in site_ips:
                if self.validator.dp_status_check(sip, "down", self.lm):
                    self.failover_manager.handle_device_failover(sip)
                else:
                    self.lm.warning(f"[IfPoll] Validation failed for {sip} — skipping failover")
        except Exception as e:
            self.lm.error(f"[IfPoll] Failover error for site '{site_name}': {e}")
            self.lm.error(traceback.format_exc())

    def _on_interface_up(self, dp_ip):
        """
        Called by if_poll_monitor immediately when an interface comes back up.
        Clears the device's failed state and restores QPS if a failover was active.
        """
        self._if_poll_device_state[dp_ip] = "up"
        self.failover_manager._known_failed_ips.discard(dp_ip)

        device_was_failed = (
            dp_ip in self.failover_manager._redistributed_ips or
            self._traffic_state.get(dp_ip) == "failed"
        )
        if not device_was_failed:
            self.lm.info(
                f"[IfPoll] {dp_ip} interface up — no active failover, nothing to restore"
            )
            return

        try:
            if self.validator.dp_status_check(dp_ip, "up", self.lm):
                self.lm.info(f"[IfPoll] {dp_ip} validated up — restoring baseline QPS")
                self.failover_manager.handle_device_recovery(dp_ip)
            else:
                self.lm.warning(f"[IfPoll] {dp_ip} failed validation on UP — skipping restore")
        except Exception as e:
            self.lm.error(f"[IfPoll] Recovery error for {dp_ip}: {e}")

    # ------------------------------------------------------------------
    # Traffic utilization monitor
    # ------------------------------------------------------------------

    def _on_device_redistributed(self, failed_ip):
        """Callback fired by DpFailoverManager immediately after a device is
        added to _redistributed_ips (e.g. by the DNS baseline monitor).
        Checks whether the full site is now down and, if so, schedules
        handle_device_failover for the remaining devices after the configured
        trigger_mgmt_down_delay window (0 = immediately).
        """
        site = self._get_site_for_ip(failed_ip)
        if site is None:
            return
        site_name    = site.get("site-name", failed_ip)
        all_site_ips = [d.get("ip") for d in site.get("devices", []) if d.get("ip")]

        if not all(self._is_device_failed(ip) for ip in all_site_ips):
            return  # site not fully down yet

        self.lm.warning(
            f"[on_redistributed] Site '{site_name}' is now fully down — triggering failover immediately"
        )

        # Cancel any existing pending timer for this site
        existing = self._dns_baseline_pending_timers.pop(site_name, None)
        if existing:
            existing.cancel()

        for ip in all_site_ips:
            if ip == failed_ip:
                continue  # already redistributed
            if ip in self.failover_manager._redistributed_ips:
                continue  # already handled
            # NOTE: do NOT acquire thread_lock here — this callback is called
            # synchronously from inside handle_device_failover, which may already
            # be running under thread_lock (e.g. from the traffic monitor loop).
            # Trying to re-acquire thread_lock here would deadlock the same thread.
            # _redistributed_ips already guards against duplicate redistribution.
            self.failover_manager.handle_device_failover(ip)

    def _is_device_failed(self, ip):
        """Return True if the device is confirmed down by ANY trigger."""
        return (
            self._if_poll_device_state.get(ip) == "down" or
            self._traffic_state.get(ip) == "failed" or
            ip in self.failover_manager._redistributed_ips
        )

    def _get_site_for_ip(self, ip):
        """Return the site dict that contains *ip*, or None."""
        for site in self.failover_manager.sites_config:
            for device in site.get("devices", []):
                if device.get("ip") == ip:
                    return site
        return None

    def _traffic_monitor_loop(self):
        """Background thread: poll inBound traffic every 3 minutes.

        Drop calculation (per device)
        ─────────────────────────────
        configured_baseline  = inbound_baseline_kbps from config.ini for this IP
        current_avg          = average of the inBound samples from the current poll
        drop %               = (configured_baseline - current_avg) / configured_baseline × 100

        Healthy → failed : drop % ≥ inbound_drop_threshold_percent → handle_device_failover
        Failed  → healthy: current_avg ≥ configured_baseline × (1 - threshold/100)
                           → handle_device_recovery
        """
        threshold  = configParser.inbound_drop_threshold_percent
        baselines  = configParser.inbound_baselines   # { ip: kbps }
        poll_secs  = 30  # 30 seconds

        while True:
            try:
                time.sleep(poll_secs)

                if not configParser.trigger_traffic_decrease:
                    self.lm.debug("[TrafficMonitor] traffic_decrease trigger is disabled, skipping poll")
                    continue

                self.lm.info("[TrafficMonitor] Starting traffic utilization poll...")

                traffic_data = self.ccc.get_inbound_traffic_per_device(
                    allowed_ips=set(baselines.keys())
                )
                # Only IPs that returned samples this cycle are eligible for site-level check
                polled_this_cycle = set()

                if not traffic_data:
                    self.lm.warning("[TrafficMonitor] No traffic data returned, skipping cycle")
                    continue

                for ip, data in traffic_data.items():
                    configured_baseline = baselines.get(ip)
                    if configured_baseline is None:
                        self.lm.debug(f"[TrafficMonitor] {ip} has no inbound_baseline_kbps configured, skipping")
                        continue

                    samples = data.get("inbound_samples", [])
                    if not samples:
                        self.lm.warning(f"[TrafficMonitor] No inBound samples for {ip} (API error?), state unchanged")
                        continue

                    current_avg = sum(samples) / len(samples)

                    drop_pct = (
                        (configured_baseline - current_avg) / configured_baseline * 100
                        if configured_baseline > 0 else 0
                    )

                    state = self._traffic_state.get(ip, "healthy")

                    # ── Healthy → check for drop ───────────────────────────────────
                    if state == "healthy":
                        if drop_pct >= threshold:
                            self.lm.warning(
                                f"[TrafficMonitor] {ip} traffic dropped {drop_pct:.1f}% "
                                f"(configured={configured_baseline:.1f} Kbps, "
                                f"current={current_avg:.1f} Kbps) — marking as failed"
                            )
                            self._traffic_state[ip] = "failed"
                            self.failover_manager._known_failed_ips.add(ip)
                        else:
                            self.lm.debug(
                                f"[TrafficMonitor] {ip} healthy — "
                                f"inBound={current_avg:.1f} Kbps, drop={drop_pct:.1f}% "
                                f"(configured baseline={configured_baseline:.1f} Kbps)"
                            )

                    # ── Failed → check for recovery ────────────────────────────────
                    else:
                        recovery_threshold = configured_baseline * (1 - threshold / 100)
                        if current_avg >= recovery_threshold:
                            self.lm.info(
                                f"[TrafficMonitor] {ip} traffic recovered "
                                f"(configured={configured_baseline:.1f}, "
                                f"current={current_avg:.1f}) — triggering recovery"
                            )
                            self._traffic_state[ip] = "healthy"
                            self.failover_manager._known_failed_ips.discard(ip)
                            with self.thread_lock:
                                self.failover_manager.handle_device_recovery(ip)
                        else:
                            self.lm.debug(
                                f"[TrafficMonitor] {ip} still failed — "
                                f"inBound={current_avg:.1f} Kbps, drop={drop_pct:.1f}%"
                            )

                    polled_this_cycle.add(ip)

                # ── Site-level failover/recovery ─────────────────────────────────────
                # Failover fires only when ALL configured devices in a site are failed.
                # A device counts as failed if:
                #   - _traffic_state marks it "failed" (traffic drop detected), OR
                #   - it is already in _redistributed_ips (detected down by DNS baseline monitor)
                # Devices that returned no data this cycle and are not already redistributed
                # are treated as healthy (unknown).
                checked_sites = set()
                for ip in polled_this_cycle:
                    site = self._get_site_for_ip(ip)
                    if site is None:
                        continue
                    site_name = site.get("site-name", ip)
                    if site_name in checked_sites:
                        continue
                    checked_sites.add(site_name)

                    # All IPs configured for this site (from config.ini)
                    all_site_ips = [d.get("ip") for d in site.get("devices", []) if d.get("ip")]
                    all_failed = all(self._is_device_failed(sip) for sip in all_site_ips)
                    prev = self._site_traffic_state.get(site_name, "healthy")

                    if all_failed:
                        if prev != "failed":
                            self.lm.error(
                                f"[TrafficMonitor] SITE FAILURE: all DPs in '{site_name}' "
                                f"are reporting traffic drop — triggering failover immediately"
                            )
                            self._site_traffic_state[site_name] = "failed"

                            # Cancel any existing pending timer for this site
                            existing = self._traffic_pending_timers.pop(site_name, None)
                            if existing:
                                existing.cancel()

                            with self.thread_lock:
                                for ip in all_site_ips:
                                    self.failover_manager.handle_device_failover(ip)
                        else:
                            self.lm.debug(f"[TrafficMonitor] Site '{site_name}' already in failed state")
                    elif prev == "failed":
                        self.lm.info(
                            f"[TrafficMonitor] Site '{site_name}' recovering — restoring healthy state"
                        )
                        self._site_traffic_state[site_name] = "healthy"

                self.lm.info("[TrafficMonitor] Poll cycle complete")

            except Exception as e:
                self.lm.error(f"[TrafficMonitor] Exception in poll cycle: {e}")
                self.lm.error(traceback.format_exc())

    def run(self):
        """Keep the main thread alive while all monitors run as daemon threads."""
        self.lm.info("BaselineTuning running — all monitors active")
        while True:
            time.sleep(60)

if __name__ == "__main__":
    bt = BaselineTuning()
    bt.run()