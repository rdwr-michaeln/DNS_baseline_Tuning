from snmp_collector import SNMPTrapReceiver
import configParser
from cc_connector import CcConnector
from validation import ConfigValidator
from dp_failover_manager import DpFailoverManager
import build_dns_baseline
import if_status_monitor
import queue
import threading
import urllib3
import traceback
from logManager import LogManager
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

M_NAME_TO_EVENT = {
    "M_07630": "DEFENSEPRO_DOWN",
    "M_07631": "DEFENSEPRO_UP",
    "M_30000_Down": "LINK_DOWN",
    "M_30000_Up": "LINK_UP",
}


class BaselineTuning:
    def __init__(self):
        self.ccc = CcConnector(configParser.username, configParser.password)
        self.lm = LogManager("BaselineTuning").get_logger()
        self.thread_lock = threading.Lock()
        self.trap_queue = queue.Queue()

        # Initialize configuration validator and failover manager
        self.validator = ConfigValidator()
        self.validator.initialize_configuration()
        self.failover_manager = DpFailoverManager()
        # Register callback: when DNS baseline monitor redistributes a device,
        # immediately check whether the full site is now down and trigger
        # redistribution for the remaining devices without waiting for the next
        # traffic monitor poll cycle.
        self.failover_manager.on_redistributed = self._on_device_redistributed
        
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

        # Per-device traffic state: { ip: "healthy" | "failed" } — used by traffic monitor
        self._traffic_state = {}
        # Per-device SNMP event state: { ip: "up" | "down" }
        self._snmp_device_state = {}
        # Per-site traffic failover state: { site_name: "healthy" | "failed" }
        self._site_traffic_state = {}
        # Per-device SNMP DOWN confirmation timers: { ip: threading.Timer }
        # Started when a DOWN trap arrives; marks the device as down when it fires.
        # Cancelled if an UP trap arrives before it fires (flap suppression).
        self._snmp_device_timers = {}
        # Pending SNMP failover timers: { site_name: threading.Timer } (kept for UP-cancel)
        self._snmp_pending_timers = {}
        # Pending traffic failover timers: { site_name: threading.Timer }
        self._traffic_pending_timers = {}
        # Pending DNS-baseline failover timers: { site_name: threading.Timer }
        self._dns_baseline_pending_timers = {}

        # Start the traffic utilization monitor (polls every 3 minutes)
        traffic_thread = threading.Thread(target=self._traffic_monitor_loop, daemon=True, name="TrafficMonitor")
        traffic_thread.start()
        self.lm.info("Traffic Monitor started in background thread")

        receiver = SNMPTrapReceiver(
            configParser.agent, configParser.port, configParser.community, self.trap_queue,
            snmp_version=configParser.snmp_version,
            v3_username=configParser.v3_username,
            v3_auth_protocol=configParser.v3_auth_protocol,
            v3_auth_passphrase=configParser.v3_auth_passphrase,
            v3_priv_protocol=configParser.v3_priv_protocol,
            v3_priv_passphrase=configParser.v3_priv_passphrase,
        )
        receiver_thread = threading.Thread(target=receiver.snmp_engine.transport_dispatcher.run_dispatcher, daemon=True)
        receiver_thread.start()
        self.EVENTS_TO_FUNC = {
            "DEFENSEPRO_DOWN": self.tune_rest_dp_event,
            "DEFENSEPRO_UP": self.tune_to_normal_event,
            "LINK_DOWN": self.tune_rest_dp_event,
            "LINK_UP": self.tune_to_normal_event,
        }

    def tune_rest_dp_event(self, event_name, trap):
        """
        Handle DefensePro DOWN / Link DOWN event.
        Failover is triggered only when ALL devices in the site are down.
        """
        trap_ip = trap.get("ip_address", "")

        # Check whether this trigger type is enabled
        if event_name == "DEFENSEPRO_DOWN" and not configParser.trigger_mgmt_down:
            self.lm.info(f"mgmt_down trigger is disabled — ignoring DEFENSEPRO_DOWN for {trap_ip}")
            return
        if event_name == "LINK_DOWN" and not configParser.trigger_interface_down:
            self.lm.info(f"interface_down trigger is disabled — ignoring LINK_DOWN for {trap_ip}")
            return

        # Extra validation for LINK_DOWN: confirm via the ifTable API that at
        # least one interface on this device actually went down compared to the
        # saved baseline snapshot captured at startup.
        if event_name == "LINK_DOWN":
            saved_devices = if_status_monitor.load_interface_devices()
            confirmed, current_ifaces = if_status_monitor.check_interface_change(
                self.ccc, trap_ip, saved_devices, "down", self.lm
            )
            if not confirmed:
                self.lm.warning(
                    f"[IfCheck] LINK_DOWN for {trap_ip} not confirmed by live ifTable API "
                    "— ignoring trap (no baseline change detected)"
                )
                return
            # Update the snapshot so the next LINK_UP can compare against the
            # post-down state, avoiding a spurious "no change" result.
            if current_ifaces:
                saved_devices[trap_ip] = current_ifaces
                if_status_monitor.save_interface_devices(
                    if_status_monitor.BASELINE_FILE, saved_devices
                )
                self.lm.info(f"[IfCheck] Interface snapshot updated for {trap_ip} (post-down state)")

        delay = (configParser.trigger_mgmt_down_delay
                 if event_name == "DEFENSEPRO_DOWN"
                 else configParser.trigger_interface_down_delay)

        # Cancel any previous pending confirmation timer for this device (re-trap before timeout)
        existing_device_timer = self._snmp_device_timers.pop(trap_ip, None)
        if existing_device_timer:
            existing_device_timer.cancel()

        def _confirm_device_down(ip=trap_ip, ev=event_name):
            """Fired after down_delay_minutes — marks the device as confirmed down,
            then immediately triggers site-wide failover if all devices are now down."""
            self.lm.warning(f"{ev} confirmed for {ip} after delay — marking device as down")
            self._snmp_device_state[ip] = "down"
            self._snmp_device_timers.pop(ip, None)

            site = self._get_site_for_ip(ip)
            if site is None:
                self.lm.warning(f"No site found for {ip}, skipping failover")
                return

            site_name = site.get("site-name", ip)
            site_ips  = [d.get("ip") for d in site.get("devices", [])]
            all_down  = all(self._is_device_failed(s) for s in site_ips)

            if not all_down:
                down_count = sum(1 for s in site_ips if self._is_device_failed(s))
                self.lm.warning(
                    f"Device {ip} confirmed down, but site '{site_name}' is not fully down "
                    f"({down_count}/{len(site_ips)} devices down) — waiting for remaining devices"
                )
                return

            self.lm.warning(f"All devices in site '{site_name}' are down — triggering failover immediately")
            try:
                for sip in site_ips:
                    validation_result = self.validator.dp_status_check(sip, "down", self.lm)
                    if validation_result:
                        self.lm.info(f"Device validation passed for {sip}, initiating failover...")
                        self.failover_manager.handle_device_failover(sip)
                        self.lm.info(f"Failover process completed for {sip}")
                    else:
                        self.lm.warning(f"Device validation failed for {sip}, skipping failover")
            except Exception as e:
                self.lm.error(f"Error during failover process for site '{site_name}': {e}")
                self.lm.error(traceback.format_exc())

        if delay == 0:
            self.lm.warning(f"Processing {event_name} for {trap_ip} — no delay configured, marking down immediately")
            _confirm_device_down()
        else:
            self.lm.warning(
                f"Processing {event_name} for {trap_ip} — "
                f"will confirm as down in {delay}s (flap suppression)"
            )
            t = threading.Timer(delay, _confirm_device_down)
            t.daemon = True
            self._snmp_device_timers[trap_ip] = t
            t.start()


    def tune_to_normal_event(self, event_name, trap):
        
        """
        Handle DefensePro UP event - validate device and restore bandwidth configurations
        """
        trap_ip = trap.get("ip_address", "")
        self.lm.info(f"✅ Processing DefensePro UP event for IP: {trap_ip}")

        # Cancel any pending per-device confirmation timer (flap: came back up before delay expired)
        device_timer = self._snmp_device_timers.pop(trap_ip, None)
        if device_timer:
            device_timer.cancel()
            self.lm.info(f"Cancelled pending DOWN confirmation timer for {trap_ip} — device came back up")

        self._snmp_device_state[trap_ip] = "up"

        # Cancel any pending failover timers for this device's site
        site = self._get_site_for_ip(trap_ip)
        if site:
            site_name = site.get("site-name", trap_ip)
            for timers_dict, label in [
                (self._snmp_pending_timers,         "SNMP"),
                (self._dns_baseline_pending_timers, "DNS-baseline"),
            ]:
                timer = timers_dict.pop(site_name, None)
                if timer:
                    timer.cancel()
                    self.lm.info(f"Cancelled pending {label} failover timer for site '{site_name}' — device {trap_ip} came back up")

        # Extra validation for LINK_UP: confirm via the ifTable API that at
        # least one interface on this device actually came back up compared to
        # the saved baseline snapshot (which was updated to the post-down state
        # when the LINK_DOWN trap was processed).
        if event_name == "LINK_UP":
            saved_devices = if_status_monitor.load_interface_devices()
            confirmed, current_ifaces = if_status_monitor.check_interface_change(
                self.ccc, trap_ip, saved_devices, "up", self.lm
            )
            if not confirmed:
                self.lm.warning(
                    f"[IfCheck] LINK_UP for {trap_ip} not confirmed by live ifTable API "
                    "— ignoring trap (no baseline change detected)"
                )
                return False
            # Update snapshot to reflect the recovered (up) state so future
            # LINK_DOWN traps for this device compare against the correct baseline.
            if current_ifaces:
                saved_devices[trap_ip] = current_ifaces
                if_status_monitor.save_interface_devices(
                    if_status_monitor.BASELINE_FILE, saved_devices
                )
                self.lm.info(f"[IfCheck] Interface snapshot updated for {trap_ip} (post-recovery state)")

        # Only restore if a failover was actually applied for this device.
        # If the script started while the interface was already down, no
        # LINK_DOWN trap was ever processed and no QPS redistribution happened —
        # so there is nothing to restore.
        device_was_failed = (
            trap_ip in self.failover_manager._redistributed_ips or
            self._snmp_device_state.get(trap_ip) == "down" or
            self._traffic_state.get(trap_ip) == "failed"
        )
        if not device_was_failed:
            self.lm.info(
                f"[{event_name}] {trap_ip} came up but no failover was active for this device "
                "— skipping restore (nothing to recover)"
            )
            return True

        try:
            # First validate the device is truly up
            validation_result = self.validator.dp_status_check(trap_ip, "up", self.lm)
            
            if validation_result:
                self.lm.info(f"✅ Device validation passed for {trap_ip}, initiating bandwidth restoration...")
                
                # Trigger bandwidth restoration
                self.failover_manager.handle_device_recovery(trap_ip)
                
                self.lm.info(f"✅ Recovery process completed for {trap_ip}")
            else:
                self.lm.warning(f"⚠️  Device validation failed for {trap_ip}, skipping recovery")
                
            return validation_result
            
        except Exception as e:
            self.lm.error(f"❌ Error during recovery process for {trap_ip}: {e}")
            return False


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
        """Return True if the device is confirmed down by ANY trigger.
        A device with a pending per-device timer is NOT yet confirmed down —
        it is still in the flap-suppression window.
        """
        if ip in self._snmp_device_timers:
            return False  # timer still running — not yet confirmed
        return (
            self._snmp_device_state.get(ip) == "down" or
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

    def parseEvent(self, trap):
        # The m_num field contains the actual message number (e.g., "M_07630")
        m_num = trap.get("m_num", "")
        self.lm.info(f"Received trap with m_num: {m_num}")
        
        if m_num in M_NAME_TO_EVENT:
            event_name = M_NAME_TO_EVENT[m_num]
            self.lm.info(f"{event_name} trap received {trap}")
            self.EVENTS_TO_FUNC[event_name](event_name, trap)
        else:
            self.lm.warning(f"Unknown trap message number: {m_num}")

    def run(self):
        while True:
            try:
                time.sleep(3)
                trap = self.trap_queue.get()
                print(trap)
                self.lm.debug(f"DEBUG: Received trap from queue: {trap}")
                self.parseEvent(trap)
            except Exception as e:
                self.lm.error(f"general exception: {e}")
                self.lm.error(f"{traceback.format_exc()}")

if __name__ == "__main__":
    bt = BaselineTuning()
    bt.run()