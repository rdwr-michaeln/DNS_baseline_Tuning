#!/usr/bin/env python3
"""
if_poll_monitor.py

Polls dns_baseline.json every 20 seconds and detects interface
operational-status changes (ifOperStatus "1"=up / "2"=down) by comparing
the current snapshot against the previously seen state.

When a transition is detected:
  - DOWN (1→2): log immediately; start a per-device confirmation timer
                equal to trigger.interface_down.down_delay_minutes.
                If the interface is still down when the timer fires, call
                on_interface_down(dp_ip).
  - UP   (2→1): log immediately; cancel any running confirmation timer
                for that device; call on_interface_up(dp_ip).

The callbacks on_interface_down / on_interface_up are injected by the
caller (BaselineTuning) so this module has no direct dependency on it.
"""

import json
import os
import threading
import time
from datetime import datetime

import configParser
import if_status_monitor

POLL_INTERVAL   = 5          # seconds between reads of dns_baseline.json
BASELINE_FILE   = "dns_baseline.json"
OPER_UP         = "1"
OPER_DOWN       = "2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_snapshot():
    """Return the interface_snapshot.devices dict from dns_baseline.json."""
    return if_status_monitor.load_interface_devices(BASELINE_FILE)


def _iface_states(ifaces):
    """
    Convert a list of interface dicts into { ifIndex: ifOperStatus }.
    Restricts to ifIndex values present in the list.
    """
    return {iface["ifIndex"]: iface.get("ifOperStatus", OPER_UP) for iface in ifaces}


# ---------------------------------------------------------------------------
# Main polling loop
# ---------------------------------------------------------------------------

def run(on_interface_down, on_interface_up, logger=None):
    """
    Long-running polling loop.  Intended to run in a daemon thread.

    Parameters
    ----------
    on_interface_down(dp_ip) : callable
        Called after the configured down_delay_minutes when an interface
        is confirmed still down.
    on_interface_up(dp_ip)   : callable
        Called immediately when a previously-down interface comes back up.
    logger                   : optional Python logger
    """

    def _log(level, msg):
        print(msg)
        if logger:
            getattr(logger, level)(msg)

    delay_secs  = configParser.trigger_interface_down_delay  # already in seconds
    sites       = configParser.sites_config

    # Build ip → (device_name, monitored_ifindexes) lookup
    ip_info = {
        dev["ip"]: {
            "name":    dev["name"],
            "monitor": dev.get("monitored_if_indexes") or set(),
        }
        for site in sites
        for dev in site.get("devices", [])
        if dev.get("ip")
    }

    # Last known state per device:  { dp_ip: { ifIndex: ifOperStatus } }
    _prev_states = {}
    # Pending DOWN confirmation timers: { dp_ip: threading.Timer }
    _down_timers = {}

    if logger:
        logger.info("[IfPollMonitor] Started — polling dns_baseline.json every "
                    f"{POLL_INTERVAL}s, down delay={delay_secs}s")

    while True:
        time.sleep(POLL_INTERVAL)

        snapshot = _load_snapshot()
        if not snapshot:
            continue

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for dp_ip, ifaces in snapshot.items():
            info      = ip_info.get(dp_ip)
            if not info:
                continue
            dev_name  = info["name"]
            monitored = info["monitor"]

            # Filter to monitored indexes only (empty set = all)
            if monitored:
                ifaces = [i for i in ifaces
                          if int(i.get("ifIndex", 0)) in monitored]

            curr = _iface_states(ifaces)
            prev = _prev_states.get(dp_ip, {})

            for ifidx, status in curr.items():
                prev_status = prev.get(ifidx, OPER_UP)  # assume up on first seen

                # ── DOWN transition ─────────────────────────────────────────
                if status == OPER_DOWN and prev_status != OPER_DOWN:
                    iface_name = next(
                        (i.get("ifDescr", ifidx) for i in ifaces
                         if i.get("ifIndex") == ifidx), ifidx
                    )
                    _log("warning",
                         f"[IfPollMonitor] [{now_str}] ⬇  {dev_name} ({dp_ip}) "
                         f"interface {iface_name} (idx {ifidx}) went DOWN — "
                         f"will confirm in {delay_secs}s")

                    # Cancel any stale timer for this device
                    old = _down_timers.pop(dp_ip, None)
                    if old:
                        old.cancel()

                    if delay_secs == 0:
                        _log("warning",
                             f"[IfPollMonitor] No delay configured — "
                             f"announcing {dev_name} ({dp_ip}) as DOWN immediately")
                        on_interface_down(dp_ip)
                    else:
                        def _fire_down(ip=dp_ip, name=dev_name):
                            _log("warning",
                                 f"[IfPollMonitor] ⏰ Delay elapsed — "
                                 f"{name} ({ip}) confirmed DOWN")
                            _down_timers.pop(ip, None)
                            on_interface_down(ip)

                        t = threading.Timer(delay_secs, _fire_down)
                        t.daemon = True
                        _down_timers[dp_ip] = t
                        t.start()

                # ── UP transition ────────────────────────────────────────────
                elif status == OPER_UP and prev_status == OPER_DOWN:
                    iface_name = next(
                        (i.get("ifDescr", ifidx) for i in ifaces
                         if i.get("ifIndex") == ifidx), ifidx
                    )
                    _log("info",
                         f"[IfPollMonitor] [{now_str}] ⬆  {dev_name} ({dp_ip}) "
                         f"interface {iface_name} (idx {ifidx}) came UP")

                    # Cancel pending DOWN timer — interface recovered before delay elapsed
                    old = _down_timers.pop(dp_ip, None)
                    if old:
                        old.cancel()
                        _log("info",
                             f"[IfPollMonitor] Cancelled DOWN timer for "
                             f"{dev_name} ({dp_ip}) — interface recovered in time")

                    on_interface_up(dp_ip)

            _prev_states[dp_ip] = curr
