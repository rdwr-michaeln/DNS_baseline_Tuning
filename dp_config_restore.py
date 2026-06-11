#!/usr/bin/env python3
"""
dp_config_restore.py

After a DefensePro site fully recovers from failover, connects to each
recovered device via SSH and pastes the saved policy config templates from
the dns_baselines/ directory.

SSH session flow per device:
  1.  Connect using per-device credentials from config.ini
      (falls back to [cyber_controller] username/password if not set per device)
  2.  Send:  system config paste start
  3.  Send the content of every dns_baselines/<DeviceName>_*.cfg file
      that belongs to that device, in filename-sorted order
  4.  Send:  system config paste stop
"""

import glob
import os
import time

import paramiko

import configParser
from logManager import LogManager

OUTPUT_DIR = "dns_baselines"

_log = LogManager("DpConfigRestore").get_logger()

# Seconds to wait for a prompt / command response over SSH
SSH_TIMEOUT      = 30
# Small delay between individual lines sent during paste (seconds)
LINE_DELAY       = 0.02
# Delay after "system config paste start" before sending content
PASTE_START_WAIT = 1.0
# Delay after sending all content before "system config paste stop"
PASTE_STOP_WAIT  = 1.0
# SSH port – DefensePro management CLI always listens on 22
SSH_PORT         = 22


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cfg_files_for_device(device_name):
    """
    Return a sorted list of .cfg file paths in OUTPUT_DIR whose name starts
    with <device_name>_ (e.g. DefensePro-2_policy1.cfg).
    """
    safe_name = device_name.replace("/", "_").replace(" ", "_")
    pattern   = os.path.join(OUTPUT_DIR, f"{safe_name}_*.cfg")
    return sorted(glob.glob(pattern))


def _read_cfg(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def _send_command(shell, command, wait=1.0):
    """Send a single command line and wait briefly for a response."""
    shell.send(command + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode("utf-8", errors="replace")
    return output


def _send_content(shell, content):
    """
    Send multi-line config content line by line with a small inter-line delay
    to avoid overwhelming the device input buffer.
    """
    for line in content.splitlines():
        shell.send(line + "\n")
        time.sleep(LINE_DELAY)
    # Drain any echo / acknowledgement
    time.sleep(PASTE_STOP_WAIT)
    output = ""
    while shell.recv_ready():
        output += shell.recv(65536).decode("utf-8", errors="replace")
    return output


# ---------------------------------------------------------------------------
# Per-device restore
# ---------------------------------------------------------------------------

def restore_device(dp_ip, device_name):
    """
    Open an SSH session to dp_ip, paste all cfg files for device_name,
    and close the session.

    Returns True on success, False on any error.
    """
    cfg_files = _cfg_files_for_device(device_name)
    if not cfg_files:
        msg = f"[ConfigRestore] No .cfg files found for '{device_name}' in {OUTPUT_DIR}/ — skipping"
        print(msg)
        _log.warning(msg)
        return False

    creds    = configParser.device_credentials.get(dp_ip, {})
    username = creds.get("username", configParser.username)
    password = creds.get("password", configParser.password)

    print(f"[ConfigRestore] Connecting to {device_name} ({dp_ip}) via SSH...")
    _log.info(f"Connecting to {device_name} ({dp_ip}) via SSH")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=dp_ip,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

        shell = client.invoke_shell()
        time.sleep(1.0)
        # Drain the login banner
        while shell.recv_ready():
            shell.recv(4096)

        # ── paste start ──────────────────────────────────────────────
        print(f"[ConfigRestore]   → system config paste start")
        _log.info(f"{device_name} ({dp_ip}): system config paste start")
        _send_command(shell, "system config paste start", wait=PASTE_START_WAIT)

        # ── send each cfg file ───────────────────────────────────────
        for filepath in cfg_files:
            filename = os.path.basename(filepath)
            content  = _read_cfg(filepath)
            lines    = content.count("\n") + 1
            print(f"[ConfigRestore]   → pasting {filename} ({lines} lines)")
            _log.info(f"{device_name} ({dp_ip}): pasting {filename} ({lines} lines)")
            _send_content(shell, content)

        # ── trailing Enter to ensure the last line is submitted ──────
        shell.send("\n")
        time.sleep(LINE_DELAY)

        # ── paste stop ───────────────────────────────────────────────
        print(f"[ConfigRestore]   → system config paste stop")
        _log.info(f"{device_name} ({dp_ip}): system config paste stop")
        out = _send_command(shell, "system config paste stop", wait=2.0)
        if out.strip():
            _log.debug(f"{device_name} ({dp_ip}) paste stop response: {out.strip()}")

        # ── update policies ──────────────────────────────────────────
        print(f"[ConfigRestore]   → dp update-policies set 1")
        _log.info(f"{device_name} ({dp_ip}): dp update-policies set 1")
        out = _send_command(shell, "dp update-policies set 1", wait=2.0)
        if out.strip():
            _log.debug(f"{device_name} ({dp_ip}) update-policies response: {out.strip()}")

        print(f"[ConfigRestore] ✅ {device_name} ({dp_ip}) config restored successfully")
        _log.info(f"{device_name} ({dp_ip}) config restored successfully")
        return True

    except Exception as e:
        msg = f"[ConfigRestore] ❌ SSH restore failed for {device_name} ({dp_ip}): {e}"
        print(msg)
        _log.error(msg)
        return False
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Site-level restore (called from the on_restored callback)
# ---------------------------------------------------------------------------

def restore_site(recovered_ips, sites_config):
    """
    For each IP in recovered_ips, look up the device name and call restore_device().
    recovered_ips can be a single IP string or an iterable of IP strings.
    """
    if isinstance(recovered_ips, str):
        recovered_ips = [recovered_ips]

    # Build ip → device_name map from sites_config
    ip_to_name = {
        dev.get("ip"): dev.get("name", dev.get("ip"))
        for site in sites_config
        for dev in site.get("devices", [])
        if dev.get("ip")
    }

    for dp_ip in recovered_ips:
        device_name = ip_to_name.get(dp_ip, dp_ip)
        restore_device(dp_ip, device_name)
