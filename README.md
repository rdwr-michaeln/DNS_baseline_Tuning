# DefensePro Failover Manager

Automated DNS QPS failover and recovery system for Radware DefensePro devices managed through a Cyber Controller (CC).

The system continuously monitors inbound traffic per device, listens for SNMP traps, and polls interface operational status. When a DefensePro goes down (traffic drop, SNMP trap, or interface down), it automatically redistributes DNS QPS from the failed device to the surviving devices. When the device recovers, it restores the original QPS values from the saved baseline.

---

## Architecture

```
baseline_tuning.py          ← Main entry point (run this)
│
├── SNMPTrapReceiver        ← Listens for M_07630 / M_07631 / M_30000 traps (UDP 162)
├── DnsBaselineMonitor      ← Background thread: polls DNS QPS every 60 s → dns_baseline.json
├── TrafficMonitor          ← Background thread: polls inbound traffic every 120 s
└── DpFailoverManager       ← Handles QPS redistribution and restore via CC REST API
```

| File | Purpose |
|---|---|
| `baseline_tuning.py` | Main entry point, SNMP trap handling, traffic monitoring loop |
| `build_dns_baseline.py` | Polls all DPs and saves current DNS QPS + interface snapshot to `dns_baseline.json` |
| `dp_failover_manager.py` | Redistribution logic, restore logic, read-back verification |
| `cc_connector.py` | All Cyber Controller REST API calls (login, QPS read/write, traffic, ifTable) |
| `if_status_monitor.py` | Fetches / saves / compares interface operational status (ifTable API) |
| `configParser.py` | Parses `config.ini` and exposes settings as module variables |
| `validation.py` | Validates config structure and device reachability |
| `logManager.py` | Rotating file + console logger |
| `snmp_collector.py` | SNMP trap receiver (pysnmp) |
| `config.ini` | **Single configuration file — edit this before running** |
| `dns_baseline.json` | Auto-generated at runtime; stores last known QPS + interface snapshot per device |

---

## Requirements

- Python 3.10+
- Virtual environment with dependencies (see below)
- Network access to the Cyber Controller (HTTPS)
- SNMP traps forwarded to this host on UDP port 162
- Root or `CAP_NET_BIND_SERVICE` capability to bind UDP port 162

### Install dependencies

```bash
python3 -m venv myvenv
source myvenv/bin/activate
pip install requests pysnmp urllib3
```

---

## Running

```bash
source myvenv/bin/activate
python baseline_tuning.py
```

The process stays in the foreground. Use `systemd`, `screen`, or `nohup` for production deployment.

---

## Configuration file — `config.ini`

This is the **only file you need to edit**. Copy `config.ini.example` to `config.ini` and fill in the values for your environment.

```bash
cp config.ini.example config.ini
```

---

### `[snmp]`

Controls the SNMP trap listener.

| Key | Type | Required | Description |
|---|---|---|---|
| `agent` | string | Yes | IP address this host listens on for incoming SNMP traps. Use `0.0.0.0` to listen on all interfaces. |
| `targets` | string | Yes | Comma-separated list of IP addresses of SNMP managers (the devices that **send** traps to this system — typically the Cyber Controller or a dedicated SNMP manager). |
| `port` | integer | Yes | UDP port to receive SNMP traps on. Default: `162`. Requires root privileges. |
| `community` | string | Yes | SNMP v1/v2c community string. Must match the string configured on the DefensePro devices sending traps. |

```ini
[snmp]
agent     = 0.0.0.0
targets   = 10.213.50.80
port      = 162
community = radware
```

> **Traps handled:**
> - `M_07630` — DefensePro management DOWN → triggers failover
> - `M_07631` — DefensePro management UP → triggers recovery
> - `M_30000_Down` — Network interface DOWN → triggers failover (with ifTable confirmation)
> - `M_30000_Up` — Network interface UP → triggers recovery (with ifTable confirmation)

---

### `[time_settings]`

| Key | Type | Description |
|---|---|---|
| `pull_interval` | integer | How often **in minutes** to poll all DefensePro devices for DNS QPS values and interface status. Controls how frequently `dns_baseline.json` is refreshed when all devices are healthy. Default: `1`. |

```ini
[time_settings]
pull_interval = 1
```

---

### `[logging]`

| Key | Type | Description |
|---|---|---|
| `log_level` | string | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Recommended: `INFO` for production, `DEBUG` for troubleshooting. |
| `log_max_size_kb` | integer | Maximum size of a single log file in KB before it rotates. Default: `512`. |
| `log_backup_count` | integer | Number of rotated backup log files to keep. Default: `10`. |

```ini
[logging]
log_level        = INFO
log_max_size_kb  = 512
log_backup_count = 10
```

Logs are written to `/var/log/tune_dns_baseline/tune_dns_baseline.log`.

---

### `[cyber_controller]`

| Key | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Login username for the Cyber Controller REST API. |
| `password` | string | Yes | Login password for the Cyber Controller REST API. |

```ini
[cyber_controller]
username = radware
password = radware
```

The CC IP address is hardcoded in `cc_connector.py` (`self.base_url`). Update it there if the CC IP changes. The connector automatically follows CC HA failover redirects.

---

### `[trigger.mgmt_down]`

Fires when a DefensePro **management** interface goes down — detected via SNMP trap `M_07630` (`DEFENSEPRO_DOWN`).

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | Set `false` to completely disable this trigger. Default: `true`. |
| `down_delay_minutes` | integer | Minutes to wait after **all** devices in a site are detected as down before triggering failover. Use this to absorb brief management-plane blips without acting on them. `0` = trigger immediately. Default: `2`. |

```ini
[trigger.mgmt_down]
enabled            = true
down_delay_minutes = 2
```

---

### `[trigger.interface_down]`

Fires when a DefensePro **network** interface goes down — detected via SNMP trap `M_30000_Down` (`LINK_DOWN`).

Before acting, the system performs a **live ifTable API check** against the saved interface snapshot in `dns_baseline.json`. The trap is only processed if the API confirms at least one interface changed from up → down. This prevents stale or spurious traps from triggering unnecessary failovers.

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | Set `false` to completely disable this trigger. Default: `true`. |
| `down_delay_minutes` | integer | Minutes to wait after all devices in a site are detected as down before triggering failover. Allows link flaps to recover without action. `0` = trigger immediately. Default: `2`. |

```ini
[trigger.interface_down]
enabled            = true
down_delay_minutes = 2
```

---

### `[trigger.traffic_decrease]`

Fires when inbound traffic on a device drops significantly below its configured baseline — detected by the background traffic monitor (polls every 120 seconds).

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | Set `false` to completely disable this trigger. Default: `true`. |
| `down_delay_minutes` | integer | Minutes to wait after the entire site is detected as failed before triggering failover. The drop must persist for the full window. `0` = trigger immediately. Default: `2`. |
| `inbound_drop_threshold_percent` | integer | Percentage drop from `inbound_baseline_kbps` that marks a device as failed. Default: `50`. |
| `site_failure_on_all_dp_down` | boolean | Only trigger site failover when **all** devices in the site are reporting a traffic drop. Default: `true`. |

```ini
[trigger.traffic_decrease]
enabled                        = true
down_delay_minutes             = 2
inbound_drop_threshold_percent = 50
site_failure_on_all_dp_down    = true
```

> **Drop formula:**
> ```
> drop% = (inbound_baseline_kbps - current_avg_kbps) / inbound_baseline_kbps × 100
> ```
> Failover triggers when `drop% >= inbound_drop_threshold_percent`.

---

### `[site.<name>]` and `[site.<name>.device.<device-name>]`

Define your sites and DefensePro devices. Each site section lists its devices; each device section provides the IP and traffic baseline.

```ini
[site.Tel-Aviv]
devices = DefensePro-1, DefensePro-2

[site.Tel-Aviv.device.DefensePro-1]
ip                    = 10.213.50.50
inbound_baseline_kbps = 1000

[site.Tel-Aviv.device.DefensePro-2]
ip                    = 10.213.50.51
inbound_baseline_kbps = 1000
```

| Key | Type | Required | Description |
|---|---|---|---|
| `devices` | string | Yes | Comma-separated list of device names defined in this site. Each name must have a matching `[site.<name>.device.<device-name>]` section. |
| `ip` | string | Yes | Management IP of the DefensePro as registered in the Cyber Controller. |
| `inbound_baseline_kbps` | number | Yes | Expected normal inbound traffic for this device in Kbps. Failover triggers when traffic drops below `(1 - threshold/100) × inbound_baseline_kbps`. |

> **How to determine `inbound_baseline_kbps`:**
> Run the system for a period with no incidents and observe the traffic values in the logs:
> ```
> [TrafficMonitor] 10.213.50.50 healthy — inBound=2337.5 Kbps, drop=-133.8%
> ```
> Set `inbound_baseline_kbps` to roughly 120% of the observed normal traffic. For example, if normal is ~2300 Kbps, set `2800`. With a 50% threshold, failover then triggers if traffic falls below 1400 Kbps.

---

### Full `config.ini` example

```ini
[snmp]
agent     = 0.0.0.0
targets   = 10.213.50.80
port      = 162
community = radware

[time_settings]
pull_interval = 1

[logging]
log_level        = INFO
log_max_size_kb  = 512
log_backup_count = 10

[cyber_controller]
username = radware
password = radware

[trigger.mgmt_down]
enabled            = true
down_delay_minutes = 2

[trigger.interface_down]
enabled            = true
down_delay_minutes = 2

[trigger.traffic_decrease]
enabled                        = true
down_delay_minutes             = 2
inbound_drop_threshold_percent = 50
site_failure_on_all_dp_down    = true

[site.Tel-Aviv]
devices = DefensePro-1, DefensePro-2

[site.Tel-Aviv.device.DefensePro-1]
ip                    = 10.213.50.50
inbound_baseline_kbps = 1000

[site.Tel-Aviv.device.DefensePro-2]
ip                    = 10.213.50.51
inbound_baseline_kbps = 1000

[site.Haifa]
devices = DefensePro-3, DefensePro-4

[site.Haifa.device.DefensePro-3]
ip                    = 10.213.50.52
inbound_baseline_kbps = 1000

[site.Haifa.device.DefensePro-4]
ip                    = 10.213.50.53
inbound_baseline_kbps = 1000
```

---

## dns_baseline.json

This file is **auto-generated** and **must not be edited manually**. It is created and maintained by the system at runtime.

It stores two independent sections:

### DNS QPS baseline (`timestamp` / `sites`)

Updated every 60 seconds when all devices are healthy. **Frozen** during an active failover to preserve the pre-failure QPS values used for redistribution and recovery.

Used to:
- Know how much QPS to add to alive devices during failover
- Know what QPS values to restore after recovery

### Interface snapshot (`interface_snapshot`)

Updated every poll cycle for all reachable devices, **even during failover**. Devices that are currently down retain their last-known entry so recovery comparisons work correctly.

Used to confirm that SNMP LINK_DOWN / LINK_UP traps reflect a real interface state change before acting on them.

```json
{
  "timestamp": "...",
  "sites": [ "..." ],
  "interface_snapshot": {
    "fetched_at": "2026-05-11T11:37:17.772930",
    "devices": {
      "10.213.50.50": [
        {"ifIndex": "1",     "ifDescr": "Unknown-1", "ifOperStatus": "1"},
        {"ifIndex": "2",     "ifDescr": "Unknown-2", "ifOperStatus": "1"},
        {"ifIndex": "MNG-1", "ifDescr": "1Gbps-3",   "ifOperStatus": "1"}
      ]
    }
  }
}
```

`ifOperStatus`: `"1"` = up, `"2"` = down.

---

## Failover logic summary

```
SNMP M_07630 (mgmt down) / M_30000_Down (link down) / Traffic drop detected
    └── [LINK_DOWN only] Query live ifTable API → confirm interface actually went down
        └── If not confirmed → discard trap (stale/spurious)
    └── Mark device as down
    └── Wait down_delay_minutes (configurable per trigger)
        └── If device recovers during wait → cancel timer, no action
    └── Re-check: are ALL devices in the site down?
        └── If not → defer (wait for remaining devices)
    └── Validate device is really down
    └── Read dns_baseline.json
    └── For each alive device at the same site index in every other site:
            new_qps = alive_dp_current + failed_dp_baseline
            Write to device via CC API → read back and verify ✅
    └── Freeze dns_baseline.json DNS updates

SNMP M_07631 (mgmt up) / M_30000_Up (link up) / Traffic recovers
    └── [LINK_UP only] Query live ifTable API → confirm interface actually came back up
        └── If not confirmed → discard trap (stale/spurious)
    └── Cancel any pending failover delay timer for this site
    └── Validate device is truly up
    └── Read dns_baseline.json (original pre-failover values)
    └── Restore each device's QPS to baseline values → read back and verify ✅
    └── Re-poll all devices → save updated snapshot
    └── Unfreeze dns_baseline.json DNS updates
```


---

