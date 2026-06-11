# DefensePro DNS Baseline Tuning

Automated DNS QPS failover and recovery system for Radware DefensePro devices managed through a Cyber Controller (CC).

The system continuously monitors DefensePro devices via the CC REST API and SSH. When a site fails (traffic drop, management plane unreachable, or interface down), it redistributes DNS QPS values from the failed devices to the surviving ones. On recovery, it restores baseline QPS values and SSH-pastes saved policy config back to every device.

---

## Table of Contents

- [Architecture](#architecture)
- [Process Flow](#process-flow)
- [File Reference](#file-reference)
- [Requirements](#requirements)
- [Running the Script](#running-the-script)
  - [With virtualenv](#with-virtualenv)
  - [Without virtualenv (system Python)](#without-virtualenv-system-python)
  - [In a Docker container](#in-a-docker-container)
- [Configuration — config.ini](#configuration--configini)
- [Runtime files](#runtime-files)
- [Failover logic — step by step](#failover-logic--step-by-step)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
baseline_tuning.py          ← Main entry point (run this)
│
├── DnsBaselineMonitor      ← Thread: polls DNS QPS every pull_interval min
│                              saves dns_baseline.json
│                              detects management-plane failures
│                              fires redistribution after down_delay_minutes
│
├── DpPoliciesMonitor       ← Thread: fetches policy names from CC daily
│                              saves dp_policies.json
│
├── PolicyTemplateExport    ← Thread: exports policy config templates every 60 s
│                              saves dns_baselines/<device>_<policy>.cfg
│                              freezes during active failover + 1-hour cooldown
│
├── TrafficMonitor          ← Thread: polls inbound traffic every 30 s
│                              triggers failover on sustained traffic drop
│
├── IfPollMonitor           ← Thread: polls dns_baseline.json every 20 s
│                              detects interface operational-status changes
│                              fires on_interface_down / on_interface_up callbacks
│
└── DpFailoverManager       ← Redistribution engine
                               QPS redistribution via CC REST API
                               QPS restore via CC REST API
                               AAAA quota restore via CC REST API
                               SSH config-paste via paramiko
```

---

## Process Flow

### Normal operation

```
Every pull_interval minutes
  └── Query all DPs via CC REST API
      ├── All alive → save dns_baseline.json (QPS + interface snapshot)
      └── Any failed → freeze baseline, start down_delay_minutes timer

Every 20 seconds (IfPollMonitor)
  └── Read interface_snapshot from dns_baseline.json
      ├── Interface went down → start down_delay_minutes confirmation timer
      └── Interface came back up → cancel timer, check for recovery

Every 30 seconds (TrafficMonitor)
  └── Poll inbound traffic per device
      ├── Drop >= threshold → mark device failed
      └── Traffic recovered → mark device healthy, trigger restore
```

### Failure path (triggered by any monitor)

```
Device detected as down
  └── Wait down_delay_minutes (configurable per trigger type)
      └── If device recovers during wait → cancel, no action taken
  └── Delay elapsed — re-check: is the ENTIRE site down?
      └── Not fully down → wait for remaining devices before acting
  └── Site fully down confirmed
  └── Lock target device via CC API
  └── Step 1 — QPS redistribution:
      Read failed device's baseline QPS from dns_baseline.json
      new_ExpectedQps  = alive_device_current + failed_device_baseline
      new_MaxAllowQps  = alive_device_current + failed_device_baseline
      PUT to CC REST API → update_policy
  └── Step 2 — AAAA quota push:
      Read alive device's own rsDnsProtProfileDnsAaaaQuota from dns_baseline.json
      PUT to CC REST API → update_policy
  └── Read back and verify applied values
  └── Unlock target device
  └── Freeze dns_baseline.json updates (preserve pre-failure values)
  └── Freeze dns_baselines/ template exports
```

### Recovery path

```
Device detected as recovered (interface up or traffic restored)
  └── Validate device is truly reachable
  └── Lock device via CC API
  └── Step 1 — QPS restore:
      Read original QPS from dns_baseline.json
      PUT baseline values to CC REST API → update_policy
  └── Step 2 — AAAA quota restore:
      Read device's own rsDnsProtProfileDnsAaaaQuota from dns_baseline.json
      PUT to CC REST API → update_policy
  └── Read back and verify applied values
  └── Unlock device
  └── SSH into ALL DefensePro devices (not just the recovered one)
      system config paste start
      Paste content of dns_baselines/<device>_<policy>.cfg for each policy
      (trailing Enter to commit last line)
      system config paste stop
      dp update-policies set 1
  └── Re-poll all devices → update dns_baseline.json
  └── Unfreeze baseline updates
  └── Unfreeze template exports (1-hour cooldown before resuming)
```

### QPS position mapping (multi-site)

Devices are matched by **position index** across sites. Example with 2 sites, 2 devices each:

```
Site Tel-Aviv:  [DefensePro-2 (index 0), DefensePro-5 (index 1)]
Site Haifa:     [DefensePro-3 (index 0), DefensePro-4 (index 1)]

DefensePro-2 fails (Tel-Aviv index 0)
  → redistribute its QPS to Haifa index 0 = DefensePro-3

DefensePro-5 fails (Tel-Aviv index 1)
  → redistribute its QPS to Haifa index 1 = DefensePro-4
```

---

## File Reference

| File | Purpose |
|---|---|
| `baseline_tuning.py` | Main entry point — starts all threads, wires failover callbacks |
| `build_dns_baseline.py` | Polls DNS QPS + interface status; manages failover timers; saves `dns_baseline.json` |
| `build_dp_policies.py` | Fetches policy names per DP from CC API; refreshes daily at midnight |
| `export_policy_templates.py` | Exports per-device/policy CLI config templates every 60 s to `dns_baselines/` |
| `dp_config_restore.py` | SSH config-paste restore after recovery (paramiko-based) |
| `dp_failover_manager.py` | QPS redistribution, restore, AAAA quota push, read-back verification |
| `cc_connector.py` | All CC REST API calls: login, QPS read/write, AAAA quota, traffic, ifTable, policy templates |
| `if_status_monitor.py` | Fetches / saves / updates interface operational status (ifTable API) |
| `if_poll_monitor.py` | Polls `dns_baseline.json` every 20 s; fires interface up/down callbacks |
| `configParser.py` | Parses `config.ini`; exposes all settings as module-level variables |
| `validation.py` | Validates config structure and device reachability on startup |
| `logManager.py` | Rotating file logger (`/var/log/tune_dns_baseline/tune_dns_baseline.log`) |
| `config.ini` | **The only file you need to edit** |
| `dns_baseline.json` | Auto-generated — current DNS QPS + interface snapshot per device |
| `dp_policies.json` | Auto-generated — maps device IPs to policy name lists |
| `dns_baselines/` | Auto-populated — one `.cfg` file per device/policy combination |

---

## Requirements

- Python 3.10 or newer
- Network access to the Cyber Controller (HTTPS, typically port 443)
- SSH access to each DefensePro (port 22) for config-paste restore
- Write access to `/var/log/tune_dns_baseline/` (created automatically)

---

## Running the Script

### With virtualenv

```bash
# Create the virtual environment (first time only)
python3 -m venv myvenv

# Activate
source myvenv/bin/activate

# Install dependencies (first time only)
pip install -r requirements.txt

# Copy and edit configuration
cp config.ini.example config.ini
nano config.ini

# Run
python baseline_tuning.py
```

To run in the background and keep it running after logout:

```bash
nohup python baseline_tuning.py > /var/log/tune_dns_baseline/stdout.log 2>&1 &
```

Or using `screen`:

```bash
screen -S dp-failover
source myvenv/bin/activate
python baseline_tuning.py
# Detach: Ctrl+A then D
# Reattach: screen -r dp-failover
```

---

### Without virtualenv (system Python)

```bash
# Install dependencies system-wide (requires pip and root/sudo)
pip3 install -r requirements.txt

# Or on Debian/Ubuntu with apt-managed Python:
pip3 install --break-system-packages -r requirements.txt

# Copy and edit configuration
cp config.ini.example config.ini
nano config.ini

# Run
python3 baseline_tuning.py
```

---

### In a Docker container

**1. Create a `Dockerfile` in the project directory:**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/tune_dns_baseline

CMD ["python", "baseline_tuning.py"]
```

**2. Build the image:**

```bash
docker build -t dp-failover .
```

**3. Run the container:**

```bash
docker run -d \
  --name dp-failover \
  --restart unless-stopped \
  -v $(pwd)/config.ini:/app/config.ini:ro \
  -v $(pwd)/dns_baseline.json:/app/dns_baseline.json \
  -v $(pwd)/dns_baselines:/app/dns_baselines \
  -v /var/log/tune_dns_baseline:/var/log/tune_dns_baseline \
  dp-failover
```

| Volume | Purpose |
|---|---|
| `config.ini` | Mount your config read-only so it survives rebuilds |
| `dns_baseline.json` | Persist the baseline across container restarts |
| `dns_baselines/` | Persist exported policy templates across restarts |
| `/var/log/...` | Write logs to the host so they survive container restarts |

**4. View logs:**

```bash
# Container stdout (print output)
docker logs -f dp-failover

# Rotating log file
tail -f /var/log/tune_dns_baseline/tune_dns_baseline.log
```

**5. Stop / restart:**

```bash
docker stop dp-failover
docker start dp-failover
docker restart dp-failover
```

---

## Configuration — config.ini

Copy the example file and edit it:

```bash
cp config.ini.example config.ini
```

---

### `[time_settings]`

| Key | Type | Description |
|---|---|---|
| `pull_interval` | integer (minutes) | How often to poll all DPs for DNS QPS and interface status. Controls how frequently `dns_baseline.json` is refreshed. Default: `1`. |

```ini
[time_settings]
pull_interval = 1
```

---

### `[logging]`

| Key | Type | Description |
|---|---|---|
| `log_level` | string | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL`. Use `INFO` for production, `DEBUG` for troubleshooting. |
| `log_max_size_kb` | integer | Max size of one log file in KB before rotation. Default: `512`. |
| `log_backup_count` | integer | Number of rotated log files to keep. Default: `10`. |

Logs are written to `/var/log/tune_dns_baseline/tune_dns_baseline.log`.

```ini
[logging]
log_level        = INFO
log_max_size_kb  = 512
log_backup_count = 10
```

---

### `[cyber_controller]`

| Key | Required | Description |
|---|---|---|
| `base_url` | Yes | HTTPS URL of the Cyber Controller, e.g. `https://10.213.50.40` |
| `username` | Yes | CC login username |
| `password` | Yes | CC login password |

```ini
[cyber_controller]
base_url = https://10.213.50.40
username = radware
password = radware
```

---

### `[trigger.mgmt_down]`

Fires when a DefensePro **management plane** becomes unreachable (detected by the DNS baseline monitor failing to reach the CC API for that device).

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | `false` to disable this trigger entirely. Default: `true`. |
| `down_delay_minutes` | integer | Minutes to wait after all devices in a site are unreachable before triggering failover. Absorbs transient management blips. `0` = trigger immediately. Default: `2`. |

```ini
[trigger.mgmt_down]
enabled            = true
down_delay_minutes = 2
```

---

### `[trigger.interface_down]`

Fires when a DefensePro **network interface** goes down, detected by comparing `ifOperStatus` values in `dns_baseline.json` every 20 seconds.

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | `false` to disable. Default: `true`. |
| `down_delay_minutes` | integer | Minutes to wait after all devices in a site have a down interface before triggering failover. Absorbs brief link flaps. `0` = immediately. Default: `2`. |

```ini
[trigger.interface_down]
enabled            = true
down_delay_minutes = 2
```

---

### `[trigger.traffic_decrease]`

Fires when inbound traffic on a device drops significantly below its configured baseline.

| Key | Type | Description |
|---|---|---|
| `enabled` | boolean | `false` to disable. Default: `false`. |
| `down_delay_minutes` | integer | Minutes to wait after the site is detected as failed before triggering failover. `0` = immediately. Default: `2`. |
| `inbound_drop_threshold_percent` | integer | Drop percentage that marks a device as failed. Default: `50`. |
| `site_failure_on_all_dp_down` | boolean | Only trigger when **all** devices in the site report a drop. Default: `true`. |

Drop formula:
```
drop% = (inbound_baseline_kbps - current_avg_kbps) / inbound_baseline_kbps × 100
```
Failover triggers when `drop% >= inbound_drop_threshold_percent`.

```ini
[trigger.traffic_decrease]
enabled                        = false
down_delay_minutes             = 2
inbound_drop_threshold_percent = 50
site_failure_on_all_dp_down    = true
```

---

### `[site.<name>]` and `[site.<name>.device.<device-name>]`

Define your sites and DefensePro devices. Device order within a site matters — redistribution is done by matching index positions across sites.

| Key | Required | Description |
|---|---|---|
| `devices` | Yes | Comma-separated list of device names within this site |
| `ip` | Yes | Management IP of the DefensePro (as registered in CC) |
| `inbound_baseline_kbps` | Yes | Expected normal inbound traffic in Kbps (for traffic trigger) |
| `monitored_if_indexes` | No | Comma-separated `ifIndex` values to watch. Omit to monitor all interfaces. |
| `username` | No | SSH username for config-paste restore. Falls back to `[cyber_controller]` username. |
| `password` | No | SSH password for config-paste restore. Falls back to `[cyber_controller]` password. |

```ini
[site.Tel-Aviv]
devices = DefensePro-2

[site.Tel-Aviv.device.DefensePro-2]
ip                    = 10.213.50.51
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2
username              = admin
password              = secret

[site.Haifa]
devices = DefensePro-3, DefensePro-4

[site.Haifa.device.DefensePro-3]
ip                    = 10.213.50.52
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2

[site.Haifa.device.DefensePro-4]
ip                    = 10.213.50.53
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2
```

> **Tip — setting `inbound_baseline_kbps`:** run the system for a period with no incidents and check the logs:
> ```
> [TrafficMonitor] 10.213.50.51 healthy — inBound=2337.5 Kbps, drop=-133.8%
> ```
> Set `inbound_baseline_kbps` to roughly 120 % of the observed normal traffic.

---

## Runtime files

### `dns_baseline.json`

Auto-generated. **Do not edit manually.**

Updated every `pull_interval` minutes when all devices are healthy. Frozen during active failover to preserve pre-failure QPS values. Contains:

- `timestamp` + `sites` — DNS QPS baseline per device/PO, including `rsDnsProtProfileExpectedQps`, `rsDnsProtProfileMaxAllowQps`, and `rsDnsProtProfileDnsAaaaQuota`
- `interface_snapshot` — latest `ifOperStatus` per interface, updated every poll cycle even during failover

### `dp_policies.json`

Auto-generated. Maps each device IP to its list of policy names. Refreshed daily at midnight.

### `dns_baselines/<DeviceName>_<PolicyName>.cfg`

Auto-generated CLI config templates, one per device/policy combination. Exported every 60 seconds, frozen during failover and for 1 hour after recovery. These are the files SSH-pasted back to the devices on recovery.

---

## Failover logic — step by step

```
Any trigger fires (mgmt down / interface down / traffic drop)
│
├── Mark device as down in shared state
├── Wait down_delay_minutes
│   └── Device recovers during wait → cancel timer, no action
│
├── Delay elapsed
├── Is ENTIRE site down?
│   └── No → defer, wait for remaining devices
│
├── Site fully confirmed down
├── For each alive device at matching index in other sites:
│   ├── Lock device (CC API) — unlock/retry if already locked
│   ├── QPS redistribution:
│   │   new_ExpectedQps = alive_current + failed_baseline
│   │   new_MaxAllowQps = alive_current + failed_baseline
│   │   PUT → update_policy
│   ├── AAAA quota push:
│   │   quota = alive device's own value from dns_baseline.json
│   │   PUT → update_policy
│   ├── Read back & verify
│   └── Unlock device
│
├── Freeze dns_baseline.json updates
└── Freeze dns_baselines/ exports

Recovery detected (any trigger)
│
├── Validate device is reachable
├── Lock device (CC API)
├── QPS restore:
│   Read original values from dns_baseline.json → PUT → update_policy
├── AAAA quota restore:
│   Read own quota from dns_baseline.json → PUT → update_policy
├── Read back & verify
├── Unlock device
│
├── SSH to ALL DefensePro devices:
│   ├── system config paste start
│   ├── Paste dns_baselines/<device>_<policy>.cfg (one per policy)
│   ├── Send trailing Enter (commits last line)
│   ├── system config paste stop
│   └── dp update-policies set 1
│
├── Re-poll all devices → refresh dns_baseline.json
└── Unfreeze exports (1-hour cooldown before resuming)
```

---

## Troubleshooting

### "Position-matched target is also down"

The failover manager could not reach the target device. Causes:

1. **Session expiry** — the CC session used by `DpFailoverManager` expired. The system retries automatically (2 attempts with session re-login).
2. **Device genuinely unreachable** — verify connectivity to the CC API for that device IP.
3. **CC HA failover** — if the CC itself failed over, the `base_url` is updated automatically via the `/ha/healthcheck/` endpoint on next login.

### Interface changes not detected

1. Check `dns_baseline.json` is being updated:
   ```bash
   python3 -c "import json; d=json.load(open('dns_baseline.json')); print(d['interface_snapshot']['fetched_at'])"
   ```
2. Check `monitored_if_indexes` in `config.ini`. Leave empty to monitor all interfaces.
3. Set `log_level = DEBUG` and look for `[IfPollMonitor]` lines in the log.

### SSH config-paste restore fails

1. Verify SSH credentials under each device section in `config.ini`.
2. Test connectivity manually:
   ```bash
   ssh admin@10.213.50.51
   ```
3. Check `dns_baselines/` for `.cfg` files for the device. Templates are exported every 60 seconds — wait up to 1 minute after first startup.

### Policy templates not being exported

- Exports are frozen during any active failover.
- After recovery, exports resume after a **1-hour cooldown**.
- Check logs for `[TemplateExport]` lines.

### Log file location

```
/var/log/tune_dns_baseline/tune_dns_baseline.log
```

The directory is created automatically on first run.


---

## Architecture

```
baseline_tuning.py          ← Main entry point (run this)
│
├── DnsBaselineMonitor      ← Background thread: polls DNS QPS every pull_interval min → dns_baseline.json
├── DpPoliciesMonitor       ← Background thread: fetches DefensePro policy names daily → dp_policies.json
├── PolicyTemplateExport    ← Background thread: exports policy templates hourly → dns_baselines/
├── TrafficMonitor          ← Background thread: polls inbound traffic every 120 s
├── IfPollMonitor           ← Background thread: polls dns_baseline.json every 20 s for interface changes
└── DpFailoverManager       ← Handles QPS redistribution, restore via CC REST API, and SSH config-paste
```

| File | Purpose |
|---|---|
| `baseline_tuning.py` | Main entry point; starts all monitors and wires failover callbacks |
| `build_dns_baseline.py` | Polls all DPs and saves current DNS QPS + interface snapshot to `dns_baseline.json` |
| `build_dp_policies.py` | Fetches policy names per device from CC API; refreshes daily at midnight → `dp_policies.json` |
| `export_policy_templates.py` | Exports per-device/policy config templates hourly to `dns_baselines/`; freezes during failover |
| `dp_config_restore.py` | SSH-based config-paste restore after failover recovery |
| `dp_failover_manager.py` | Redistribution logic, restore logic, read-back verification |
| `cc_connector.py` | All Cyber Controller REST API calls (login, QPS read/write, traffic, ifTable, policy templates) |
| `if_status_monitor.py` | Fetches / saves / compares interface operational status (ifTable API) |
| `if_poll_monitor.py` | Polls `dns_baseline.json` every 20 s; fires `on_interface_down` / `on_interface_up` callbacks |
| `configParser.py` | Parses `config.ini` and exposes settings as module variables |
| `validation.py` | Validates config structure and device reachability |
| `logManager.py` | Rotating file + console logger |
| `config.ini` | **Single configuration file — edit this before running** |
| `dns_baseline.json` | Auto-generated at runtime; stores last known QPS + interface snapshot per device |
| `dp_policies.json` | Auto-generated at runtime; maps device IPs to policy name lists |
| `dns_baselines/` | Auto-populated at runtime; one `.cfg` file per device/policy |

---

## Requirements

- Python 3.10+
- Virtual environment with dependencies (see below)
- Network access to the Cyber Controller (HTTPS)
- SSH access to each DefensePro (port 22) for config-paste restore

### Install dependencies

```bash
python3 -m venv myvenv
source myvenv/bin/activate
pip install -r requirements.txt
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

The CC IP address is hardcoded in `cc_connector.py` (`self.base_url`). Update it there if the CC IP changes.

---

### `[trigger.mgmt_down]`

Fires when a DefensePro **management** interface goes down — detected by the interface poll monitor.

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

Fires when a DefensePro **network** interface goes down — detected by the interface poll monitor reading `dns_baseline.json` every 20 seconds.

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
| `down_delay_minutes` | integer | Minutes to wait after the entire site is detected as failed before triggering failover. `0` = trigger immediately. Default: `2`. |
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

Define your sites and DefensePro devices.

```ini
[site.Tel-Aviv]
devices = DefensePro-2

[site.Tel-Aviv.device.DefensePro-2]
ip                    = 10.213.50.51
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2
username              = admin
password              = secret
```

| Key | Type | Required | Description |
|---|---|---|---|
| `devices` | string | Yes | Comma-separated list of device names. Each must have a matching `[site.<name>.device.<device-name>]` section. |
| `ip` | string | Yes | Management IP of the DefensePro as registered in the Cyber Controller. |
| `inbound_baseline_kbps` | number | Yes | Expected normal inbound traffic in Kbps. |
| `monitored_if_indexes` | string | No | Comma-separated `ifIndex` values to watch. Leave empty to monitor all interfaces. |
| `username` | string | No | SSH username for config-paste restore. Falls back to `[cyber_controller]` username if omitted. |
| `password` | string | No | SSH password for config-paste restore. Falls back to `[cyber_controller]` password if omitted. |

> **How to determine `inbound_baseline_kbps`:**
> Run the system for a period with no incidents and observe the traffic values in the logs:
> ```
> [TrafficMonitor] 10.213.50.50 healthy — inBound=2337.5 Kbps, drop=-133.8%
> ```
> Set `inbound_baseline_kbps` to roughly 120% of the observed normal traffic.

---

### Full `config.ini` example

```ini
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
devices = DefensePro-2

[site.Tel-Aviv.device.DefensePro-2]
ip                    = 10.213.50.51
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2
username              = admin
password              = secret

[site.Haifa]
devices = DefensePro-3, DefensePro-4

[site.Haifa.device.DefensePro-3]
ip                    = 10.213.50.52
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2

[site.Haifa.device.DefensePro-4]
ip                    = 10.213.50.53
inbound_baseline_kbps = 1000
monitored_if_indexes  = 1, 2
```

---

## dns_baseline.json

This file is **auto-generated** and **must not be edited manually**.

### DNS QPS baseline (`timestamp` / `sites`)

Updated every `pull_interval` minutes when all devices are healthy. **Frozen** during an active failover to preserve pre-failure QPS values.

### Interface snapshot (`interface_snapshot`)

Updated every poll cycle for all reachable devices, even during failover. Polled every 20 seconds by `if_poll_monitor.py` to detect interface state changes.

```json
{
  "timestamp": "...",
  "sites": [ "..." ],
  "interface_snapshot": {
    "fetched_at": "2026-05-11T11:37:17.772930",
    "devices": {
      "10.213.50.51": [
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
Traffic drop detected / Interface down detected (poll monitor)
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
    └── Freeze dns_baselines/ policy template exports

Traffic recovers / Interface up detected (poll monitor)
    └── Cancel any pending failover delay timer for this site
    └── Validate device is truly up
    └── Read dns_baseline.json (original pre-failover values)
    └── Restore each device's QPS to baseline values → read back and verify ✅
    └── SSH into each recovered DefensePro → paste saved config from dns_baselines/
    └── Re-poll all devices → save updated snapshot
    └── Unfreeze dns_baseline.json DNS updates
    └── Unfreeze dns_baselines/ policy template exports (after 1-hour cooldown)
```

---

## Troubleshooting

### Interface changes not detected

1. **Check `dns_baseline.json` is being updated:**
   ```bash
   cat dns_baseline.json | python3 -m json.tool | grep fetched_at
   ```

2. **Check `monitored_if_indexes`** in `config.ini`. Set to empty or omit to monitor all interfaces.

3. **Increase log verbosity** to `DEBUG` and look for `[IfPollMonitor]` log lines.

### SSH config-paste restore fails

1. **Verify SSH credentials** in `config.ini` under each device section (`username` / `password`).

2. **Check connectivity:**
   ```bash
   ssh admin@10.213.50.51
   ```

3. **Check `dns_baselines/` folder** for `.cfg` files for the recovered device. Templates are exported hourly — wait up to 1 hour after first startup.

### Policy templates not being exported

- Templates are exported hourly and frozen during any active failover.
- After recovery, exports resume after a **1-hour cooldown**.
- Check logs for `[PolicyTemplateExport]` lines.
