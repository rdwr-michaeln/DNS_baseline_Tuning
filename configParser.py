import configparser
import os, sys

config_file_path = 'config.ini'

if not os.path.exists(config_file_path):
    print(f"Error: Configuration file not found: {config_file_path}")
    sys.exit(1)

_cfg = configparser.ConfigParser()
_cfg.read(config_file_path)

# [snmp]
_snmp = _cfg['snmp'] if 'snmp' in _cfg else {}
targets_raw = _snmp.get('targets', '')
targets = [t.strip() for t in targets_raw.split(',') if t.strip()]
if not targets:
    print("Error: SNMP targets are missing in the configuration file.")
    sys.exit(1)
agent     = _snmp.get('agent', '0.0.0.0')
port      = int(_snmp.get('port', '162'))
community = _snmp.get('community', 'public')

# SNMPv3 settings (only used when version = v3)
snmp_version       = _snmp.get('version', 'v2c').strip().lower()
v3_username        = _snmp.get('v3_username',        '').strip()
v3_auth_protocol   = _snmp.get('v3_auth_protocol',   'SHA').strip()
v3_auth_passphrase = _snmp.get('v3_auth_passphrase', '').strip()
v3_priv_protocol   = _snmp.get('v3_priv_protocol',   'AES128').strip()
v3_priv_passphrase = _snmp.get('v3_priv_passphrase', '').strip()

if snmp_version == 'v3' and not v3_username:
    print("Error: v3_username is required when snmp version = v3.")
    sys.exit(1)

if snmp_version == 'v3' and v3_auth_protocol.upper() != 'NONE':
    if len(v3_auth_passphrase) < 8:
        print(f"Error: v3_auth_passphrase must be at least 8 characters (SNMPv3 RFC 3414 requirement). Current length: {len(v3_auth_passphrase)}.")
        sys.exit(1)

if snmp_version == 'v3' and v3_priv_protocol.upper() != 'NONE':
    if len(v3_priv_passphrase) < 8:
        print(f"Error: v3_priv_passphrase must be at least 8 characters (SNMPv3 RFC 3414 requirement). Current length: {len(v3_priv_passphrase)}.")
        sys.exit(1)

# [time_settings]
pull_interval = int(_cfg.get('time_settings', 'pull_interval', fallback='10'))
if not pull_interval:
    print("Error: Time Settings is missing in the configuration file.")
    sys.exit(1)

# [logging]
log_level        = _cfg.get('logging', 'log_level',        fallback='INFO')
log_max_size_kb  = int(_cfg.get('logging', 'log_max_size_kb',  fallback='512'))
log_backup_count = int(_cfg.get('logging', 'log_backup_count', fallback='10'))
log_path         = '/var/log/tune_dns_baseline/'
log_filename     = 'tune_dns_baseline.log'
full_log_path    = os.path.join(log_path, log_filename)

# [cyber_controller]
cc_base_url = _cfg.get('cyber_controller', 'base_url',  fallback='https://10.213.50.40')
username    = _cfg.get('cyber_controller', 'username',  fallback='radware')
password    = _cfg.get('cyber_controller', 'password',  fallback='radware')

# [trigger.mgmt_down]
trigger_mgmt_down             = _cfg.getboolean('trigger.mgmt_down', 'enabled',             fallback=True)
trigger_mgmt_down_delay       = int(_cfg.get(    'trigger.mgmt_down', 'down_delay_minutes',  fallback='0')) * 60

# [trigger.interface_down]
trigger_interface_down        = _cfg.getboolean('trigger.interface_down', 'enabled',             fallback=True)
trigger_interface_down_delay  = int(_cfg.get(   'trigger.interface_down', 'down_delay_minutes',  fallback='0')) * 60

# [trigger.traffic_decrease]
trigger_traffic_decrease         = _cfg.getboolean('trigger.traffic_decrease', 'enabled',                        fallback=True)
trigger_traffic_decrease_delay   = int(_cfg.get(   'trigger.traffic_decrease', 'down_delay_minutes',             fallback='0')) * 60
inbound_drop_threshold_percent   = int(_cfg.get(   'trigger.traffic_decrease', 'inbound_drop_threshold_percent', fallback='50'))
site_failure_on_all_dp_down      = _cfg.getboolean('trigger.traffic_decrease', 'site_failure_on_all_dp_down',    fallback=True)

# Per-device inbound baselines: { ip: kbps (float) }
# Read from sections named [site.<name>.device.<device-name>]
inbound_baselines = {}
for _section in _cfg.sections():
    _parts = _section.split('.')
    if len(_parts) == 4 and _parts[0] == 'site' and _parts[2] == 'device':
        _dev = _cfg[_section]
        _ip  = _dev.get('ip')
        _kbps = _dev.get('inbound_baseline_kbps')
        if _ip and _kbps is not None:
            inbound_baselines[_ip] = float(_kbps)

# sites_config: list of site dicts compatible with the old JSON format
# [{ "site-name": ..., "devices": [{"name": ..., "ip": ..., "inbound_baseline_kbps": ...}] }]
sites_config = []
for _section in _cfg.sections():
    _parts = _section.split('.')
    if len(_parts) == 2 and _parts[0] == 'site':
        _site_name = _parts[1]
        _device_names = [d.strip() for d in _cfg.get(_section, 'devices', fallback='').split(',') if d.strip()]
        _devices = []
        for _dname in _device_names:
            _dsection = f'site.{_site_name}.device.{_dname}'
            if _dsection in _cfg:
                _d = _cfg[_dsection]
                _if_idx_raw = _d.get('monitored_if_indexes', '')
                _if_idxs = {int(x.strip()) for x in _if_idx_raw.split(',') if x.strip().isdigit()}
                _devices.append({
                    'name': _dname,
                    'ip': _d.get('ip', ''),
                    'inbound_baseline_kbps': float(_d.get('inbound_baseline_kbps', 0)),
                    'monitored_if_indexes': _if_idxs,
                })
        sites_config.append({'site-name': _site_name, 'devices': _devices})

# Flat lookup: { device_ip: set of monitored ifIndex ints }
# Empty set means "monitor all interfaces" (no filter applied).
device_monitored_if_indexes = {
    dev['ip']: dev['monitored_if_indexes']
    for site in sites_config
    for dev in site.get('devices', [])
    if dev.get('ip')
}
