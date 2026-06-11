import configparser
import os
import sys

config_file_path = 'config.ini'


def _csv_values(raw):
    return [value.strip() for value in raw.split(',') if value.strip()]


def _device_section_name(site_name, device_name):
    return f'site.{site_name}.device.{device_name}'


def _parse_monitored_if_indexes(indexes_raw):
    return {
        int(index.strip())
        for index in indexes_raw.split(',')
        if index.strip().isdigit()
    }


if not os.path.exists(config_file_path):
    print(f"Error: Configuration file not found: {config_file_path}")
    sys.exit(1)

_cfg = configparser.ConfigParser()
_cfg.read(config_file_path)

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
        _device_names = _csv_values(_cfg.get(_section, 'devices', fallback=''))
        _devices = []
        for _dname in _device_names:
            _dsection = _device_section_name(_site_name, _dname)
            if _dsection in _cfg:
                _d = _cfg[_dsection]
                _if_idx_raw = _d.get('monitored_if_indexes', '')
                _if_idxs = _parse_monitored_if_indexes(_if_idx_raw)
                _devices.append({
                    'name': _dname,
                    'ip': _d.get('ip', ''),
                    'inbound_baseline_kbps': float(_d.get('inbound_baseline_kbps', 0)),
                    'monitored_if_indexes': _if_idxs,
                    'username': _d.get('username', username),
                    'password': _d.get('password', password),
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

# Per-device credentials lookup: { device_ip: {'username': str, 'password': str} }
# Falls back to [cyber_controller] username/password when not set on the device.
device_credentials = {
    dev['ip']: {'username': dev['username'], 'password': dev['password']}
    for site in sites_config
    for dev in site.get('devices', [])
    if dev.get('ip')
}
