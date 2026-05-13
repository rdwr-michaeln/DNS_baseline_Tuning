import configParser
import os


class ConfigValidator:
    def __init__(self):
        pass

    def _get_sites(self):
        """Return the sites list from configParser."""
        return configParser.sites_config
    
    def initialize_configuration(self):
        """
        Validate and display the sites configuration loaded from config.ini
        """
        print("Checking sites configuration from config.ini...")

        sites_config = self._get_sites()

        if not sites_config:
            print("Sites configuration is empty or missing in config.ini")
            return False

        print("Sites configuration loaded successfully!")

        # Display configuration in human-readable format
        print("\n" + "="*60)
        print("SITES CONFIGURATION OVERVIEW")
        print("="*60)

        total_devices = 0

        for i, site in enumerate(sites_config, 1):
            site_name = site.get("site-name", f"Site_{i}")
            devices   = site.get("devices", [])

            print(f"\nSite {i}: {site_name}")
            print(f"   Devices: {len(devices)}")

            for j, device in enumerate(devices, 1):
                device_name = device.get("name", f"Device_{j}")
                device_ip   = device.get("ip", "IP not specified")
                ip_status   = "OK" if self._is_valid_ip(device_ip) else "WARN"

                print(f"   [{ip_status}] Device {j}: {device_name}  IP: {device_ip}")
                total_devices += 1

        print(f"\n" + "="*60)
        print(f"Total devices: {total_devices}")
        print("="*60)

        self._validate_configuration_issues(sites_config)
        return True

    
    def _is_valid_ip(self, ip):
        """
        Basic IP address validation
        """
        if not isinstance(ip, str) or ip == "IP not specified":
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False
    
    def _validate_configuration_issues(self, sites_config):
        """
        Check for common configuration issues
        """
        print("\nCONFIGURATION VALIDATION:")

        issues_found = 0

        # Check for duplicate device IPs
        all_ips = []
        duplicate_ips = []
        for site in sites_config:
            for device in site.get("devices", []):
                ip = device.get("ip")
                if ip and ip != "IP not specified":
                    if ip in all_ips and ip not in duplicate_ips:
                        duplicate_ips.append(ip)
                    all_ips.append(ip)

        if duplicate_ips:
            issues_found += 1
            print(f"  Issue {issues_found}: Duplicate device IPs found: {duplicate_ips}")

        # Check for duplicate site names
        site_names = [s.get("site-name", "") for s in sites_config]
        duplicate_sites = [n for n in set(site_names) if site_names.count(n) > 1 and n]
        if duplicate_sites:
            issues_found += 1
            print(f"  Issue {issues_found}: Duplicate site names found: {duplicate_sites}")

        # Check for missing required fields
        missing_fields = []
        for i, site in enumerate(sites_config, 1):
            if not site.get("site-name"):
                missing_fields.append(f"Site {i}: missing site-name")
            if not site.get("devices"):
                missing_fields.append(f"Site {i}: missing devices")

        if missing_fields:
            issues_found += 1
            print(f"  Issue {issues_found}: Missing required fields:")
            for field in missing_fields:
                print(f"    - {field}")

        if issues_found == 0:
            print("  No issues found - configuration looks good!")
        else:
            print(f"  Found {issues_found} issue(s) that should be addressed.")

        print("-" * 60)

    
    def load_sites_config(self):
        """Return the sites list from configParser."""
        return self._get_sites()
    
    def find_affected_groups(self, sites_config, device_ip):
        """
        Find all groups that contain the specified device IP
        """
        affected_groups = []
        
        if not isinstance(sites_config, list):
            return affected_groups
        
        for group in sites_config:
            if not isinstance(group, dict):
                continue
            
            devices = group.get("devices", [])
            if not isinstance(devices, list):
                continue
            
            # Check if this group contains the device with the specified IP
            for device in devices:
                if isinstance(device, dict) and device.get("ip") == device_ip:
                    affected_groups.append(group)
                    break  # Found the device in this group, move to next group
        
        return affected_groups
    
    def dp_status_check(self, trap_ip, event_type="down", logger=None):
        """
        Handle DefensePro status events - find affected groups and process
        
        Args:
            trap_ip (str): IP address of the device
            event_type (str): "down" for DOWN event, "up" for UP event
            logger: Standard Python logger instance
        """
        # Load sites configuration
        sites_config = self.load_sites_config()
        if not sites_config:
            if logger:
                logger.error("❌ Failed to load sites configuration")
            else:
                print("ERROR: ❌ Failed to load sites configuration")
            return None
        
        # Find affected groups
        affected_groups = self.find_affected_groups(sites_config, trap_ip)
        
        if affected_groups:
            if event_type.lower() == "down":
                if logger:
                    logger.info(f"Found device in {len(affected_groups)} site(s):")
                    for group in affected_groups:
                        logger.info(f"   - Site: {group.get('site-name', 'Unknown')} (Devices: {len(group.get('devices', []))})")
                else:
                    print(f"Found device in {len(affected_groups)} site(s):")
                    for group in affected_groups:
                        print(f"   - Site: {group.get('site-name', 'Unknown')} (Devices: {len(group.get('devices', []))})")
            else:  # event_type == "up"
                if logger:
                    logger.info(f"📍 Device {trap_ip} is back online in {len(affected_groups)} group(s):")
                    for group in affected_groups:
                        group_name = group.get("group_name", "Unknown")
                        logger.info(f"   - Group: {group_name} - Device restored")
                else:
                    print(f"Device {trap_ip} is back online in {len(affected_groups)} site(s):")
                    for group in affected_groups:
                        print(f"   - Site: {group.get('site-name', 'Unknown')} - Device restored")
        else:
            if logger:
                logger.warning(f"Device IP {trap_ip} not found in any site")
            else:
                print(f"WARNING: Device IP {trap_ip} not found in any site")
        
        if event_type.lower() == "down" and logger:
            logger.debug(f"Affected groups data: {affected_groups}")
        
        return affected_groups

