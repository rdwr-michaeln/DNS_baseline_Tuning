import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CcConnector:
    def __init__(self, username = "radware", password = "radware"):
        self.base_url = "https://10.213.50.40"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.login()

    def active_cc_check(self):
        try:
            url = f"{self.base_url}/ha/healthcheck/"
            r = self.session.get(url, verify=False)
            if r.status_code == 418:
                if r.text.strip():
                    try:
                        self.base_url = f'https://{r.json()["remoteHost"]}'
                        print(f"Switched to remote host: {self.base_url}")
                    except (ValueError, KeyError) as e:
                        print(f"Failed to parse remote host from healthcheck: {e}")
        except Exception as e:
            print(f"Exception in active_cc_check: {e}")
        
    def login(self):
        try:
            self.active_cc_check()
            url = f"{self.base_url}/mgmt/system/user/login"
            payload = {"username": self.username, "password": self.password}
            r = self.session.post(url, json=payload, verify=False)
            
            if r.status_code == 200:
                print("Login successful")
            else:
                print(f"Login failed with status code: {r.status_code}")
                if r.text:
                    print(f"Login error response: {r.text[:200]}...")
        except Exception as e:
            print(f"Exception during login: {e}")

    def _request(self, method, url, **kwargs):
        """
        Wrapper around session.request that automatically re-logins and retries
        once on a 401 Unauthorized response (expired session).
        """
        r = self.session.request(method, url, **kwargs)
        if r.status_code == 401:
            print("Session expired — re-logging in and retrying...")
            # Clear stale cookies so duplicate JSESSIONID values don't accumulate
            self.session.cookies.clear()
            self.login()
            # Refresh jsessionid header with the newly issued cookie
            if "headers" in kwargs and "jsessionid" in kwargs["headers"]:
                kwargs["headers"]["jsessionid"] = next(
                    (c.value for c in self.session.cookies if c.name == "JSESSIONID"), ""
                )
            r = self.session.request(method, url, **kwargs)
        return r



    def get_device_orm_map(self, allowed_ips=None):
        """
        Returns a dict mapping managementIp -> ormId.
        If allowed_ips is provided (set/list), only those IPs are returned.
        This prevents non-DP devices (e.g. DefenseFlow / the CC itself) from
        being included and causing 401 errors on the utilization API.
        """
        try:
            url = f"{self.base_url}/mgmt/system/config/itemlist/alldevices"
            r = self.session.get(url, verify=False)
            if r.status_code == 200:
                return {
                    d["managementIp"]: d["ormId"]
                    for d in r.json()
                    if d.get("managementIp") and d.get("ormId")
                    and (allowed_ips is None or d["managementIp"] in allowed_ips)
                }
            else:
                print(f"Failed to get device list, status code: {r.status_code}")
                return {}
        except Exception as e:
            print(f"Exception in get_device_orm_map: {e}")
            return {}

    def lock_device(self, dp_ip):
        """
        Lock a DefensePro device by its IP address.
        """
        try:
            url = f"{self.base_url}/mgmt/system/config/tree/device/byip/{dp_ip}/lock"
            r = self.session.post(url, verify=False)
            if r.status_code == 200:
                print(f"Successfully locked device {dp_ip}")
                return True
            else:
                print(f"Failed to lock device {dp_ip}, status code: {r.status_code}")
                return False
        except Exception as e:
            print(f"Exception in lock_device: {e}")
            return False
    
    def update_policy(self, dp_ip):
        """
        Update the policy on a DefensePro device by its IP address.
        """
        try:
            url = f"{self.base_url}/mgmt/device/byip/{dp_ip}/config/updatepolicies"
            r = self.session.post(url, verify=False)
            if r.status_code == 200:
                print(f"Successfully updated policy on device {dp_ip}")
                return True
            else:
                print(f"Failed to update policy on device {dp_ip}, status code: {r.status_code}")
                return False
        except Exception as e:
            print(f"Exception in update_policy: {e}")
            return False

    def dp_dns_qps_update(self, dp_ip, po_name, expected_qps, max_allow_qps):
        """
        Update DNS QPS settings on a DefensePro device by its IP address.
        
        Args:
            dp_ip (str): Device IP address
            po_name (str): Protection Object name
            expected_qps (int): Expected DNS Query Rate
            max_allow_qps (int): Max Allowed QPS
        """
        try:
            url = f"{self.base_url}/mgmt/device/byip/{dp_ip}/config/rsDnsProtProfileTable/{po_name}/"
            payload = {
                "rsDnsProtProfileName": po_name,
                "rsDnsProtProfileExpectedQps": expected_qps,
                "rsDnsProtProfileMaxAllowQps": max_allow_qps
            }
            r = self.session.put(url, json=payload, verify=False)
            if r.status_code == 200:
                print(f"Successfully updated DNS QPS settings on device {dp_ip}")
                return True
            else:
                print(f"Failed to update DNS QPS settings on device {dp_ip}, status code: {r.status_code}")
                return False
        except Exception as e:
            print(f"Exception in dp_dns_qps_update: {e}")
            return False


    def get_po_dns_per_dp(self, dp_ip):
        """
        Get DNS protection profile information for each DefensePro device.
        Returns a dictionary where keys are device IPs and values contain lists of PO information.
        Format: {'IP': [{'po_name': 'name1', 'expected_qps': value1, 'max_allow_qps': value2}, ...]}
        """
        try:
            url = f"{self.base_url}/mgmt/device/byip/{dp_ip}/config/rsDnsProtProfileTable?count=50&props=rsDnsProtProfileName,rsDnsProtProfileAction,rsDnsProtProfilePacketReportStatus,rsDnsProtProfileDnsAStatus,rsDnsProtProfileDnsMxStatus,rsDnsProtProfileDnsPtrStatus,rsDnsProtProfileDnsHttpsStatus,rsDnsProtProfileDnsAaaaStatus,rsDnsProtProfileDnsTextStatus,rsDnsProtProfileDnsSoaStatus,rsDnsProtProfileDnsNaptrStatus,rsDnsProtProfileDnsSrvStatus,rsDnsProtProfileDnsOtherStatus,rsDnsProtProfileExpectedQps,rsDnsProtProfileMaxAllowQps,rsDnsProtProfileSigRateLimTarget,rsDnsProtProfileProtectedDnsServer,rsDnsProtProfileManualTriggerStatus,rsDnsProtProfileFootprintStrictness,rsDnsProtProfileLearningSuppressionThreshold,rsDnsProtProfileComplianceCheck,rsDnsProtProfileLargeEdnsPackets"
            r = self.session.get(url, verify=False)
            if r.status_code == 200:
                dp_po_data = r.json()
                dns_info = {}
                
                # Initialize the IP key with an empty list if not exists
                if dp_ip not in dns_info:
                    dns_info[dp_ip] = []
                
                # Iterate through all POs and add them to the list for this IP
                for po in dp_po_data["rsDnsProtProfileTable"]:
                    po_name = po['rsDnsProtProfileName']
                    expected_qps = po["rsDnsProtProfileExpectedQps"]
                    max_allow_qps = po["rsDnsProtProfileMaxAllowQps"]
                    if po_name:
                        po_info = {
                            "po_name": po_name,
                            "expected_qps": expected_qps,
                            "max_allow_qps": max_allow_qps
                        }
                        dns_info[dp_ip].append(po_info)

                
                return dns_info
            else:
                print(f"Failed to get devices, status code: {r.status_code}")
                return {}
        except Exception as e:
            print(f"Exception in get_po_dns_per_dp: {e}")
            return {}


    def get_traffic_utilization(self, orm_id):
        """
        POST to the traffic utilization endpoint for a given ormId.
        Returns a list of inBound values (one per time-sample) or an empty list on error.

        Args:
            orm_id (str): The device ormId as returned by get_device_orm_map()
        """
        try:
            url = f"{self.base_url}/mgmt/monitor/security/dp/traffic/utilization"
            payload = {
                "filter": {
                    "protocol": {"operator": "=", "value": "All"},
                    "traffic":  {"operator": "=", "value": "Inbound"},
                    "units":    {"operator": "=", "value": "Kbps"}
                },
                "reportScope": {
                    "range": 60,
                    "devices": [orm_id],
                    "ports": {
                        "source": [{"deviceId": orm_id, "port": "1"}],
                        "dest":   [],
                        "biDir":  []
                    },
                    "policies":       [],
                    "policySelected": False
                },
                "sort": []
            }
            jsessionid = next(
                (c.value for c in self.session.cookies if c.name == "JSESSIONID"), ""
            )
            headers = {"jsessionid": jsessionid} if jsessionid else {}
            r = self._request("POST", url, json=payload, headers=headers, verify=False)
            if r.status_code == 200:
                samples = r.json()
                return [s["inBound"] for s in samples if s.get("inBound") is not None]
            else:
                print(f"Failed to get traffic utilization for ormId {orm_id}, status: {r.status_code}")
                return []
        except Exception as e:
            print(f"Exception in get_traffic_utilization: {e}")
            return []

    def get_inbound_traffic_per_device(self, allowed_ips=None):
        """
        Collect the latest inBound traffic (Kbps) for every managed device.
        Pass allowed_ips to restrict to configured DefensePro IPs only.

        Returns a dict:
            { managementIp: {"orm_id": str, "inbound_samples": [int, ...]} }
        """
        orm_map = self.get_device_orm_map(allowed_ips=allowed_ips)
        result  = {}
        for ip, orm_id in orm_map.items():
            samples = self.get_traffic_utilization(orm_id)
            result[ip] = {"orm_id": orm_id, "inbound_samples": samples}
        return result

    def get_if_table(self, dp_ip):
        """
        Fetch interface operational status from a DefensePro device.
        Only ifIndex, ifDescr and ifOperStatus are requested.
        ifOperStatus: "1" = up, "2" = down.
        """
        try:
            url = f"{self.base_url}/mgmt/device/byip/{dp_ip}/config/ifTable?count=50&props=ifIndex,ifDescr,ifOperStatus"
            r = self.session.get(url, verify=False, timeout=10)
            if r.status_code == 200:
                return r.json().get("ifTable", [])
            else:
                print(f"ifTable query failed for {dp_ip}: status {r.status_code}")
                return []
        except Exception as e:
            print(f"Exception in get_if_table for {dp_ip}: {e}")
            return []
