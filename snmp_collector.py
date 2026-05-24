from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pyasn1.codec.ber import decoder as _ber_decoder
from pyasn1.type import univ as _asn1univ
import json


# ---------------------------------------------------------------------------
# SNMPv3 dynamic engine-ID registration
# ---------------------------------------------------------------------------

def _extract_v3_engine_id(whole_msg):
    """
    Parse the raw SNMPv3 packet just enough to extract
    msgAuthoritativeEngineID and msgUserName without authenticating it.
    Returns (engine_id_bytes, username_str) or (None, None) for non-v3 / errors.
    """
    try:
        msg, _ = _ber_decoder.decode(whole_msg, asn1Spec=_asn1univ.Sequence())
        if int(msg[0]) != 3:          # not SNMPv3
            return None, None
        sec_raw = bytes(msg[2])       # msgSecurityParameters (BER-encoded)
        usm, _ = _ber_decoder.decode(sec_raw, asn1Spec=_asn1univ.Sequence())
        engine_id = bytes(usm[0])     # msgAuthoritativeEngineID
        username  = bytes(usm[3]).decode("utf-8", errors="replace")  # msgUserName
        return engine_id, username
    except Exception:
        return None, None


def _patch_for_any_engine(snmp_engine, username, auth_proto, auth_key,
                          priv_proto, priv_key, debug=False):
    """
    Monkey-patch snmpEngine.message_dispatcher.receive_message so that
    the first trap from any previously-unseen engine is handled correctly.

    Problem: pysnmp localizes auth/priv keys to the engine ID given at
    add_v3_user() time.  Using the wildcard 0x0000000000 only works for
    noAuthNoPriv; authPriv traps are silently dropped because the HMAC is
    computed against the real engine ID, not the wildcard.

    Fix: intercept each raw UDP packet, decode the engine ID before pysnmp's
    USM runs, register the user (with correctly localized keys) for that engine
    ID if we haven't seen it before, then let normal processing continue.

    debug=True prints a one-liner for every raw packet received — useful for
    confirming that UDP packets are actually reaching the process.
    """
    _registered = set()
    original = snmp_engine.message_dispatcher.receive_message

    def _receive(eng, transport_domain, transport_address, whole_msg):
        engine_id, msg_user = _extract_v3_engine_id(whole_msg)
        if debug:
            eid_hex = engine_id.hex() if engine_id else "n/a"
            print(f"[RAW] {len(whole_msg)} bytes  src={transport_address}"
                  f"  engineId={eid_hex}  user={msg_user!r}", flush=True)
        if (
            engine_id
            and engine_id not in _registered
            and msg_user == username
        ):
            _registered.add(engine_id)
            print(f"[v3] New engine ID {engine_id.hex()} — registering user '{username}'"
                  " with localized keys", flush=True)
            try:
                config.add_v3_user(
                    eng, username,
                    authProtocol  = auth_proto,
                    authKey       = auth_key,
                    privProtocol  = priv_proto,
                    privKey       = priv_key,
                    securityEngineId = engine_id,
                )
            except Exception as e:
                print(f"[v3] add_v3_user failed: {e}", flush=True)
        return original(eng, transport_domain, transport_address, whole_msg)

    snmp_engine.message_dispatcher.receive_message = _receive


# Maps config-file strings to pysnmp 7.x USM constants
_AUTH_PROTO_MAP = {
    "MD5":    config.USM_AUTH_HMAC96_MD5,
    "SHA":    config.USM_AUTH_HMAC96_SHA,
    "SHA224": config.USM_AUTH_HMAC128_SHA224,
    "SHA256": config.USM_AUTH_HMAC192_SHA256,
    "SHA384": config.USM_AUTH_HMAC256_SHA384,
    "SHA512": config.USM_AUTH_HMAC384_SHA512,
}

_PRIV_PROTO_MAP = {
    "AES128": config.USM_PRIV_CFB128_AES,
    "AES256": config.USM_PRIV_CFB256_AES,
    "DES":    config.USM_PRIV_CBC56_DES,
}


class SNMPTrapReceiver:
    TRAP_DIC = {
        "M_07630": {
            "m_num": 0,
            "device_name": 3,
            "status": 7,
            "ip_address": 8,
        },
        "M_07631": {
            "m_num": 0,
            "device_name": 3,
            "status": 7,
            "ip_address": 8,
        },
        "M_30000_Down": {
            "ip_address": 3,
        },
        "M_30000_Up": {
            "ip_address": 3,
        },
    }

    def __init__(self, agent_address, port, community, trap_queue,
                 snmp_version='v2c',
                 v3_username='', v3_auth_protocol='MD5', v3_auth_passphrase='',
                 v3_priv_protocol='AES', v3_priv_passphrase=''):
        self.snmp_engine = engine.SnmpEngine()
        self.agent_address = agent_address
        self.port = port
        self.community = community
        self.trap = []
        self.trap_queue = trap_queue

        # Configure transport
        config.add_transport(
            self.snmp_engine,
            udp.DOMAIN_NAME + (1,),
            udp.UdpTransport().open_server_mode((self.agent_address, self.port)),
        )

        # Configure security based on version
        snmp_version = snmp_version.lower()
        if snmp_version == 'v3':
            auth_proto = _AUTH_PROTO_MAP.get(v3_auth_protocol.upper(), config.USM_AUTH_NONE)
            priv_proto = _PRIV_PROTO_MAP.get(v3_priv_protocol.upper(), config.USM_PRIV_NONE)
            # Pass empty string as None so pysnmp treats it as "no key"
            auth_key = v3_auth_passphrase if v3_auth_passphrase else None
            priv_key = v3_priv_passphrase if v3_priv_passphrase else None
            # Register with wildcard for noAuthNoPriv / fallback
            config.add_v3_user(
                self.snmp_engine,
                v3_username,
                authProtocol=auth_proto,
                authKey=auth_key,
                privProtocol=priv_proto,
                privKey=priv_key,
                securityEngineId=bytes.fromhex("0000000000"),
            )
            # For authPriv: dynamically register the user for each sender's
            # real engine ID before pysnmp's USM authentication runs.
            _patch_for_any_engine(
                self.snmp_engine, v3_username,
                auth_proto, auth_key, priv_proto, priv_key,
            )
        else:
            # SNMPv1 / SNMPv2c – community-string based
            config.add_v1_system(self.snmp_engine, "my-area", self.community)

        # Attach callback
        ntfrcv.NotificationReceiver(self.snmp_engine, self.trap_callback)

    def trap_callback(
        self,
        snmp_engine,
        state_reference,
        context_engine_id,
        context_name,
        var_binds,
        cb_ctx,
    ):
        """Callback for handling incoming traps."""
        # print("Received new Trap message in JSON format:")
        trap_data = {name.prettyPrint(): val.prettyPrint() for name, val in var_binds}

        
        # Get the raw string value without JSON encoding
        raw_trap_string = trap_data["1.3.6.1.4.1.89.35.10.1.2"]
        
        # Clean up the string by removing unwanted characters and splitting
        self.trap = raw_trap_string.replace("[", "").replace(".", "").replace("]", "").replace(":", "").replace('"', "").split()
        
        ip_address = trap_data.get("1.3.6.1.4.1.89.35.10.1.10", "")
        if ip_address:  # Only add if IP address is not empty
            self.trap.append(ip_address)
        self.trap_parser()


    def trap_parser(self):
        base_key = self.trap[0]

        # M_30000 has both Link Down and Link Up under the same number —
        # build a compound key from the status word at index 2
        if base_key == "M_30000":
            status_word = self.trap[2] if len(self.trap) > 2 else ""
            lookup_key = f"M_30000_{status_word}"  # "M_30000_Down" or "M_30000_Up"
        else:
            lookup_key = base_key

        if lookup_key in SNMPTrapReceiver.TRAP_DIC:
            params = SNMPTrapReceiver.TRAP_DIC[lookup_key]
            trap = {}
            for key, val in params.items():
                trap[key] = self.trap[val]
            # Always set m_num to the lookup key so routing works correctly
            trap["m_num"] = lookup_key
            self.trap_queue.put(trap)

            


    def start_listening(self):
        """Start the SNMP trap receiver."""
        print(f"Starting SNMP trap receiver on {self.agent_address}:{self.port}")
        print("Press Ctrl+C to stop...")
        try:
            self.snmp_engine.transport_dispatcher.job_started(1)
            self.snmp_engine.transport_dispatcher.run_dispatcher()
        except KeyboardInterrupt:
            print("\nShutting down SNMP trap receiver...")
            self.snmp_engine.transport_dispatcher.close_dispatcher()


if __name__ == "__main__":
    import queue

    # Configuration
    AGENT_ADDRESS = "0.0.0.0"  # Listen on all interfaces
    PORT = 162  # Using non-privileged port for testing (standard port 162 requires root)

    # SNMPv2c settings
    SNMP_VERSION = "v2c"
    COMMUNITY    = "radddos"

    # SNMPv3 settings (used only when SNMP_VERSION = "v3")
    V3_USERNAME        = "trapuser"
    V3_AUTH_PROTOCOL   = "SHA"     # MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
    V3_AUTH_PASSPHRASE = "authpass"
    V3_PRIV_PROTOCOL   = "AES128"  # AES128 | AES256 | DES
    V3_PRIV_PASSPHRASE = "privpass"

    # Create a queue to store received traps
    trap_queue = queue.Queue()

    # Create and start the SNMP trap receiver
    receiver = SNMPTrapReceiver(
        AGENT_ADDRESS, PORT, COMMUNITY, trap_queue,
        snmp_version=SNMP_VERSION,
        v3_username=V3_USERNAME,
        v3_auth_protocol=V3_AUTH_PROTOCOL,
        v3_auth_passphrase=V3_AUTH_PASSPHRASE,
        v3_priv_protocol=V3_PRIV_PROTOCOL,
        v3_priv_passphrase=V3_PRIV_PASSPHRASE,
    )
    
    try:
        receiver.start_listening()
    except PermissionError:
        print("Permission denied. Port 162 requires root privileges.")
        print("Try running with sudo or use a higher port number (e.g., 1162)")
        print("To use port 1162, change PORT = 1162 in the script")
