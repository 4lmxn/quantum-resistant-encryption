import os
import pathlib

# config.py

# Sensor and actuator session keys are NOT set here any more. They are agreed
# per connection by the ML-KEM-768 handshake in pqc.py.

# Provisioned pre-shared key for the constrained ESP32 node. A microcontroller
# flashed at the factory has no handshake partner at boot, so this leg falls
# back to a provisioned key. Exactly 32 bytes for AES-256-GCM.
#
# It is NOT committed. Nothing in the repository can forge ESP32 telemetry,
# because the key is generated at runtime and persisted only to the gitignored
# provisioning directory. `make enroll` generates and prints it, and a real
# board is flashed with that value at commissioning -- genuine provisioning, not
# a shared secret hiding in the source.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PSK_PATH = PROJECT_ROOT / "identities" / "device.psk"


def load_or_provision_device_psk():
    """Returns the 32-byte device PSK, generating and persisting it once.

    Precedence: an explicit DEVICE_PSK env var, else the provisioning file, else
    a freshly generated key written to that file so every process in this
    deployment (server, simulator) reads the same one. The file lives under the
    gitignored identities/ directory, so the key never enters version control.
    """
    env = os.environ.get("DEVICE_PSK")
    if env is not None:
        key = env.encode()
        assert len(key) == 32, "DEVICE_PSK env var must be exactly 32 bytes for AES-256"
        return key

    if _PSK_PATH.exists():
        return bytes.fromhex(_PSK_PATH.read_text().strip())

    key = os.urandom(32)
    _PSK_PATH.parent.mkdir(exist_ok=True)
    try:
        # First writer wins: a concurrent import must not clobber the key another
        # process already generated, or the two would seal with different keys.
        with open(_PSK_PATH, "x") as f:
            f.write(key.hex())
        os.chmod(_PSK_PATH, 0o600)
        print(f"[config] provisioned a fresh device PSK at {_PSK_PATH}")
        print(f"[config] flash this into a real ESP32: {key.hex()}")
    except FileExistsError:
        key = bytes.fromhex(_PSK_PATH.read_text().strip())
    return key


DEVICE_PSK = load_or_provision_device_psk()
assert len(DEVICE_PSK) == 32, "DEVICE_PSK must be exactly 32 bytes for AES-256"

# ---------------------------------------------------------------- safety ----
# SIS-01: the trip setpoint for the emergency shutdown function. Crossing it
# latches a trip; only an authenticated operator RESET clears it.
TRIP_SETPOINT_C = 80.0

# An operator may move the setpoint, but not anywhere. Oldsmar was a legitimate
# control path used to make an illegitimate change, so the bound matters as much
# as the authentication: a signed command that asks for 11,100 is still refused.
SETPOINT_MIN_C = 40.0
SETPOINT_MAX_C = 120.0
SETPOINT_MAX_STEP_C = 15.0

# How stale a signed operator command may be before the server refuses it.
OPERATOR_MAX_SKEW_S = 30.0

# Dead-man heartbeat on the safety link. The actuator trips when these stop, so
# cutting the network closes the valve instead of freezing it open.
HEARTBEAT_PERIOD_S = 2.0
HEARTBEAT_TIMEOUT_S = 6.0

# Port 5000 is occupied by AirPlay Receiver on macOS, hence 5001.
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001
SERVER_URL = "http://127.0.0.1:5001"

# MQTT transport (report §3.1: MQTT over TLS 1.3). The Socket.IO path above
# still serves the browser dashboard, which is a UI client, not an IoT node.
MQTT_HOST = "127.0.0.1"
MQTT_TLS_PORT = 8883
# Absolute, so every entry point resolves them the same way regardless of cwd.
CERT_DIR = PROJECT_ROOT / "certs"
MQTT_CA_CERT = str(CERT_DIR / "ca.crt")

TOPIC_HELLO = "iot/handshake/hello"
TOPIC_PUBKEY = "iot/handshake/pubkey"      # + /<node_id>
TOPIC_ENCAPS = "iot/handshake/encaps"      # + /<node_id>
TOPIC_TELEMETRY = "iot/telemetry"          # + /<node_id>
TOPIC_COMMAND = "iot/command"              # + /<node_id>
