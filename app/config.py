import os
import pathlib

# config.py

# Sensor and actuator session keys are NOT set here any more. They are agreed
# per connection by the ML-KEM-768 handshake in pqc.py.

# Provisioned pre-shared key for the constrained ESP32 node only. A
# microcontroller flashed at the factory has no handshake partner at boot, so
# this leg falls back to a burned-in key. Exactly 32 bytes for AES-256-GCM.
# WARNING: this is a demo key committed to the repository, so anyone reading the
# source can forge ESP32 telemetry. Override it in any real deployment:
#   export DEVICE_PSK="<32 bytes>"
DEVICE_PSK = os.environ.get("DEVICE_PSK", "esp32_provisioned_aes256_key_32B").encode()
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
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
CERT_DIR = PROJECT_ROOT / "certs"
MQTT_CA_CERT = str(CERT_DIR / "ca.crt")

TOPIC_HELLO = "iot/handshake/hello"
TOPIC_PUBKEY = "iot/handshake/pubkey"      # + /<node_id>
TOPIC_ENCAPS = "iot/handshake/encaps"      # + /<node_id>
TOPIC_TELEMETRY = "iot/telemetry"          # + /<node_id>
TOPIC_COMMAND = "iot/command"              # + /<node_id>
