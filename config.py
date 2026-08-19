# config.py

# Sensor and actuator session keys are NOT set here any more. They are agreed
# per connection by the ML-KEM-768 handshake in pqc.py.

# Provisioned pre-shared key for the constrained ESP32 node only. A
# microcontroller flashed at the factory has no handshake partner at boot, so
# this leg falls back to a burned-in key. Exactly 32 bytes for AES-256-GCM.
DEVICE_PSK = b"esp32_provisioned_aes256_key_32B"

TEMP_THRESHOLD = 30.0

# Port 5000 is occupied by AirPlay Receiver on macOS, hence 5001.
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001
SERVER_URL = "http://127.0.0.1:5001"
