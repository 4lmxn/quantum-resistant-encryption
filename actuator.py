import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socketio
from config import SESSION_KEY_B

sio = socketio.Client()
session_key_b = bytearray(SESSION_KEY_B)

class SimulatedActuatorNode:
    def __init__(self, key_b):
        self.key_b = key_b
        self.relay_state = "OFF"

    def process_command(self, packet):
        """Decrypts command and verifies the AES-256-GCM authentication tag."""
        aesgcm = AESGCM(bytes(self.key_b))
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        # Decrypt & Validate GCM Tag
        decrypted_raw = aesgcm.decrypt(nonce, ciphertext, None)
        cmd_data = json.loads(decrypted_raw.decode("utf-8"))

        if cmd_data.get("command") == "FAN_ON":
            self.relay_state = "ON"
            return True, f"Relay State: {self.relay_state} (Fan Running)"
        return False, "Unknown Command"

actuator = SimulatedActuatorNode(session_key_b)

@sio.on("connect")
def on_connect():
    print("[ACTUATOR NODE] Connected and listening for server commands...")

@sio.on("execute_actuator_command")
def on_actuator_command(packet):
    try:
        success, msg = actuator.process_command(packet)
        sio.emit("actuator_ack_event", f"ACTUATOR ACK: {msg}")
        sio.emit(
            "security_log",
            {"type": "SUCCESS", "msg": f"[ACTUATOR] {msg} (AES Tag Verified)"},
        )
        sio.emit("update_actuator_ui", {"relay": actuator.relay_state})
    except Exception as e:
        sio.emit(
            "security_log",
            {
                "type": "ERROR",
                "msg": f"[ACTUATOR REJECTED] Tag Mismatch / Tampering Detected: {e}",
            },
        )

def run_actuator_node():
    sio.connect("http://127.0.0.1:5000")
    sio.wait()

if __name__ == "__main__":
    run_actuator_node()