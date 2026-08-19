import json

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import SERVER_URL
from pqc import LINK_ACTUATOR, encapsulate, key_fingerprint

sio = socketio.Client()


class SimulatedActuatorNode:
    def __init__(self):
        self.key_b = None
        self.relay_state = "OFF"

    def establish_session(self, encapsulation_key):
        session_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_ACTUATOR)
        self.key_b = bytearray(session_key)
        return kem_ciphertext

    def process_command(self, packet):
        """Decrypts command and verifies the AES-256-GCM authentication tag."""
        aesgcm = AESGCM(bytes(self.key_b))
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        # Decrypt & Validate GCM Tag
        cmd_data = json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8"))

        command = cmd_data.get("command")
        if command == "FAN_ON":
            self.relay_state = "ON"
        elif command == "FAN_OFF":
            self.relay_state = "OFF"
        elif command == "FAN_TOGGLE":
            # The actuator owns the relay state, so a toggle needs no state
            # sync with the server and cannot drift out of step with it.
            self.relay_state = "OFF" if self.relay_state == "ON" else "ON"
        else:
            return False, f"Unknown Command: {command!r}"

        running = "Fan Running" if self.relay_state == "ON" else "Fan Stopped"
        return True, f"Relay State: {self.relay_state} ({running})"

    def zeroize_key(self):
        if self.key_b is None:
            return
        for i in range(len(self.key_b)):
            self.key_b[i] = 0
        print("\n[ACTUATOR] Session Key B zeroized from RAM.")


actuator = SimulatedActuatorNode()


@sio.on("connect")
def on_connect():
    print("[ACTUATOR NODE] Connected. Starting ML-KEM-768 handshake...")
    sio.emit("pqc_hello", {"role": "actuator"})


@sio.on("pqc_public_key")
def on_public_key(data):
    kem_ciphertext = actuator.establish_session(bytes.fromhex(data["encapsulation_key"]))
    # A hash of our derived key, so the server can prove agreement on the
    # dashboard without either side transmitting key material.
    sio.emit(
        "pqc_encapsulation",
        {
            "kem_ciphertext": kem_ciphertext.hex(),
            "key_fingerprint": key_fingerprint(bytes(actuator.key_b)),
        },
    )


@sio.on("pqc_established")
def on_established(data):
    print("[ACTUATOR NODE] Session Key B derived. Listening for server commands...")


@sio.on("execute_actuator_command")
def on_actuator_command(packet):
    if actuator.key_b is None:
        sio.emit(
            "relay_log",
            {"type": "ERROR", "msg": "[ACTUATOR REJECTED] No session key established."},
        )
        return
    try:
        success, msg = actuator.process_command(packet)
        sio.emit("actuator_ack_event", f"ACTUATOR ACK: {msg}")
        # The tag verified either way; an unrecognised command is still a
        # failure and must not be logged as a success.
        sio.emit(
            "relay_log",
            {
                "type": "SUCCESS" if success else "ERROR",
                "msg": f"[ACTUATOR] {msg} (AES Tag Verified)",
            },
        )
        if success:
            sio.emit("relay_actuator_ui", {"relay": actuator.relay_state})
    except Exception as e:
        sio.emit(
            "relay_log",
            {
                "type": "ERROR",
                "msg": f"[ACTUATOR REJECTED] Tag Mismatch / Tampering Detected "
                       f"({type(e).__name__})",
            },
        )


def run_actuator_node():
    sio.connect(SERVER_URL)
    try:
        sio.wait()
    except KeyboardInterrupt:
        pass
    finally:
        actuator.zeroize_key()
        sio.disconnect()


if __name__ == "__main__":
    run_actuator_node()
