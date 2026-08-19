import argparse
import json
import os
import time

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity
from app.config import SERVER_URL, TOPIC_COMMAND, TOPIC_ENCAPS, TOPIC_HELLO, TOPIC_PUBKEY
from app.pqc import LINK_ACTUATOR, encapsulate, key_fingerprint

sio = socketio.Client()

# Device credentials, provisioned out of band by `make enroll`. Without them the
# node cannot prove who it is and the server will refuse the handshake.
DEVICE_ID = os.environ.get("DEVICE_ID", "actuator-01")
_key_dir = identity.REGISTRY_PATH.parent / "identities"
DEVICE_SECRET = (_key_dir / f"{DEVICE_ID}.key").read_bytes() if (
    _key_dir / f"{DEVICE_ID}.key").exists() else None
SERVER_PUBLIC = (_key_dir / "server.pub").read_bytes() if (
    _key_dir / "server.pub").exists() else None



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
    encapsulation_key = bytes.fromhex(data["encapsulation_key"])

    if data.get("authenticated"):
        if SERVER_PUBLIC is None:
            print("[ACTUATOR NODE] Server is authenticated but this device has no "
                  "server public key. Run: make enroll")
            sio.disconnect()
            return
        transcript = identity.handshake_transcript("actuator", encapsulation_key)
        if not identity.verify(SERVER_PUBLIC, transcript,
                               bytes.fromhex(data.get("server_signature", "") or "")):
            # An unverifiable offer is exactly what a man in the middle produces.
            print("[ACTUATOR NODE] ABORT: server signature invalid — refusing to continue.")
            sio.disconnect()
            return
        print("[ACTUATOR NODE] Server identity verified (ML-DSA-65).")

    kem_ciphertext = actuator.establish_session(encapsulation_key)
    # A hash of our derived key, so the server can prove agreement on the
    # dashboard without either side transmitting key material.
    sio.emit(
        "pqc_encapsulation",
        {
            "kem_ciphertext": kem_ciphertext.hex(),
            "key_fingerprint": key_fingerprint(bytes(actuator.key_b)),
            "device_id": DEVICE_ID,
            "device_signature": identity.sign(
                DEVICE_SECRET,
                identity.handshake_transcript("actuator", encapsulation_key, kem_ciphertext),
            ).hex() if DEVICE_SECRET else "",
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


def run_actuator_node_mqtt():
    """Same node, same GCM tag check — carried over MQTT with TLS 1.3."""
    from app.transport.mqtt_transport import MqttLink

    node_id = f"actuator-{os.getpid()}"
    link = MqttLink(node_id)

    def on_public_key(topic, payload):
        kem_ciphertext = actuator.establish_session(
            bytes.fromhex(payload["encapsulation_key"])
        )
        link.publish(
            f"{TOPIC_ENCAPS}/{node_id}",
            {
                "kem_ciphertext": kem_ciphertext.hex(),
                "key_fingerprint": key_fingerprint(bytes(actuator.key_b)),
            },
        )
        print("[ACTUATOR NODE] Session Key B derived (ML-KEM-768 over MQTT/TLS).")

    def on_command(topic, packet):
        if actuator.key_b is None:
            print("[ACTUATOR REJECTED] No session key established.")
            return
        try:
            success, msg = actuator.process_command(packet)
            print(f"[ACTUATOR] {msg} (AES Tag Verified)" if success
                  else f"[ACTUATOR REJECTED] {msg}")
        except Exception as exc:
            print(f"[ACTUATOR REJECTED] Tag Mismatch / Tampering Detected ({type(exc).__name__})")

    link.subscribe(f"{TOPIC_PUBKEY}/{node_id}", on_public_key)
    link.subscribe(f"{TOPIC_COMMAND}/{node_id}", on_command)
    link.connect()
    print(f"[ACTUATOR NODE] Connected over MQTT, TLS {link.tls_version()}.")
    link.publish(TOPIC_HELLO, {"node_id": node_id, "role": "actuator"})

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        actuator.zeroize_key()
        link.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post-quantum IoT actuator node")
    parser.add_argument("--transport", choices=["socketio", "mqtt"], default="socketio",
                        help="mqtt uses MQTT over TLS 1.3 and needs broker.py running")
    args = parser.parse_args()
    if args.transport == "mqtt":
        run_actuator_node_mqtt()
    else:
        run_actuator_node()
