import argparse
import json
import os
import random
import sys
import threading
import time

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity, legacy
from app.config import SERVER_URL, TOPIC_ENCAPS, TOPIC_HELLO, TOPIC_PUBKEY, TOPIC_TELEMETRY
from app.pqc import LINK_SENSOR, encapsulate, key_fingerprint

sio = socketio.Client()

# TT-101 process model. NORMAL_C sits comfortably below the 80 C default trip
# setpoint, and an excursion climbs past it in about ten readings, which is a
# demonstrable length of time rather than an instant jump.
NORMAL_C = 68.0
EXCURSION_RAMP_C = 2.5

# Device credentials, provisioned out of band by `make enroll`. Without them the
# node cannot prove who it is and the server will refuse the handshake.
DEVICE_ID = os.environ.get("DEVICE_ID", "sensor-01")
_key_dir = identity.REGISTRY_PATH.parent / "identities"
DEVICE_SECRET = (_key_dir / f"{DEVICE_ID}.key").read_bytes() if (
    _key_dir / f"{DEVICE_ID}.key").exists() else None
SERVER_PUBLIC = (_key_dir / "server.pub").read_bytes() if (
    _key_dir / "server.pub").exists() else None



class SimulatedSensorNode:
    """Holds no key until the ML-KEM-768 handshake with the server completes."""

    def __init__(self):
        self.key_a = None
        self.temperature = NORMAL_C
        self.excursion = False

    def toggle_excursion(self):
        """Starts or stops the process upset. Stopping lets it settle back to
        NORMAL_C so the plant can be reset and the demo run again."""
        self.excursion = not self.excursion
        return self.excursion

    def establish_session(self, encapsulation_key):
        """Encapsulates against the server's public key. Returns the KEM ciphertext."""
        session_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_SENSOR)
        self.key_a = bytearray(session_key)
        return kem_ciphertext

    def read_process_and_encrypt(self):
        """Reads TT-101 and seals it with AES-256-GCM.

        The old model returned a room temperature between 26 and 35 C, which was
        fine for a thermostat and useless for a trip demo: the setpoint clamp
        floor is 40 C, so no operator command could ever bring the two together
        and the plant could never trip. This models the process instead -- a
        vessel that idles near NORMAL_C and wanders a little, and, once an
        excursion is started, climbs until something stops it.
        """
        if self.excursion:
            self.temperature += EXCURSION_RAMP_C
        else:
            # Random walk with a pull back toward normal, so it drifts without
            # wandering off on its own and tripping the plant unattended.
            self.temperature += random.uniform(-1.2, 1.2)
            self.temperature += (NORMAL_C - self.temperature) * 0.25

        telemetry = {
            "temperature": round(self.temperature, 2),
            "humidity": round(random.uniform(40.0, 65.0), 2),
        }
        aesgcm = AESGCM(bytes(self.key_a))
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, json.dumps(telemetry).encode("utf-8"), None)
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}

    def zeroize_key(self):
        """Wipes the negotiated session key from memory for forward secrecy."""
        if self.key_a is None:
            return
        for i in range(len(self.key_a)):
            self.key_a[i] = 0
        print("\n[SENSOR] Session Key A zeroized from RAM.")


sensor = SimulatedSensorNode()


# Bumped on every completed handshake. A reconnect can restore sio.connected
# before the previous loop wakes from its sleep, so "am I still connected?" is
# not enough to retire an old loop -- without this each reconnect would leave
# another stream running forever.
stream_generation = 0


def watch_for_upset():
    """ENTER in this terminal starts or stops a process upset.

    Deliberately not a dashboard button or a new Socket.IO event: the trip has
    to be demonstrable on cue, and reading this terminal's stdin needs no
    protocol, no server handler, and nothing that could be confused with a real
    control path into the safety function.
    """
    print("[SENSOR NODE] Press ENTER to start a process upset (ENTER again to stop).")
    for _ in sys.stdin:
        if sensor.toggle_excursion():
            print(f"[SENSOR NODE] UPSET STARTED — climbing {EXCURSION_RAMP_C}°C "
                  f"per reading from {sensor.temperature:.1f}°C.")
        else:
            print("[SENSOR NODE] Upset stopped. Settling back toward normal.")


def stream_telemetry(generation):
    print("[SENSOR NODE] Streaming telemetry to Central Server...")
    while sio.connected and generation == stream_generation:
        sio.emit("sensor_telemetry_event", sensor.read_process_and_encrypt())
        sio.sleep(4)  # Non-blocking Socket.IO sleep to preserve ping/pong loop


LEGACY_MODE = False


@sio.on("connect")
def on_connect():
    if LEGACY_MODE:
        print("[SENSOR NODE] Connected. Requesting CLASSICAL RSA key transport...")
        sio.emit("legacy_hello", {})
        return
    print("[SENSOR NODE] Connected. Starting ML-KEM-768 handshake...")
    sio.emit("pqc_hello", {"role": "sensor"})


@sio.on("legacy_public_key")
def on_legacy_public_key(data):
    """Classical key transport: the node picks the session key and encrypts it
    under the server's RSA public key. Recovering that key recovers everything."""
    session_key = os.urandom(32)
    sensor.key_a = bytearray(session_key)
    blocks, chunk = legacy.wrap_session_key(session_key, (data["n"], data["e"]))
    sio.emit("legacy_key_transport", {
        "blocks": blocks, "chunk": chunk,
        "key_fingerprint": key_fingerprint(session_key),
    })
    print(f"[SENSOR NODE] Session key sent under RSA-{data['n'].bit_length()} "
          f"(no post-quantum protection).")


@sio.on("pqc_public_key")
def on_public_key(data):
    encapsulation_key = bytes.fromhex(data["encapsulation_key"])

    if data.get("authenticated"):
        if SERVER_PUBLIC is None:
            print("[SENSOR NODE] Server is authenticated but this device has no "
                  "server public key. Run: make enroll")
            sio.disconnect()
            return
        transcript = identity.handshake_transcript("sensor", encapsulation_key)
        if not identity.verify(SERVER_PUBLIC, transcript,
                               bytes.fromhex(data.get("server_signature", "") or "")):
            # An unverifiable offer is exactly what a man in the middle produces.
            print("[SENSOR NODE] ABORT: server signature invalid — refusing to continue.")
            sio.disconnect()
            return
        print("[SENSOR NODE] Server identity verified (ML-DSA-65).")

    kem_ciphertext = sensor.establish_session(encapsulation_key)
    # A hash of our derived key, so the server can prove agreement on the
    # dashboard without either side transmitting key material.
    sio.emit(
        "pqc_encapsulation",
        {
            "kem_ciphertext": kem_ciphertext.hex(),
            "key_fingerprint": key_fingerprint(bytes(sensor.key_a)),
            "device_id": DEVICE_ID,
            "device_signature": identity.sign(
                DEVICE_SECRET,
                identity.handshake_transcript("sensor", encapsulation_key, kem_ciphertext),
            ).hex() if DEVICE_SECRET else "",
        },
    )
    print("[SENSOR NODE] Encapsulated shared secret, sent KEM ciphertext to server.")


@sio.on("pqc_established")
def on_established(data):
    global stream_generation
    print("[SENSOR NODE] Session Key A established via "
          + ("classical RSA key transport." if LEGACY_MODE
             else "ML-KEM-768 -> SHAKE-256 -> HKDF-SHA256."))
    stream_generation += 1
    sio.start_background_task(stream_telemetry, stream_generation)
    # A plain thread, not a Socket.IO background task: this one blocks on stdin,
    # which would stall the event loop and drop the connection.
    if stream_generation == 1 and sys.stdin.isatty():
        threading.Thread(target=watch_for_upset, daemon=True).start()


@sio.on("disconnect")
def on_disconnect():
    print("[SENSOR NODE] Disconnected from Central Server.")


def run_sensor_node():
    sio.connect(SERVER_URL)
    try:
        sio.wait()
    except KeyboardInterrupt:
        pass
    finally:
        sensor.zeroize_key()
        sio.disconnect()


def run_sensor_node_mqtt():
    """Same node, same crypto — carried over MQTT with TLS 1.3 instead."""
    from app.transport.mqtt_transport import MqttLink

    node_id = f"sensor-{os.getpid()}"
    link = MqttLink(node_id)
    established = {"ready": False}

    def on_public_key(topic, payload):
        kem_ciphertext = sensor.establish_session(
            bytes.fromhex(payload["encapsulation_key"])
        )
        link.publish(
            f"{TOPIC_ENCAPS}/{node_id}",
            {
                "kem_ciphertext": kem_ciphertext.hex(),
                "key_fingerprint": key_fingerprint(bytes(sensor.key_a)),
            },
        )
        established["ready"] = True
        print("[SENSOR NODE] Session Key A derived (ML-KEM-768 over MQTT/TLS).")

    link.subscribe(f"{TOPIC_PUBKEY}/{node_id}", on_public_key)
    link.connect()
    print(f"[SENSOR NODE] Connected over MQTT, TLS {link.tls_version()}.")
    link.publish(TOPIC_HELLO, {"node_id": node_id, "role": "sensor"})

    try:
        while True:
            if established["ready"]:
                link.publish(
                    f"{TOPIC_TELEMETRY}/{node_id}", sensor.read_process_and_encrypt()
                )
            time.sleep(4)
    except KeyboardInterrupt:
        pass
    finally:
        sensor.zeroize_key()
        link.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post-quantum IoT sensor node")
    parser.add_argument("--transport", choices=["socketio", "mqtt"], default="socketio",
                        help="mqtt uses MQTT over TLS 1.3 and needs broker.py running")
    parser.add_argument("--legacy", action="store_true",
                        help="use classical RSA key transport instead of ML-KEM-768, "
                             "so attack 1 has a breakable channel to demonstrate against")
    args = parser.parse_args()
    LEGACY_MODE = args.legacy
    if args.transport == "mqtt":
        run_sensor_node_mqtt()
    else:
        run_sensor_node()
