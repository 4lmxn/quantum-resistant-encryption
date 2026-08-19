import argparse
import json
import os
import random
import time

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import SERVER_URL, TOPIC_ENCAPS, TOPIC_HELLO, TOPIC_PUBKEY, TOPIC_TELEMETRY
from pqc import LINK_SENSOR, encapsulate, key_fingerprint

sio = socketio.Client()


class SimulatedSensorNode:
    """Holds no key until the ML-KEM-768 handshake with the server completes."""

    def __init__(self):
        self.key_a = None

    def establish_session(self, encapsulation_key):
        """Encapsulates against the server's public key. Returns the KEM ciphertext."""
        session_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_SENSOR)
        self.key_a = bytearray(session_key)
        return kem_ciphertext

    def read_dht22_and_encrypt(self):
        """Simulates physical sensor reading and encrypts via AES-256-GCM."""
        telemetry = {
            "temperature": round(random.uniform(26.0, 35.0), 2),
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


def stream_telemetry(generation):
    print("[SENSOR NODE] Streaming telemetry to Central Server...")
    while sio.connected and generation == stream_generation:
        sio.emit("sensor_telemetry_event", sensor.read_dht22_and_encrypt())
        sio.sleep(4)  # Non-blocking Socket.IO sleep to preserve ping/pong loop


@sio.on("connect")
def on_connect():
    print("[SENSOR NODE] Connected. Starting ML-KEM-768 handshake...")
    sio.emit("pqc_hello", {"role": "sensor"})


@sio.on("pqc_public_key")
def on_public_key(data):
    kem_ciphertext = sensor.establish_session(bytes.fromhex(data["encapsulation_key"]))
    # A hash of our derived key, so the server can prove agreement on the
    # dashboard without either side transmitting key material.
    sio.emit(
        "pqc_encapsulation",
        {
            "kem_ciphertext": kem_ciphertext.hex(),
            "key_fingerprint": key_fingerprint(bytes(sensor.key_a)),
        },
    )
    print("[SENSOR NODE] Encapsulated shared secret, sent KEM ciphertext to server.")


@sio.on("pqc_established")
def on_established(data):
    global stream_generation
    print("[SENSOR NODE] Session Key A derived (ML-KEM-768 -> HKDF-SHA256).")
    stream_generation += 1
    sio.start_background_task(stream_telemetry, stream_generation)


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
    from mqtt_transport import MqttLink

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
                    f"{TOPIC_TELEMETRY}/{node_id}", sensor.read_dht22_and_encrypt()
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
    args = parser.parse_args()
    if args.transport == "mqtt":
        run_sensor_node_mqtt()
    else:
        run_sensor_node()
