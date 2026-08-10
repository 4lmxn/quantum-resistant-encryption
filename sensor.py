import json
import os
import random
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socketio

# Initialize Socket.IO Client
sio = socketio.Client()

# Import Session Key A from the Central Server
from server import server_engine

session_key_a = bytearray(server_engine.session_key_a)


class SimulatedSensorNode:

    def __init__(self, key_a):
        self.key_a = key_a

    def read_dht22_and_encrypt(self):
        """Simulates physical sensor reading and encrypts via AES-256-GCM."""
        telemetry = {
            "temperature": round(random.uniform(26.0, 35.0), 2),
            "humidity": round(random.uniform(40.0, 65.0), 2),
        }

        aesgcm = AESGCM(bytes(self.key_a))
        nonce = os.urandom(12)  # 96-bit nonce
        payload = json.dumps(telemetry).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, payload, None)

        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}

    def zeroize_key(self):
        """Wipes Session Key A from memory for forward secrecy."""
        for i in range(len(self.key_a)):
            self.key_a[i] = 0
        print("\n[SENSOR] Session Key A zeroized from RAM.")


@sio.on("connect")
def on_connect():
    print("[SENSOR NODE] Connected to Central Server WebSockets.")


@sio.on("disconnect")
def on_disconnect():
    print("[SENSOR NODE] Disconnected from Central Server.")


def run_sensor_node():
    sensor = SimulatedSensorNode(session_key_a)
    sio.connect("http://localhost:5000")

    print("[SENSOR NODE] Streaming telemetry to Central Server...")
    try:
        while True:
            packet = sensor.read_dht22_and_encrypt()
            sio.emit("sensor_telemetry_event", packet)
            time.sleep(4)  # Poll sensor every 4 seconds
    except KeyboardInterrupt:
        sensor.zeroize_key()
        sio.disconnect()


if __name__ == "__main__":
    run_sensor_node()