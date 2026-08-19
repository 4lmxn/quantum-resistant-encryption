"""Self-check for the ESP32 HTTP leg. Server must be running. Run: python test_device_leg.py"""

import json
import os

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import DEVICE_PSK, SERVER_URL


def seal_like_esp32(temperature, humidity):
    """Reproduces sketch.ino's sealPayload(): 12-byte nonce, ciphertext||tag hex."""
    plaintext = f'{{"temperature": {temperature:.2f}, "humidity": {humidity:.2f}}}'
    nonce = os.urandom(12)
    sealed = AESGCM(DEVICE_PSK).encrypt(nonce, plaintext.encode(), None)
    return {"nonce": nonce.hex(), "ciphertext": sealed.hex()}


def test_server_accepts_device_packet():
    response = requests.post(f"{SERVER_URL}/telemetry", json=seal_like_esp32(33.5, 55.0))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "accepted"
    assert "threshold" in response.json(), "node needs the threshold to drive its relay"


def test_server_rejects_forged_device_packet():
    packet = seal_like_esp32(33.5, 55.0)
    tampered = bytearray(bytes.fromhex(packet["ciphertext"]))
    tampered[0] ^= 0xFF
    packet["ciphertext"] = tampered.hex()

    response = requests.post(f"{SERVER_URL}/telemetry", json=packet)
    assert response.status_code == 400, "forged ESP32 packet was accepted"
    assert response.json()["status"] == "rejected"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
