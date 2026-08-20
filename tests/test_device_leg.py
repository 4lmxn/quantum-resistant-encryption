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
    body = response.json()
    assert body["status"] == "accepted"
    # The BPCS leg is told the safety state; it does not get to change it.
    assert body["trip_state"] in ("HEALTHY", "TRIPPED"), body
    assert body["valve"] in ("OPEN", "CLOSED"), body
    assert isinstance(body["setpoint"], (int, float)), body
    assert "threshold" not in body, "the thermostat threshold is gone from this response"


def test_server_rejects_forged_device_packet():
    packet = seal_like_esp32(33.5, 55.0)
    tampered = bytearray(bytes.fromhex(packet["ciphertext"]))
    tampered[0] ^= 0xFF
    packet["ciphertext"] = tampered.hex()

    response = requests.post(f"{SERVER_URL}/telemetry", json=packet)
    assert response.status_code == 400, "forged ESP32 packet was accepted"
    assert response.json()["status"] == "rejected"


def test_replayed_device_packet_is_rejected():
    """A captured packet must be usable exactly once, even though it is valid."""
    packet = seal_like_esp32(31.0, 44.0)

    first = requests.post(f"{SERVER_URL}/telemetry", json=packet)
    assert first.status_code == 200, "a fresh packet should be accepted"

    replay = requests.post(f"{SERVER_URL}/telemetry", json=packet)
    assert replay.status_code == 409, "the same packet was accepted twice"
    assert replay.json()["status"] == "replay"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
