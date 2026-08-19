"""Stand-in for the constrained ESP32 node.

Does exactly what wokwi/sketch.ino does — seals a reading with the provisioned
AES-256-GCM key and POSTs it to /telemetry — so the constrained-device leg can
be demonstrated without any hardware or simulator.

Run: python device_sim.py            (well-behaved device)
     python device_sim.py --forge    (attacker forging device packets)
"""

import argparse
import json
import os
import random
import sys
import time

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import DEVICE_PSK, SERVER_URL


def seal_reading(temperature, humidity):
    """Byte-for-byte the layout sketch.ino produces: 12-byte nonce, ct||tag."""
    payload = f'{{"temperature": {temperature:.2f}, "humidity": {humidity:.2f}}}'
    nonce = os.urandom(12)
    sealed = AESGCM(DEVICE_PSK).encrypt(nonce, payload.encode(), None)
    return {"nonce": nonce.hex(), "ciphertext": sealed.hex()}


def forge_reading():
    """What an attacker without the provisioned key can actually produce."""
    packet = seal_reading(99.0, 10.0)
    tampered = bytearray(bytes.fromhex(packet["ciphertext"]))
    tampered[0] ^= 0xFF
    packet["ciphertext"] = tampered.hex()
    return packet


def run(forge, interval):
    label = "FORGED" if forge else "SEALED"
    print(f"[DEVICE] Posting {label} telemetry to {SERVER_URL}/telemetry every {interval}s")
    print("[DEVICE] Ctrl-C to stop.\n")

    while True:
        temperature = round(random.uniform(26.0, 35.0), 2)
        humidity = round(random.uniform(40.0, 65.0), 2)
        packet = forge_reading() if forge else seal_reading(temperature, humidity)

        try:
            response = requests.post(f"{SERVER_URL}/telemetry", json=packet, timeout=5)
        except requests.RequestException as exc:
            print(f"[DEVICE] Server unreachable: {exc}")
            time.sleep(interval)
            continue

        if response.status_code == 200:
            print(f"[DEVICE] {temperature}°C / {humidity}% -> accepted "
                  f"(threshold {response.json().get('threshold')}°C)")
        else:
            print(f"[DEVICE] Rejected, HTTP {response.status_code} — "
                  f"the GCM tag did not verify.")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forge", action="store_true",
                        help="send tampered packets to demonstrate rejection")
    parser.add_argument("--interval", type=float, default=4.0)
    args = parser.parse_args()
    try:
        run(args.forge, args.interval)
    except KeyboardInterrupt:
        print("\n[DEVICE] Stopped.")
        sys.exit(0)
