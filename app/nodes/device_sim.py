"""Stand-in for the constrained ESP32 node.

This mirrors what the real firmware should do on hardware: run the full
ML-KEM-768 + ML-DSA-65 handshake over HTTP, derive a per-connection AES-256-GCM
session key, and seal telemetry with that key -- no pre-shared key. It is the
verifiable proof that the constrained leg can be a full post-quantum node, not a
weak static-key exception.

Run: python -m app.nodes.device_sim              (authenticated PQC device)
     python -m app.nodes.device_sim --forge      (attacker forging packets)
     python -m app.nodes.device_sim --legacy-psk  (un-provisioned board, PSK path)
"""

import argparse
import hashlib
import os
import random
import sys
import time

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity
from app.config import DEVICE_PSK, SERVER_URL
from app.pqc import LINK_SENSOR, encapsulate, key_fingerprint

# This board's enrolled identity, provisioned out of band by `make enroll`.
DEVICE_ID = os.environ.get("DEVICE_ID", "esp32-01")
_key_dir = identity.REGISTRY_PATH.parent / "identities"
DEVICE_SECRET = (_key_dir / f"{DEVICE_ID}.key").read_bytes() if (
    _key_dir / f"{DEVICE_ID}.key").exists() else None
SERVER_PUBLIC = (_key_dir / "server.pub").read_bytes() if (
    _key_dir / "server.pub").exists() else None


def handshake():
    """Runs the three-message ML-KEM-768 handshake. Returns the session key.

    Step 1: say hello, get the server's signed encapsulation key.
    Step 2: verify that signature, encapsulate a fresh secret, sign the
            ciphertext with our own key, send it.
    Step 3: derive the same AES-256-GCM key the server derived.
    """
    hello = requests.post(f"{SERVER_URL}/pqc/hello",
                          json={"device_id": DEVICE_ID, "role": "sensor"}, timeout=5).json()
    encapsulation_key = bytes.fromhex(hello["encapsulation_key"])

    if hello.get("authenticated"):
        if SERVER_PUBLIC is None:
            raise SystemExit("[DEVICE] Server is authenticated but this board has no "
                             "server public key. Run: make enroll")
        transcript = identity.handshake_transcript("sensor", encapsulation_key)
        if not identity.verify(SERVER_PUBLIC, transcript,
                               bytes.fromhex(hello.get("server_signature", "") or "")):
            raise SystemExit("[DEVICE] ABORT: server signature invalid — refusing to continue.")
        print("[DEVICE] Server identity verified (ML-DSA-65).")

    session_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_SENSOR)
    signature = identity.sign(
        DEVICE_SECRET,
        identity.handshake_transcript("sensor", encapsulation_key, kem_ciphertext),
    ).hex() if DEVICE_SECRET else ""

    established = requests.post(f"{SERVER_URL}/pqc/encapsulate", json={
        "handshake_id": hello["handshake_id"],
        "device_id": DEVICE_ID,
        "kem_ciphertext": kem_ciphertext.hex(),
        "device_signature": signature,
        "key_fingerprint": key_fingerprint(session_key),
    }, timeout=5).json()

    if established.get("status") != "established" or not established.get("agreed"):
        raise SystemExit(f"[DEVICE] Handshake refused: {established}")
    print(f"[DEVICE] Session key established via ML-KEM-768 + HKDF-SHA256 "
          f"(fingerprint {established['server_fingerprint']}).")
    return session_key


def seal_reading(session_key, temperature, humidity):
    """12-byte nonce, ciphertext||tag — the layout the firmware reproduces."""
    payload = (f'{{"unit": "{DEVICE_ID}", "temperature": {temperature:.2f}, '
               f'"humidity": {humidity:.2f}}}')
    nonce = os.urandom(12)
    sealed = AESGCM(session_key).encrypt(nonce, payload.encode(), None)
    return {"device_id": DEVICE_ID, "nonce": nonce.hex(), "ciphertext": sealed.hex()}


def forge_reading(session_key):
    """What an attacker without the session key can actually produce."""
    packet = seal_reading(session_key, 99.0, 10.0)
    tampered = bytearray(bytes.fromhex(packet["ciphertext"]))
    tampered[0] ^= 0xFF
    packet["ciphertext"] = tampered.hex()
    return packet


def run(forge, legacy_psk, interval):
    if legacy_psk:
        # An un-provisioned board with only the static device key: the fallback
        # path, deliberately kept off the safety lane.
        session_key = DEVICE_PSK
        print(f"[DEVICE] LEGACY PSK path (unprovisioned). Not on the safety lane.")
    else:
        session_key = handshake()

    label = "FORGED" if forge else "SEALED"
    print(f"[DEVICE] Posting {label} telemetry every {interval}s. Ctrl-C to stop.\n")

    while True:
        temperature = round(random.uniform(64.0, 72.0), 2)
        humidity = round(random.uniform(40.0, 65.0), 2)
        packet = forge_reading(session_key) if forge else seal_reading(session_key, temperature, humidity)
        if legacy_psk:
            packet.pop("device_id", None)  # the PSK path is not tied to an identity

        try:
            response = requests.post(f"{SERVER_URL}/telemetry", json=packet, timeout=5)
        except requests.RequestException as exc:
            print(f"[DEVICE] Server unreachable: {exc}")
            time.sleep(interval)
            continue

        if response.status_code == 200:
            body = response.json()
            print(f"[DEVICE] {temperature}°C / {humidity}% -> accepted "
                  f"(setpoint {body.get('setpoint')}°C, plant {body.get('trip_state')})")
        else:
            print(f"[DEVICE] Rejected, HTTP {response.status_code} — the GCM tag did not verify.")
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forge", action="store_true",
                        help="send tampered packets to demonstrate rejection")
    parser.add_argument("--legacy-psk", action="store_true",
                        help="skip the handshake and use the static provisioned key")
    parser.add_argument("--interval", type=float, default=4.0)
    args = parser.parse_args()
    try:
        run(args.forge, args.legacy_psk, args.interval)
    except KeyboardInterrupt:
        print("\n[DEVICE] Stopped.")
        sys.exit(0)
