"""The constrained node does the real handshake over HTTP.
Run: python -m tests.test_http_handshake

The ESP32 leg used to fall back to a static pre-shared key because a
microcontroller cannot open a websocket. It now runs the same ML-KEM-768 +
ML-DSA-65 handshake as every other node, carried over three POSTs, and becomes a
full safety transmitter with a per-connection key -- no shared secret on the
path. This exercises that end to end against an in-process server.
"""

import os
import threading
import time

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity, server
from app.pqc import LINK_SENSOR, encapsulate, key_fingerprint

PORT = 5099
URL = f"http://127.0.0.1:{PORT}"
_kd = identity.REGISTRY_PATH.parent / "identities"


def _boot():
    threading.Thread(target=lambda: server.socketio.run(
        server.app, host="127.0.0.1", port=PORT, debug=False,
        allow_unsafe_werkzeug=True), daemon=True).start()
    for _ in range(40):
        try:
            requests.get(URL, timeout=1)
            return
        except requests.RequestException:
            time.sleep(0.25)
    raise RuntimeError("server did not start")


def _handshake(device_id="esp32-01"):
    """Runs a correctly signed handshake; returns the derived session key."""
    secret = (_kd / f"{device_id}.key").read_bytes()
    server_pub = (_kd / "server.pub").read_bytes()
    hello = requests.post(f"{URL}/pqc/hello",
                          json={"device_id": device_id, "role": "sensor"}).json()
    ek = bytes.fromhex(hello["encapsulation_key"])
    assert identity.verify(server_pub, identity.handshake_transcript("sensor", ek),
                           bytes.fromhex(hello["server_signature"])), "server signature bad"
    sk, ct = encapsulate(ek, LINK_SENSOR)
    sig = identity.sign(secret, identity.handshake_transcript("sensor", ek, ct)).hex()
    established = requests.post(f"{URL}/pqc/encapsulate", json={
        "handshake_id": hello["handshake_id"], "device_id": device_id,
        "kem_ciphertext": ct.hex(), "device_signature": sig,
        "key_fingerprint": key_fingerprint(sk),
    }).json()
    return sk, established


def _seal(key, temp, device_id="esp32-01"):
    payload = f'{{"unit": "{device_id}", "temperature": {temp:.2f}, "humidity": 40.00}}'
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, payload.encode(), None)
    return {"device_id": device_id, "nonce": nonce.hex(), "ciphertext": ct.hex()}


_booted = False


def setup():
    global _booted
    if not _booted:
        _boot()
        _booted = True


def test_a_real_handshake_agrees_a_key():
    setup()
    sk, established = _handshake()
    assert established["status"] == "established", established
    assert established["agreed"], "the two sides derived different keys"


def test_the_handshaked_node_is_a_full_safety_transmitter():
    """A PSK node can never trip; a handshaked one can, because it proved itself."""
    setup()
    server.server_engine.trip_setpoint = 75.0
    server.server_engine.trip_state = "HEALTHY"
    sk, _ = _handshake()
    r = requests.post(f"{URL}/telemetry", json=_seal(sk, 90.0))
    assert r.status_code == 200, r.text
    assert server.server_engine.trip_state == "TRIPPED", \
        "an authenticated post-quantum node could not trip the plant"


def test_a_forged_packet_on_the_session_is_rejected():
    setup()
    sk, _ = _handshake()
    packet = _seal(sk, 68.0)
    bad = bytearray(bytes.fromhex(packet["ciphertext"]))
    bad[0] ^= 0xFF
    packet["ciphertext"] = bad.hex()
    r = requests.post(f"{URL}/telemetry", json=packet)
    assert r.status_code == 400, "a forged packet was accepted"


def test_a_bad_device_signature_is_refused():
    setup()
    hello = requests.post(f"{URL}/pqc/hello",
                          json={"device_id": "esp32-01", "role": "sensor"}).json()
    ek = bytes.fromhex(hello["encapsulation_key"])
    sk, ct = encapsulate(ek, LINK_SENSOR)
    r = requests.post(f"{URL}/pqc/encapsulate", json={
        "handshake_id": hello["handshake_id"], "device_id": "esp32-01",
        "kem_ciphertext": ct.hex(), "device_signature": "00" * 100,
        "key_fingerprint": key_fingerprint(sk),
    })
    assert r.status_code == 403, "a bad ML-DSA signature was accepted"


def test_an_unenrolled_device_is_refused():
    setup()
    hello = requests.post(f"{URL}/pqc/hello",
                          json={"device_id": "rogue-99", "role": "sensor"}).json()
    ek = bytes.fromhex(hello["encapsulation_key"])
    sk, ct = encapsulate(ek, LINK_SENSOR)
    r = requests.post(f"{URL}/pqc/encapsulate", json={
        "handshake_id": hello["handshake_id"], "device_id": "rogue-99",
        "kem_ciphertext": ct.hex(), "device_signature": "00",
        "key_fingerprint": key_fingerprint(sk),
    })
    assert r.status_code == 403, "an unenrolled device completed a handshake"


def test_a_replayed_session_packet_is_rejected():
    setup()
    sk, _ = _handshake()
    packet = _seal(sk, 68.0)
    assert requests.post(f"{URL}/telemetry", json=packet).status_code == 200
    assert requests.post(f"{URL}/telemetry", json=packet).status_code == 409, \
        "a captured session packet was accepted twice"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
