"""The firmware's crypto completes a real handshake with the live server.
Run: python -m tests.test_firmware_e2e

tests/test_pqc_interop proves each primitive interoperates. This goes further:
it runs the *exact* PQClean C the ESP32 sketch calls -- ML-KEM-768 encapsulation
and ML-DSA-65 signing -- and drives it through the running server's /pqc/hello
and /pqc/encapsulate endpoints, deriving the session key the same way the
firmware does. If the server answers `agreed: true`, the on-device handshake is
proven end to end against the real server; only the WiFi/HTTP transport on a
physical board is left to hardware.

Skips cleanly if no C compiler is present.
"""

import hashlib
import hmac
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import requests

from app import identity, server
from app.pqc import LINK_SENSOR

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "firmware" / "pqc" / "src"
TEST = ROOT / "firmware" / "pqc" / "test"
CC = shutil.which("cc") or shutil.which("gcc")
PORT = 5096
URL = f"http://127.0.0.1:{PORT}"

KEM_TUS = ["kem.c", "indcpa.c", "poly.c", "polyvec.c", "ntt.c", "reduce.c",
           "cbd.c", "symmetric-shake.c", "verify.c", "fips202.c", "randombytes.c"]
DSA_TUS = ["d_sign.c", "d_packing.c", "d_poly.c", "d_polyvec.c", "d_ntt.c",
           "d_reduce.c", "d_rounding.c", "d_symmetric-shake.c", "fips202.c", "randombytes.c"]

_state = {}


def _build(tmp):
    enc = os.path.join(tmp, "enc")
    dsa = os.path.join(tmp, "dsa")
    subprocess.run([CC, "-O2", f"-I{SRC}", "-o", enc, str(TEST / "kem_enc.c")]
                   + [str(SRC / t) for t in KEM_TUS], check=True, capture_output=True)
    subprocess.run([CC, "-O2", f"-I{SRC}", "-o", dsa, str(TEST / "dsa_signverify.c")]
                   + [str(SRC / t) for t in DSA_TUS], check=True, capture_output=True)
    return enc, dsa


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


def _derive(ss):
    """The same SHAKE-256 extract + HKDF-SHA256 the firmware and server use."""
    extracted = hashlib.shake_256(ss + LINK_SENSOR).digest(32)
    prk = hmac.new(b"\x00" * 32, extracted, hashlib.sha256).digest()
    return hmac.new(prk, LINK_SENSOR + b"\x01", hashlib.sha256).digest()[:32]


def test_firmware_crypto_completes_the_server_handshake():
    if CC is None:
        print("SKIP (no C compiler found)")
        sys.exit(0)
    if not _state:
        _boot()
        _state["up"] = True

    device_sk = (identity.REGISTRY_PATH.parent / "identities" / "esp32-01.key").read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        enc, dsa = _build(tmp)

        hello = requests.post(f"{URL}/pqc/hello",
                              json={"device_id": "esp32-01", "role": "sensor"}).json()
        ek = bytes.fromhex(hello["encapsulation_key"])

        out = subprocess.run([enc, ek.hex()], capture_output=True, text=True, check=True)
        ct_hex, ss_hex = out.stdout.split()
        ct, ss = bytes.fromhex(ct_hex), bytes.fromhex(ss_hex)

        session_key = _derive(ss)
        fp = hashlib.sha256(session_key).hexdigest()[:16]
        transcript = identity.handshake_transcript("sensor", ek, ct)
        sig = subprocess.run([dsa, "sign", device_sk.hex(), transcript.hex()],
                             capture_output=True, text=True, check=True).stdout.strip()

        established = requests.post(f"{URL}/pqc/encapsulate", json={
            "handshake_id": hello["handshake_id"], "device_id": "esp32-01",
            "kem_ciphertext": ct.hex(), "device_signature": sig, "key_fingerprint": fp,
        }).json()

        assert established.get("status") == "established", established
        assert established.get("agreed"), "server and firmware derived different keys"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
