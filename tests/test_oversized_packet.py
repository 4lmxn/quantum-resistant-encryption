"""Self-check for the application-layer ciphertext size cap. Run: python test_oversized_packet.py"""

import os

from app.config import MAX_CIPHERTEXT_HEX_CHARS
from app.server import server_engine


def test_an_oversized_ciphertext_is_rejected_before_decrypt_is_attempted():
    key = os.urandom(32)
    huge_ciphertext = os.urandom(2_000_000).hex()
    packet = {"nonce": os.urandom(12).hex(), "ciphertext": huge_ciphertext}
    try:
        server_engine.decrypt_sensor_data(key, packet)
    except ValueError as exc:
        assert "hex chars" in str(exc), f"rejected for the wrong reason: {exc}"
        return
    raise AssertionError("an oversized ciphertext field was not rejected")


def test_a_genuine_sized_packet_is_unaffected_by_the_cap():
    key = os.urandom(32)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import json

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps({"temperature": 42.0}).encode(), None)
    packet = {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    assert len(packet["ciphertext"]) < MAX_CIPHERTEXT_HEX_CHARS
    data = server_engine.decrypt_sensor_data(key, packet)
    assert data == {"temperature": 42.0}


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
