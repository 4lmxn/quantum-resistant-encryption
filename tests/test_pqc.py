"""Self-check for the post-quantum handshake. Run: python test_pqc.py"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.pqc import (
    KEM_CIPHERTEXT_BYTES,
    LINK_ACTUATOR,
    LINK_SENSOR,
    decapsulate,
    encapsulate,
    generate_keypair,
)


def test_handshake_agrees_on_one_key():
    encapsulation_key, decapsulation_key = generate_keypair()
    node_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_SENSOR)
    server_key = decapsulate(decapsulation_key, kem_ciphertext, LINK_SENSOR)
    assert node_key == server_key, "node and server derived different session keys"
    assert len(node_key) == 32, f"AES-256 needs 32 bytes, got {len(node_key)}"
    assert len(kem_ciphertext) == KEM_CIPHERTEXT_BYTES


def test_links_are_domain_separated():
    encapsulation_key, decapsulation_key = generate_keypair()
    _, kem_ciphertext = encapsulate(encapsulation_key, LINK_SENSOR)
    sensor_key = decapsulate(decapsulation_key, kem_ciphertext, LINK_SENSOR)
    actuator_key = decapsulate(decapsulation_key, kem_ciphertext, LINK_ACTUATOR)
    assert sensor_key != actuator_key, "both links derived the same AES key"


def test_every_session_is_fresh():
    encapsulation_key, _ = generate_keypair()
    first, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    second, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    assert first != second, "session keys repeat; no forward secrecy"


def test_tampered_ciphertext_is_rejected():
    encapsulation_key, decapsulation_key = generate_keypair()
    node_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_ACTUATOR)
    server_key = decapsulate(decapsulation_key, kem_ciphertext, LINK_ACTUATOR)

    nonce = os.urandom(12)
    sealed = bytearray(AESGCM(server_key).encrypt(nonce, b'{"command": "FAN_ON"}', None))
    sealed[0] ^= 0xFF  # flip a bit, as the MITM stage does

    try:
        AESGCM(node_key).decrypt(nonce, bytes(sealed), None)
    except Exception:
        return
    raise AssertionError("GCM tag accepted a tampered command")


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
