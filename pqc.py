"""Post-quantum key establishment for the IoT links.

ML-KEM-768 (NIST FIPS 203, the standardised form of CRYSTALS-Kyber) agrees a
shared secret over the untrusted channel; HKDF-SHA256 stretches that secret
into the AES-256-GCM session key each link actually uses.

Nothing here is a stand-in: keys are generated per connection, so an attacker
recording the whole handshake still cannot recover the session key without the
server's decapsulation key.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

# Domain separation: the sensor and actuator links must never derive the same
# AES key, even in the freak case that two handshakes share a secret.
LINK_SENSOR = b"quantum-iot/sensor-link/aes256gcm"
LINK_ACTUATOR = b"quantum-iot/actuator-link/aes256gcm"

ENCAPSULATION_KEY_BYTES = 1184
KEM_CIPHERTEXT_BYTES = 1088


def generate_keypair():
    """Server side. Returns (encapsulation_key, decapsulation_key)."""
    return ML_KEM_768.keygen()


def encapsulate(encapsulation_key, link_label):
    """Node side. Returns (aes_session_key, kem_ciphertext)."""
    shared_secret, kem_ciphertext = ML_KEM_768.encaps(encapsulation_key)
    return _derive_aes_key(shared_secret, link_label), kem_ciphertext


def decapsulate(decapsulation_key, kem_ciphertext, link_label):
    """Server side. Recovers the same aes_session_key the node derived."""
    shared_secret = ML_KEM_768.decaps(decapsulation_key, kem_ciphertext)
    return _derive_aes_key(shared_secret, link_label)


def _derive_aes_key(shared_secret, link_label):
    """HKDF-SHA256 to exactly 32 bytes, so an AES-256 key is never the wrong length."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=link_label
    ).derive(shared_secret)


def key_fingerprint(aes_key):
    """A short public digest of a session key.

    Safe to display and to send over the wire: it is a one-way hash, so it
    proves two parties derived the same key without revealing any of it.
    """
    return hashlib.sha256(aes_key).hexdigest()[:16]
