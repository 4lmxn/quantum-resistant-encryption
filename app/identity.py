"""Device identity and handshake authentication with ML-DSA-65 (NIST FIPS 204).

This closes the two structural gaps the base system documents:

  * the ML-KEM handshake proved nobody was *watching*, not who you were talking
    to, so an attacker present from the first packet could sit in the middle;
  * a node's role was asserted rather than proven, so anything that claimed to
    be the actuator received real commands.

Both are answered the same way. The server holds a long-term ML-DSA keypair and
signs the encapsulation key it offers; a node that cannot verify that signature
refuses to continue. Each node holds its own keypair, enrolled in advance, and
signs its KEM ciphertext; the server refuses a handshake it cannot attribute to
an enrolled device.

ML-DSA is used rather than a classical signature because a classically signed
post-quantum handshake would reintroduce exactly the weakness ML-KEM removes.
"""

import json
import os
import pathlib

from dilithium_py.ml_dsa import ML_DSA_65

from app.config import PROJECT_ROOT

# FIPS 204 security category 3, matching ML-KEM-768's category 3 for the KEM.
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309

REGISTRY_PATH = PROJECT_ROOT / "identities.json"


def generate_identity():
    """Returns (public_key, secret_key) for one device or server."""
    return ML_DSA_65.keygen()


def sign(secret_key, message):
    return ML_DSA_65.sign(secret_key, message)


def verify(public_key, message, signature):
    """False on any failure, so a malformed signature is a rejection, not a crash."""
    try:
        return ML_DSA_65.verify(public_key, message, signature)
    except Exception:
        return False


def handshake_transcript(role, encapsulation_key, kem_ciphertext=b""):
    """The bytes both parties sign.

    Binding the role and both halves of the exchange means a signature captured
    from one handshake cannot be replayed into another, and a node enrolled as a
    sensor cannot have its signature reused to enrol as an actuator.
    """
    return b"|".join([b"quantum-iot/v1", role.encode(), encapsulation_key, kem_ciphertext])


class IdentityRegistry:
    """Enrolled device public keys, plus the server's own keypair.

    Provisioning a device out of band is the trust anchor; this file stands in
    for the manufacturing step that would burn a key into a real device.
    """

    def __init__(self, path=REGISTRY_PATH):
        self.path = pathlib.Path(path)
        self.server_public = None
        self.server_secret = None
        self.devices = {}  # device_id -> public key bytes
        self.load()

    def load(self):
        if not self.path.exists():
            return False
        raw = json.loads(self.path.read_text())
        self.server_public = bytes.fromhex(raw["server"]["public"])
        self.server_secret = bytes.fromhex(raw["server"]["secret"])
        self.devices = {k: bytes.fromhex(v) for k, v in raw["devices"].items()}
        return True

    def save(self):
        self.path.write_text(json.dumps({
            "server": {"public": self.server_public.hex(), "secret": self.server_secret.hex()},
            "devices": {k: v.hex() for k, v in self.devices.items()},
        }, indent=2))
        os.chmod(self.path, 0o600)  # contains the server's signing key

    def bootstrap(self, device_ids):
        """Creates the server identity and enrols the listed devices.

        Real deployments would enrol each device at manufacture. Returned secrets
        are handed to the devices once and never stored here.
        """
        self.server_public, self.server_secret = generate_identity()
        secrets = {}
        for device_id in device_ids:
            public, secret = generate_identity()
            self.devices[device_id] = public
            secrets[device_id] = secret
        self.save()
        return secrets

    def is_enrolled(self, device_id):
        return device_id in self.devices

    def public_key_of(self, device_id):
        return self.devices.get(device_id)
