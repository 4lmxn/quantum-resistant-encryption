"""Self-check for ML-DSA-65 handshake authentication.

Run: python -m tests.test_identity
"""

import pathlib
import tempfile

from app import identity

SCRATCH = pathlib.Path(tempfile.gettempdir()) / "qiot-test-identities.json"


def fresh_registry():
    SCRATCH.unlink(missing_ok=True)
    registry = identity.IdentityRegistry(path=SCRATCH)
    secrets = registry.bootstrap(["sensor-01", "actuator-01"])
    return registry, secrets


def test_enrolled_device_is_accepted():
    registry, secrets = fresh_registry()
    transcript = identity.handshake_transcript("sensor", b"E" * 1184, b"C" * 1088)
    signature = identity.sign(secrets["sensor-01"], transcript)
    assert identity.verify(registry.public_key_of("sensor-01"), transcript, signature)


def test_unenrolled_device_is_rejected():
    """The rogue-actuator gap: claiming a role must not be enough."""
    registry, _ = fresh_registry()
    assert not registry.is_enrolled("rogue-99")
    assert registry.public_key_of("rogue-99") is None


def test_one_device_cannot_impersonate_another():
    registry, secrets = fresh_registry()
    transcript = identity.handshake_transcript("actuator", b"E" * 1184, b"C" * 1088)
    signature = identity.sign(secrets["sensor-01"], transcript)
    assert not identity.verify(registry.public_key_of("actuator-01"), transcript, signature)


def test_signature_is_bound_to_its_role():
    """A signature captured from a sensor handshake must not enrol an actuator."""
    registry, secrets = fresh_registry()
    signed = identity.handshake_transcript("sensor", b"E" * 1184, b"C" * 1088)
    signature = identity.sign(secrets["sensor-01"], signed)
    swapped = identity.handshake_transcript("actuator", b"E" * 1184, b"C" * 1088)
    assert not identity.verify(registry.public_key_of("sensor-01"), swapped, signature)


def test_signature_is_bound_to_the_offered_key():
    """A man in the middle substituting its own encapsulation key is detected."""
    registry, secrets = fresh_registry()
    genuine = identity.handshake_transcript("sensor", b"E" * 1184, b"C" * 1088)
    signature = identity.sign(secrets["sensor-01"], genuine)
    substituted = identity.handshake_transcript("sensor", b"X" * 1184, b"C" * 1088)
    assert not identity.verify(registry.public_key_of("sensor-01"), substituted, signature)


def test_server_offer_cannot_be_forged():
    """The core MITM defence: a node refuses an offer it cannot attribute."""
    registry, _ = fresh_registry()
    attacker_public, attacker_secret = identity.generate_identity()
    transcript = identity.handshake_transcript("sensor", b"E" * 1184)
    forged = identity.sign(attacker_secret, transcript)
    assert not identity.verify(registry.server_public, transcript, forged)

    genuine = identity.sign(registry.server_secret, transcript)
    assert identity.verify(registry.server_public, transcript, genuine)


def test_malformed_signature_is_a_rejection_not_a_crash():
    registry, _ = fresh_registry()
    transcript = identity.handshake_transcript("sensor", b"E" * 1184)
    for bad in (b"", b"\x00", b"garbage" * 10):
        assert identity.verify(registry.server_public, transcript, bad) is False


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
    SCRATCH.unlink(missing_ok=True)
