"""Self-check for the signed operator path. Run: python -m tests.test_operator_auth

No server and no network: `handle_operator_command` never touches Flask's
`request`, so it can be called directly. The ML-DSA-65 keys are real — mocking
the signature check would only prove the mock works.
"""

import os
import time

from app import identity, server
from app.config import (
    OPERATOR_MAX_SKEW_S,
    SETPOINT_MAX_C,
    SETPOINT_MAX_STEP_C,
    SETPOINT_MIN_C,
)

OPERATOR_ID = "operator-01"


class FakeRegistry:
    """The enrolment file, without the file."""

    def __init__(self):
        self.server_public, self.server_secret = identity.generate_identity()
        public, self.operator_secret = identity.generate_identity()
        self.devices = {OPERATOR_ID: public}

    def is_enrolled(self, device_id):
        return device_id in self.devices

    def public_key_of(self, device_id):
        return self.devices.get(device_id)


class harness:
    """Swaps in a fresh engine and registry for one check."""

    def __init__(self):
        self.engine = server.CentralServer()
        self.registry = FakeRegistry()
        self.logs = []

    def __enter__(self):
        self.original = (
            server.server_engine, server.registry, server.AUTHENTICATED,
            server.send_actuator_command, server.socketio.emit, server.log,
        )
        server.server_engine = self.engine
        server.registry = self.registry
        server.AUTHENTICATED = True
        server.send_actuator_command = lambda *a, **k: None
        server.socketio.emit = lambda *a, **k: None
        server.log = lambda log_type, msg: self.logs.append((log_type, msg))
        return self

    def __exit__(self, *exc):
        (server.server_engine, server.registry, server.AUTHENTICATED,
         server.send_actuator_command, server.socketio.emit, server.log) = self.original
        return False

    def command(self, action, value=None, operator_id=OPERATOR_ID,
                nonce_hex=None, timestamp=None, secret=None):
        """Builds a genuinely signed operator_command payload."""
        nonce_hex = nonce_hex or os.urandom(16).hex()
        timestamp = int(time.time()) if timestamp is None else int(timestamp)
        transcript = identity.operator_transcript(
            operator_id, action, value, nonce_hex, timestamp)
        return {
            "operator_id": operator_id,
            "action": action,
            "value": value,
            "nonce": nonce_hex,
            "timestamp": timestamp,
            "signature": identity.sign(
                secret or self.registry.operator_secret, transcript).hex(),
        }

    def refused(self):
        return any(t == "ERROR" and "REFUSED" in m for t, m in self.logs)


def test_a_signed_setpoint_change_is_applied():
    with harness() as h:
        wanted = h.engine.trip_setpoint + 5.0
        server.handle_operator_command(h.command("SET_SETPOINT", wanted))
        assert h.engine.trip_setpoint == wanted, h.engine.trip_setpoint
        assert not h.refused(), h.logs


def test_an_unenrolled_operator_is_refused():
    with harness() as h:
        before = h.engine.trip_setpoint
        server.handle_operator_command(
            h.command("SET_SETPOINT", 85.0, operator_id="intruder-99"))
        assert h.engine.trip_setpoint == before, "an unknown operator moved the setpoint"
        assert h.refused(), h.logs


def test_a_tampered_signature_is_refused():
    with harness() as h:
        before = h.engine.trip_setpoint
        payload = h.command("SET_SETPOINT", 85.0)
        # Flip a byte in the signature, exactly as a bit-flip on the wire would.
        signature = bytearray(bytes.fromhex(payload["signature"]))
        signature[0] ^= 0xFF
        payload["signature"] = signature.hex()
        server.handle_operator_command(payload)
        assert h.engine.trip_setpoint == before, "a forged signature was accepted"
        assert h.refused(), h.logs


def test_a_signature_cannot_be_moved_to_another_value():
    """The transcript covers the value, so re-labelling a signed command fails."""
    with harness() as h:
        payload = h.command("SET_SETPOINT", 85.0)
        payload["value"] = 120.0
        server.handle_operator_command(payload)
        assert h.engine.trip_setpoint != 120.0
        assert h.refused(), h.logs


def test_a_replayed_nonce_is_refused_the_second_time():
    with harness() as h:
        payload = h.command("SET_SETPOINT", h.engine.trip_setpoint + 5.0)
        server.handle_operator_command(payload)
        applied = h.engine.trip_setpoint
        h.logs.clear()

        server.handle_operator_command(payload)  # byte-for-byte replay
        assert h.engine.trip_setpoint == applied
        assert h.refused(), "a captured command was accepted twice"


def test_a_stale_command_is_refused():
    """A command captured during commissioning must not be usable during an upset."""
    with harness() as h:
        before = h.engine.trip_setpoint
        stale = time.time() - (OPERATOR_MAX_SKEW_S + 60)
        server.handle_operator_command(
            h.command("SET_SETPOINT", 85.0, timestamp=stale))
        assert h.engine.trip_setpoint == before, "a stale command was accepted"
        assert h.refused(), h.logs


def test_a_setpoint_outside_the_clamp_is_refused_even_when_signed():
    """THE OLDSMAR LESSON, and the most important assertion in this file.

    The Oldsmar intruder used a legitimate control path — the problem was not
    that the command was unauthenticated, it was that the system would carry out
    an obviously absurd instruction. So a valid ML-DSA-65 signature is necessary
    here and deliberately not sufficient: the value is still clamped.
    """
    with harness() as h:
        for absurd in (SETPOINT_MAX_C + 1.0, SETPOINT_MIN_C - 1.0, 11100.0, -40.0):
            h.logs.clear()
            before = h.engine.trip_setpoint
            payload = h.command("SET_SETPOINT", absurd)
            # Prove the signature itself is genuine, so the refusal below can
            # only be the clamp and never an accidental signature failure.
            assert identity.verify(
                h.registry.public_key_of(OPERATOR_ID),
                identity.operator_transcript(
                    OPERATOR_ID, "SET_SETPOINT", absurd,
                    payload["nonce"], payload["timestamp"]),
                bytes.fromhex(payload["signature"]),
            ), "test built an invalid signature; the clamp was not what refused"

            server.handle_operator_command(payload)
            assert h.engine.trip_setpoint == before, (
                f"a correctly signed command moved the setpoint to {absurd}°C")
            assert h.refused(), h.logs


def test_an_oversized_step_is_refused_even_when_signed():
    """Authentication does not license a lurch. Walking the setpoint out of the
    safe region one legal step at a time is at least visible; one jump is not."""
    with harness() as h:
        before = h.engine.trip_setpoint
        wanted = before + SETPOINT_MAX_STEP_C + 1.0
        assert SETPOINT_MIN_C <= wanted <= SETPOINT_MAX_C, "test value must be in range"
        server.handle_operator_command(h.command("SET_SETPOINT", wanted))
        assert h.engine.trip_setpoint == before, "an oversized single step was accepted"
        assert h.refused(), h.logs


def test_a_failed_signature_does_not_burn_the_nonce():
    """An attacker who watches a nonce go by must not be able to spend it.

    Burning nonces before verifying would let anyone deny a legitimate operator
    their command by echoing its nonce back with garbage attached.
    """
    with harness() as h:
        nonce_hex = os.urandom(16).hex()

        forged = h.command("SET_SETPOINT", 85.0, nonce_hex=nonce_hex)
        forged["signature"] = ("00" * 3309)
        server.handle_operator_command(forged)
        assert h.refused(), "the forged command should have been refused"
        assert nonce_hex not in h.engine.operator_nonces, "a bad signature burnt the nonce"

        h.logs.clear()
        wanted = h.engine.trip_setpoint + 5.0
        server.handle_operator_command(
            h.command("SET_SETPOINT", wanted, nonce_hex=nonce_hex))
        assert h.engine.trip_setpoint == wanted, (
            "the operator's own nonce was spent by an attacker")
        assert not h.refused(), h.logs


def test_signed_reset_clears_a_latched_trip():
    with harness() as h:
        h.engine.trip_state = "TRIPPED"
        server.handle_operator_command(h.command("RESET"))
        assert h.engine.trip_state == "HEALTHY", h.engine.trip_state


def test_signed_bypass_is_asserted_and_cleared():
    with harness() as h:
        server.handle_operator_command(h.command("BYPASS_ON"))
        assert h.engine.bypass is True
        server.handle_operator_command(h.command("BYPASS_OFF"))
        assert h.engine.bypass is False


def test_an_unknown_action_is_refused():
    with harness() as h:
        server.handle_operator_command(h.command("OPEN_EVERYTHING"))
        assert h.refused(), h.logs


def test_nothing_is_accepted_when_no_identities_are_enrolled():
    """Unauthenticated mode must refuse operator actions outright, not fall back
    to trusting them."""
    with harness() as h:
        server.AUTHENTICATED = False
        before = h.engine.trip_setpoint
        server.handle_operator_command(h.command("SET_SETPOINT", 85.0))
        assert h.engine.trip_setpoint == before
        assert h.refused(), h.logs


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
