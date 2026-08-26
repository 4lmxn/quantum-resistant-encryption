"""Net-new coverage for docs/SAFETY_MODEL.md's INVARIANT-02, closing the one
real gap the safety audit found. Run: python -m tests.test_safety_invariants

INVARIANT-02: a forged telemetry message must never directly cause an unsafe
actuator command. `tests/test_device_leg.py` already proves this for the
HTTP/constrained-node leg; nothing previously drove `handle_sensor_telemetry`
-- the primary Socket.IO safety-lane path -- with a forged or replayed
packet. This file exercises exactly that path, against the real server
handler rather than a re-implementation of it.

Every other invariant in docs/SAFETY_MODEL.md already has direct coverage
elsewhere (see that document's summary table); this file does not repeat it.

No server and no network: `request.sid` is the only piece of Flask context
`handle_sensor_telemetry` touches, so it is monkeypatched exactly like
server_engine, log and socketio.emit are in the other harness-based test
files (test_operator_auth.py, test_trip_logic.py).
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import server

SID = "test-sensor-sid"
SESSION_KEY = os.urandom(32)


class FakeRequest:
    sid = SID


def seal(temperature, key=SESSION_KEY, nonce=None):
    nonce = nonce or os.urandom(12)
    payload = f'{{"temperature": {temperature}, "humidity": 50.0}}'.encode()
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


class harness:
    """Swaps in a fresh engine, a fake request.sid, and captures every
    command the trip decision would have sent -- same pattern as the other
    handler-level test files, so a failing check cannot poison the next."""

    def __init__(self, setpoint=80.0):
        self.engine = server.CentralServer()
        self.engine.trip_setpoint = setpoint
        self.engine.sensor_keys[SID] = SESSION_KEY
        self.engine.actuator_keys["fake-actuator"] = os.urandom(32)
        self.commands = []
        self.logs = []

    def __enter__(self):
        self.original = (
            server.server_engine, server.request,
            server.send_actuator_command, server.socketio.emit, server.log,
        )
        server.server_engine = self.engine
        server.request = FakeRequest()
        server.send_actuator_command = self.commands.append
        server.socketio.emit = lambda *a, **k: None
        server.log = lambda log_type, msg: self.logs.append((log_type, msg))
        return self

    def __exit__(self, *exc):
        (server.server_engine, server.request,
         server.send_actuator_command, server.socketio.emit, server.log) = self.original
        return False

    def errors(self):
        return [msg for kind, msg in self.logs if kind == "ERROR"]


def test_a_genuine_over_setpoint_reading_trips():
    """Control case: proves the harness itself would show a trip if the
    forged packet in the next test had been accepted."""
    with harness() as h:
        server.handle_sensor_telemetry(seal(95.0))
        assert h.engine.trip_state == "TRIPPED", h.engine.trip_state
        assert h.commands == ["TRIP"], h.commands


def test_a_forged_telemetry_packet_never_reaches_the_trip_decision():
    """INVARIANT-02. A tampered ciphertext must fail the GCM tag and be
    dropped before process_telemetry / decide_trip ever sees it -- even
    though the plaintext it claims to carry is well over the setpoint."""
    with harness() as h:
        packet = seal(95.0)
        tampered = bytearray(bytes.fromhex(packet["ciphertext"]))
        tampered[0] ^= 0xFF
        packet["ciphertext"] = tampered.hex()

        server.handle_sensor_telemetry(packet)

        assert h.engine.trip_state == "HEALTHY", (
            "a forged telemetry packet moved the safety state")
        assert h.commands == [], f"a forged packet produced a command: {h.commands}"
        assert any("Decryption failed" in m for m in h.errors()), h.logs


def test_telemetry_sealed_under_the_wrong_key_never_reaches_the_trip_decision():
    """The same property from a different angle: a packet that is
    structurally well-formed AEAD but sealed with a key this session never
    agreed on -- not a bit-flip, a genuinely different key."""
    with harness() as h:
        attacker_key = os.urandom(32)
        packet = seal(95.0, key=attacker_key)

        server.handle_sensor_telemetry(packet)

        assert h.engine.trip_state == "HEALTHY"
        assert h.commands == []
        assert any("Decryption failed" in m for m in h.errors()), h.logs


def test_a_replayed_sensor_telemetry_packet_is_blocked_before_decryption():
    """A captured genuine reading, replayed verbatim. Freshness is checked
    before decryption is even attempted (accept_nonce gates
    decrypt_sensor_data in handle_sensor_telemetry), so this proves the
    nonce store -- not the AEAD tag -- is what stops the second delivery."""
    with harness(setpoint=200.0) as h:  # keep it HEALTHY; isolate replay from trip logic
        packet = seal(30.0)

        server.handle_sensor_telemetry(packet)
        assert h.engine.trip_state == "HEALTHY"
        assert h.engine.replays_blocked == 0

        server.handle_sensor_telemetry(packet)  # byte-for-byte replay
        assert h.engine.replays_blocked == 1, "a replayed telemetry packet was not blocked"
        assert any("REPLAY BLOCKED" in m for m in h.errors()), h.logs


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
