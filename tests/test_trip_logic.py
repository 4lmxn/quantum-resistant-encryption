"""Self-check for the latching safety trip. Run: python -m tests.test_trip_logic

Pure logic — no server, no network. Exercises the SIS-01 state machine directly.

The thermostat this replaces had two edges and could reset itself. A safety
function has one edge: once the process variable reaches the setpoint the trip
latches, and only an authenticated operator RESET clears it.
"""

import time

from app import server


class FakeEngine:
    def __init__(self, setpoint=80.0, bypass=False, with_actuator=True,
                 bypass_asserted_at=None, bypass_last_reminder_at=None):
        self.trip_setpoint = setpoint
        self.trip_state = "HEALTHY"
        self.bypass = bypass
        self.bypass_asserted_at = bypass_asserted_at if bypass_asserted_at is not None else (
            time.time() if bypass else None)
        self.bypass_last_reminder_at = (
            bypass_last_reminder_at if bypass_last_reminder_at is not None else (
                time.time() if bypass else None))
        self.actuator_keys = {"fake-actuator": b"\x00" * 32} if with_actuator else {}


def run(temperatures, bypass=False, with_actuator=True):
    """Returns (states, commands) after feeding the readings in order."""
    engine, commands = FakeEngine(bypass=bypass, with_actuator=with_actuator), []
    with patched(engine, commands):
        states = []
        for temperature in temperatures:
            server.decide_trip(temperature)
            states.append(engine.trip_state)
        return states, commands


class patched:
    """Swaps the module globals decide_trip/clear_trip reach out to, and puts
    them back afterwards so one failing check cannot poison the next."""

    def __init__(self, engine, commands):
        self.engine = engine
        self.commands = commands

    def __enter__(self):
        self.original = (
            server.server_engine, server.send_actuator_command,
            server.socketio.emit, server.log,
        )
        server.server_engine = self.engine
        server.send_actuator_command = self.commands.append
        server.socketio.emit = lambda *a, **k: None
        server.log = lambda *a, **k: None
        return self.engine

    def __exit__(self, *exc):
        (server.server_engine, server.send_actuator_command,
         server.socketio.emit, server.log) = self.original
        return False


def test_reaching_the_setpoint_latches_and_trips():
    states, commands = run([70.0, 80.0])
    assert states == ["HEALTHY", "TRIPPED"], states
    assert commands == ["TRIP"], commands


def test_above_the_setpoint_also_trips():
    states, commands = run([84.2])
    assert states == ["TRIPPED"], states
    assert commands == ["TRIP"], commands


def test_the_latch_does_not_clear_when_it_cools():
    """The core behaviour change. The old thermostat reset itself here; a trip
    must not, because the plant cooling down is not evidence the cause was dealt
    with."""
    states, commands = run([85.0, 60.0, 40.0, 20.0])
    assert states == ["TRIPPED"] * 4, states
    assert commands == ["TRIP"], f"latch cleared or re-sent: {commands}"


def test_speaks_only_on_the_edge_into_tripped():
    _, commands = run([85.0, 86.0, 90.0, 100.0])
    assert commands == ["TRIP"], f"one command per reading, not per edge: {commands}"


def test_bypass_suspends_the_trip_entirely():
    states, commands = run([85.0, 120.0], bypass=True)
    assert states == ["HEALTHY", "HEALTHY"], states
    assert commands == [], f"bypass asserted but the trip still fired: {commands}"


def test_bypass_auto_expires_and_the_trip_fires_again():
    """J-3: bypass must not stand forever. Once BYPASS_MAX_DURATION_S has
    elapsed, the next reading re-arms trip logic and evaluates normally --
    an over-setpoint reading right after expiry still latches."""
    engine = FakeEngine(bypass=True,
                         bypass_asserted_at=time.time() - server.BYPASS_MAX_DURATION_S - 1)
    commands = []
    with patched(engine, commands):
        server.decide_trip(120.0)
    assert engine.bypass is False, "bypass did not auto-clear past its limit"
    assert engine.trip_state == "TRIPPED", "expired bypass did not re-arm trip logic"
    assert commands == ["TRIP"], commands


def test_bypass_short_of_expiry_still_suspends_the_trip():
    engine = FakeEngine(bypass=True,
                         bypass_asserted_at=time.time() - (server.BYPASS_MAX_DURATION_S - 5))
    commands = []
    with patched(engine, commands):
        server.decide_trip(120.0)
    assert engine.bypass is True, "bypass cleared before its limit"
    assert engine.trip_state == "HEALTHY", "trip fired while bypass still valid"
    assert commands == [], commands


def test_latches_even_with_no_actuator_listening():
    """The server-side latch and the delivery are separate concerns. Nothing is
    holding a session, so nothing physical moves — but the SIS still knows it
    tripped, and the actuator's own heartbeat watchdog is the backstop."""
    states, commands = run([85.0], with_actuator=False)
    assert states == ["TRIPPED"], states
    assert commands == [], f"sent a command with no actuator session: {commands}"


def test_clear_trip_resets_and_sends_reset():
    engine, commands = FakeEngine(), []
    with patched(engine, commands):
        server.decide_trip(85.0)
        assert engine.trip_state == "TRIPPED"
        server.clear_trip("operator-01")
        assert engine.trip_state == "HEALTHY", "RESET did not clear the latch"
        assert commands == ["TRIP", "RESET"], commands


def test_clear_trip_when_healthy_sends_nothing():
    engine, commands = FakeEngine(), []
    with patched(engine, commands):
        server.clear_trip("operator-01")
        assert engine.trip_state == "HEALTHY", engine.trip_state
        assert commands == [], f"RESET on a healthy plant moved the valve: {commands}"


def test_a_cleared_trip_can_latch_again():
    engine, commands = FakeEngine(), []
    with patched(engine, commands):
        server.decide_trip(85.0)
        server.clear_trip("operator-01")
        server.decide_trip(85.0)
        assert engine.trip_state == "TRIPPED"
        assert commands == ["TRIP", "RESET", "TRIP"], commands


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
