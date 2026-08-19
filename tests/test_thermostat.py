"""Self-check for the relay decision. Run: python -m tests.test_thermostat

Pure logic — no server, no network. Exercises the state machine directly.
"""

from app import server


class FakeEngine:
    def __init__(self, threshold=30.0, hysteresis=1.0):
        self.temp_threshold = threshold
        self.relay_hysteresis = hysteresis
        self.desired_relay = "OFF"
        self.manual_mode = False
        self.actuator_keys = {"fake-actuator": b"\x00" * 32}


def run(temperatures):
    """Returns (states, commands) after feeding the readings in order."""
    engine, commands = FakeEngine(), []
    original_engine, original_send, original_emit = (
        server.server_engine, server.send_actuator_command, server.socketio.emit
    )
    server.server_engine = engine
    server.send_actuator_command = commands.append
    server.socketio.emit = lambda *a, **k: None
    server.log = lambda *a, **k: None
    try:
        states = []
        for t in temperatures:
            server.decide_relay(t)
            states.append(engine.desired_relay)
        return states, commands
    finally:
        server.server_engine, server.send_actuator_command = original_engine, original_send
        server.socketio.emit = original_emit


def test_turns_on_above_the_limit_and_off_below():
    states, commands = run([26.0, 31.0, 26.0])
    assert states == ["OFF", "ON", "OFF"], states
    assert commands == ["FAN_ON", "FAN_OFF"], commands


def test_does_not_latch_on_forever():
    """The original bug: one warm reading left the fan on permanently."""
    states, _ = run([35.0, 20.0, 20.0, 20.0])
    assert states[-1] == "OFF", "fan latched on and never came back off"


def test_holds_state_inside_the_hysteresis_band():
    """Between 29 and 30 nothing should change, in either direction."""
    on_states, on_cmds = run([31.0, 29.5, 29.6, 29.4])
    assert on_states == ["ON"] * 4, on_states
    assert on_cmds == ["FAN_ON"], "relay chattered inside the band"

    off_states, off_cmds = run([29.5, 29.9, 30.0])
    assert off_states == ["OFF"] * 3, off_states
    assert off_cmds == [], "turned on without crossing the upper edge"


def test_speaks_only_when_the_decision_changes():
    _, commands = run([33.0, 34.0, 35.0, 33.5])
    assert commands == ["FAN_ON"], f"re-sent commands with no change: {commands}"




def test_manual_mode_suspends_the_thermostat():
    """The reported bug: a manual switch was undone by the next warm reading."""
    engine, commands = FakeEngine(), []
    original = (server.server_engine, server.send_actuator_command, server.socketio.emit)
    server.server_engine = engine
    server.send_actuator_command = commands.append
    server.socketio.emit = lambda *a, **k: None
    server.log = lambda *a, **k: None
    try:
        server.decide_relay(33.0)                 # thermostat turns it on
        assert engine.desired_relay == "ON"

        engine.manual_mode = True                 # operator switches it off
        engine.desired_relay = "OFF"

        for hot in (33.0, 34.0, 35.0):            # thermostat must stay quiet
            server.decide_relay(hot)
        assert engine.desired_relay == "OFF", "manual choice was overridden"

        engine.manual_mode = False                # back to automatic
        server.decide_relay(33.0)
        assert engine.desired_relay == "ON", "thermostat did not resume"
    finally:
        server.server_engine, server.send_actuator_command, server.socketio.emit = original


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
