"""A genuine command is single-use. Run: python -m tests.test_command_replay

The server refuses a repeated nonce on telemetry coming in. This direction --
server to actuator -- was unprotected: a captured TRIP or RESET could be sent
again and the valve would obey, which is the flaw the FDA described in the 2019
MiniMed insulin pump recall. Record the wireless traffic, replay it, the device
acts.

Pure logic, no network.
"""

from app.nodes.actuator import SimulatedActuatorNode
from app.server import CentralServer

KEY = bytes(range(32))


def sealed(command):
    return CentralServer().encrypt_actuator_command(KEY, command)


def fresh_node():
    n = SimulatedActuatorNode()
    n.key_b = bytearray(KEY)
    return n


def test_a_genuine_command_is_obeyed_once():
    n = fresh_node()
    ok, msg = n.process_command(sealed("TRIP"))
    assert ok and n.valve_state == "CLOSED", msg


def test_the_same_command_replayed_is_refused():
    """The reported gap: a captured command re-sent, tag perfect, obeyed twice."""
    n = fresh_node()
    packet = sealed("TRIP")
    n.process_command(packet)
    n.valve_state = "OPEN"  # pretend an operator reopened it
    ok, msg = n.process_command(packet)  # attacker replays the captured TRIP
    assert not ok, "a replayed command was obeyed"
    assert "REPLAY REFUSED" in msg, msg
    assert n.valve_state == "OPEN", "the replay moved the valve"


def test_a_different_command_still_works():
    """The nonce store must not block distinct commands."""
    n = fresh_node()
    assert n.process_command(sealed("TRIP"))[0]
    assert n.process_command(sealed("RESET"))[0], "a fresh RESET was refused"
    assert n.valve_state == "OPEN"


def test_the_replayed_reset_cannot_reopen_after_a_trip():
    """The attack that matters: capture a RESET, let a real trip happen, replay
    the RESET to reopen the valve."""
    n = fresh_node()
    captured_reset = sealed("RESET")
    n.process_command(captured_reset)          # server's genuine reset, obeyed
    n.process_command(sealed("TRIP"))          # a real excursion trips the valve
    assert n.valve_state == "CLOSED"
    ok, msg = n.process_command(captured_reset)  # attacker replays the old reset
    assert not ok and n.valve_state == "CLOSED", "the valve reopened on a replayed reset"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
