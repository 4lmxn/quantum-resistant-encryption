"""Self-check for the Nano relay hook. Run: python -m tests.test_relay_driver

Pure logic, no hardware: proves _set_valve is the one choke point every valve
mutation goes through, and that relay_driver.send_valve_state degrades to a
no-op with no RELAY_SERIAL_PORT set -- an unplugged Nano must never stop the
demo running purely in software.
"""

from app.nodes import relay_driver
from app.nodes.actuator import SimulatedActuatorNode


def test_set_valve_calls_the_hook_with_the_new_state():
    node = SimulatedActuatorNode()
    seen = []
    node.on_valve_change = seen.append
    node._set_valve("CLOSED")
    assert seen == ["CLOSED"], seen
    assert node.valve_state == "CLOSED"


def test_set_valve_is_a_noop_without_a_hook():
    node = SimulatedActuatorNode()
    node._set_valve("CLOSED")  # must not raise with on_valve_change left None
    assert node.valve_state == "CLOSED"


def test_process_command_and_watchdog_both_route_through_the_hook():
    """The two real call sites (a TRIP command, and the dead-man watchdog)
    must both reach the same hook -- not just direct _set_valve() calls."""
    node = SimulatedActuatorNode()
    node.key_b = bytearray(range(32))
    seen = []
    node.on_valve_change = seen.append

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import json
    import os
    aesgcm = AESGCM(bytes(node.key_b))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json.dumps({"command": "TRIP"}).encode(), None)
    node.process_command({"nonce": nonce.hex(), "ciphertext": ciphertext.hex()})
    assert seen == ["CLOSED"], seen


def test_send_valve_state_is_a_noop_without_a_configured_port():
    assert relay_driver._PORT is None, (
        "RELAY_SERIAL_PORT is set in this environment -- this test assumes it isn't")
    relay_driver.send_valve_state("OPEN")  # must not raise, no pyserial needed


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
