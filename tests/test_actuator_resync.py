"""On reconnect, the actuator is re-synced to the server's valve state.
Run: python -m tests.test_actuator_resync

A reconnecting actuator -- after a server restart, or a dropped link that made
its dead-man watchdog trip -- must be told where the valve should be. Without
that, it sits latched CLOSED with nothing able to reach it, and even a signed
operator RESET lands before the handshake finishes and reaches no one. Standard
SIS practice: the controller re-asserts its outputs on every reconnect.

Pure logic, no network: drives sync_actuator_state directly.
"""

from app import server
from app.nodes.actuator import SimulatedActuatorNode

KEY = bytes(range(32))


class Harness:
    """A server engine with one actuator session, capturing what gets sent."""

    def __init__(self, trip_state):
        self.engine = server.CentralServer()
        self.engine.trip_state = trip_state
        self.engine.actuator_keys["act-1"] = KEY
        self.sent = []

    def __enter__(self):
        self._saved = (server.server_engine, server._dispatch_to_actuator, server.log)
        server.server_engine = self.engine
        server._dispatch_to_actuator = lambda sid, pkt: self.sent.append((sid, pkt))
        server.log = lambda *a, **k: None
        return self

    def __exit__(self, *a):
        server.server_engine, server._dispatch_to_actuator, server.log = self._saved


def decode(packet):
    """Decrypt a captured command the way the real actuator would."""
    node = SimulatedActuatorNode()
    node.key_b = bytearray(KEY)
    ok, _ = node.process_command(packet)
    return node.valve_state


def test_sync_sends_reset_when_the_server_is_healthy():
    with Harness("HEALTHY") as h:
        server.sync_actuator_state("act-1")
        assert len(h.sent) == 1, "nothing was sent to the actuator"
        assert decode(h.sent[0][1]) == "OPEN", "a healthy server did not reopen the valve"


def test_sync_sends_trip_when_the_server_is_tripped():
    with Harness("TRIPPED") as h:
        server.sync_actuator_state("act-1")
        assert decode(h.sent[0][1]) == "CLOSED", "a tripped server did not keep the valve shut"


def test_a_watchdog_tripped_actuator_reopens_on_a_healthy_resync():
    """The reported bug: valve stuck CLOSED after a server restart."""
    actuator = SimulatedActuatorNode()
    actuator.key_b = bytearray(KEY)
    actuator.valve_state = "CLOSED"
    actuator.tripped_by_watchdog = True

    with Harness("HEALTHY") as h:
        server.sync_actuator_state("act-1")
        ok, _ = actuator.process_command(h.sent[0][1])
    assert actuator.valve_state == "OPEN", "the stuck valve did not reopen"
    assert not actuator.tripped_by_watchdog, "the watchdog latch was not cleared"


def test_sync_is_a_noop_without_a_session():
    with Harness("TRIPPED") as h:
        server.sync_actuator_state("no-such-sid")
        assert h.sent == [], "sent a command to an actuator with no session key"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
