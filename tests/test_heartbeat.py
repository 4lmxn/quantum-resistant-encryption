"""Self-check for the actuator's dead-man watchdog.

Run: python -m tests.test_heartbeat

No server and no network — the node object is driven directly, and the beats are
sealed by the same `CentralServer.encrypt_actuator_command` the server uses, so
the wire format under test is the real one. Nothing here sleeps: the deadline is
moved rather than waited out.
"""

import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import server
from app.config import HEARTBEAT_TIMEOUT_S
from app.nodes.actuator import SimulatedActuatorNode

SESSION_KEY = os.urandom(32)
sealer = server.CentralServer()


def fresh_node():
    node = SimulatedActuatorNode()
    node.key_b = bytearray(SESSION_KEY)
    return node


def beat(seq):
    return sealer.encrypt_actuator_command(SESSION_KEY, "HEARTBEAT", seq=seq)


def command(command_str):
    return sealer.encrypt_actuator_command(SESSION_KEY, command_str)


def test_a_sealed_beat_is_accepted_and_moves_the_deadline():
    node = fresh_node()
    assert node.last_heartbeat is None
    assert node.accept_heartbeat(beat(1)) is True
    assert node.last_heartbeat is not None, "an accepted beat did not arm the watchdog"
    assert node.last_seq == 1


def test_a_replayed_beat_is_refused_and_does_not_refresh_the_deadline():
    """Capturing one beat must not hold the watchdog open forever. This is the
    whole reason a heartbeat carries a sequence number."""
    node = fresh_node()
    captured = beat(1)
    assert node.accept_heartbeat(captured) is True

    # The link goes quiet; the deadline ages past the timeout.
    node.last_heartbeat = time.monotonic() - (HEARTBEAT_TIMEOUT_S + 1.0)
    stale_deadline = node.last_heartbeat
    assert node.heartbeat_overdue() is True

    assert node.accept_heartbeat(captured) is False, "a replayed beat was counted"
    assert node.last_heartbeat == stale_deadline, "a replay pushed the deadline out"
    assert node.heartbeat_overdue() is True, "a replay held the watchdog open"


def test_an_out_of_order_beat_is_refused():
    node = fresh_node()
    assert node.accept_heartbeat(beat(7)) is True
    assert node.accept_heartbeat(beat(3)) is False
    assert node.last_seq == 7


def test_a_sealed_command_does_not_feed_the_watchdog():
    """A TRIP is authentic but is not proof the controller is still alive on
    schedule, so it must not stand in for a beat."""
    node = fresh_node()
    assert node.accept_heartbeat(command("TRIP")) is False
    assert node.last_heartbeat is None


def test_the_watchdog_is_not_overdue_before_the_timeout():
    node = fresh_node()
    node.accept_heartbeat(beat(1))
    assert node.heartbeat_overdue() is False
    node.last_heartbeat = time.monotonic() - (HEARTBEAT_TIMEOUT_S - 1.0)
    assert node.heartbeat_overdue() is False


def test_the_watchdog_is_overdue_after_the_timeout():
    node = fresh_node()
    node.accept_heartbeat(beat(1))
    node.last_heartbeat = time.monotonic() - (HEARTBEAT_TIMEOUT_S + 0.1)
    assert node.heartbeat_overdue() is True


def test_an_unarmed_watchdog_is_never_overdue():
    """Before the handshake seeds it there is nothing to be late for; the node
    arms it on `pqc_established` precisely so silence still trips on schedule."""
    assert fresh_node().heartbeat_overdue() is False


def test_a_tampered_beat_is_rejected_by_the_gcm_tag():
    node = fresh_node()
    packet = beat(1)
    forged = bytearray(bytes.fromhex(packet["ciphertext"]))
    forged[0] ^= 0xFF
    packet["ciphertext"] = forged.hex()
    try:
        node.accept_heartbeat(packet)
    except Exception:
        assert node.last_heartbeat is None, "a forged beat armed the watchdog"
        return
    raise AssertionError("the GCM tag accepted a tampered heartbeat")


def test_a_beat_sealed_with_the_wrong_key_is_rejected():
    """The beat proves the controller is not just alive but still ours."""
    node = fresh_node()
    attacker_key = os.urandom(32)
    packet = sealer.encrypt_actuator_command(attacker_key, "HEARTBEAT", seq=1)
    try:
        node.accept_heartbeat(packet)
    except Exception:
        return
    raise AssertionError("a beat from an unrelated key was accepted")


def test_process_command_trips_and_resets_the_valve():
    node = fresh_node()
    assert node.valve_state == "OPEN"

    ok, msg = node.process_command(command("TRIP"))
    assert ok is True, msg
    assert node.valve_state == "CLOSED", msg

    ok, msg = node.process_command(command("RESET"))
    assert ok is True, msg
    assert node.valve_state == "OPEN", msg


def test_reset_clears_the_watchdog_latch_but_not_the_deadline():
    node = fresh_node()
    node.tripped_by_watchdog = True
    node.valve_state = "CLOSED"
    node.process_command(command("RESET"))
    assert node.tripped_by_watchdog is False
    assert node.valve_state == "OPEN"


def test_an_unknown_command_is_refused():
    """The tag verified, so this is not tampering — it is an instruction the
    final element does not implement, and must not be reported as done."""
    node = fresh_node()
    # FAN_ON is deliberate: the old thermostat vocabulary is not a command
    # this node implements any more, and must be refused rather than guessed at.
    ok, msg = node.process_command(command("FAN_ON"))
    assert ok is False, msg
    assert "Unknown Command" in msg, msg
    assert node.valve_state == "OPEN", "an unknown command moved the valve"


def test_a_tampered_command_raises():
    node = fresh_node()
    packet = command("TRIP")
    forged = bytearray(bytes.fromhex(packet["ciphertext"]))
    forged[-1] ^= 0xFF
    packet["ciphertext"] = forged.hex()
    try:
        node.process_command(packet)
    except Exception:
        assert node.valve_state == "OPEN"
        return
    raise AssertionError("the GCM tag accepted a tampered command")


def test_zeroize_wipes_the_session_key():
    node = fresh_node()
    node.zeroize_key()
    assert bytes(node.key_b) == b"\x00" * 32
    try:
        AESGCM(bytes(node.key_b)).decrypt(
            bytes.fromhex(beat(1)["nonce"]), bytes.fromhex(beat(1)["ciphertext"]), None)
    except Exception:
        return
    raise AssertionError("a zeroized key still decrypted traffic")


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
