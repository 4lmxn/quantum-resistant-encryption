"""One enrolled identity, one live session. Run: python -m tests.test_duplicate_identity

A valid ML-DSA signature proves possession of a key. It does not prove that the
holder is the only one. There is exactly one TT-101 bolted to the plant, so a
second session claiming to be it is a fault however it arose -- a stale node left
running, or a stolen key -- and the failure hides in plain sight: the readings
interleave, the log looks busy rather than wrong, and the number on the dashboard
flickers between two plants.

Pure logic, no server and no network.
"""

import contextlib
import types

from app import identity, server
from app.pqc import ENCAPSULATION_KEY_BYTES, generate_keypair


class FakeRegistry:
    """Two enrolled identities, real ML-DSA keys."""

    def __init__(self):
        self.server_public, self.server_secret = identity.generate_identity()
        self.devices = {}
        self.secrets = {}
        for device_id in ("sensor-01", "sensor-02"):
            public, secret = identity.generate_identity()
            self.devices[device_id] = public
            self.secrets[device_id] = secret

    def is_enrolled(self, device_id):
        return device_id in self.devices

    def public_key_of(self, device_id):
        return self.devices.get(device_id)


@contextlib.contextmanager
def patched():
    """Swaps in a fresh engine, a fake registry and a stub request/emit."""
    saved = (server.server_engine, server.registry, server.AUTHENTICATED,
             server.request, server.emit, server.log, server.socketio.emit,
             server.broadcast_pqc_status)
    engine = server.CentralServer()
    registry = FakeRegistry()
    logs, refusals = [], []

    server.server_engine = engine
    server.registry = registry
    server.AUTHENTICATED = True
    server.request = types.SimpleNamespace(sid=None)
    server.emit = lambda event, data=None, **kw: refusals.append((event, data))
    server.log = lambda kind, msg: logs.append((kind, msg))
    server.socketio.emit = lambda *a, **kw: None
    server.broadcast_pqc_status = lambda: None
    try:
        yield engine, registry, logs, refusals
    finally:
        (server.server_engine, server.registry, server.AUTHENTICATED,
         server.request, server.emit, server.log, server.socketio.emit,
         server.broadcast_pqc_status) = saved


def handshake(registry, sid, device_id, role="sensor"):
    """Drives one complete, correctly signed handshake for `sid`."""
    server.request.sid = sid
    encapsulation_key = server.server_engine.begin_handshake(sid, role)
    assert len(encapsulation_key) == ENCAPSULATION_KEY_BYTES

    from app.pqc import LINK_SENSOR, LINK_ACTUATOR, encapsulate, key_fingerprint
    label = LINK_SENSOR if role == "sensor" else LINK_ACTUATOR
    session_key, kem_ciphertext = encapsulate(encapsulation_key, label)

    transcript = identity.handshake_transcript(role, encapsulation_key, kem_ciphertext)
    server.handle_pqc_encapsulation({
        "kem_ciphertext": kem_ciphertext.hex(),
        "key_fingerprint": key_fingerprint(session_key),
        "device_id": device_id,
        "device_signature": identity.sign(registry.secrets[device_id], transcript).hex(),
    })


def test_a_first_handshake_is_accepted():
    with patched() as (engine, registry, logs, _):
        handshake(registry, "sid-aaa", "sensor-01")
        assert engine.active_devices == {"sensor-01": "sid-aaa"}, engine.active_devices
        assert "sid-aaa" in engine.sensor_keys


def test_a_second_session_for_the_same_identity_is_refused():
    """The reported bug: two sensor nodes ran at once and both were served."""
    with patched() as (engine, registry, logs, refusals):
        handshake(registry, "sid-aaa", "sensor-01")
        handshake(registry, "sid-bbb", "sensor-01")

        assert engine.active_devices == {"sensor-01": "sid-aaa"}, \
            "the second session took the identity from the first"
        assert "sid-bbb" not in engine.sensor_keys, \
            "the refused node was still given a session key"
        assert any("already holds a live session" in m for _, m in logs), logs
        assert ("pqc_refused", {"reason": "duplicate_device_id",
                                "device_id": "sensor-01"}) in refusals, refusals


def test_the_first_session_keeps_working_after_a_refusal():
    """Refusing the intruder must not disturb the node already doing its job."""
    with patched() as (engine, registry, logs, _):
        handshake(registry, "sid-aaa", "sensor-01")
        original_key = engine.sensor_keys["sid-aaa"]
        handshake(registry, "sid-bbb", "sensor-01")

        assert engine.sensor_keys.get("sid-aaa") == original_key, \
            "the incumbent's session key changed"
        assert "sid-aaa" in engine.sessions


def test_a_different_identity_is_still_accepted():
    """This is a per-identity rule, not a one-node-only rule."""
    with patched() as (engine, registry, _, _r):
        handshake(registry, "sid-aaa", "sensor-01")
        handshake(registry, "sid-bbb", "sensor-02")
        assert engine.active_devices == {"sensor-01": "sid-aaa", "sensor-02": "sid-bbb"}


def test_the_identity_is_released_on_disconnect():
    """A node that drops must be able to reconnect, or one crash locks its own
    identity out until the server restarts."""
    with patched() as (engine, registry, _, _r):
        handshake(registry, "sid-aaa", "sensor-01")
        engine.forget("sid-aaa")
        assert engine.active_devices == {}, "identity stayed claimed after disconnect"

        handshake(registry, "sid-ccc", "sensor-01")
        assert engine.active_devices == {"sensor-01": "sid-ccc"}, \
            "the node could not reclaim its own identity after reconnecting"


def test_forget_releases_only_the_disconnecting_session():
    with patched() as (engine, registry, _, _r):
        handshake(registry, "sid-aaa", "sensor-01")
        handshake(registry, "sid-bbb", "sensor-02")
        engine.forget("sid-aaa")
        assert engine.active_devices == {"sensor-02": "sid-bbb"}, engine.active_devices


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
