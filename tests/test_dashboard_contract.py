"""The dashboard event contract, backend side. Run: python -m tests.test_dashboard_contract

Covers what the reskinned HMI builds against: telemetry without a humidity key
(the MAX6675 measures temperature only), the 1 Hz rig_status re-broadcast and
its field whitelist, relay link status, per-stage link/stopped_by, the physical
before/after on every finding, attack_progress, the single-campaign guard, and
the SIS_SERVER_URL override. No server and no network: request.sid, emit, log
and sleep are swapped exactly as in test_safety_invariants.py.
"""

import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import server
from app.attacks import attacks
from app.nodes import actuator as actuator_node
from app.nodes import relay_driver

LINKS = {"sensor_link", "actuator_link", "operator", "key_exchange", "server"}


class FakeRequest:
    def __init__(self, sid):
        self.sid = sid


class harness:
    """Fresh engine, fake request.sid, every emit and log captured."""

    def __init__(self, sid="test-sid"):
        self.engine = server.CentralServer()
        self.sid = sid
        self.emits = []
        self.logs = []

    def __enter__(self):
        self.original = (server.server_engine, server.request, server.log,
                         server._persist_finding)
        server.server_engine = self.engine
        server.request = FakeRequest(self.sid)
        server.log = lambda log_type, msg: self.logs.append((log_type, msg))
        server._persist_finding = lambda identifier, record: None
        server.socketio.emit = lambda event, payload=None, **kw: self.emits.append((event, payload))
        server.socketio.sleep = lambda seconds: None
        return self

    def __exit__(self, *exc):
        (server.server_engine, server.request, server.log,
         server._persist_finding) = self.original
        del server.socketio.emit, server.socketio.sleep  # back to the class methods

    def payloads(self, event):
        return [payload for name, payload in self.emits if name == event]


def test_telemetry_without_humidity_is_accepted_and_emitted_as_null():
    """Through the real HTTP leg: decrypt, nonce gate, process_telemetry."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    plain = b'{"unit":"esp32-01","sensor":"MAX6675","temperature":42.50}'
    packet = {"device_id": "esp32-01", "nonce": nonce.hex(),
              "ciphertext": AESGCM(key).encrypt(nonce, plain, None).hex()}
    with harness() as h:
        h.engine.http_sessions["esp32-01"] = key
        server.request = h.original[1]  # a real HTTP request, not a fake sid
        before_ms = int(time.time() * 1000)
        response = server.app.test_client().post("/telemetry", json=packet)
        assert response.status_code == 200, response.get_json()
        (telemetry,) = h.payloads("update_telemetry")
    assert telemetry["humidity"] is None, telemetry
    assert telemetry["sensor"] == "MAX6675"
    assert telemetry["device_id"] == "esp32-01"
    assert telemetry["temp"] == 42.5
    assert before_ms <= telemetry["received_at"] <= int(time.time() * 1000) + 1


def test_telemetry_with_humidity_keeps_it_and_unlabelled_sensor_is_null():
    with harness() as h:
        server.process_telemetry({"temperature": 30.0, "humidity": 55.5}, "sensor node")
        (telemetry,) = h.payloads("update_telemetry")
    assert telemetry["humidity"] == 55.5
    assert telemetry["sensor"] is None and telemetry["device_id"] is None


def test_socketio_sensor_telemetry_carries_the_enrolled_device_id():
    key = os.urandom(32)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, b'{"temperature": 31.0, "sensor": "simulated"}', None)
    with harness(sid="sensor-sid") as h:
        h.engine.sensor_keys["sensor-sid"] = key
        h.engine.active_devices["sensor-01"] = "sensor-sid"
        server.handle_sensor_telemetry({"nonce": nonce.hex(), "ciphertext": sealed.hex()})
        (telemetry,) = h.payloads("update_telemetry")
    assert telemetry["device_id"] == "sensor-01"
    assert telemetry["sensor"] == "simulated" and telemetry["humidity"] is None


def test_every_catalog_entry_has_link_and_stopped_by():
    assert set(attacks.ATTACK_CATALOG) == set(attacks.ATTACK_ORDER)
    for identifier, entry in attacks.ATTACK_CATALOG.items():
        assert entry.get("link") in LINKS, (identifier, entry.get("link"))
        stopped_by = entry.get("stopped_by")
        assert isinstance(stopped_by, str) and stopped_by.strip(), identifier
        assert len(stopped_by.split()) <= 4, (identifier, stopped_by)


def test_relay_status_unconfigured():
    assert relay_driver._PORT is None, "RELAY_SERIAL_PORT is set in this environment"
    relay_driver.send_valve_state("OPEN")
    assert relay_driver.status() == {"configured": False, "connected": False, "port": None}


class FlakySerial:
    def __init__(self):
        self.fail = False

    def write(self, data):
        if self.fail:
            raise OSError("device unplugged")


def test_relay_status_failed_open_and_write_failure():
    saved = (relay_driver._PORT, relay_driver._conn, relay_driver._last_write_ok)
    try:
        # Port set but the open fails (no such device, or no pyserial).
        relay_driver._PORT, relay_driver._conn = "/dev/does-not-exist-sis01", None
        relay_driver.send_valve_state("OPEN")
        assert relay_driver.status() == {
            "configured": True, "connected": False, "port": "/dev/does-not-exist-sis01"}

        # Port open: connected while writes land, not once one fails.
        port = FlakySerial()
        relay_driver._conn = port
        relay_driver.send_valve_state("OPEN")
        assert relay_driver.status()["connected"] is True
        port.fail = True
        relay_driver.send_valve_state("OPEN")
        assert relay_driver.status()["connected"] is False
    finally:
        relay_driver._PORT, relay_driver._conn, relay_driver._last_write_ok = saved


def test_actuator_rig_status_shape_without_a_relay():
    report = actuator_node.rig_status()
    assert set(report) == {"device_id", "valve", "pump", "relay", "heartbeat",
                           "tripped_by_watchdog"}
    assert report["pump"] is None  # no relay board configured
    assert report["relay"]["configured"] is False
    assert set(report["heartbeat"]) == {"age_s", "timeout_s", "period_s"}


def test_rig_status_rebroadcast_whitelists_fields():
    hostile = {
        "device_id": "spoofed-99", "valve": "WIDE_OPEN", "pump": "ON",
        "relay": {"configured": "yes", "connected": True, "port": "x" * 500, "extra": 1},
        "heartbeat": {"age_s": "nan", "timeout_s": 6.0, "period_s": 2, "injected": True},
        "tripped_by_watchdog": 1, "<script>": "alert(1)",
    }
    with harness(sid="act-sid") as h:
        h.engine.actuator_keys["act-sid"] = os.urandom(32)
        h.engine.active_devices["actuator-01"] = "act-sid"
        server.handle_relay_rig_status(hostile)
        (rig,) = h.payloads("rig_status")
    assert set(rig) == {"device_id", "valve", "pump", "relay", "heartbeat",
                        "tripped_by_watchdog", "received_at"}, rig
    assert rig["device_id"] == "actuator-01"  # the server's record, not the claim
    assert rig["valve"] is None and rig["pump"] == "ON"
    assert rig["relay"] == {"configured": False, "connected": True, "port": "x" * 128}
    assert rig["heartbeat"] == {"age_s": None, "timeout_s": 6.0, "period_s": 2.0}
    assert rig["tripped_by_watchdog"] is False
    assert isinstance(rig["received_at"], int)


def test_rig_status_from_a_non_actuator_sid_is_dropped():
    with harness(sid="browser-sid") as h:
        server.handle_relay_rig_status({"valve": "OPEN"})
        assert h.payloads("rig_status") == []


def test_single_stage_emits_progress_and_physical_snapshot():
    with harness() as h:
        status = server.run_attack_stage("grover")
        events = [name for name, _ in h.emits if name in ("attack_progress", "attack_result")]
        progress = h.payloads("attack_progress")
        (result,) = h.payloads("attack_result")
    assert status == "DEFENDED"
    assert events == ["attack_progress", "attack_result", "attack_progress"], events
    assert progress[0] == {"id": "grover", "phase": "start", "index": 1, "total": 1,
                           "campaign": False}
    assert progress[1]["phase"] == "done"
    assert result["link"] == "key_exchange" and result["stopped_by"]
    assert result["physical"] == {"valve_before": "OPEN", "valve_after": "OPEN",
                                  "trip_before": "HEALTHY", "trip_after": "HEALTHY"}


def test_physical_snapshot_is_taken_when_the_stage_starts():
    """A stage that trips the plant must show OPEN -> CLOSED, not CLOSED -> CLOSED."""
    original = attacks.run_stage

    def tripping_stage(name, log, sleep, report, *rest):
        server.server_engine.trip_state = "TRIPPED"
        report(name, status="DEFENDED", confidence="Observed", evidence="", outcome="")

    attacks.run_stage = tripping_stage
    try:
        with harness() as h:
            server.run_attack_stage("silence")
            (result,) = h.payloads("attack_result")
    finally:
        attacks.run_stage = original
    assert result["physical"] == {"valve_before": "OPEN", "valve_after": "CLOSED",
                                  "trip_before": "HEALTHY", "trip_after": "TRIPPED"}


def test_a_second_campaign_is_refused_while_one_runs():
    started = []
    original = server.socketio.start_background_task
    server.socketio.start_background_task = lambda target, *a: started.append(target)
    try:
        with harness() as h:
            server.handle_trigger_campaign({})
            server.handle_trigger_campaign({})
        assert len(started) == 1, started
        assert any(t == "ALERT" and "already running" in m for t, m in h.logs), h.logs
    finally:
        server.socketio.start_background_task = original
        server._campaign_lock.release()


def test_campaign_done_counts_by_reported_status():
    statuses = iter(["DEFENDED", "SUCCEEDED", "INCONCLUSIVE", "NOT APPLICABLE", None])
    original = server.run_attack_stage
    server.run_attack_stage = lambda name, index, total, campaign: next(statuses, "DEFENDED")
    try:
        with harness() as h:
            server._campaign_lock.acquire()
            server.run_campaign()
            (done,) = h.payloads("campaign_done")
    finally:
        server.run_attack_stage = original
    assert server._campaign_lock.acquire(blocking=False), "campaign left the lock held"
    server._campaign_lock.release()
    total = len(attacks.ATTACK_ORDER)
    assert done["total"] == total
    assert (done["defended"], done["succeeded"], done["inconclusive"],
            done["not_applicable"], done["no_result"]) == (total - 4, 1, 1, 1, 1), done
    assert isinstance(done["duration_s"], float)


def test_server_url_comes_from_the_environment():
    def server_url(env):
        return subprocess.run(
            [sys.executable, "-c", "from app.config import SERVER_URL; print(SERVER_URL)"],
            env=env, capture_output=True, text=True, check=True).stdout.strip()

    base = {k: v for k, v in os.environ.items() if k != "SIS_SERVER_URL"}
    assert server_url(base) == "http://127.0.0.1:5001"
    assert server_url({**base, "SIS_SERVER_URL": "http://192.168.1.7:5001"}) == \
        "http://192.168.1.7:5001"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
