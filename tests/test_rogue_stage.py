"""Rogue-node stage scores only what it actually tested. Run: python -m tests.test_rogue_stage

It used to impersonate a hard-coded sensor-01. On the physical rig that identity
is often not connected (the ESP32 is esp32-01), so the claim "succeeded" against
nobody and the dashboard showed a breach that never happened.
"""

from app import server
from app.attacks import attacks


def run_stage(held):
    server.server_engine.active_devices.clear()
    server.server_engine.active_devices.update(held)
    reports = []
    attacks.stage_rogue(lambda *a: None, lambda s: None,
                        lambda ident, **kw: reports.append(kw), server._attack_impersonate)
    return reports[0], dict(server.server_engine.active_devices)


def test_nothing_connected_is_inconclusive_not_a_breach():
    report, _ = run_stage({})
    assert report["status"] == "INCONCLUSIVE", report


def test_held_identity_is_defended_and_left_with_its_owner():
    report, after = run_stage({"actuator-01": "sid-valve"})
    assert report["status"] == "DEFENDED", report
    assert "actuator-01" in report["evidence"]
    assert after == {"actuator-01": "sid-valve"}, after


def test_prefers_a_transmitter_when_one_is_connected():
    report, after = run_stage({"actuator-01": "sid-valve", "sensor-01": "sid-sensor"})
    assert "sensor-01" in report["evidence"], report
    assert after["sensor-01"] == "sid-sensor"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
