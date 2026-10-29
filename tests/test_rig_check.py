"""scripts/rig_check.py on synthetic files and fake system commands -- no
hardware, no server, no pyserial. Run: python -m tests.test_rig_check
"""

import json
import pathlib
import socket
import tempfile
from types import SimpleNamespace

from app import identity
from scripts import rig_check
from scripts.emit_firmware_keys import c_array

OK, FAIL, WARN = rig_check.OK, rig_check.FAIL, rig_check.WARN
SERVER_PK, SERVER_SK = identity.generate_identity()
ESP_PK, ESP_SK = identity.generate_identity()
ACT_PK, ACT_SK = identity.generate_identity()


def write_registry(root, devices=None):
    devices = devices or {"actuator-01": ACT_PK, "esp32-01": ESP_PK, "operator-01": ESP_PK}
    (root / "identities.json").write_text(json.dumps({
        "server": {"public": SERVER_PK.hex(), "secret": ""},
        "devices": {k: v.hex() for k, v in devices.items()},
    }))
    keys = root / "identities"
    keys.mkdir(exist_ok=True)
    (keys / "server.pub").write_bytes(SERVER_PK)
    (keys / "actuator-01.key").write_bytes(ACT_SK)


def write_keys_h(path, device_id="esp32-01", secret=ESP_SK, server_public=SERVER_PK):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#pragma once\n#define DEVICE_ID "{device_id}"\n'
                    + c_array("DEVICE_SECRET", secret) + c_array("SERVER_PUBLIC", server_public))


_TMP = []  # held so each directory lives until exit, then cleans itself up


def tmp_root():
    _TMP.append(tempfile.TemporaryDirectory(prefix="rig_check_"))
    return pathlib.Path(_TMP[-1].name)


def test_secret_matches_public_needs_no_signing():
    assert rig_check.secret_matches_public(ESP_SK, ESP_PK)
    assert not rig_check.secret_matches_public(ESP_SK, ACT_PK)
    assert not rig_check.secret_matches_public(b"", ESP_PK)


def test_parse_keys_h_round_trips_the_emitter():
    root = tmp_root()
    write_keys_h(root / "keys.h")
    parsed = rig_check.parse_keys_h((root / "keys.h").read_text())
    assert parsed == {"DEVICE_ID": "esp32-01", "DEVICE_SECRET": ESP_SK, "SERVER_PUBLIC": SERVER_PK}


def test_parse_keys_h_rejects_a_truncated_array():
    try:
        rig_check.parse_keys_h("static const uint8_t SERVER_PUBLIC[4] = {1,2,3};")
    except ValueError as exc:
        assert "declared 4" in str(exc)
    else:
        raise AssertionError("short array accepted")


def test_keys_h_consistent():
    root = tmp_root()
    write_registry(root)
    write_keys_h(root / "firmware/sketch_pqc/keys.h")
    status, msg, _ = rig_check.check_keys_h(root / "firmware/sketch_pqc/keys.h", root / "identities.json")
    assert status == OK, msg
    assert "esp32-01" in msg


def test_keys_h_stale_server_key_is_a_failure_with_fingerprints_only():
    root = tmp_root()
    write_registry(root)
    other_pk, _ = identity.generate_identity()
    write_keys_h(root / "firmware/sketch_pqc/keys.h", server_public=other_pk)
    status, msg, fix = rig_check.check_keys_h(root / "firmware/sketch_pqc/keys.h", root / "identities.json")
    assert status == FAIL and "SERVER_PUBLIC" in msg and "make firmware-keys" in fix, msg
    assert rig_check.fingerprint(other_pk) in msg and rig_check.fingerprint(SERVER_PK) in msg
    assert other_pk.hex()[:64] not in msg and len(msg) < 300, "key bytes must never be printed"


def test_keys_h_wrong_device_secret_and_unenrolled_id():
    root = tmp_root()
    write_registry(root)
    keys_h = root / "firmware/sketch_pqc/keys.h"
    write_keys_h(keys_h, secret=ACT_SK)
    assert rig_check.check_keys_h(keys_h, root / "identities.json")[0] == FAIL
    write_keys_h(keys_h, device_id="esp32-99")
    status, msg, _ = rig_check.check_keys_h(keys_h, root / "identities.json")
    assert status == FAIL and "not enrolled" in msg, msg


def test_keys_h_template_is_reported_not_crashed():
    root = tmp_root()
    write_registry(root)
    keys_h = root / "firmware/sketch_pqc/keys.h"
    keys_h.parent.mkdir(parents=True)
    keys_h.write_text(pathlib.Path("firmware/sketch_pqc/keys.h.example").read_text())
    status, msg, _ = rig_check.check_keys_h(keys_h, root / "identities.json")
    assert status == FAIL, msg


def test_identities_missing_partial_and_complete():
    root = tmp_root()
    assert rig_check.check_identities(root / "identities.json", root / "identities")[0] == FAIL
    write_registry(root, devices={"actuator-01": ACT_PK})
    status, msg, _ = rig_check.check_identities(root / "identities.json", root / "identities")
    assert status == FAIL and "esp32-01" in msg, msg
    write_registry(root)
    status, msg, _ = rig_check.check_identities(root / "identities.json", root / "identities")
    assert status == OK, msg
    (root / "identities/actuator-01.key").write_bytes(ESP_SK)
    assert rig_check.check_identities(root / "identities.json", root / "identities")[0] == FAIL


def test_lan_ip_against_the_sketch_server_constant():
    root = tmp_root()
    sketch = root / "sketch_pqc.ino"
    sketch.write_text('static const char *SERVER = "http://192.168.1.36:5001";\n')
    assert rig_check.check_lan_ip([("en0", "192.168.1.36")], sketch)[0] == OK
    status, msg, fix = rig_check.check_lan_ip([("en0", "10.0.0.5")], sketch)
    assert status == WARN and "server http://10.0.0.5:5001" in fix, fix
    assert rig_check.check_lan_ip([], sketch)[0] == FAIL
    sketch.write_text('static char SERVER[64] = "http://10.0.0.5:5001";\n')  # a mutable form
    assert rig_check.check_lan_ip([("en0", "10.0.0.5")], sketch)[0] == OK


def test_lan_ipv4_parses_ifconfig():
    out = ("lo0: flags=8049<UP>\n\tinet 127.0.0.1 netmask 0xff000000\n"
           "en0: flags=8863<UP>\n\tinet6 fe80::1%en0\n\tinet 192.168.1.36 netmask 0xffffff00\n")
    run = lambda *_a, **_k: SimpleNamespace(stdout=out)
    assert rig_check.lan_ipv4(run) == [("en0", "192.168.1.36")]


def _fake_firewall(answers):
    def run(cmd, **_kw):
        return SimpleNamespace(stdout=answers.get(cmd[1], ""))
    return run


def test_firewall_states():
    off = _fake_firewall({"--getglobalstate": "Firewall is disabled. (State = 0)"})
    assert rig_check.check_firewall(off, ["/py"])[0] == OK
    blocked = _fake_firewall({"--getglobalstate": "Firewall is enabled. (State = 1)",
                              "--getblockall": "Firewall has block all state set to disabled.",
                              "--getappblocked": "Incoming connection to /py is blocked."})
    status, _, fix = rig_check.check_firewall(blocked, ["/py"])
    assert status == FAIL and "--unblockapp /py" in fix
    block_all = _fake_firewall({"--getglobalstate": "Firewall is enabled. (State = 1)",
                                "--getblockall": "Firewall has block all state set to enabled."})
    assert rig_check.check_firewall(block_all, ["/py"])[0] == FAIL


def test_arduino_bad_cpu_ctags_points_at_rosetta():
    home = tmp_root()
    ctags = home / "Library/Arduino15/packages/builtin/tools/ctags/5.8-arduino11/ctags"
    ctags.parent.mkdir(parents=True)
    ctags.write_text("")

    def run(cmd, **_kw):
        if cmd[0] == str(ctags):
            raise OSError(86, "Bad CPU type in executable")
        return SimpleNamespace(stdout="esp32:esp32 3.3.11 3.3.11 esp32\n")
    status, msg, fix = rig_check.check_arduino(lambda _n: "/bin/arduino-cli", run, home)
    assert status == WARN and "Bad CPU type" in msg and "install-rosetta" in fix, (msg, fix)
    assert rig_check.check_arduino(lambda _n: None, run, home)[0] == WARN


def _closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_end_to_end_with_everything_absent():
    def nothing(*_a, **_k):
        raise FileNotFoundError("absent")

    def no_serial(_name):
        raise ImportError("No module named 'serial'")
    results, found = rig_check.collect(
        root=tmp_root(), find=lambda: (None, None, "pyserial not installed"),
        port=_closed_port(), run=nothing, which=lambda _n: None,
        importer=no_serial, home=tmp_root())
    by_name = {name: status for name, status, _m, _f in results}
    assert by_name["pyserial"] == FAIL and by_name["relay board"] == FAIL
    assert by_name["identities"] == FAIL and by_name["keys.h"] == FAIL
    assert by_name["LAN / SERVER"] == FAIL and by_name["server"] == WARN
    assert found[1] is None
    text = rig_check.render(results)
    assert text.count("fix:") == len([r for r in results if r[1] != OK and r[3]])


def test_click_pulses_then_releases():
    written = []
    conn = SimpleNamespace(write=written.append, in_waiting=0)
    rig_check.click(conn, ask=lambda _p: "y", sleep=lambda _s: None)
    assert written == [b"1\n", b"0\n"], written
    written.clear()
    rig_check.click(conn, ask=lambda _p: "", sleep=lambda _s: None)
    assert written == [], "no confirmation, no click"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
