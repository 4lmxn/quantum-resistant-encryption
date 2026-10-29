"""Preflight for the SIS-01 physical rig (docs/MINI_PLANT.md). Observes only.

    python -m scripts.rig_check            # checklist, exit 1 if a hard check fails
    python -m scripts.rig_check --click    # also pulse both relays for 1.5 s

Every check returns (status, message, fix): status is OK, FAIL (hard: the rig
will not work) or WARN (worth fixing, may not matter today). Key material is
never printed -- only short SHA-256 fingerprints.
"""

import argparse
import hashlib
import importlib
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from app.config import SERVER_HOST, SERVER_PORT
from app.nodes import relay_driver

ROOT = pathlib.Path(__file__).resolve().parent.parent
OK, FAIL, WARN = "✓", "✗", "!"
# What the rig itself needs: the actuator node, the ESP32, and an operator to reset.
RIG_IDENTITIES = ("actuator-01", "esp32-01", "operator-01")
ML_DSA_PUBLIC, ML_DSA_SECRET = 1952, 4032
FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"
CTAGS_GLOB = "Library/Arduino15/packages/builtin/tools/ctags/*/ctags"


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()[:12]


def secret_matches_public(secret, public):
    """FIPS 204 sk = rho || K || tr || ..., with pk = rho || t1 and tr = SHAKE256(pk, 64).

    So a secret belongs to a public key iff both checks hold -- no signing needed.
    """
    return (len(secret) == ML_DSA_SECRET and len(public) == ML_DSA_PUBLIC
            and secret[:32] == public[:32]
            and secret[64:128] == hashlib.shake_256(public).digest(64))


# --------------------------------------------------------------- checks -----

def check_pyserial(importer=importlib.import_module):
    try:
        importer("serial")
        return OK, "pyserial importable", None
    except ImportError:
        return FAIL, "pyserial not installed", ".venv/bin/pip install pyserial"


def check_relay_board(found):
    """found is relay_driver.find_relay_board()'s (device, conn, why)."""
    device, conn, why = found
    if conn:
        return OK, f"relay board on {device} ({why})", None
    if "pyserial" in why:
        return FAIL, "cannot scan for the relay board: " + why, ".venv/bin/pip install pyserial"
    return (FAIL, f"no relay board found ({why})",
            "plug the Uno in by USB and upload firmware/nano_relay/nano_relay.ino (board: Uno)")


def load_registry(path):
    """(server_public, {device_id: public}) or None when there is no usable file."""
    try:
        raw = json.loads(pathlib.Path(path).read_text())
        return (bytes.fromhex(raw["server"]["public"]),
                {k: bytes.fromhex(v) for k, v in raw["devices"].items()})
    except (OSError, ValueError, KeyError, TypeError):
        return None


def check_identities(registry_path, key_dir):
    registry = load_registry(registry_path)
    if registry is None:
        return FAIL, f"{registry_path.name} missing or unreadable", "make enroll"
    server_public, devices = registry
    missing = [i for i in RIG_IDENTITIES if i not in devices]
    if missing:
        return FAIL, "not enrolled: " + ", ".join(missing), "make enroll"
    pub_file = key_dir / "server.pub"
    if not pub_file.exists() or pub_file.read_bytes() != server_public:
        return (FAIL, "identities/server.pub missing or differs from identities.json",
                "make enroll --force (then make firmware-keys and reflash the ESP32)")
    actuator_key = key_dir / "actuator-01.key"
    if not actuator_key.exists() or not secret_matches_public(
            actuator_key.read_bytes(), devices["actuator-01"]):
        return (FAIL, "identities/actuator-01.key missing or not the enrolled actuator-01 key",
                "make enroll --force")
    return OK, (f"enrolled: {', '.join(sorted(devices))}; "
                f"server key {fingerprint(server_public)}"), None


_DEFINE_RE = re.compile(r'#define\s+DEVICE_ID\s+"([^"]+)"')
_ARRAY_RE = re.compile(r"uint8_t\s+(\w+)\s*\[\s*(\d+)\s*\]\s*=\s*\{([^}]*)\}", re.S)


def parse_keys_h(text):
    """{'DEVICE_ID': str|None, <ARRAY>: bytes} from a generated keys.h."""
    parsed = {"DEVICE_ID": None}
    m = _DEFINE_RE.search(text)
    if m:
        parsed["DEVICE_ID"] = m.group(1)
    for name, declared, body in _ARRAY_RE.findall(text):
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        values = [int(v, 0) for v in body.replace("\n", "").split(",") if v.strip()]
        if len(values) != int(declared) or any(not 0 <= v <= 255 for v in values):
            raise ValueError(f"{name}: {len(values)} bytes, declared {declared}")
        parsed[name] = bytes(values)
    return parsed


def check_keys_h(keys_h, registry_path):
    fix = "make firmware-keys, then reflash firmware/sketch_pqc"
    if not keys_h.exists():
        return FAIL, f"{keys_h.relative_to(keys_h.parents[2])} missing", fix
    try:
        parsed = parse_keys_h(keys_h.read_text())
    except ValueError as exc:
        return FAIL, f"keys.h malformed ({exc})", fix
    if "SERVER_PUBLIC" not in parsed or "DEVICE_SECRET" not in parsed or not parsed["DEVICE_ID"]:
        return FAIL, "keys.h lacks DEVICE_ID, DEVICE_SECRET or SERVER_PUBLIC (still the template?)", fix
    registry = load_registry(registry_path)
    if registry is None:
        return FAIL, "cannot compare keys.h: identities.json missing", "make enroll && " + fix
    server_public, devices = registry
    flashed, enrolled = parsed["SERVER_PUBLIC"], server_public
    if flashed != enrolled:
        # The classic cause of "[PQC] ABORT: server signature invalid".
        return (FAIL, f"keys.h SERVER_PUBLIC {fingerprint(flashed)} != enrolled server key "
                      f"{fingerprint(enrolled)} (stale keys.h after re-enrolling)", fix)
    device_id = parsed["DEVICE_ID"]
    if device_id not in devices:
        return FAIL, f"keys.h DEVICE_ID {device_id!r} is not enrolled", "make enroll && " + fix
    if not secret_matches_public(parsed["DEVICE_SECRET"], devices[device_id]):
        return (FAIL, f"keys.h DEVICE_SECRET is not {device_id}'s enrolled key "
                      f"(enrolled {fingerprint(devices[device_id])})", fix)
    return OK, (f"keys.h consistent: {device_id}, server key {fingerprint(flashed)} "
                f"(reflash if the board predates this file)"), None


def lan_ipv4(run=subprocess.run):
    """[(iface, ip)] for non-loopback IPv4 addresses, from ifconfig."""
    try:
        out = run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found, iface = [], None
    for line in out.splitlines():
        if line and not line[0].isspace():
            iface = line.split(":", 1)[0]
        m = re.match(r"\s+inet (\d+\.\d+\.\d+\.\d+)", line)
        if m and not m.group(1).startswith("127.") and iface:
            found.append((iface, m.group(1)))
    return found


_SERVER_RE = re.compile(r'\bSERVER\b[^=;\n]*=\s*"([^"]+)"')


def check_lan_ip(ips, sketch):
    if not ips:
        return FAIL, "no LAN IPv4 address -- the ESP32 cannot reach this Mac", "join the same WiFi as the ESP32"
    have = ", ".join(f"{iface} {ip}" for iface, ip in ips)
    m = _SERVER_RE.search(sketch.read_text()) if sketch.exists() else None
    if not m:
        return WARN, f"Mac: {have}; no SERVER constant found in {sketch.name}", None
    url = urllib.parse.urlsplit(m.group(1))
    console_fix = (f"set SERVER in {sketch.name} to http://{ips[0][1]}:{SERVER_PORT} and reflash, "
                   f"or on the ESP32 serial console: server http://{ips[0][1]}:{SERVER_PORT}")
    if url.hostname not in {ip for _, ip in ips}:
        return WARN, f"Mac: {have}; sketch SERVER is {m.group(1)} (not this Mac)", console_fix
    if url.port != SERVER_PORT:
        return WARN, f"sketch SERVER {m.group(1)} uses port {url.port}, server listens on {SERVER_PORT}", console_fix
    return OK, f"Mac: {have}; sketch SERVER {m.group(1)} matches", None


def _connects(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_server(port, ips):
    if not _connects("127.0.0.1", port):
        return WARN, f"nothing listening on :{port}", "make server   (in its own terminal)"
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as resp:
            answered = f"GET / -> {resp.status}"
    except Exception as exc:
        return FAIL, f":{port} is open but GET / failed ({exc})", "restart make server; is something else on the port?"
    if SERVER_HOST != "0.0.0.0":
        return FAIL, f"{answered}, but config binds {SERVER_HOST}", "set SERVER_HOST = \"0.0.0.0\" in app/config.py"
    if ips and not _connects(ips[0][1], port):
        return FAIL, f"{answered} on loopback, but not on {ips[0][1]}", "restart make server (it binds 0.0.0.0)"
    where = f"loopback and {ips[0][1]}" if ips else "loopback"
    return OK, f"{answered} on {where}", None


def _python_binaries():
    """The binaries the firewall may see: the venv's real interpreter, plus the
    framework's Python.app, which is what actually runs on a macOS framework build."""
    paths = [pathlib.Path(sys.executable).resolve()]
    app = pathlib.Path(sys.base_prefix) / "Resources/Python.app/Contents/MacOS/Python"
    if app.exists():
        paths.append(app.resolve())
    return paths


def check_firewall(run=subprocess.run, binaries=None):
    def ask(*args):
        return run([FIREWALL, *args], capture_output=True, text=True, timeout=5).stdout

    try:
        state = ask("--getglobalstate")
    except (OSError, subprocess.SubprocessError):
        return WARN, "could not query the macOS firewall (not macOS?)", None
    if "disabled" in state.lower() or "state = 0" in state:
        return OK, "macOS firewall off", None
    if "enabled" in ask("--getblockall").lower():
        return (FAIL, "firewall blocks ALL incoming connections -- the ESP32 cannot reach the server",
                "System Settings > Network > Firewall > Options: turn off 'Block all incoming connections'")
    blocked = [str(p) for p in (binaries or _python_binaries()) if "blocked" in ask("--getappblocked", str(p))]
    if blocked:
        return (FAIL, f"firewall blocks {blocked[0]}",
                f"sudo {FIREWALL} --unblockapp {blocked[0]}")
    return (OK, "firewall on, Python not blocked (click Allow if macOS asks on first make server)", None)


def check_arduino(which=shutil.which, run=subprocess.run, home=pathlib.Path.home()):
    cli = which("arduino-cli")
    if not cli:
        return WARN, "arduino-cli not found (needed only to flash)", "make firmware-setup"
    try:
        cores = run([cli, "core", "list"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return WARN, f"arduino-cli core list failed ({exc})", "make firmware-setup"
    if "esp32:esp32" not in cores:
        return WARN, "arduino-cli present, esp32 core not installed", "make firmware-setup"
    ctags = sorted(home.glob(CTAGS_GLOB))
    if not ctags:
        return OK, "arduino-cli + esp32 core (bundled ctags not installed yet)", None
    try:
        run([str(ctags[-1]), "--version"], capture_output=True, timeout=10)
    except OSError as exc:
        # errno 86, EBADARCH: an x86_64 binary on Apple Silicon without Rosetta.
        return (WARN, f"bundled ctags will not run ({exc.strerror}) -- every compile fails",
                "softwareupdate --install-rosetta --agree-to-license")
    except subprocess.SubprocessError as exc:
        return WARN, f"bundled ctags hung ({exc})", None
    return OK, "arduino-cli + esp32 core, ctags runs", None


# ----------------------------------------------------------------- main -----

def collect(root=ROOT, find=None, port=SERVER_PORT, run=subprocess.run, which=shutil.which,
            importer=importlib.import_module, home=pathlib.Path.home(), quiet=True):
    """[(name, status, message, fix)], plus the relay result for --click."""
    found = (find or (lambda: relay_driver.find_relay_board(
        log=(lambda _msg: None) if quiet else print)))()
    ips = lan_ipv4(run)
    sketch = root / "firmware/sketch_pqc/sketch_pqc.ino"
    results = [
        ("pyserial", *check_pyserial(importer)),
        ("relay board", *check_relay_board(found)),
        ("identities", *check_identities(root / "identities.json", root / "identities")),
        ("keys.h", *check_keys_h(root / "firmware/sketch_pqc/keys.h", root / "identities.json")),
        ("LAN / SERVER", *check_lan_ip(ips, sketch)),
        ("server", *check_server(port, ips)),
        ("firewall", *check_firewall(run)),
        ("arduino", *check_arduino(which, run, home)),
    ]
    return results, found


def render(results):
    lines = []
    for name, status, message, fix in results:
        lines.append(f"  {status} {name:<13} {message}")
        if fix and status != OK:
            lines.append(f"      fix: {fix}")
    return "\n".join(lines)


def click(conn, ask=input, sleep=time.sleep):
    """Energise both relays for 1.5 s, then release, echoing the board's replies."""
    if ask("Energise XV-101 + P-101 for 1.5 s? Water will flow if 12 V is on. [y/N] ").strip().lower() != "y":
        print("  skipped")
        return
    conn.write(b"1\n")
    sleep(1.5)  # under the board's 3 s link watchdog, so it holds without a keepalive
    relay_driver.drain(conn, log=lambda m: print("  " + m))
    conn.write(b"0\n")
    sleep(0.3)
    relay_driver.drain(conn, log=lambda m: print("  " + m))


def main(argv=None):
    parser = argparse.ArgumentParser(description="SIS-01 rig preflight")
    parser.add_argument("--click", action="store_true", help="pulse both relays for 1.5 s")
    args = parser.parse_args(argv)
    print("SIS-01 rig check\n")
    results, (_device, conn, _why) = collect(quiet=False)
    print(render(results))
    if args.click:
        print()
        if conn:
            click(conn)
        else:
            print("  --click: no relay board to click")
    if conn:
        conn.close()
    failed = [name for name, status, *_ in results if status == FAIL]
    print(f"\n{len(failed)} hard failure(s)" + (f": {', '.join(failed)}" if failed else " -- rig is go"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
