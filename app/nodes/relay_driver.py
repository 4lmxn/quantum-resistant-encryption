"""Serial bridge from the real actuator node to the Nano relay driver.

The Nano holds no key and makes no safety decision. It only mirrors an
already-authenticated valve_state over a local USB-serial link and toggles one
GPIO pin, which switches the 12V feed to the solenoid valve and pump (see the
"SIS-01 Hardware RFQ" doc, section on the physical trip rig). The trip
decision and the GCM decrypt it depends on stay in SimulatedActuatorNode,
unmodified.

Best-effort by design: no RELAY_SERIAL_PORT set, or the board unplugged, must
never stop the demo running purely in software -- every failure here is
swallowed and logged, same as _persist_finding in app/server.py.

RELAY_SERIAL_PORT=auto finds the board itself: see find_relay_board().
"""
import os
import time

_PORT = os.environ.get("RELAY_SERIAL_PORT")
_BAUD = int(os.environ.get("RELAY_SERIAL_BAUD", "9600"))
_conn = None  # None = not tried yet, False = tried and failed, else an open Serial
# Whether the most recent write reached the port. An open port the Nano has
# stopped accepting is not a link, so status() needs both.
_last_write_ok = False
# The port actually in use. Equals _PORT unless _PORT is "auto".
_detected_port = None
# Partial line read back from the board, carried between drains.
_rx = bytearray()

# nano_relay.ino prints this prefix on every line, including the one setup()
# emits at boot: "[NANO RELAY] valve CLOSED, pump OFF (boot -- ...)".
BANNER = b"[NANO RELAY]"
# Opening the port resets the Uno; the bootloader holds ~1.5 s before setup()
# runs and prints. 4 s per candidate leaves room for a slow clone bootloader.
PROBE_TIMEOUT_S = 4.0

# USB-serial bridge vendor IDs, best guess first. CH340 and CP210x are just as
# common on ESP32 dev boards, which is why a VID match only earns a probe: the
# banner decides.
_BRIDGES = {
    0x2341: (0, "Arduino"),
    0x2A03: (0, "Arduino.org"),
    0x0403: (1, "FTDI"),
    0x1A86: (2, "CH340"),
    0x10C4: (2, "CP210x"),
}
_SKIP_WORDS = ("bluetooth", "debug")


def rank_ports(ports):
    """[(device, why)] for ports worth probing, likeliest first.

    ports are serial.tools.list_ports ListPortInfo-likes (device, vid,
    description). Unknown-VID ports are kept only if the name looks like a USB
    serial bridge, and rank last.
    """
    ranked = []
    for p in ports:
        name = f"{p.device} {getattr(p, 'description', '') or ''}".lower()
        if any(word in name for word in _SKIP_WORDS):
            continue
        vid = getattr(p, "vid", None)
        if vid in _BRIDGES:
            rank, label = _BRIDGES[vid]
            ranked.append((rank, p.device, f"USB VID {vid:04X} ({label})"))
        elif any(tag in name for tag in ("usbmodem", "usbserial", "wchusbserial", "ttyacm", "ttyusb")):
            ranked.append((3, p.device, "USB-serial name, unknown VID"))
    ranked.sort()
    return [(device, why) for _, device, why in ranked]


def probe_port(device, open_serial, timeout=PROBE_TIMEOUT_S, clock=time.monotonic):
    """Open device, wait up to timeout for the boot banner.

    Returns (open_conn, banner_line) on success, (None, reason) otherwise. Never
    writes: a port is not ours to talk to until it has said who it is.
    """
    try:
        conn = open_serial(device)
    except Exception as exc:
        return None, f"could not open ({exc})"
    deadline = clock() + timeout
    buf = b""
    try:
        while clock() < deadline:
            chunk = conn.read(64)  # bounded by the port's own read timeout
            if not chunk:
                continue
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for line in lines:
                line = line.strip()
                if line.startswith(BANNER):
                    return conn, line.decode("ascii", "replace")
            buf = buf[-256:]  # an ESP32 at 115200 read at 9600 is just noise
    except Exception as exc:
        reason = f"read failed ({exc})"
    else:
        reason = f"no {BANNER.decode()} banner within {timeout:g}s"
    try:
        conn.close()
    except Exception:
        pass
    return None, reason


def _default_list_ports():
    from serial.tools import list_ports
    return list_ports.comports()


def _default_open(device):
    import serial
    # 0.2 s read timeout: probe_port loops on it, so each read stays short.
    return serial.Serial(device, _BAUD, timeout=0.2)


def find_relay_board(list_ports=None, open_serial=None, timeout=PROBE_TIMEOUT_S, log=print):
    """Returns (device, open_conn, why) for the relay board, or (None, None, why).

    Candidates are probed in rank order and the first that prints the
    nano_relay.ino banner wins; later ones are never opened. Opening a port
    pulses DTR, so an ESP32 probed on the way reboots and re-handshakes -- that
    is why Arduino-VID ports go first.
    """
    try:
        ports = (list_ports or _default_list_ports)()
    except ImportError:
        return None, None, "pyserial not installed (.venv/bin/pip install pyserial)"
    candidates = rank_ports(ports)
    if not candidates:
        return None, None, "no USB-serial ports present"
    tried = []
    for device, why in candidates:
        log(f"[RELAY] Probing {device} ({why})...")
        conn, result = probe_port(device, open_serial or _default_open, timeout)
        if conn:
            return device, conn, f"{why}, banner: {result}"
        tried.append(f"{device}: {result}")
    return None, None, "; ".join(tried)


def _connect():
    global _conn, _detected_port
    if _conn is not None or not _PORT:
        return _conn
    if _PORT.lower() == "auto":
        device, conn, why = find_relay_board()
        if conn:
            # The banner proves setup() has run, which is what the 2 s wait on
            # the explicit path stands in for -- so no extra sleep here.
            _conn, _detected_port = conn, device
            print(f"[RELAY] Found relay board on {device} -- {why}.")
        else:
            print(f"[RELAY] No relay board found -- running without physical relay. ({why})")
            _conn = False
        return _conn
    try:
        import serial
        _conn = serial.Serial(_PORT, _BAUD, timeout=1)
        _detected_port = _PORT
        # Opening the port pulses DTR, which resets an Uno/Nano into its
        # bootloader for ~1.5 s; bytes sent before it boots are lost, so the
        # startup sync would never arrive. First open happens in
        # run_actuator_node() before sio.connect, so blocking here is safe.
        time.sleep(2)
        print(f"[RELAY] Connected to Nano on {_PORT} @ {_BAUD}.")
    except Exception as exc:
        print(f"[RELAY] Could not open {_PORT}: {exc}. Running without physical relay.")
        _conn = False
    return _conn


def drain(conn, log=print):
    """Read whatever the board has already sent, without waiting for more.

    The Nano prints one line per relay transition -- its own confirmation that
    the relay moved. Left unread they back up the OS buffer; read here they
    become log lines. Only in_waiting bytes are read, so this cannot block the
    actuator's watchdog loop.
    """
    global _rx
    try:
        waiting = conn.in_waiting
        if not waiting:
            return
        _rx += conn.read(waiting)
    except Exception:
        return  # a dead port is reported by the write path, not here
    *lines, rest = bytes(_rx).split(b"\n")
    _rx = bytearray(rest[-256:])
    for line in lines:
        text = line.strip().decode("ascii", "replace")
        if text:
            log(f"[RELAY] board: {text}")


def send_valve_state(state):
    """state is 'OPEN' or 'CLOSED'.

    The valve is normally-closed, energize-to-open (see the RFQ doc) -- so
    this byte is the ONLY thing holding it open. Losing this link, same as
    losing the heartbeat, fails the valve shut.
    """
    global _last_write_ok
    conn = _connect()
    if not conn:
        _last_write_ok = False
        return
    try:
        conn.write(b"1\n" if state == "OPEN" else b"0\n")
        _last_write_ok = True
    except Exception as exc:
        _last_write_ok = False
        print(f"[RELAY] Write failed: {exc}")
    drain(conn)


def status():
    """The relay link as the dashboard shows it.

    connected means the port is open AND the last write landed. It is the
    keepalive the Nano's own watchdog depends on, so a port that opened once
    and then stopped taking bytes must read as disconnected.
    """
    auto = bool(_PORT) and _PORT.lower() == "auto"
    return {
        "configured": bool(_PORT),
        "connected": bool(_conn) and _last_write_ok,
        "port": _detected_port if auto else (_PORT or None),
    }
