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
"""
import os
import time

_PORT = os.environ.get("RELAY_SERIAL_PORT")
_BAUD = int(os.environ.get("RELAY_SERIAL_BAUD", "9600"))
_conn = None  # None = not tried yet, False = tried and failed, else an open Serial


def _connect():
    global _conn
    if _conn is not None or not _PORT:
        return _conn
    try:
        import serial
        _conn = serial.Serial(_PORT, _BAUD, timeout=1)
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


def send_valve_state(state):
    """state is 'OPEN' or 'CLOSED'.

    The valve is normally-closed, energize-to-open (see the RFQ doc) -- so
    this byte is the ONLY thing holding it open. Losing this link, same as
    losing the heartbeat, fails the valve shut.
    """
    conn = _connect()
    if not conn:
        return
    try:
        conn.write(b"1\n" if state == "OPEN" else b"0\n")
    except Exception as exc:
        print(f"[RELAY] Write failed: {exc}")
