"""RELAY_SERIAL_PORT=auto, with fake ports and fake serial -- no pyserial, no
hardware. Run: python -m tests.test_relay_autodetect

The point of the banner check: CH340 and CP210x bridges sit on ESP32 dev boards
as often as on Uno clones, so a VID match alone would happily start writing
valve commands into the safety transmitter's console.
"""

import contextlib
import io
from types import SimpleNamespace

from app.nodes import relay_driver

BOOT = b"[NANO RELAY] valve CLOSED, pump OFF (boot -- opens only once actuator.py syncs us)\r\n"


def port(device, vid=None, description=""):
    return SimpleNamespace(device=device, vid=vid, description=description)


class FakeSerial:
    """Hands out scripted chunks from read(); b'' once they run out, like a timeout."""

    def __init__(self, chunks=(), pending=b""):
        self.chunks = list(chunks)
        self.pending = bytearray(pending)
        self.written = []
        self.closed = False

    def read(self, n=1):
        if self.pending:
            if n > len(self.pending):
                raise AssertionError("read past in_waiting -- this would block")
            out, self.pending = bytes(self.pending[:n]), self.pending[n:]
            return out
        return self.chunks.pop(0) if self.chunks else b""

    @property
    def in_waiting(self):
        return len(self.pending)

    def write(self, data):
        self.written.append(data)

    def close(self):
        self.closed = True


def test_rank_puts_arduino_first_and_skips_bluetooth_and_debug():
    rank = relay_driver.rank_ports([
        port("/dev/cu.Bluetooth-Incoming-Port"),
        port("/dev/cu.debug-console"),
        port("/dev/cu.usbserial-110", vid=0x1A86),
        port("/dev/cu.usbmodem1101", vid=0x2341),
        port("/dev/cu.SLAB_USBtoUART", vid=0x10C4),
        port("/dev/cu.usbserial-A50285BI", vid=0x0403),
        port("/dev/cu.soundcoreP40i"),
    ])
    devices = [d for d, _ in rank]
    assert devices[0] == "/dev/cu.usbmodem1101", rank
    assert devices[1] == "/dev/cu.usbserial-A50285BI", rank
    assert set(devices[2:]) == {"/dev/cu.usbserial-110", "/dev/cu.SLAB_USBtoUART"}, rank
    assert "CH340" in dict(rank)["/dev/cu.usbserial-110"]


def test_banner_split_across_reads_is_accepted():
    fake = FakeSerial([b"", b"\x00garbage\n[NANO RE", b"LAY] valve CLOSED, pump OFF (boot)\r\n"])
    conn, line = relay_driver.probe_port("/dev/x", lambda _d: fake, timeout=1)
    assert conn is fake and line.startswith("[NANO RELAY]"), line
    assert not fake.closed and fake.written == [], "probe must never write"


def test_esp32_on_ch340_without_banner_is_rejected_and_closed():
    esp32 = FakeSerial([b"\xf0\x8f\x11ets Jun  8 2016 rst:0x1\n", b"[BOOT] esp32-01\n"])
    conn, reason = relay_driver.probe_port("/dev/cu.usbserial-110", lambda _d: esp32, timeout=0.05)
    assert conn is None and "banner" in reason, reason
    assert esp32.closed and esp32.written == []


def test_find_picks_the_banner_board_not_the_first_ch340():
    esp32, uno = FakeSerial([b"rst:0x1 (POWERON_RESET)\n"]), FakeSerial([BOOT])
    opened = []

    def open_serial(device):
        opened.append(device)
        return {"/dev/cu.usbserial-110": esp32, "/dev/cu.wchusbserial-220": uno}[device]

    ports = [port("/dev/cu.usbserial-110", vid=0x10C4), port("/dev/cu.wchusbserial-220", vid=0x1A86)]
    device, conn, why = relay_driver.find_relay_board(
        lambda: ports, open_serial, timeout=0.05, log=lambda _m: None)
    assert device == "/dev/cu.wchusbserial-220" and conn is uno, (device, why)
    assert esp32.closed and "[NANO RELAY]" in why


def test_find_stops_at_the_first_confirmed_board():
    uno = FakeSerial([BOOT])
    opened = []

    def open_serial(device):
        opened.append(device)
        return uno if device.endswith("1101") else FakeSerial()

    ports = [port("/dev/cu.usbmodem1101", vid=0x2341), port("/dev/cu.usbserial-110", vid=0x1A86)]
    relay_driver.find_relay_board(lambda: ports, open_serial, timeout=0.05, log=lambda _m: None)
    assert opened == ["/dev/cu.usbmodem1101"], "an ESP32 further down must not be reset for nothing"


def test_find_reports_no_ports_and_missing_pyserial():
    assert relay_driver.find_relay_board(lambda: [], log=lambda _m: None)[:2] == (None, None)

    def no_pyserial():
        raise ImportError("No module named 'serial'")
    device, conn, why = relay_driver.find_relay_board(no_pyserial, log=lambda _m: None)
    assert (device, conn) == (None, None) and "pyserial" in why


def test_open_failure_is_a_rejection_not_a_crash():
    def busy(_device):
        raise OSError("Resource busy")
    conn, reason = relay_driver.probe_port("/dev/x", busy, timeout=0.05)
    assert conn is None and "Resource busy" in reason


def test_drain_reads_only_what_is_waiting_and_logs_whole_lines():
    relay_driver._rx = bytearray()
    seen = []
    fake = FakeSerial(pending=b"[NANO RELAY] valve OPEN, pump ON (actuator)\r\n[NANO RE")
    relay_driver.drain(fake, log=seen.append)  # FakeSerial.read raises if asked for more
    assert seen == ["[RELAY] board: [NANO RELAY] valve OPEN, pump ON (actuator)"], seen
    fake.pending += b"LAY] valve CLOSED, pump OFF (actuator)\n"
    relay_driver.drain(fake, log=seen.append)
    assert seen[-1] == "[RELAY] board: [NANO RELAY] valve CLOSED, pump OFF (actuator)", seen
    relay_driver._rx = bytearray()


def test_drain_with_nothing_waiting_does_not_read():
    class NoRead(FakeSerial):
        def read(self, n=1):
            raise AssertionError("read() with nothing waiting would block on a real port")
    relay_driver.drain(NoRead(), log=lambda _m: None)


def test_drain_tolerates_a_port_without_in_waiting():
    relay_driver.drain(object(), log=lambda _m: None)  # must not raise


def _with_auto(found, check):
    saved = (relay_driver._PORT, relay_driver._conn, relay_driver._last_write_ok,
             relay_driver._detected_port, relay_driver.find_relay_board)
    try:
        relay_driver._PORT, relay_driver._conn, relay_driver._detected_port = "auto", None, None
        relay_driver.find_relay_board = lambda: found
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            relay_driver.send_valve_state("OPEN")
        check(out.getvalue())
    finally:
        (relay_driver._PORT, relay_driver._conn, relay_driver._last_write_ok,
         relay_driver._detected_port, relay_driver.find_relay_board) = saved


def test_auto_mode_uses_the_detected_port_in_status():
    uno = FakeSerial(pending=b"[NANO RELAY] valve OPEN, pump ON (actuator)\n")

    def check(printed):
        assert uno.written == [b"1\n"], uno.written
        assert relay_driver.status() == {
            "configured": True, "connected": True, "port": "/dev/cu.usbmodem1101"}
        assert "Found relay board on /dev/cu.usbmodem1101" in printed, printed
        assert "board: [NANO RELAY] valve OPEN" in printed, printed
    _with_auto(("/dev/cu.usbmodem1101", uno, "USB VID 2341 (Arduino)"), check)


def test_auto_mode_without_a_board_runs_in_software():
    def check(printed):
        assert relay_driver.status() == {"configured": True, "connected": False, "port": None}
        assert "No relay board found -- running without physical relay" in printed, printed
    _with_auto((None, None, "no USB-serial ports present"), check)


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
