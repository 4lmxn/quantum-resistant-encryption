/*
 * nano_relay.ino -- dumb GPIO relay driver for the SIS-01 physical trip rig.
 * Runs unchanged on an Arduino Nano or Uno (same ATmega328P, same pins).
 *
 * This board holds no key, runs no crypto, and makes no safety decision. It
 * is the last few centimetres of wire between the real actuator
 * (app/nodes/actuator.py, which does the GCM decrypt and the trip logic) and
 * the valve coil. It reads one byte at a time over USB-serial from
 * app/nodes/relay_driver.py and does exactly one thing with it: switch two
 * relay channels. Do not add crypto, WiFi, or a trip decision here -- that would
 * make this board a second, unauthenticated actuator, which is exactly the
 * "roles are validated, deliberately" mistake CLAUDE.md warns against on the
 * network side. This one has no network at all, on purpose.
 *
 * Protocol: one ASCII byte per line, 9600 baud.
 *   '1' -> valve OPEN, pump ON   (process running)
 *   '0' -> pump OFF, valve CLOSED (emergency shutdown)
 *   anything else (e.g. the trailing '\n') is ignored.
 *
 * The pump follows the valve. A shutdown that closes XV-101 but leaves P-101
 * running dead-heads the pump against a shut valve, so the trip stops both,
 * the way a real ESD trips the pump alongside the block valve.
 *
 * Link watchdog: actuator.py re-sends the current state every second. If
 * nothing arrives for LINK_TIMEOUT_MS -- actuator crashed, session dropped,
 * USB pulled while the board stays powered -- this board shuts the plant down
 * on its own. Holding the last state would freeze the valve open on a dead
 * link, the same fail-danger path the heartbeat watchdog replaced upstream.
 *
 * Wiring note -- confirm on the real board before trusting this default:
 * the valve must be spec'd NORMALLY CLOSED, energise-to-open (see
 * docs/MINI_PLANT.md). That makes losing power to this board, or to the 12V
 * supply, fail the valve shut with no code involved. If your relay module is
 * active-LOW (most cheap opto boards are: the relay clicks ON at boot when it
 * should be OFF), flip RELAY_ACTIVE_LOW below -- do not invert the serial
 * protocol to compensate, that would silently swap OPEN and CLOSED in the log
 * actuator.py prints.
 */

const int VALVE_PIN = 2;  // relay channel 1 -- XV-101 solenoid valve
const int PUMP_PIN = 3;   // relay channel 2 -- P-101 circulation pump
const bool RELAY_ACTIVE_LOW = false;
const unsigned long LINK_TIMEOUT_MS = 3000;  // 3 missed keepalives

bool running = false;
unsigned long lastByteAt = 0;

void writeRelay(int pin, bool energised) {
  digitalWrite(pin, (energised != RELAY_ACTIVE_LOW) ? HIGH : LOW);
}

void setPlant(bool run, const char *why) {
  if (run) {
    writeRelay(VALVE_PIN, true);   // open the path first...
    writeRelay(PUMP_PIN, true);    // ...then push flow into it
  } else {
    writeRelay(PUMP_PIN, false);   // stop flow first...
    writeRelay(VALVE_PIN, false);  // ...then block the line
  }
  if (run != running) {  // log transitions only; keepalives are silent
    Serial.print(run ? "[NANO RELAY] valve OPEN, pump ON" : "[NANO RELAY] valve CLOSED, pump OFF");
    Serial.print(" (");
    Serial.print(why);
    Serial.println(")");
  }
  running = run;
}

void setup() {
  pinMode(VALVE_PIN, OUTPUT);
  pinMode(PUMP_PIN, OUTPUT);
  Serial.begin(9600);
  running = true;  // force the boot transition to be logged
  setPlant(false, "boot -- opens only once actuator.py syncs us");
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    if (c == '1') {
      lastByteAt = millis();
      setPlant(true, "actuator");
    } else if (c == '0') {
      lastByteAt = millis();
      setPlant(false, "actuator");
    }
    // '\n', '\r', anything else: ignored, and does not count as a keepalive.
  }
  if (running && millis() - lastByteAt > LINK_TIMEOUT_MS) {
    setPlant(false, "link watchdog: no keepalive from actuator.py");
  }
}
