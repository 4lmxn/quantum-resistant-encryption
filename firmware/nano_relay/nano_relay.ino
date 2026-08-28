/*
 * nano_relay.ino -- dumb GPIO relay driver for the SIS-01 physical trip rig.
 *
 * This board holds no key, runs no crypto, and makes no safety decision. It
 * is the last few centimetres of wire between the real actuator
 * (app/nodes/actuator.py, which does the GCM decrypt and the trip logic) and
 * the valve coil. It reads one byte at a time over USB-serial from
 * app/nodes/relay_driver.py and does exactly one thing with it: toggle a
 * GPIO pin. Do not add crypto, WiFi, or a trip decision here -- that would
 * make this board a second, unauthenticated actuator, which is exactly the
 * "roles are validated, deliberately" mistake CLAUDE.md warns against on the
 * network side. This one has no network at all, on purpose.
 *
 * Protocol: one ASCII byte per line, 9600 baud.
 *   '1' -> VALVE_PIN HIGH  (relay energised, valve OPEN -- see wiring note)
 *   '0' -> VALVE_PIN LOW   (relay de-energised, valve CLOSED)
 *   anything else (e.g. the trailing '\n') is ignored.
 *
 * Wiring note -- confirm on the real board before trusting this default:
 * the valve must be spec'd NORMALLY CLOSED, energise-to-open (see the
 * "SIS-01 Hardware RFQ" doc). That makes losing this link, same as losing
 * the sensor's heartbeat, fail the valve shut with no code involved. If your
 * relay module is active-LOW (most cheap opto boards are), flip
 * RELAY_ACTIVE_LOW below -- do not invert the serial protocol to compensate,
 * that would silently swap OPEN and CLOSED in the log actuator.py prints.
 */

const int VALVE_PIN = 2;   // relay channel 1 -- XV-101 stand-in
const int PUMP_PIN = 3;    // relay channel 2 -- process flow, runs continuously
const bool RELAY_ACTIVE_LOW = false;

void writeRelay(int pin, bool energised) {
  digitalWrite(pin, (energised != RELAY_ACTIVE_LOW) ? HIGH : LOW);
}

void setup() {
  pinMode(VALVE_PIN, OUTPUT);
  pinMode(PUMP_PIN, OUTPUT);
  writeRelay(VALVE_PIN, false);  // boot CLOSED -- open only once actuator.py syncs us
  writeRelay(PUMP_PIN, true);    // pump runs continuously; the valve is what gates flow
  Serial.begin(9600);
  Serial.println("[NANO RELAY] ready, valve CLOSED, pump ON");
}

void loop() {
  if (!Serial.available()) return;
  char c = Serial.read();
  if (c == '1') {
    writeRelay(VALVE_PIN, true);
    Serial.println("[NANO RELAY] valve OPEN");
  } else if (c == '0') {
    writeRelay(VALVE_PIN, false);
    Serial.println("[NANO RELAY] valve CLOSED");
  }
  // '\n', '\r', anything else: ignored.
}
