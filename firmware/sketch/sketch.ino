/*
 * Quantum-Resistant IoT — SIS-01 basic process control transmitter (ESP32).
 *
 * This board is TT-101, the BPCS process temperature transmitter on the plant.
 * It reads a K-type thermocouple through a MAX6675, reads the maintenance
 * bypass request switch, seals the whole reading with AES-256-GCM on the
 * ESP32's hardware crypto, and POSTs it to the Flask server. The server
 * answers with the current setpoint, trip state and valve position, which this
 * board mirrors on two local lamps.
 *
 * It is deliberately NOT on the safety path. The ML-KEM-768 handshake and the
 * ML-DSA-65 identity proof run on the Python nodes; this board holds only the
 * provisioned device key. A static provisioning key is not an authenticated
 * identity, so the server marks this telemetry
 * safety_relevant=false: it is displayed and logged, and it can never trip the
 * plant. The safety loop trips on the sensor node's reading, and XV-101 is
 * driven by the actuator node — never from here.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/gcm.h"

/*
 * Wokwi has no MAX6675 part -- the MAX6675 projects you find there ship a
 * community custom chip, not a stock one. So the checked-in diagram.json keeps
 * a DHT22 as a visual stand-in for the transmitter, and this switch says which
 * one the firmware actually reads.
 *
 *   0 = MAX6675 K-type thermocouple on SPI. Real hardware, the real design.
 *   1 = DHT22 on GPIO 15. Wokwi only, so the simulated demo still moves.
 *
 * Either way the sealed payload is byte-for-byte the same shape.
 */
#define SIM_DHT22_STANDIN 0

#if SIM_DHT22_STANDIN
#include "DHTesp.h"
static const int DHT_PIN = 15;
static DHTesp dht;
#else
#include "MAX6675.h"
#endif

/*
 * TLS switch. It does NOT save flash, despite what the comment here used to
 * claim: HTTPClient.h pulls in WiFiClientSecure and the whole mbedtls TLS stack
 * whether this is 0 or 1. Measured on this sketch, ESP32 Arduino core 3.3.11:
 *
 *     USE_TLS 0  ->  1031560 B
 *     USE_TLS 1  ->  1032116 B
 *
 * 556 bytes apart, i.e. nothing. So choose on reachability, never on size:
 * leave it at 0 for plain http, set it to 1 for the https-only free-Wokwi
 * tunnel.
 *
 * If image size ever actually matters, the only real win is dropping
 * HTTPClient entirely and writing the POST over a raw WiFiClient. That was
 * measured at 890316 B on the previous revision of this sketch -- about 138 KB
 * back, and the cost is hand-rolling the request and response parsing.
 *
 * The telemetry is sealed end to end either way, so TLS here is defence in
 * depth, never the thing protecting the reading.
 */
#define USE_TLS 0

#if USE_TLS
#include <WiFiClientSecure.h>
#endif

// Wokwi's built-in network. Open password, channel 6 — connects in ~1s.
static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASS = "";

// Must end in /telemetry. See firmware/README.md for which URL to use.
#if USE_TLS
static const char *TELEMETRY_URL = "https://REPLACE-ME.trycloudflare.com/telemetry";
#else
static const char *TELEMETRY_URL = "http://host.wokwi.internal:5001/telemetry";
#endif

// Provisioning key. Run `make enroll` on the server: it generates a random
// 32-byte key, prints it as hex, and stores it under identities/ (gitignored).
// Paste those 32 bytes here at commissioning. This placeholder is all zeros on
// purpose -- it will NOT match the server until you provision it, which is the
// point: no working key ships in the firmware.
static const uint8_t DEVICE_PSK[32] = {
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};

// Which transmitter this board is. Appears on the dashboard and audit trail.
static const char *UNIT_ID = "TT-101";

// MAX6675 on hardware SPI pins. Read-only device: no MOSI, so three wires.
static const int TC_SCK_PIN = 18;
static const int TC_SO_PIN = 19;
static const int TC_CS_PIN = 5;

static const int BYPASS_REQ_PIN = 4;  // slide switch: LOW = bypass requested
static const int RUNNING_PIN = 26;    // local "process running" lamp
static const int TRIPPED_LED_PIN = 27; // local "plant tripped" lamp

/*
 * A thermocouple measures temperature and nothing else. The server's telemetry
 * payload carries a humidity field because the Python sensor node has one, and
 * this leg keeps the wire format identical rather than forking the schema for
 * one board. So this is a fixed nominal value, honestly a placeholder: nothing
 * on the plant measures it and nothing downstream acts on it.
 */
static const float NOMINAL_HUMIDITY = 45.0f;

static const size_t NONCE_LEN = 12;  // 96-bit GCM nonce
static const size_t TAG_LEN = 16;

#if !SIM_DHT22_STANDIN
// RobTillaart's constructor is (select, miso, clock) -- NOT Adafruit's
// (clock, select, miso). Swapping libraries without reordering these three
// silently reads a dead bus and reports a constant temperature, which on a
// safety transmitter is the worst possible failure: plausible and wrong.
static MAX6675 thermocouple(TC_CS_PIN, TC_SO_PIN, TC_SCK_PIN);
#endif

// ---------------------------------------------------------------- crypto ---

static void toHex(const uint8_t *bytes, size_t len, char *out) {
  static const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = digits[bytes[i] >> 4];
    out[i * 2 + 1] = digits[bytes[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

/*
 * Seals plaintext with AES-256-GCM. Writes nonce and ciphertext||tag as hex,
 * matching exactly what Python's AESGCM.encrypt() produces, since cryptography
 * appends the tag to the ciphertext.
 */
static bool sealPayload(const char *plaintext, char *nonceHex, char *cipherHex) {
  size_t len = strlen(plaintext);
  uint8_t nonce[NONCE_LEN];
  uint8_t ciphertext[192];
  uint8_t tag[TAG_LEN];

  if (len + TAG_LEN > sizeof(ciphertext)) return false;

  // esp_random() is a true hardware RNG once WiFi is up. A repeated nonce
  // under the same key would be catastrophic for GCM, so never counter this.
  for (size_t i = 0; i < NONCE_LEN; i += 4) {
    uint32_t r = esp_random();
    memcpy(nonce + i, &r, 4);
  }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, DEVICE_PSK, 256);
  if (rc == 0) {
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, NONCE_LEN,
                                   NULL, 0, (const uint8_t *)plaintext, ciphertext,
                                   TAG_LEN, tag);
  }
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    Serial.printf("[CRYPTO] mbedtls failure: -0x%04x\n", -rc);
    return false;
  }

  memcpy(ciphertext + len, tag, TAG_LEN);  // Python expects ciphertext||tag
  toHex(nonce, NONCE_LEN, nonceHex);
  toHex(ciphertext, len + TAG_LEN, cipherHex);
  return true;
}

// ----------------------------------------------------------- process I/O ---

/* Returns the process temperature in C, or NAN if the sensor could not be read.
   The MAX6675 reports an open thermocouple in its status bit; read() surfaces
   that as STATUS_NOREAD and we turn it into NAN ourselves. A burnt-out probe
   must never be published as 0 C -- on a transmitter feeding a trip decision,
   a confident wrong number is more dangerous than an obvious absence. */
static float readProcessTemperature() {
#if SIM_DHT22_STANDIN
  TempAndHumidity reading = dht.getTempAndHumidity();
  if (dht.getStatus() != DHTesp::ERROR_NONE) {
    Serial.printf("[SENSOR] DHT22 stand-in read failed: %s (check GPIO %d)\n",
                  dht.getStatusString(), DHT_PIN);
    return NAN;
  }
  return reading.temperature;
#else
  uint8_t status = thermocouple.read();
  if (status != STATUS_OK) {
    Serial.printf("[SENSOR] MAX6675 status 0x%02X (%s)\n", status,
                  status == STATUS_NOREAD ? "open thermocouple / no probe"
                                          : "SPI communication fault");
    return NAN;
  }
  return thermocouple.getCelsius();
#endif
}

/*
 * Both outputs are LOCAL INDICATION ONLY. This board does not drive XV-101 and
 * has no path to it: the shutdown valve is driven by the actuator node, which
 * only obeys commands sealed under its own ML-KEM session key. These two lamps
 * mirror what the server reported, so a fitter standing at the transmitter sees
 * the same state as the control room without this board being able to cause it.
 */
static void showPlantState(bool tripped) {
  digitalWrite(TRIPPED_LED_PIN, tripped ? HIGH : LOW);
  digitalWrite(RUNNING_PIN, tripped ? LOW : HIGH);
}

void setup() {
  Serial.begin(115200);
  // The serial monitor attaches after boot, so output in the first moments is
  // routinely lost. Without this pause a working sketch can look completely dead.
  delay(2000);
  Serial.println();
  Serial.println("========================================");
  Serial.printf("[BOOT] SIS-01 BPCS transmitter %s\n", UNIT_ID);
  Serial.printf("[BOOT] Sensor: %s\n",
                SIM_DHT22_STANDIN ? "DHT22 stand-in (Wokwi)" : "MAX6675 K-type thermocouple");
  Serial.println("[BOOT] Not on the safety path: PSK-sealed, reported only.");
  Serial.printf("[BOOT] Target: %s (TLS %s)\n", TELEMETRY_URL, USE_TLS ? "on" : "off");
  Serial.println("========================================");

  pinMode(RUNNING_PIN, OUTPUT);
  pinMode(TRIPPED_LED_PIN, OUTPUT);
  showPlantState(false);
  pinMode(BYPASS_REQ_PIN, INPUT_PULLUP);
#if SIM_DHT22_STANDIN
  dht.setup(DHT_PIN, DHTesp::DHT22);
#else
  thermocouple.begin();
  delay(500);  // MAX6675 needs ~200ms after power-up before its first conversion
#endif

  if (strstr(TELEMETRY_URL, "/telemetry") == NULL) {
    Serial.println("[BOOT] WARNING: TELEMETRY_URL has no /telemetry path.");
    Serial.println("[BOOT]          Every POST will fail with HTTP 405.");
  }

  Serial.print("[NODE] Connecting to WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
  while (WiFi.status() != WL_CONNECTED) {
    delay(200);
    Serial.print(".");
  }
  Serial.printf("\n[NODE] Online as %s\n", WiFi.localIP().toString().c_str());
}

// ------------------------------------------------------------- responses ---

/* Reads the numeric value of "key" from a flat response body. Returns fallback
   if the key is absent, so a truncated reply changes nothing. Pass the key with
   its colon, e.g. "\"setpoint\":". */
static float valueOf(const String &body, const char *key, float fallback) {
  int idx = body.indexOf(key);
  if (idx < 0) return fallback;
  return body.substring(idx + strlen(key)).toFloat();
}

/* Reads the quoted string value of "key" into out. The server now answers with
   trip_state "HEALTHY"/"TRIPPED" and valve "OPEN"/"CLOSED", so toFloat() would
   silently return 0 for every one of them and pin the lamps to healthy.
   Whitespace-tolerant, because Flask pretty-prints its JSON in debug mode and
   packs it in production. Returns false if the key or its value is missing, so
   a truncated reply leaves the lamps where they were. */
static bool stringOf(const String &body, const char *key, char *out, size_t outLen) {
  int idx = body.indexOf(key);
  if (idx < 0) return false;
  int start = body.indexOf('"', idx + strlen(key));  // opening quote of the value
  if (start < 0) return false;
  int end = body.indexOf('"', start + 1);
  if (end < 0) return false;
  size_t len = (size_t)(end - start - 1);
  if (len > outLen - 1) len = outLen - 1;
  memcpy(out, body.c_str() + start + 1, len);
  out[len] = '\0';
  return true;
}

// ------------------------------------------------------------------ main ---

void loop() {
  float temperature = readProcessTemperature();
  if (isnan(temperature)) {
    Serial.printf("[SENSOR] %s fault: open thermocouple or no sensor on GPIO %d/%d/%d\n",
                  UNIT_ID, TC_SCK_PIN, TC_SO_PIN, TC_CS_PIN);
    delay(2000);
    return;
  }

  /*
   * Pulled up, so the switch shorting to ground is a bypass REQUEST. It is
   * reported and nothing more. This board must never bypass anything locally:
   * per the SIS contract a maintenance bypass is an operator-authenticated
   * server action, signed with ML-DSA-65 and checked against the identity
   * registry. A switch on a transmitter is a request, not an authorisation.
   */
  bool bypassRequested = digitalRead(BYPASS_REQ_PIN) == LOW;

  char plaintext[160];
  snprintf(plaintext, sizeof(plaintext),
           "{\"unit\": \"%s\", \"temperature\": %.2f, \"humidity\": %.2f, "
           "\"bypass_request\": %s}",
           UNIT_ID, temperature, NOMINAL_HUMIDITY, bypassRequested ? "true" : "false");

  char nonceHex[NONCE_LEN * 2 + 1];
  char cipherHex[192 * 2 + 1];
  if (!sealPayload(plaintext, nonceHex, cipherHex)) {
    delay(4000);
    return;
  }

  char body[600];
  snprintf(body, sizeof(body), "{\"nonce\":\"%s\",\"ciphertext\":\"%s\"}", nonceHex,
           cipherHex);

  HTTPClient http;
#if USE_TLS
  // setInsecure() skips certificate validation. Acceptable here only because
  // the payload is already sealed with AES-256-GCM end to end.
  static WiFiClientSecure secureClient;
  secureClient.setInsecure();
  http.begin(secureClient, TELEMETRY_URL);
#else
  http.begin(TELEMETRY_URL);
#endif
  http.addHeader("Content-Type", "application/json");
  int status = http.POST((uint8_t *)body, strlen(body));

  if (status == 200) {
    // The server owns the trip decision; the board only mirrors it, so the
    // transmitter and the audit trail can never disagree about what happened.
    String response = http.getString();
    float setpoint = valueOf(response, "\"setpoint\":", 0.0f);
    char tripState[16] = "?";
    char valve[16] = "?";
    if (stringOf(response, "\"trip_state\":", tripState, sizeof(tripState))) {
      showPlantState(strcmp(tripState, "TRIPPED") == 0);
    }
    stringOf(response, "\"valve\":", valve, sizeof(valve));
    Serial.printf("[NODE] Sealed %.2fC (bypass req %s) -> accepted "
                  "(setpoint %.1fC, %s, XV-101 %s)\n",
                  temperature, bypassRequested ? "ASSERTED" : "clear", setpoint,
                  tripState, valve);
  } else {
    Serial.printf("[NODE] POST failed, HTTP %d (%s)\n", status,
                  http.errorToString(status).c_str());
  }
  http.end();

  delay(4000);
}
