/*
 * SIS-01 constrained node — the FULL post-quantum handshake on the ESP32.
 *
 * Unlike firmware/sketch (which uses a provisioned AES key), this node runs the
 * real ML-KEM-768 + ML-DSA-65 handshake over HTTP, derives a per-connection
 * session key, and seals telemetry with it — exactly like the Python nodes.
 * The vendored PQClean crypto (firmware/pqc) is interop-verified against the
 * server's kyber-py / dilithium-py by `make pqc-interop`.
 *
 * Provision first:  make enroll  &&  make firmware-keys   (writes keys.h)
 * Then set WIFI_* and SERVER below.
 *
 * This board is TT-101 on the mini plant (docs/MINI_PLANT.md). Its reading is
 * a real safety-lane input: at or above the setpoint the server latches a trip
 * and the actuator closes XV-101. Sensor, chosen by TT101_SENSOR below:
 *   MAX6675 + K-type probe: SCK 18, SO 19, CS 5 (the real design)
 *   DHT22 fallback:         data on GPIO 15 (max 80 C -- the setpoint ceiling)
 *
 * Three lamps mirror what the server reports (each LED via 220R to GND):
 *   GREEN  GPIO 25 = HEALTHY, confirmed by the server on the last reading
 *   RED    GPIO 27 = TRIPPED, latched until a signed operator RESET
 *   YELLOW GPIO 26 = fault: no session, server unreachable, or sensor failed.
 *                    Green goes dark with it -- the board will not vouch for a
 *                    plant state it could not confirm.
 *
 * ML-DSA-65 signing needs ~45 KB of stack, so the handshake runs in a dedicated
 * FreeRTOS task with a 64 KB stack, not the 8 KB Arduino loop task.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

// Which transmitter TT-101 is. 1 = MAX6675 K-type thermocouple, 0 = DHT22.
#define TT101_MAX6675 1

#if TT101_MAX6675
#include "MAX6675.h"
#else
#include "DHTesp.h"
#endif

extern "C" {
  #include "api.h"      // ML-KEM-768
  #include "d_api.h"    // ML-DSA-65
  #include "fips202.h"  // SHAKE-256
}
#include "keys.h"       // DEVICE_ID, DEVICE_SECRET, SERVER_PUBLIC  (generated, gitignored)

// Real hardware: the ESP32 must join the SAME network as the machine running
// `make server`. 2.4 GHz only -- the ESP32 has no 5 GHz radio.
static const char *WIFI_SSID = "YOUR_WIFI_SSID";
static const char *WIFI_PASS = "YOUR_WIFI_PASSWORD";
// Server base URL, no trailing slash: http://<server LAN IP>:5001.
// On macOS: `ipconfig getifaddr en0`.
static const char *SERVER = "http://172.20.10.2:5001";

static const char *ROLE = "sensor";
static const char *LINK_LABEL = "quantum-iot/sensor-link/aes256gcm";
static const char *TRANSCRIPT_PREFIX = "quantum-iot/v1|sensor|";

static const int TC_SCK_PIN = 18;
static const int TC_SO_PIN = 19;
static const int TC_CS_PIN = 5;
static const int DHT_PIN = 15;

static const int GREEN_LED_PIN = 25;
static const int YELLOW_LED_PIN = 26;
static const int RED_LED_PIN = 27;

#if TT101_MAX6675
// The MAX6675 converts in ~220 ms; one reading a second is real time for a
// thermal process and keeps the HTTP leg comfortably under its round trip.
static const uint32_t SAMPLE_PERIOD_MS = 1000;
// A thermocouple measures temperature only. The telemetry schema carries a
// humidity field because the Python sensor has one; this is a fixed nominal
// value, not a measurement, and nothing downstream acts on it.
static const float NOMINAL_HUMIDITY = 45.0f;
#else
// The DHT22 cannot sample faster than once every 2 s.
static const uint32_t SAMPLE_PERIOD_MS = 2000;
#endif
// Consecutive rejected/failed posts before the session is assumed dead (e.g.
// the server restarted and forgot it) and a fresh handshake is run.
static const int MAX_POST_FAILURES = 3;

// Sizes from the vendored PQClean headers.
#define EK_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   // 1184
#define CT_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  // 1088
#define SIG_BYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES             // 3309

static uint8_t g_session_key[32];
static volatile bool g_have_key = false;
static volatile bool g_handshaking = false;
#if TT101_MAX6675
// RobTillaart's constructor is (select, miso, clock) -- not Adafruit's order.
static MAX6675 thermocouple(TC_CS_PIN, TC_SO_PIN, TC_SCK_PIN);
#else
static DHTesp dht;
#endif

// ---------------------------------------------------------------- helpers ---

static void toHex(const uint8_t *b, size_t n, char *out) {
  static const char *h = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) { out[2 * i] = h[b[i] >> 4]; out[2 * i + 1] = h[b[i] & 15]; }
  out[2 * n] = 0;
}
static bool fromHex(const char *h, uint8_t *b, size_t n) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; i++) {
    int hi = nib(h[2 * i]), lo = nib(h[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    b[i] = (hi << 4) | lo;
  }
  return true;
}

/* Copies the hex string value of "key":"...." from a flat JSON body into out.
   Returns its length in hex chars, or 0 if absent. */
static size_t jsonHex(const String &body, const char *key, char *out, size_t cap) {
  int k = body.indexOf(key);
  if (k < 0) return 0;
  int q1 = body.indexOf('"', body.indexOf(':', k) + 1);
  int q2 = body.indexOf('"', q1 + 1);
  if (q1 < 0 || q2 < 0) return 0;
  size_t len = q2 - q1 - 1;
  if (len + 1 > cap) return 0;
  memcpy(out, body.c_str() + q1 + 1, len);
  out[len] = 0;
  return len;
}

static String postJson(const char *path, const String &body) {
  HTTPClient http;
  http.begin(String(SERVER) + path);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST((uint8_t *)body.c_str(), body.length());
  String resp = (code == 200) ? http.getString() : String("");
  if (code != 200) Serial.printf("[NET] POST %s -> HTTP %d\n", path, code);
  http.end();
  return resp;
}

// HKDF-SHA256(salt=zeros32, ikm, info) -> 32 bytes, matching the server's derivation.
static void hkdf32(const uint8_t *ikm, size_t ikmlen, const char *info, uint8_t out[32]) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  uint8_t zeros[32] = {0}, prk[32];
  mbedtls_md_hmac(md, zeros, 32, ikm, ikmlen, prk);            // extract
  uint8_t buf[64]; size_t il = strlen(info);
  memcpy(buf, info, il); buf[il] = 0x01;                       // info || 0x01
  mbedtls_md_hmac(md, prk, 32, buf, il + 1, out);              // expand, L=32
}

// session key = HKDF( SHAKE256(shared_secret || label)[:32] ), exactly as pqc.py.
static void deriveSessionKey(const uint8_t *ss, uint8_t out[32]) {
  size_t ll = strlen(LINK_LABEL);
  uint8_t absorb[32 + 64], extracted[32];
  memcpy(absorb, ss, 32);
  memcpy(absorb + 32, LINK_LABEL, ll);
  shake256(extracted, 32, absorb, 32 + ll);
  hkdf32(extracted, 32, LINK_LABEL, out);
}

static void fingerprint16(const uint8_t key[32], char out[17]) {
  uint8_t d[32];
  mbedtls_sha256(key, 32, d, 0);
  toHex(d, 8, out);  // first 16 hex chars = first 8 bytes, matches key_fingerprint()[:16]
}

// ---------------------------------------------------------------- handshake -

static bool runHandshake() {
  // Step 1: hello
  String hello = postJson("/pqc/hello",
                          String("{\"device_id\":\"") + DEVICE_ID + "\",\"role\":\"" + ROLE + "\"}");
  if (hello.length() == 0) return false;

  static char hid[64];
  static char ekHex[EK_BYTES * 2 + 1];
  static char sigHex[SIG_BYTES * 2 + 1];
  jsonHex(hello, "\"handshake_id\"", hid, sizeof(hid));
  if (jsonHex(hello, "\"encapsulation_key\"", ekHex, sizeof(ekHex)) != EK_BYTES * 2) return false;

  static uint8_t ek[EK_BYTES];
  fromHex(ekHex, ek, EK_BYTES);

  // Step 2: verify the server's ML-DSA-65 signature over prefix||ek
  if (jsonHex(hello, "\"server_signature\"", sigHex, sizeof(sigHex))) {
    static uint8_t ssig[SIG_BYTES];
    size_t slen = strlen(sigHex) / 2;
    fromHex(sigHex, ssig, slen);
    size_t pl = strlen(TRANSCRIPT_PREFIX);
    static uint8_t tr[64 + EK_BYTES];
    memcpy(tr, TRANSCRIPT_PREFIX, pl);
    memcpy(tr + pl, ek, EK_BYTES);
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(ssig, slen, tr, pl + EK_BYTES, SERVER_PUBLIC) != 0) {
      Serial.println("[PQC] ABORT: server signature invalid — possible MITM.");
      return false;
    }
    Serial.println("[PQC] Server identity verified (ML-DSA-65).");
  }

  // Step 3: encapsulate, derive the session key
  static uint8_t ct[CT_BYTES], ss[32];
  PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, ek);
  deriveSessionKey(ss, g_session_key);

  // Step 4: sign prefix||ek||"|"||ct with our device key
  size_t pl = strlen(TRANSCRIPT_PREFIX);
  static uint8_t tr2[64 + EK_BYTES + 1 + CT_BYTES];
  size_t o = 0;
  memcpy(tr2 + o, TRANSCRIPT_PREFIX, pl); o += pl;
  memcpy(tr2 + o, ek, EK_BYTES);         o += EK_BYTES;
  tr2[o++] = '|';
  memcpy(tr2 + o, ct, CT_BYTES);         o += CT_BYTES;

  static uint8_t dsig[SIG_BYTES]; size_t dsl;
  PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(dsig, &dsl, tr2, o, DEVICE_SECRET);

  // Step 5: send the ciphertext + our signature + the key fingerprint
  static char ctHex[CT_BYTES * 2 + 1];
  static char dsigHex[SIG_BYTES * 2 + 1];
  char fp[17];
  toHex(ct, CT_BYTES, ctHex);
  toHex(dsig, dsl, dsigHex);
  fingerprint16(g_session_key, fp);

  String body = String("{\"handshake_id\":\"") + hid + "\",\"device_id\":\"" + DEVICE_ID +
                "\",\"kem_ciphertext\":\"" + ctHex + "\",\"device_signature\":\"" + dsigHex +
                "\",\"key_fingerprint\":\"" + fp + "\"}";
  String est = postJson("/pqc/encapsulate", body);
  if (est.indexOf("established") < 0) { Serial.println("[PQC] Handshake refused."); return false; }

  Serial.printf("[PQC] Session established. Key fingerprint %s\n", fp);
  g_have_key = true;
  return true;
}

// ---------------------------------------------------------------- telemetry -

/* Returns the server's reply on acceptance, or "" if the post failed. */
static String sealAndPost(float temp, float hum) {
  char plain[160];
  snprintf(plain, sizeof(plain),
           "{\"unit\":\"%s\",\"temperature\":%.2f,\"humidity\":%.2f}", DEVICE_ID, temp, hum);
  size_t len = strlen(plain);
  uint8_t nonce[12], ct[192], tag[16];
  for (int i = 0; i < 12; i += 4) { uint32_t r = esp_random(); memcpy(nonce + i, &r, 4); }

  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, g_session_key, 256);
  int rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, nonce, 12, NULL, 0,
                                     (const uint8_t *)plain, ct, 16, tag);
  mbedtls_gcm_free(&gcm);
  if (rc != 0) return String("");
  memcpy(ct + len, tag, 16);

  char nHex[25], cHex[192 * 2 + 1];
  toHex(nonce, 12, nHex);
  toHex(ct, len + 16, cHex);
  String body = String("{\"device_id\":\"") + DEVICE_ID + "\",\"nonce\":\"" + nHex +
                "\",\"ciphertext\":\"" + cHex + "\"}";
  String r = postJson("/telemetry", body);
  return r.indexOf("accepted") >= 0 ? r : String("");
}

// ---------------------------------------------------------------- tasks -----

static void handshakeTask(void *) {
  while (!runHandshake()) {
    Serial.println("[PQC] Handshake failed; retrying in 3s.");
    vTaskDelay(pdMS_TO_TICKS(3000));
  }
  g_handshaking = false;
  vTaskDelete(NULL);  // done; loop() takes over telemetry
}

static void startHandshake() {
  if (g_handshaking) return;
  g_have_key = false;
  g_handshaking = true;
  // 64 KB stack: ML-DSA-65 signing needs ~45 KB, far past the 8 KB loop task.
  xTaskCreatePinnedToCore(handshakeTask, "pqc-handshake", 64 * 1024, NULL, 1, NULL, 1);
}

void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.printf("\n[BOOT] %s — full post-quantum handshake node\n", DEVICE_ID);

  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(YELLOW_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);
  digitalWrite(YELLOW_LED_PIN, HIGH);  // fault until the server confirms otherwise
#if TT101_MAX6675
  thermocouple.begin();
  delay(500);  // MAX6675 needs ~200 ms after power-up before its first conversion
#else
  dht.setup(DHT_PIN, DHTesp::DHT22);
#endif

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[NET] WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(200); Serial.print("."); }
  Serial.printf(" up as %s\n", WiFi.localIP().toString().c_str());

  startHandshake();
}

// Unknown plant state: yellow on, green off. Red keeps its last confirmed
// value -- a latched trip does not clear because the link dropped.
static void showFault() {
  digitalWrite(YELLOW_LED_PIN, HIGH);
  digitalWrite(GREEN_LED_PIN, LOW);
}

static void showPlantState(bool tripped) {
  digitalWrite(YELLOW_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, tripped ? LOW : HIGH);
  digitalWrite(RED_LED_PIN, tripped ? HIGH : LOW);
}

/* Process temperature in C, or NAN if the sensor could not be read. A burnt-out
   probe must never be published as a plausible number: on the safety lane a
   confident wrong reading is worse than an obvious absence. */
static float readProcessTemperature(float *humidity) {
#if TT101_MAX6675
  uint8_t status = thermocouple.read();
  if (status != STATUS_OK) {
    Serial.printf("[SENSOR] MAX6675 status 0x%02X (%s)\n", status,
                  status == STATUS_NOREAD ? "open thermocouple / no probe"
                                          : "SPI fault -- check GPIO 18/19/5");
    return NAN;
  }
  *humidity = NOMINAL_HUMIDITY;
  return thermocouple.getCelsius();
#else
  TempAndHumidity reading = dht.getTempAndHumidity();
  if (dht.getStatus() != DHTesp::ERROR_NONE) {
    Serial.printf("[SENSOR] DHT22 read failed: %s (check wiring on GPIO %d)\n",
                  dht.getStatusString(), DHT_PIN);
    return NAN;
  }
  *humidity = reading.humidity;
  return reading.temperature;
#endif
}

void loop() {
  static uint32_t lastSample = 0;
  static int failures = 0;

  if (!g_have_key) { showFault(); delay(50); return; }
  if (millis() - lastSample < SAMPLE_PERIOD_MS) { delay(20); return; }
  lastSample = millis();

  float humidity = 0.0f;
  float temperature = readProcessTemperature(&humidity);
  if (isnan(temperature)) {
    // Never publish a made-up number. The server sees silence, not a false value.
    showFault();
    return;
  }

  String reply = sealAndPost(temperature, humidity);
  if (reply.length() == 0) {
    showFault();
    Serial.printf("[TX] %.2fC NOT accepted (%d/%d)\n", temperature,
                  ++failures, MAX_POST_FAILURES);
    if (failures >= MAX_POST_FAILURES) {
      Serial.println("[PQC] Session presumed lost; re-running the handshake.");
      failures = 0;
      startHandshake();
    }
    return;
  }
  failures = 0;

  // The server owns the trip decision; the lamps only mirror it.
  bool tripped = reply.indexOf("TRIPPED") >= 0;
  showPlantState(tripped);
  Serial.printf("[TX] %.2fC sealed -> accepted, plant %s\n",
                temperature, tripped ? "TRIPPED" : "HEALTHY");
}
