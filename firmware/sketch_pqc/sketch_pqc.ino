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
 * WiFi and the server address can then be set at the bench without reflashing:
 * open the Serial Monitor at 115200 (line ending: Newline) and type `help`.
 * The WIFI_* and SERVER constants below are only the defaults until then.
 *
 * This board is TT-101 on the mini plant (docs/MINI_PLANT.md). Its reading is
 * a real safety-lane input: at or above the setpoint the server latches a trip
 * and the actuator closes XV-101. Sensor, chosen by TT101_MAX6675 below:
 *   MAX6675 + K-type probe: SCK 18, SO 19, CS 5 (the real design)
 *   DHT22 fallback:         data on GPIO 15 (max 80 C -- the setpoint ceiling)
 *
 * Three lamps mirror what the server reports (external LEDs via 220R to GND):
 *   HEALTHY GPIO 2  = confirmed by the server on the last reading. GPIO 2 is
 *                     the onboard LED on most DevKits; with a green LED, wire
 *                     it to GPIO 25 and set HEALTHY_LED_PIN to 25.
 *   TRIPPED GPIO 27 = steady: latched until a signed operator RESET
 *   FAULT   GPIO 26 = blinking: no WiFi, no session, server unreachable, or
 *                     sensor failed. Healthy goes dark with it -- the board
 *                     will not vouch for a plant state it could not confirm.
 * The fault lamp blinks rather than glowing steady so the rig works with two
 * LEDs of the same colour: steady means tripped, blinking means fault.
 *
 * ML-DSA-65 signing needs ~45 KB of stack, so the handshake runs in a dedicated
 * FreeRTOS task with a 64 KB stack, not the 8 KB Arduino loop task.
 *
 * Every function is defined before its first use: the build stubs out ctags,
 * so the Arduino builder generates no prototypes.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

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

// Defaults only: `wifi` and `server` on the Serial Monitor override them and
// persist in NVS. The ESP32 must join the SAME network as the machine running
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

static const int HEALTHY_LED_PIN = 2;   // onboard LED; 25 for an external green
static const int FAULT_LED_PIN = 26;
static const int TRIPPED_LED_PIN = 27;
static const uint32_t FAULT_BLINK_MS = 250;

#if TT101_MAX6675
static const char *SENSOR_NAME = "MAX6675 K-type thermocouple";
// The MAX6675 converts in ~220 ms; one reading a second is real time for a
// thermal process and keeps the HTTP leg comfortably under its round trip.
static const uint32_t SAMPLE_PERIOD_MS = 1000;
// Calibration knob. A MAX6675 with a cheap K-type probe is commonly a few
// degrees off; check it against ice water or a reference thermometer on the
// bench and put the correction here, rather than moving the trip setpoint.
static const float TC_OFFSET_C = 0.0f;
#else
static const char *SENSOR_NAME = "DHT22 (fallback, max 80 C)";
// The DHT22 cannot sample faster than once every 2 s.
static const uint32_t SAMPLE_PERIOD_MS = 2000;
#endif
// Consecutive rejected/failed posts before the session is assumed dead (e.g.
// the server restarted and forgot it) and a fresh handshake is run.
static const int MAX_POST_FAILURES = 3;

// Every HTTP call is bounded, so a dead or unreachable server costs at most
// connect + read (~6 s) of the loop or of the handshake task, never a hang.
static const int32_t HTTP_CONNECT_TIMEOUT_MS = 3000;
static const uint16_t HTTP_READ_TIMEOUT_MS = 3000;
// How long one WiFi join attempt is given before it is restarted. A WPA2 join
// takes 2-4 s; restarting sooner could abort a join that was about to land.
static const uint32_t WIFI_RETRY_MS = 10000;

static const char *NVS_NAMESPACE = "tt101";

// Sizes from the vendored PQClean headers.
#define EK_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   // 1184
#define CT_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  // 1088
#define SIG_BYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES             // 3309

// ---------------------------------------------------------------- commands --
/* Serial provisioning commands, one per line. The venue WiFi and the server
   laptop's address are what change between benches, so they are typed in
   rather than compiled in. This section is plain C on purpose -- no Arduino
   calls -- so the parser can be compiled and tested on a host.

     wifi <ssid> <password>       quote an SSID with spaces: wifi "Lab Guest" pa55word
     server http://<host>:<port>  base URL only; trailing slashes are stripped
     show | help | forget | reboot                                              */

static const size_t CMD_LINE_MAX = 160;
static const size_t SSID_MAX = 32;    // 802.11 limit, in bytes
static const size_t PASS_MIN = 8;     // WPA2-PSK passphrase; open networks are not supported
static const size_t PASS_MAX = 63;
static const size_t SERVER_MAX = 96;

enum CommandKind { CMD_EMPTY, CMD_HELP, CMD_SHOW, CMD_REBOOT, CMD_FORGET,
                   CMD_WIFI, CMD_SERVER, CMD_INVALID };

struct Command {
  CommandKind kind;
  const char *error;            // why, when kind == CMD_INVALID
  char ssid[SSID_MAX + 1];
  char pass[PASS_MAX + 1];
  char server[SERVER_MAX + 1];
};

static bool isBlank(char ch) { return ch == ' ' || ch == '\t'; }

static void invalid(Command *c, const char *why) {
  c->kind = CMD_INVALID;
  c->error = why;
}

/* The password is everything after the SSID, so it may contain spaces and
   quotes of its own; only an SSID with spaces needs quoting. */
static void parseWifi(const char *p, const char *end, Command *c) {
  if (p == end) return invalid(c, "usage: wifi <ssid> <password>  (quote an SSID with spaces)");
  const char *s, *se;
  if (*p == '"') {
    s = ++p;
    while (p < end && *p != '"') p++;
    if (p == end) return invalid(c, "SSID has an opening quote but no closing one");
    se = p++;
    if (p < end && !isBlank(*p)) return invalid(c, "put a space after the quoted SSID");
  } else {
    s = p;
    while (p < end && !isBlank(*p)) p++;
    se = p;
  }
  while (p < end && isBlank(*p)) p++;
  size_t sl = se - s, pl = end - p;
  if (sl == 0) return invalid(c, "SSID is empty");
  if (sl > SSID_MAX) return invalid(c, "SSID is longer than 32 bytes");
  if (pl == 0) return invalid(c, "missing password (open networks are not supported)");
  if (pl < PASS_MIN || pl > PASS_MAX) return invalid(c, "WPA2 password must be 8-63 characters");
  memcpy(c->ssid, s, sl); c->ssid[sl] = 0;
  memcpy(c->pass, p, pl); c->pass[pl] = 0;
  c->kind = CMD_WIFI;
}

/* A base URL the node can append /pqc/hello, /pqc/encapsulate and /telemetry
   to. The port is required: forgetting it would silently aim at port 80,
   where nothing answers, and look like a dead server. */
static void parseServer(const char *p, const char *end, Command *c) {
  if (p == end) return invalid(c, "usage: server http://<host>:<port>");
  if (end - p < 7 || strncasecmp(p, "http://", 7) != 0)
    return invalid(c, "server must start with http:// (no TLS: ML-DSA authenticates the server)");
  while (end - p > 7 && end[-1] == '/') end--;
  const char *host = p + 7, *colon = NULL;
  for (const char *q = host; q < end; q++) {
    if (!isgraph((unsigned char)*q) || *q == '/' || *q == '?' || *q == '#' || *q == '@' || *q == '"')
      return invalid(c, "server is a base URL only: http://<host>:<port>, no path");
    if (*q == ':' && !colon) colon = q;
  }
  if (host == end || colon == host) return invalid(c, "server URL has no host");
  if (!colon || colon + 1 == end) return invalid(c, "include the port, e.g. http://192.168.1.20:5001");
  long port = 0;
  for (const char *d = colon + 1; d < end; d++) {
    if (!isdigit((unsigned char)*d)) return invalid(c, "port must be a number");
    port = port * 10 + (*d - '0');
    if (port > 65535) return invalid(c, "port must be 1-65535");
  }
  if (port == 0) return invalid(c, "port must be 1-65535");
  size_t n = end - p;
  if (n > SERVER_MAX) return invalid(c, "server URL is longer than 96 characters");
  memcpy(c->server, "http://", 7);  // normalise the scheme's case
  memcpy(c->server + 7, host, n - 7);
  c->server[n] = 0;
  c->kind = CMD_SERVER;
}

static void parseCommand(const char *line, Command *c) {
  memset(c, 0, sizeof(*c));
  const char *end = line + strlen(line);
  while (line < end && isspace((unsigned char)*line)) line++;
  while (end > line && isspace((unsigned char)end[-1])) end--;
  if (line == end) { c->kind = CMD_EMPTY; return; }

  const char *verbEnd = line;
  while (verbEnd < end && !isBlank(*verbEnd)) verbEnd++;
  const char *arg = verbEnd;
  while (arg < end && isBlank(*arg)) arg++;
  size_t vl = verbEnd - line;
  auto is = [&](const char *word) { return strlen(word) == vl && strncasecmp(line, word, vl) == 0; };

  if (is("wifi")) return parseWifi(arg, end, c);
  if (is("server")) return parseServer(arg, end, c);
  CommandKind kind = (is("help") || is("?")) ? CMD_HELP
                   : is("show")              ? CMD_SHOW
                   : is("reboot")            ? CMD_REBOOT
                   : is("forget")            ? CMD_FORGET
                                             : CMD_INVALID;
  if (kind == CMD_INVALID) return invalid(c, "unknown command; type 'help'");
  if (arg != end) return invalid(c, "this command takes no arguments");
  c->kind = kind;
}

// ---------------------------------------------------------------- state -----

// Live configuration. Written only by loop() (serial commands); the handshake
// task reads g_server through a snapshot taken under g_mux.
static char g_ssid[SSID_MAX + 1];
static char g_pass[PASS_MAX + 1];
static char g_server[SERVER_MAX + 1];
static bool g_wifi_saved = false;    // true = from NVS, false = compiled default
static bool g_server_saved = false;

static uint8_t g_session_key[32];
static volatile bool g_have_key = false;
static volatile bool g_handshaking = false;
// Bumped whenever the current session stops being trustworthy (WiFi dropped,
// server or network changed, posts rejected). A handshake that started under
// an older generation is discarded instead of installed, so a session agreed
// with the previous server can never be used against the new one.
static uint32_t g_session_gen = 0;  // only touched under g_mux, which is the barrier
static portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t g_wifi_attempt_ms = 0;

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

static String postJson(const char *server, const char *path, const String &body) {
  HTTPClient http;
  http.setConnectTimeout(HTTP_CONNECT_TIMEOUT_MS);
  http.setTimeout(HTTP_READ_TIMEOUT_MS);
  if (!http.begin(String(server) + path)) {
    Serial.printf("[NET] Cannot parse server URL %s\n", server);
    return String("");
  }
  http.addHeader("Content-Type", "application/json");
  int code = http.POST((uint8_t *)body.c_str(), body.length());
  String resp = (code == 200) ? http.getString() : String("");
  if (code != 200)
    Serial.printf("[NET] POST %s%s -> %d %s\n", server, path, code,
                  code < 0 ? HTTPClient::errorToString(code).c_str() : "");
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

/* Runs one handshake against `server` and leaves the agreed key in key_out.
   It does not install the key: handshakeTask() decides whether it is still
   wanted. */
static bool runHandshake(const char *server, uint8_t key_out[32]) {
  // Step 1: hello
  String hello = postJson(server, "/pqc/hello",
                          String("{\"device_id\":\"") + DEVICE_ID + "\",\"role\":\"" + ROLE + "\"}");
  if (hello.length() == 0) return false;

  static char hid[64];
  static char ekHex[EK_BYTES * 2 + 1];
  static char sigHex[SIG_BYTES * 2 + 1];
  jsonHex(hello, "\"handshake_id\"", hid, sizeof(hid));
  if (jsonHex(hello, "\"encapsulation_key\"", ekHex, sizeof(ekHex)) != EK_BYTES * 2) return false;

  static uint8_t ek[EK_BYTES];
  if (!fromHex(ekHex, ek, EK_BYTES)) return false;

  // Step 2: verify the server's ML-DSA-65 signature over prefix||ek against the
  // pinned SERVER_PUBLIC. A missing signature is refused exactly like a bad
  // one: an unsigned offer is what a rogue server or a man in the middle would
  // send, and this check is what makes the URL safe to change at runtime.
  static uint8_t ssig[SIG_BYTES];
  if (jsonHex(hello, "\"server_signature\"", sigHex, sizeof(sigHex)) != SIG_BYTES * 2 ||
      !fromHex(sigHex, ssig, SIG_BYTES)) {
    Serial.println("[PQC] ABORT: server offer is unsigned or malformed — possible MITM.");
    return false;
  }
  size_t pl = strlen(TRANSCRIPT_PREFIX);
  static uint8_t tr[64 + EK_BYTES];
  memcpy(tr, TRANSCRIPT_PREFIX, pl);
  memcpy(tr + pl, ek, EK_BYTES);
  if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(ssig, SIG_BYTES, tr, pl + EK_BYTES, SERVER_PUBLIC) != 0) {
    Serial.println("[PQC] ABORT: server signature invalid — possible MITM.");
    return false;
  }
  Serial.println("[PQC] Server identity verified (ML-DSA-65).");

  // Step 3: encapsulate, derive the session key
  static uint8_t ct[CT_BYTES], ss[32];
  PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, ek);
  deriveSessionKey(ss, key_out);
  mbedtls_platform_zeroize(ss, sizeof(ss));

  // Step 4: sign prefix||ek||"|"||ct with our device key
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
  fingerprint16(key_out, fp);

  String body = String("{\"handshake_id\":\"") + hid + "\",\"device_id\":\"" + DEVICE_ID +
                "\",\"kem_ciphertext\":\"" + ctHex + "\",\"device_signature\":\"" + dsigHex +
                "\",\"key_fingerprint\":\"" + fp + "\"}";
  String est = postJson(server, "/pqc/encapsulate", body);
  if (est.indexOf("established") < 0) { Serial.println("[PQC] Handshake refused."); return false; }

  Serial.printf("[PQC] Session established. Key fingerprint %s\n", fp);
  return true;
}

// ---------------------------------------------------------------- telemetry -

/* Returns the server's reply on acceptance, or "" if the post failed. */
static String sealAndPost(float temp, float hum) {
  // Under ct[] below (192), so a full buffer still encrypts in place.
  char plain[160];
#if TT101_MAX6675
  // A thermocouple measures temperature only, so there is no humidity key at
  // all -- the server shows "not measured" rather than a made-up number.
  (void)hum;
  snprintf(plain, sizeof(plain),
           "{\"unit\":\"%s\",\"sensor\":\"MAX6675\",\"temperature\":%.2f}", DEVICE_ID, temp);
#else
  snprintf(plain, sizeof(plain),
           "{\"unit\":\"%s\",\"sensor\":\"DHT22\",\"temperature\":%.2f,\"humidity\":%.2f}",
           DEVICE_ID, temp, hum);
#endif
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
  String r = postJson(g_server, "/telemetry", body);
  return r.indexOf("accepted") >= 0 ? r : String("");
}

// ---------------------------------------------------------------- tasks -----

/* Drops the current session: the key is wiped, the lamps go to FAULT on the
   next pass, and loop() starts a fresh handshake once WiFi is up. */
static void invalidateSession() {
  portENTER_CRITICAL(&g_mux);
  g_session_gen++;
  g_have_key = false;
  mbedtls_platform_zeroize(g_session_key, sizeof(g_session_key));
  portEXIT_CRITICAL(&g_mux);
}

static void handshakeTask(void *) {
  static char server[SERVER_MAX + 1];
  static uint8_t key[32];
  // Exits when WiFi drops; loop() starts a new task once it is back.
  while (WiFi.status() == WL_CONNECTED) {
    portENTER_CRITICAL(&g_mux);
    uint32_t gen = g_session_gen;
    memcpy(server, g_server, sizeof(server));
    portEXIT_CRITICAL(&g_mux);

    bool ok = runHandshake(server, key);
    bool installed = false;
    if (ok) {
      portENTER_CRITICAL(&g_mux);
      if (gen == g_session_gen) {
        memcpy(g_session_key, key, sizeof(key));
        g_have_key = true;
        installed = true;
      }
      portEXIT_CRITICAL(&g_mux);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (installed) break;
    if (ok) { Serial.println("[PQC] Settings changed mid-handshake; discarding that session."); continue; }
    Serial.println("[PQC] Handshake failed; retrying in 3s.");
    vTaskDelay(pdMS_TO_TICKS(3000));
  }
  g_handshaking = false;
  vTaskDelete(NULL);  // done; loop() takes over telemetry
}

static void startHandshake() {
  if (g_handshaking) return;
  g_handshaking = true;
  // 64 KB stack: ML-DSA-65 signing needs ~45 KB, far past the 8 KB loop task.
  // It is allocated per handshake, so after many reconnects a fragmented heap
  // can refuse it; say so rather than wait forever on a task that never ran.
  if (xTaskCreatePinnedToCore(handshakeTask, "pqc-handshake", 64 * 1024, NULL, 1, NULL, 1) != pdPASS) {
    g_handshaking = false;
    Serial.printf("[PQC] No room for the 64 KB handshake stack (largest free block %lu B); retrying.\n",
                  (unsigned long)ESP.getMaxAllocHeap());
    delay(1000);
  }
}

// ---------------------------------------------------------------- lamps -----

static volatile bool g_fault = true;  // fault until the server confirms otherwise

// The blink runs from a FreeRTOS timer, not loop(), so it keeps going while a
// telemetry post holds the loop for up to a few seconds. A frozen lamp would
// read as steady, which on this rig means tripped.
static void faultBlink(TimerHandle_t) {
  static bool lit = false;  // tracked here: reading back an OUTPUT pin is not reliable on every core
  lit = g_fault && !lit;
  digitalWrite(FAULT_LED_PIN, lit ? HIGH : LOW);
}

// Unknown plant state: fault lamp blinking, healthy off. The tripped lamp keeps
// its last confirmed value -- a latched trip does not clear because the link
// dropped.
static void showFault() {
  g_fault = true;
  digitalWrite(HEALTHY_LED_PIN, LOW);
}

static void showPlantState(bool tripped) {
  g_fault = false;
  digitalWrite(FAULT_LED_PIN, LOW);
  digitalWrite(HEALTHY_LED_PIN, tripped ? LOW : HIGH);
  digitalWrite(TRIPPED_LED_PIN, tripped ? HIGH : LOW);
}

// ---------------------------------------------------------------- sensor ----

/* Process temperature in C, or NAN if the sensor could not be read. A burnt-out
   probe must never be published as a plausible number: on the safety lane a
   confident wrong reading is worse than an obvious absence. */
static float readProcessTemperature(float *humidity) {
#if TT101_MAX6675
  uint8_t status = thermocouple.read();
  uint16_t raw = thermocouple.getRawData();
  if (status == STATUS_ERROR) {
    Serial.println("[SENSOR] MAX6675: open thermocouple -- probe unplugged or broken");
    return NAN;
  }
  if (status != STATUS_OK) {
    Serial.printf("[SENSOR] MAX6675: no SPI answer (status 0x%02X) -- check GPIO 18/19/5 and 3V3\n", status);
    return NAN;
  }
  // Bits 15 and 1 of a real MAX6675 frame are always 0. An all-zero frame is
  // what a dead SCK or an unpowered chip reads as, and it decodes to a
  // confident 0.00 C, so it is refused too -- at the price of a genuine
  // 0.00 C reading in ice water also showing FAULT.
  if (raw == 0 || (raw & 0x8002)) {
    Serial.printf("[SENSOR] MAX6675: implausible SPI frame 0x%04X -- check GPIO 18/19/5\n", raw);
    return NAN;
  }
  *humidity = NAN;  // not measured; sealAndPost omits the key in this mode
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

// ---------------------------------------------------------------- wifi ------

static const char *wifiReason(wl_status_t s) {
  switch (s) {
    case WL_CONNECTED:       return "connected";
    case WL_NO_SSID_AVAIL:   return "SSID not found -- check the name; the ESP32 is 2.4 GHz only";
    case WL_CONNECT_FAILED:  return "join refused -- wrong password?";
    case WL_CONNECTION_LOST: return "connection lost";
    default:                 return "no answer from the access point yet";
  }
}

static void beginWifi() {
  WiFi.disconnect();
  WiFi.begin(g_ssid, g_pass);
  g_wifi_attempt_ms = millis();
}

/* Never blocks. A dead SSID is retried every WIFI_RETRY_MS while loop() keeps
   reading Serial, so wrong credentials can be fixed with `wifi` on the spot.
   Any change of link state drops the session: after an outage the server may
   have restarted and forgotten it, and a fresh handshake is cheaper than
   three rejected posts finding that out. */
static void serviceWifi() {
  static bool up = false;
  bool now = WiFi.status() == WL_CONNECTED;
  if (now != up) {
    up = now;
    invalidateSession();
    if (now) {
      Serial.printf("[NET] WiFi up on \"%s\" as %s\n", g_ssid, WiFi.localIP().toString().c_str());
    } else {
      // No rejoin here: the retry below fires at once after a long-held link,
      // and leaves alone a join that `wifi` has only just started.
      Serial.println("[NET] WiFi lost -- FAULT until it is back and a fresh handshake completes.");
    }
  }
  if (!now && millis() - g_wifi_attempt_ms >= WIFI_RETRY_MS) {
    Serial.printf("[NET] WiFi \"%s\" not joined (%s); retrying.\n", g_ssid, wifiReason(WiFi.status()));
    beginWifi();
  }
}

// ---------------------------------------------------------------- provisioning

/* Loads the saved WiFi and server, or the compiled defaults. NVS survives a
   reflash, so once something is saved the constants above stop mattering;
   `show` and the boot banner say which one is in use, and `forget` clears it. */
static void loadConfig() {
  Preferences prefs;
  bool open = prefs.begin(NVS_NAMESPACE, true);  // read-only; fails until something is saved
  g_wifi_saved = open && prefs.isKey("ssid") && prefs.isKey("pass") &&
                 prefs.getString("ssid", g_ssid, sizeof(g_ssid)) > 0 &&
                 prefs.getString("pass", g_pass, sizeof(g_pass)) > 0;
  if (!g_wifi_saved) {
    strlcpy(g_ssid, WIFI_SSID, sizeof(g_ssid));
    strlcpy(g_pass, WIFI_PASS, sizeof(g_pass));
  }
  g_server_saved = open && prefs.isKey("server") &&
                   prefs.getString("server", g_server, sizeof(g_server)) > 0;
  if (!g_server_saved) strlcpy(g_server, SERVER, sizeof(g_server));
  if (open) prefs.end();
}

static bool savePref(const char *key, const char *value) {
  Preferences prefs;
  if (!prefs.begin(NVS_NAMESPACE, false)) return false;
  bool ok = prefs.putString(key, value) == strlen(value);
  prefs.end();
  return ok;
}

static void printShow() {
  Serial.printf("[CFG] device   %s\n", DEVICE_ID);
  Serial.printf("[CFG] sensor   %s\n", SENSOR_NAME);
  Serial.printf("[CFG] wifi     \"%s\" (%s)\n", g_ssid, g_wifi_saved ? "saved" : "compiled default");
  Serial.printf("[CFG] server   %s (%s)\n", g_server, g_server_saved ? "saved" : "compiled default");
  if (WiFi.status() == WL_CONNECTED)
    Serial.printf("[CFG] link     WiFi up, IP %s, RSSI %d dBm\n",
                  WiFi.localIP().toString().c_str(), (int)WiFi.RSSI());
  else
    Serial.printf("[CFG] link     WiFi down: %s\n", wifiReason(WiFi.status()));
  Serial.printf("[CFG] session  %s\n", g_have_key    ? "established (ML-KEM-768 + ML-DSA-65)"
                                       : g_handshaking ? "handshake in progress"
                                                       : "none");
}

static void printHelp() {
  Serial.println("[CFG] Commands, one per line (Serial Monitor line ending: Newline):");
  Serial.println("  wifi <ssid> <password>       join a WPA2 network; quote an SSID with spaces:");
  Serial.println("                               wifi \"Lab Guest\" pa55word");
  Serial.println("  server http://<host>:<port>  the machine running `make server`, e.g. http://192.168.1.20:5001");
  Serial.println("  show                         settings and link state (never the password)");
  Serial.println("  forget                       erase saved settings and reboot to the compiled defaults");
  Serial.println("  reboot                       restart the board");
}

/* Changing the server here is not a way in. The node pins SERVER_PUBLIC from
   keys.h and aborts the handshake unless the offer carries a valid ML-DSA-65
   signature from that key, so pointing it at a rogue server yields no session
   and no telemetry -- just a FAULT lamp. Changing WiFi is no worse: whoever
   holds the USB port can already reflash the board. */
static void handleCommand(const char *line) {
  Command c;
  parseCommand(line, &c);
  switch (c.kind) {
    case CMD_EMPTY: break;
    case CMD_INVALID: Serial.printf("[CFG] %s\n", c.error); break;
    case CMD_HELP: printHelp(); break;
    case CMD_SHOW: printShow(); break;
    case CMD_REBOOT:
      Serial.println("[CFG] Rebooting.");
      Serial.flush();
      ESP.restart();
      break;
    case CMD_FORGET: {
      Preferences prefs;
      if (prefs.begin(NVS_NAMESPACE, false)) { prefs.clear(); prefs.end(); }
      Serial.println("[CFG] Saved settings erased; rebooting to the compiled defaults.");
      Serial.flush();
      ESP.restart();
      break;
    }
    case CMD_WIFI:
      strlcpy(g_ssid, c.ssid, sizeof(g_ssid));
      strlcpy(g_pass, c.pass, sizeof(g_pass));
      g_wifi_saved = savePref("pass", g_pass) && savePref("ssid", g_ssid);
      Serial.printf("[CFG] WiFi set to \"%s\" (password not shown)%s; reconnecting.\n", g_ssid,
                    g_wifi_saved ? ", saved" : " -- NOT saved, lost on reboot");
      invalidateSession();
      beginWifi();
      break;
    case CMD_SERVER:
      portENTER_CRITICAL(&g_mux);
      strlcpy(g_server, c.server, sizeof(g_server));
      portEXIT_CRITICAL(&g_mux);
      g_server_saved = savePref("server", g_server);
      Serial.printf("[CFG] Server set to %s%s; re-running the handshake.\n", g_server,
                    g_server_saved ? ", saved" : " -- NOT saved, lost on reboot");
      invalidateSession();
      break;
  }
  mbedtls_platform_zeroize(&c, sizeof(c));  // it may hold the WiFi password
}

/* Non-blocking: takes whatever bytes have arrived and returns. A telemetry post
   can hold loop() for up to ~6 s; typing meanwhile waits in the 256-byte UART
   buffer, which is longer than any valid command. */
static void serviceSerial() {
  static char line[CMD_LINE_MAX + 1];
  static size_t len = 0;
  static bool overflow = false;
  while (Serial.available() > 0) {
    char ch = (char)Serial.read();
    if (ch != '\n' && ch != '\r') {
      if (len < CMD_LINE_MAX) line[len++] = ch; else overflow = true;
      continue;
    }
    line[len] = 0;
    if (overflow) Serial.printf("[CFG] Ignored a line longer than %u characters.\n", (unsigned)CMD_LINE_MAX);
    else if (len > 0) handleCommand(line);
    mbedtls_platform_zeroize(line, sizeof(line));
    len = 0;
    overflow = false;
  }
}

// ---------------------------------------------------------------- main ------

void setup() {
  Serial.begin(115200);
  delay(600);

  pinMode(HEALTHY_LED_PIN, OUTPUT);
  pinMode(FAULT_LED_PIN, OUTPUT);
  pinMode(TRIPPED_LED_PIN, OUTPUT);
  TimerHandle_t blink = xTimerCreate("fault-lamp", pdMS_TO_TICKS(FAULT_BLINK_MS), pdTRUE,
                                     nullptr, faultBlink);
  if (blink == nullptr || xTimerStart(blink, 0) != pdPASS) {
    Serial.println("[BOOT] fault-lamp timer failed; fault lamp will not blink");
  }
#if TT101_MAX6675
  thermocouple.begin();
  // The library's own note: SO needs a pull-up. Without one, a missing or
  // unpowered MAX6675 floats the line and can decode as a plausible reading;
  // with it, the read is 0xFFFF and reported as no communication.
  pinMode(TC_SO_PIN, INPUT_PULLUP);
  // Bit-banged SPI: at 240 MHz the ESP32 samples SO almost on the falling SCK
  // edge, inside the chip's 100 ns data-valid time. 1 us per half-clock keeps
  // the frame clean and costs ~40 us per read.
  thermocouple.setSWSPIdelay(2);
  thermocouple.setOffset(TC_OFFSET_C);
  delay(500);  // MAX6675 needs ~200 ms after power-up before its first conversion
#else
  dht.setup(DHT_PIN, DHTesp::DHT22);
#endif

  loadConfig();
  Serial.printf("\n[BOOT] %s — full post-quantum handshake node\n", DEVICE_ID);
  Serial.printf("[BOOT] sensor %s\n", SENSOR_NAME);
  Serial.printf("[BOOT] wifi   \"%s\" (%s)\n", g_ssid, g_wifi_saved ? "saved" : "compiled default");
  Serial.printf("[BOOT] server %s (%s)\n", g_server, g_server_saved ? "saved" : "compiled default");
  Serial.println("[BOOT] type 'help' to change WiFi/server without reflashing");

  // persistent(false): the credentials live in our own NVS namespace, so the
  // WiFi driver need not rewrite its copy to flash on every join. Reconnects
  // are ours too (serviceWifi), so the driver's own retry cannot race them.
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  beginWifi();
  Serial.printf("[NET] Joining \"%s\"...\n", g_ssid);
}

void loop() {
  static uint32_t lastSample = 0;
  static int failures = 0;

  serviceSerial();
  serviceWifi();
  if (WiFi.status() != WL_CONNECTED) { showFault(); delay(10); return; }
  if (!g_have_key) {
    showFault();
    failures = 0;
    startHandshake();  // no-op while one is already running
    delay(10);
    return;
  }
  if (millis() - lastSample < SAMPLE_PERIOD_MS) { delay(10); return; }
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
      invalidateSession();  // the next pass starts it
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
