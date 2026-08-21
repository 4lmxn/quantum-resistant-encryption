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
 * Then set WIFI_* and TELEMETRY_HOST below.
 *
 * ML-DSA-65 signing needs ~45 KB of stack, so the handshake runs in a dedicated
 * FreeRTOS task with a 64 KB stack, not the 8 KB Arduino loop task.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

extern "C" {
  #include "api.h"      // ML-KEM-768
  #include "d_api.h"    // ML-DSA-65
  #include "fips202.h"  // SHAKE-256
}
#include "keys.h"       // DEVICE_ID, DEVICE_SECRET, SERVER_PUBLIC  (generated, gitignored)

static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASS = "";
// Server base URL, no trailing slash. Use http on the LAN / paid Wokwi gateway.
static const char *SERVER = "http://host.wokwi.internal:5001";

static const char *ROLE = "sensor";
static const char *LINK_LABEL = "quantum-iot/sensor-link/aes256gcm";
static const char *TRANSCRIPT_PREFIX = "quantum-iot/v1|sensor|";

static const int DHT_PIN = 15;

// Sizes from the vendored PQClean headers.
#define EK_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   // 1184
#define CT_BYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  // 1088
#define SIG_BYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES             // 3309

static uint8_t g_session_key[32];
static volatile bool g_have_key = false;

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

static bool sealAndPost(float temp, float hum) {
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
  if (rc != 0) return false;
  memcpy(ct + len, tag, 16);

  char nHex[25], cHex[192 * 2 + 1];
  toHex(nonce, 12, nHex);
  toHex(ct, len + 16, cHex);
  String body = String("{\"device_id\":\"") + DEVICE_ID + "\",\"nonce\":\"" + nHex +
                "\",\"ciphertext\":\"" + cHex + "\"}";
  String r = postJson("/telemetry", body);
  return r.indexOf("accepted") >= 0;
}

// ---------------------------------------------------------------- tasks -----

static void handshakeTask(void *) {
  while (!runHandshake()) {
    Serial.println("[PQC] Handshake failed; retrying in 3s.");
    vTaskDelay(pdMS_TO_TICKS(3000));
  }
  vTaskDelete(NULL);  // done; loop() takes over telemetry
}

void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.printf("\n[BOOT] %s — full post-quantum handshake node\n", DEVICE_ID);

  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
  Serial.print("[NET] WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(200); Serial.print("."); }
  Serial.printf(" up as %s\n", WiFi.localIP().toString().c_str());

  // 64 KB stack: ML-DSA-65 signing needs ~45 KB, far past the 8 KB loop task.
  xTaskCreatePinnedToCore(handshakeTask, "pqc-handshake", 64 * 1024, NULL, 1, NULL, 1);
}

void loop() {
  if (!g_have_key) { delay(200); return; }
  // Replace with a real DHT22 read; a plausible process value keeps the demo live.
  float temp = 66.0f + (float)(esp_random() % 400) / 100.0f;
  if (sealAndPost(temp, 45.0f))
    Serial.printf("[TX] %.2fC sealed with the session key -> accepted\n", temp);
  delay(4000);
}
