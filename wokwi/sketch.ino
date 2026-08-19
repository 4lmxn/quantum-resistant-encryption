/*
 * Quantum-Resistant IoT — constrained sensor node (ESP32 + DHT22 + relay).
 *
 * Reads a real DHT22, seals the reading with AES-256-GCM using the ESP32's
 * hardware crypto via mbedtls, and POSTs it to the Flask server. The server
 * decrypts, compares against the threshold, and answers with the relay state.
 *
 * The ML-KEM-768 handshake runs on the Python nodes, not here: this board uses
 * its provisioned key (DEVICE_PSK in config.py). Both must match exactly.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <DHTesp.h>
#include "mbedtls/gcm.h"

// Wokwi's built-in network. Open password, channel 6 — connects in ~1s.
static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASS = "";

// Pick ONE, depending on how the board reaches your server:
//
//  Free Wokwi account  -> expose the server with a tunnel (cloudflared / ngrok)
//                         and paste the https URL here. Uses the public gateway.
//  Paid Wokwi Club     -> "http://host.wokwi.internal:5001/telemetry" with the
//                         private gateway (wokwigw) running on your machine.
//  Real ESP32 hardware -> your machine's LAN IP, e.g. http://192.168.1.7:5001/telemetry
static const char *TELEMETRY_URL = "https://REPLACE-ME.trycloudflare.com/telemetry";

// Must be byte-identical to DEVICE_PSK in config.py (32 bytes, AES-256).
static const uint8_t DEVICE_PSK[32] = {
    'e', 's', 'p', '3', '2', '_', 'p', 'r', 'o', 'v', 'i', 's', 'i', 'o', 'n', 'e',
    'd', '_', 'a', 'e', 's', '2', '5', '6', '_', 'k', 'e', 'y', '_', '3', '2', 'B'};

static const int DHT_PIN = 15;
static const int RELAY_PIN = 26;
static const int FAN_LED_PIN = 27;

static const size_t NONCE_LEN = 12;  // 96-bit GCM nonce
static const size_t TAG_LEN = 16;

DHTesp dht;

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

static void setRelay(bool on) {
  digitalWrite(RELAY_PIN, on ? HIGH : LOW);
  digitalWrite(FAN_LED_PIN, on ? HIGH : LOW);
}

void setup() {
  Serial.begin(115200);
  // The serial monitor attaches after boot, so output in the first moments is
  // routinely lost. Without this pause a working sketch can look completely dead.
  delay(2000);
  Serial.println();
  Serial.println("========================================");
  Serial.println("[BOOT] Quantum-Resistant IoT sensor node");
  Serial.printf("[BOOT] Target: %s\n", TELEMETRY_URL);
  Serial.println("========================================");

  pinMode(RELAY_PIN, OUTPUT);
  pinMode(FAN_LED_PIN, OUTPUT);
  setRelay(false);
  dht.setup(DHT_PIN, DHTesp::DHT22);

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

void loop() {
  TempAndHumidity reading = dht.getTempAndHumidity();
  if (dht.getStatus() != DHTesp::ERROR_NONE) {
    Serial.printf("[SENSOR] DHT22 error: %s\n", dht.getStatusString());
    delay(2000);
    return;
  }

  char plaintext[96];
  snprintf(plaintext, sizeof(plaintext), "{\"temperature\": %.2f, \"humidity\": %.2f}",
           reading.temperature, reading.humidity);

  char nonceHex[NONCE_LEN * 2 + 1];
  char cipherHex[(192) * 2 + 1];
  if (!sealPayload(plaintext, nonceHex, cipherHex)) {
    delay(4000);
    return;
  }

  char body[600];
  snprintf(body, sizeof(body), "{\"nonce\":\"%s\",\"ciphertext\":\"%s\"}", nonceHex,
           cipherHex);

  HTTPClient http;
  if (strncmp(TELEMETRY_URL, "https:", 6) == 0) {
    // setInsecure() skips certificate validation. Acceptable here only because
    // the payload is already sealed with AES-256-GCM end to end, so TLS is
    // defence in depth rather than the thing protecting the telemetry.
    static WiFiClientSecure secureClient;
    secureClient.setInsecure();
    http.begin(secureClient, TELEMETRY_URL);
  } else {
    http.begin(TELEMETRY_URL);
  }
  http.addHeader("Content-Type", "application/json");
  int status = http.POST((uint8_t *)body, strlen(body));

  if (status == 200) {
    Serial.printf("[NODE] Sealed %.2fC / %.2f%% -> server accepted\n",
                  reading.temperature, reading.humidity);
    // The server owns the threshold decision; the node just mirrors it locally
    // so the relay reacts even before the actuator node is told.
    String response = http.getString();
    int idx = response.indexOf("\"threshold\":");
    if (idx >= 0) {
      setRelay(reading.temperature > response.substring(idx + 12).toFloat());
    }
  } else {
    Serial.printf("[NODE] POST failed, HTTP %d (%s)\n", status,
                  http.errorToString(status).c_str());
  }
  http.end();

  delay(4000);
}
