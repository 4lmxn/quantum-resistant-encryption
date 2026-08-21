/*
 * On-device proof that the constrained node can run the post-quantum handshake
 * primitives: ML-KEM-768 encapsulation and ML-DSA-65 sign/verify, from the
 * vendored PQClean sources in firmware/pqc.
 *
 * These are the exact implementations whose output interoperates with the
 * server's kyber-py / dilithium-py (proven on the host by `make pqc-interop`).
 * Flash this to a real ESP32 to see the timings; it needs no network.
 */
extern "C" {
  #include "api.h"     // ML-KEM-768
  #include "d_api.h"   // ML-DSA-65
}

void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.println("\n[PQC] ESP32 self-test — ML-KEM-768 + ML-DSA-65");

  static uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
  static uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
  static uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  static uint8_t ssA[32], ssB[32];

  uint32_t t0 = millis();
  PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
  uint32_t t1 = millis();
  PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ssA, pk);   // the node's step
  uint32_t t2 = millis();
  PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ssB, ct, sk);
  uint32_t t3 = millis();
  Serial.printf("[ML-KEM-768] keygen %lums  encaps %lums  decaps %lums  secret match %d\n",
                (unsigned long)(t1 - t0), (unsigned long)(t2 - t1),
                (unsigned long)(t3 - t2), memcmp(ssA, ssB, 32) == 0);

  static uint8_t dpk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
  static uint8_t dsk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
  static uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];
  size_t siglen;
  uint8_t msg[32] = {0};

  uint32_t t4 = millis();
  PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(dpk, dsk);
  uint32_t t5 = millis();
  PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, msg, sizeof(msg), dsk);
  uint32_t t6 = millis();
  int ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, sizeof(msg), dpk);
  uint32_t t7 = millis();
  Serial.printf("[ML-DSA-65]  keygen %lums  sign %lums  verify %lums  valid %d\n",
                (unsigned long)(t5 - t4), (unsigned long)(t6 - t5),
                (unsigned long)(t7 - t6), ok == 0);
  Serial.println("[PQC] done.");
}

void loop() {}
