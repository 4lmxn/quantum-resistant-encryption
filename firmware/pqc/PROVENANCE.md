# Provenance

- **Upstream:** PQClean (https://github.com/PQClean/PQClean), `master`.
- **Schemes:** `crypto_kem/ml-kem-768/clean` (FIPS 203), `crypto_sign/ml-dsa-65/clean` (FIPS 204).
- **Shared:** `common/fips202.c` (SHA-3 / SHAKE), `common/compat.h`.
- **Local:** `randombytes.c` — ESP32 `esp_random()` on device, `/dev/urandom` on host.
- **Modifications:** ML-DSA files carry a `d_` filename prefix (and matching include
  paths) so ML-KEM and ML-DSA coexist in one flat Arduino `src/` directory. No
  algorithmic changes.
- **Interop:** verified byte-for-byte against `kyber-py` and `dilithium-py` by
  `tests/test_pqc_interop.py` (`make pqc-interop`).
