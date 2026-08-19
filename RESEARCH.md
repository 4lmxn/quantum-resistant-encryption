# Research extension — authenticated post-quantum handshake

This branch closes the two structural gaps the main branch documents, and states
what remains against current literature.

## What the base system could not do

Two limitations on `main` shared one root cause: the ML-KEM handshake proves that
nobody *observed* the exchange, but says nothing about *who* was on the other end.

1. **No device authentication.** A client asserting `role: "actuator"` completed a
   handshake and decrypted real commands. Verified by attacking the running system —
   the rogue client printed `{'command': 'FAN_ON', ...}` in plaintext.
2. **Unauthenticated key exchange.** An adversary present from the first packet could
   run one handshake with each side and relay between them.

## What this branch adds

**ML-DSA-65 (NIST FIPS 204)** signatures on both halves of the handshake.

- The server holds a long-term signing key and signs the encapsulation key it offers.
  A node that cannot verify that signature disconnects rather than continuing.
- Each device holds its own key, enrolled out of band by `make enroll`, and signs its
  KEM ciphertext. The server refuses any handshake it cannot attribute to an enrolled
  device.
- The signed transcript binds the protocol version, the role, the encapsulation key and
  the KEM ciphertext, so a signature captured from one handshake cannot be replayed into
  another, and a sensor's signature cannot be reused to enrol as an actuator.

ML-DSA rather than a classical signature is deliberate: signing a post-quantum key
exchange with RSA or ECDSA reintroduces exactly the weakness ML-KEM removes, since an
adversary able to forge the signature can substitute their own encapsulation key.

Parameter sets are matched at NIST security category 3 — ML-KEM-768 with ML-DSA-65 —
so neither primitive is the weak link.

### Verified

`tests/test_identity.py` asserts each property directly: an enrolled device is accepted,
an unenrolled one is refused, one device cannot impersonate another, a signature is bound
to its role and to the offered key, a forged server offer is rejected, and a malformed
signature is a rejection rather than a crash.

Against the running system, the rogue-actuator attack that previously decrypted commands
now receives **zero**.

## Measured cost

From `make bench`, median over 60 rounds:

| Operation | Median | p95 | Bytes on wire |
|---|---|---|---|
| ML-KEM-768 keygen | 1.93 ms | 1.96 ms | 3,584 |
| ML-KEM-768 encapsulate | 2.59 ms | 2.63 ms | 1,088 |
| ML-KEM-768 decapsulate | 3.51 ms | 3.79 ms | — |
| ML-DSA-65 keygen | 5.71 ms | 5.77 ms | 5,984 |
| ML-DSA-65 sign | 41.61 ms | 96.82 ms | 3,309 |
| ML-DSA-65 verify | 6.44 ms | 6.60 ms | — |
| AES-256-GCM seal | 0.003 ms | 0.003 ms | 69 |

Authenticated handshake ≈ **56 ms**, **8,890 bytes**. Steady-state overhead per telemetry
message is unchanged at **28 bytes** (12-byte nonce, 16-byte tag).

Two honest caveats. These are pure-Python reference implementations; optimised C
(liboqs, pqm4) is roughly two orders of magnitude faster, so these figures are an upper
bound rather than a deployment estimate. And signing shows a wide median-to-p95 spread
(41 → 97 ms) because ML-DSA uses rejection sampling — the number of attempts varies per
signature. That variance is inherent to the scheme, not measurement noise.

## What still stands, and why

**Long-term signing keys have no forward secrecy.** Session keys rotate per connection;
identity keys do not. Extracting a device's signing key permits impersonation until
re-enrolment, and there is no revocation mechanism here.

**Single-family cryptographic risk.** ML-KEM and ML-DSA both rest on structured lattices,
so a break in that family removes key exchange and authentication together. NIST selected
**HQC** in March 2025 as a backup KEM built on code-based mathematics for exactly this
reason. A hybrid ML-KEM + HQC construction is the natural next step and would remove the
single point of failure. SLH-DSA (FIPS 205), being hash-based, is the equivalent hedge on
the signature side.

**No side-channel resistance.** Reference implementations in Python are not constant-time.
Lattice schemes are known to be sensitive to timing and power analysis on embedded targets;
production work needs a hardened implementation.

**Energy cost unmeasured on real hardware.** The figures above are from a laptop. Published
work on embedded post-quantum energy profiling indicates key generation dominates the power
budget for duty-cycled battery nodes — the case this project targets. Our numbers do not
capture that, and the ESP32 leg deliberately avoids the handshake for this reason.

## References

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), finalised August 2024.
- NIST selection of HQC as a backup key-encapsulation mechanism, March 2025.
- Energy consumption analysis of post-quantum key generation on embedded devices,
  arXiv:2505.16614.
