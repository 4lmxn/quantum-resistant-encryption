"""Measures what the post-quantum primitives actually cost.

Reports median and 95th percentile per operation, plus the bytes each one puts
on the wire. Run: python bench.py
"""

import os
import statistics
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity, legacy, pqc

ROUNDS = 60


def timed(fn, rounds=ROUNDS):
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.95) - 1]


def main():
    rows = []

    ek, dk = pqc.generate_keypair()
    _, kem_ct = pqc.encapsulate(ek, pqc.LINK_SENSOR)
    rows.append(("ML-KEM-768 keygen", *timed(pqc.generate_keypair), len(ek) + len(dk)))
    rows.append(("ML-KEM-768 encapsulate",
                 *timed(lambda: pqc.encapsulate(ek, pqc.LINK_SENSOR)), len(kem_ct)))
    rows.append(("ML-KEM-768 decapsulate",
                 *timed(lambda: pqc.decapsulate(dk, kem_ct, pqc.LINK_SENSOR)), 0))

    pk, sk = identity.generate_identity()
    message = identity.handshake_transcript("sensor", ek, kem_ct)
    sig = identity.sign(sk, message)
    rows.append(("ML-DSA-65 keygen", *timed(identity.generate_identity), len(pk) + len(sk)))
    rows.append(("ML-DSA-65 sign", *timed(lambda: identity.sign(sk, message)), len(sig)))
    rows.append(("ML-DSA-65 verify", *timed(lambda: identity.verify(pk, message, sig)), 0))

    key, payload = os.urandom(32), b'{"temperature": 30.12, "humidity": 55.00}'
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, payload, None)
    rows.append(("AES-256-GCM seal",
                 *timed(lambda: AESGCM(key).encrypt(os.urandom(12), payload, None)),
                 len(sealed) + 12))
    rows.append(("AES-256-GCM open",
                 *timed(lambda: AESGCM(key).decrypt(nonce, sealed, None)), 0))

    weak_pub, _ = legacy.generate_keypair()
    rows.append((f"RSA-{weak_pub[0].bit_length()} factorisation (attack)",
                 *timed(lambda: legacy.recover_private_key(legacy.generate_keypair()[0]), 20),
                 0))

    print(f"{'operation':<38}{'median':>10}{'p95':>10}   bytes")
    print("-" * 72)
    for name, median, p95, size in rows:
        wire = f"{size:,}" if size else "—"
        print(f"{name:<38}{median:>9.3f}ms{p95:>9.3f}ms   {wire}")

    handshake = sum(r[1] for r in rows[:2]) + rows[2][1] + rows[4][1] + rows[5][1]
    print("-" * 72)
    print(f"{'full authenticated handshake (est.)':<38}{handshake:>9.3f}ms")
    print(f"{'handshake bytes on the wire':<38}{len(ek) + len(kem_ct) + len(sig) * 2:>9,} B")
    print(f"{'per-message overhead (nonce + tag)':<38}{28:>9} B")


if __name__ == "__main__":
    main()
