"""Statistically rigorous crypto/protocol primitive benchmark.

Extends what bench.py already measures (ML-KEM-768, ML-DSA-65, AES-256-GCM)
-- it does not replace bench.py, which RESEARCH.md's published numbers cite
directly. This script adds what the research track's benchmarking sections
ask for and bench.py does not do: full statistics (mean/median/stdev/min/max
plus p50/p90/p95/p99/p99.9), configurable N, and every raw sample written to
disk rather than only the median and p95 printed to the terminal.

Default N follows the parent research brief: 1000 for lightweight operations
(AES-GCM, ML-KEM encapsulate/decapsulate, ML-DSA verify, HKDF), 100 for
expensive ones (ML-KEM/ML-DSA keygen, ML-DSA sign -- sign in particular is
slow enough, and variable enough due to rejection sampling, that 1000 rounds
would take minutes for no added statistical value the 100-round p99 doesn't
already show).

Run: python -m scripts.bench_crypto [--rounds-light N] [--rounds-heavy N]
"""

import argparse
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import identity, pqc
from scripts.bench_common import print_stats_table, stats, write_raw_csv, write_summary_json

ROUNDS_LIGHT = 1000
ROUNDS_HEAVY = 100


def timed_samples(fn, rounds):
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds-light", type=int, default=ROUNDS_LIGHT)
    parser.add_argument("--rounds-heavy", type=int, default=ROUNDS_HEAVY)
    args = parser.parse_args()

    ek, dk = pqc.generate_keypair()
    _, kem_ct = pqc.encapsulate(ek, pqc.LINK_SENSOR)
    pk, sk = identity.generate_identity()
    message = identity.handshake_transcript("sensor", ek, kem_ct)
    sig = identity.sign(sk, message)
    aes_key = os.urandom(32)
    payload = b'{"temperature": 30.12, "humidity": 55.00}'
    nonce = os.urandom(12)
    sealed = AESGCM(aes_key).encrypt(nonce, payload, None)
    shared_secret = os.urandom(32)

    ops = [
        ("ML-KEM-768 keygen", pqc.generate_keypair, args.rounds_heavy),
        ("ML-KEM-768 encapsulate", lambda: pqc.encapsulate(ek, pqc.LINK_SENSOR), args.rounds_light),
        ("ML-KEM-768 decapsulate", lambda: pqc.decapsulate(dk, kem_ct, pqc.LINK_SENSOR), args.rounds_light),
        ("ML-DSA-65 keygen", identity.generate_identity, args.rounds_heavy),
        ("ML-DSA-65 sign", lambda: identity.sign(sk, message), args.rounds_heavy),
        ("ML-DSA-65 verify", lambda: identity.verify(pk, message, sig), args.rounds_light),
        ("AES-256-GCM seal", lambda: AESGCM(aes_key).encrypt(os.urandom(12), payload, None), args.rounds_light),
        ("AES-256-GCM open", lambda: AESGCM(aes_key).decrypt(nonce, sealed, None), args.rounds_light),
        ("HKDF-SHA256 derive",
         lambda: HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=pqc.LINK_SENSOR).derive(shared_secret),
         args.rounds_light),
    ]

    results = []
    for label, fn, rounds in ops:
        samples = timed_samples(fn, rounds)
        s = stats(samples)
        results.append((label, s))
        write_raw_csv(
            "crypto_latency",
            [{"operation": label, "sample_index": i, "ms": v} for i, v in enumerate(samples)],
            fieldnames=["operation", "sample_index", "ms"],
        )

    print_stats_table(results)

    summary_path = write_summary_json("crypto_latency_summary", {
        label: s for label, s in results
    })
    print(f"\nraw samples -> results/raw/crypto_latency.csv")
    print(f"summary     -> {summary_path.relative_to(summary_path.parents[2])}")


if __name__ == "__main__":
    main()
