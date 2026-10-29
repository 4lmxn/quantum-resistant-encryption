"""Concurrent ML-DSA-65 signing and verification stay correct.
Run: python -m tests.test_concurrent_signing

The server signs every handshake offer from a Flask-SocketIO handler thread.
dilithium-py's pure-Python SHAKE wrapper is a module-global object, so two
handshakes in the same instant used to sign through one shared XOF stream and
both nodes aborted with "server signature invalid". A tiny GIL switch interval
forces the threads to interleave inside the signer, so without the lock in
app/identity.py this fails every run rather than only under unlucky timing.
"""

import sys
import threading

from app import identity

THREADS = 3
ROUNDS = 5

_PK, _SK = identity.generate_identity()


def _run_together(work, n):
    barrier = threading.Barrier(n)
    results = [None] * n

    def run(i):
        barrier.wait()
        results[i] = work(i)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(previous)
    return results


def test_concurrent_signatures_all_verify():
    for r in range(ROUNDS):
        messages = [identity.handshake_transcript("sensor", f"ek-{r}-{i}".encode())
                    for i in range(THREADS)]
        signatures = _run_together(lambda i: identity.sign(_SK, messages[i]), THREADS)
        for message, signature in zip(messages, signatures):
            assert identity.verify(_PK, message, signature), f"round {r}: corrupt signature"


def test_verify_concurrent_with_signing_does_not_refuse_a_genuine_signature():
    # A node's ciphertext signature is verified while another handshake is
    # being signed; a corrupted verify would turn away an enrolled device.
    message = identity.handshake_transcript("actuator", b"ek", b"ct")
    genuine = identity.sign(_SK, message)
    for r in range(ROUNDS):
        results = _run_together(
            lambda i: identity.verify(_PK, message, genuine) if i % 2
            else identity.sign(_SK, message), THREADS + 1)
        verdicts = [v for i, v in enumerate(results) if i % 2]
        signatures = [s for i, s in enumerate(results) if not i % 2]
        assert all(verdicts), f"round {r}: genuine signature refused under concurrency"
        assert all(identity.verify(_PK, message, s) for s in signatures), f"round {r}"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
