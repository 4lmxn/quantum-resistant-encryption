"""The server's signing key can live in a PKCS#11 HSM instead of a file.
Run: python -m tests.test_hsm

Skips cleanly unless a SoftHSM (or other PKCS#11) token is configured, so it
never blocks a machine without one. To exercise it:

    brew install softhsm
    softhsm2-util --init-token --slot 0 --label sis01-server --so-pin 3737 --pin 2415
    export SIS_HSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so
    export SIS_HSM_TOKEN=sis01-server
    export SIS_HSM_PIN=2415
    python -m tests.test_hsm
"""

import sys

from app import identity, keystore

TEST_LABEL = "sis01-test-throwaway"  # never the real server key label


def _skip_unless_hsm():
    if not keystore.hsm_configured():
        print("SKIP (SIS_HSM_* not set)")
        sys.exit(0)
    try:
        import pkcs11  # noqa: F401
    except ImportError:
        print("SKIP (python-pkcs11 not installed)")
        sys.exit(0)


def test_store_and_load_roundtrip():
    _skip_unless_hsm()
    # a throwaway key under a throwaway label — never the real server key
    _, sk = identity.generate_identity()
    keystore.store_server_secret(sk, label=TEST_LABEL)
    got = keystore.load_server_secret(file_hex=None, label=TEST_LABEL)
    assert got == sk, "HSM did not return the key it was given"


def test_a_key_loaded_from_the_hsm_signs_verifiably():
    _skip_unless_hsm()
    pk, sk = identity.generate_identity()
    keystore.store_server_secret(sk, label=TEST_LABEL)
    loaded = keystore.load_server_secret(file_hex=None, label=TEST_LABEL)
    msg = identity.handshake_transcript("sensor", b"\x11" * 1184)
    sig = identity.sign(loaded, msg)
    assert identity.verify(pk, msg, sig), "a signature made with the HSM-loaded key did not verify"


def test_file_fallback_when_hsm_not_configured(monkeypatch=None):
    """With the env unset, the keystore uses the file hex it is handed."""
    import os
    saved = {k: os.environ.pop(k, None) for k in ("SIS_HSM_MODULE", "SIS_HSM_TOKEN", "SIS_HSM_PIN")}
    try:
        pk, sk = identity.generate_identity()
        assert keystore.load_server_secret(sk.hex()) == sk
        assert keystore.load_server_secret(None) is None
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
