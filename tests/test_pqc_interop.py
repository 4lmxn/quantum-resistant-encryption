"""Cross-implementation known-answer test: the vendored C interoperates with the
Python server. Run: python -m tests.test_pqc_interop

The firmware runs PQClean's ML-KEM-768 and ML-DSA-65 (vendored in firmware/pqc);
the server runs kyber-py and dilithium-py. For the constrained node to speak to
the server on real hardware, those two independent implementations must agree
byte for byte. This compiles the C harnesses on the host and proves they do:

  * C encapsulates against a kyber-py public key  -> kyber-py recovers the same secret
  * dilithium-py signs                            -> C verifies
  * C signs                                       -> dilithium-py verifies

It needs a C compiler (cc/gcc). If none is present the test skips rather than
fails, so it never blocks a machine without a toolchain.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "firmware" / "pqc" / "src"
TEST = ROOT / "firmware" / "pqc" / "test"
CC = shutil.which("cc") or shutil.which("gcc")

# ml-kem translation units (un-prefixed) and ml-dsa (d_ prefixed), sharing fips202.
KEM_TUS = ["kem.c", "indcpa.c", "poly.c", "polyvec.c", "ntt.c", "reduce.c",
           "cbd.c", "symmetric-shake.c", "verify.c"]
DSA_TUS = ["d_sign.c", "d_packing.c", "d_poly.c", "d_polyvec.c", "d_ntt.c",
           "d_reduce.c", "d_rounding.c", "d_symmetric-shake.c"]
SHARED = ["fips202.c", "randombytes.c"]


def _build(out, main_src, tus):
    cmd = [CC, "-O2", f"-I{SRC}", "-o", out, str(main_src)]
    cmd += [str(SRC / t) for t in tus + SHARED]
    subprocess.run(cmd, check=True, capture_output=True)


def _skip_if_no_cc():
    if CC is None:
        print("SKIP (no C compiler found)")
        sys.exit(0)


def test_mlkem_c_encaps_interops_with_kyber_py():
    _skip_if_no_cc()
    from kyber_py.ml_kem import ML_KEM_768
    with tempfile.TemporaryDirectory() as d:
        binp = os.path.join(d, "kemenc")
        _build(binp, TEST / "kem_enc.c", KEM_TUS)
        ek, dk = ML_KEM_768.keygen()
        out = subprocess.run([binp, ek.hex()], capture_output=True, text=True, check=True)
        ct_hex, ss_c_hex = out.stdout.strip().splitlines()
        ss_py = ML_KEM_768.decaps(dk, bytes.fromhex(ct_hex))
        assert bytes.fromhex(ss_c_hex) == ss_py, "C encaps and kyber-py decaps disagree"


def test_mldsa_interop_both_directions():
    _skip_if_no_cc()
    from dilithium_py.ml_dsa import ML_DSA_65
    with tempfile.TemporaryDirectory() as d:
        binp = os.path.join(d, "dsa")
        _build(binp, TEST / "dsa_signverify.c", DSA_TUS)
        msg = b"quantum-iot/v1|sensor|" + b"\xab" * 32
        pk, sk = ML_DSA_65.keygen()

        # dilithium-py signs -> C verifies
        sig_py = ML_DSA_65.sign(sk, msg)
        r = subprocess.run([binp, "verify", pk.hex(), msg.hex(), sig_py.hex()],
                           capture_output=True, text=True, check=True)
        assert r.stdout.strip() == "OK", "C could not verify a dilithium-py signature"

        # C signs -> dilithium-py verifies
        r2 = subprocess.run([binp, "sign", sk.hex(), msg.hex()],
                            capture_output=True, text=True, check=True)
        sig_c = bytes.fromhex(r2.stdout.strip())
        assert ML_DSA_65.verify(pk, msg, sig_c), "dilithium-py could not verify a C signature"


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
