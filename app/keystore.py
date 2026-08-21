"""Where the server's ML-DSA-65 signing key comes from.

By default the key lives in the gitignored identities file. Point the three
environment variables below at a SoftHSM (or any PKCS#11) token and the server
loads the key from the HSM instead, behind the token PIN, so the signing key is
never sitting in a plaintext file on disk.

    export SIS_HSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so
    export SIS_HSM_TOKEN=sis01-server
    export SIS_HSM_PIN=2415

No mainstream HSM does ML-DSA natively, so the key is stored as an opaque,
login-protected data object and the server signs in software with it. That
protects the key at rest without adding a classical algorithm to the security
path -- the honest position for a post-quantum system.
"""

import os

SERVER_SK_LABEL = "sis01-server-mldsa-sk"


def hsm_configured():
    return all(os.environ.get(v) for v in ("SIS_HSM_MODULE", "SIS_HSM_TOKEN", "SIS_HSM_PIN"))


def _hsm_session(rw=False):
    import pkcs11  # imported lazily so the file-backed path needs no dependency
    lib = pkcs11.lib(os.environ["SIS_HSM_MODULE"])
    token = lib.get_token(token_label=os.environ["SIS_HSM_TOKEN"])
    return token.open(user_pin=os.environ["SIS_HSM_PIN"], rw=rw)


def load_server_secret(file_hex, label=SERVER_SK_LABEL):
    """Returns the server signing secret as bytes.

    From the HSM when it is configured; otherwise from the hex string the
    identities file carried (or None if neither is available).
    """
    if hsm_configured():
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
        with _hsm_session() as s:
            objs = list(s.get_objects({
                Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}))
            if not objs:
                raise RuntimeError(
                    "SIS_HSM_* is set but the server key is not in the token. "
                    "Run: python -m scripts.hsm_import")
            return bytes(objs[0][Attribute.VALUE])
    return bytes.fromhex(file_hex) if file_hex else None


def store_server_secret(secret, label=SERVER_SK_LABEL):
    """Writes the server signing secret into the HSM (replacing any prior copy)."""
    import pkcs11
    from pkcs11 import Attribute, ObjectClass
    with _hsm_session(rw=True) as s:
        for o in s.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}):
            o.destroy()
        s.create_object({
            Attribute.CLASS: ObjectClass.DATA,
            Attribute.TOKEN: True,
            Attribute.PRIVATE: True,   # only readable after C_Login with the PIN
            Attribute.LABEL: label,
            Attribute.VALUE: secret,
        })
