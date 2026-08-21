"""Move the server's ML-DSA-65 signing key from the file into the HSM.

Reads the enrolled server secret from the identities file, stores it in the
configured PKCS#11 token, and -- with --scrub -- removes it from the file so the
signing key exists only inside the HSM behind its PIN.

    export SIS_HSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so
    export SIS_HSM_TOKEN=sis01-server
    export SIS_HSM_PIN=2415
    python -m scripts.hsm_import            # copy into the HSM
    python -m scripts.hsm_import --scrub     # copy in, then wipe it from the file
"""

import json
import sys

from app import keystore
from app.identity import IdentityRegistry


def main(argv):
    if not keystore.hsm_configured():
        print("Set SIS_HSM_MODULE, SIS_HSM_TOKEN and SIS_HSM_PIN first.", file=sys.stderr)
        return 2

    registry = IdentityRegistry()
    # Read the secret straight from the file, not through the HSM-aware registry,
    # so importing is always "file -> HSM" and never a no-op that re-stores what
    # the HSM already holds.
    raw = json.loads(registry.path.read_text())
    file_secret_hex = raw["server"].get("secret", "")
    if not file_secret_hex:
        print("The identities file has no server secret to import. Either it is "
              "already scrubbed (key is in the HSM) or you need `make enroll`.",
              file=sys.stderr)
        return 1
    secret = bytes.fromhex(file_secret_hex)

    keystore.store_server_secret(secret)
    import os
    print(f"Server signing key ({len(secret)} bytes) stored in token "
          f"'{os.environ['SIS_HSM_TOKEN']}'.")

    if "--scrub" in argv:
        registry.save(secret_hex="")
        # confirm the file no longer carries it
        raw = json.loads(registry.path.read_text())
        assert raw["server"]["secret"] == ""
        print(f"Scrubbed the secret from {registry.path}. The key now lives only in the HSM.")
    else:
        print("The file still holds a copy. Re-run with --scrub to remove it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
