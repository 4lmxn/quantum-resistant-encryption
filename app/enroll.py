"""Device enrolment — the provisioning step that anchors trust.

Creates the server's ML-DSA identity and one keypair per device, writing each
device secret to its own file. In a real deployment this happens once at
manufacture and the secret never leaves the device.

    python -m app.enroll
"""

import os
import sys

from app.config import PROJECT_ROOT
from app.identity import IdentityRegistry

DEVICE_IDS = ["sensor-01", "actuator-01", "esp32-01"]
KEY_DIR = PROJECT_ROOT / "identities"


def main():
    registry = IdentityRegistry()
    if registry.server_public and "--force" not in sys.argv:
        print("Identities already exist. Re-run with --force to replace them.")
        print("Replacing them invalidates every enrolled device.")
        return 1

    KEY_DIR.mkdir(exist_ok=True)
    secrets = registry.bootstrap(DEVICE_IDS)

    # The server's public key is what each device must be provisioned with.
    (KEY_DIR / "server.pub").write_bytes(registry.server_public)
    for device_id, secret in secrets.items():
        path = KEY_DIR / f"{device_id}.key"
        path.write_bytes(secret)
        os.chmod(path, 0o600)

    print(f"Server identity written to {registry.path}")
    print(f"Server public key       {KEY_DIR / 'server.pub'} ({len(registry.server_public)} bytes)")
    print("Enrolled devices:")
    for device_id in DEVICE_IDS:
        print(f"  {device_id:<14} secret {KEY_DIR / (device_id + '.key')}")
    print("\nEach device now holds its own signing key and the server's public key.")
    print("A device without both cannot complete a handshake.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
