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

# An operator is just another enrolled identity. Control actions that move the
# trip setpoint or clear a latched trip must be signed by one of these, so the
# dashboard alone can no longer change what the safety function does.
OPERATOR_IDS = ["operator-01"]
KEY_DIR = PROJECT_ROOT / "identities"


def main():
    registry = IdentityRegistry()
    wanted = DEVICE_IDS + OPERATOR_IDS
    forcing = "--force" in sys.argv
    KEY_DIR.mkdir(exist_ok=True)

    if registry.server_public and not forcing:
        # Adding an identity must not cost every existing one its key. Enrolling
        # a new operator after the devices are already provisioned is the normal
        # case, not an exception, so enrol only what is missing.
        missing = [i for i in wanted if not registry.is_enrolled(i)]
        if not missing:
            print("Every identity is already enrolled. Nothing to do.")
            print("Use --force to regenerate all of them, which invalidates every device.")
            return 0
        secrets = registry.enrol_additional(missing)
        for identifier, secret in secrets.items():
            path = KEY_DIR / f"{identifier}.key"
            path.write_bytes(secret)
            os.chmod(path, 0o600)
            print(f"Enrolled {identifier:<14} secret {path}")
        print(f"\nServer identity untouched. {len(missing)} identity(ies) added.")
        return 0

    secrets = registry.bootstrap(wanted)

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
    print("Enrolled operators:")
    for operator_id in OPERATOR_IDS:
        print(f"  {operator_id:<14} secret {KEY_DIR / (operator_id + '.key')}")
    from app.config import DEVICE_PSK, _PSK_PATH
    print(f"\nESP32 provisioning key ({_PSK_PATH}):")
    print(f"  {DEVICE_PSK.hex()}")
    print("  Flash this into a real board; the Python simulator reads it from the file.")
    print("\nEach device now holds its own signing key and the server's public key.")
    print("A device without both cannot complete a handshake.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
