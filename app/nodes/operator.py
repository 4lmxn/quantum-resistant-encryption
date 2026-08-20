"""Operator console — the only way to change what the safety function does.

The dashboard is a view. It can show the plant, but it cannot move the trip
setpoint, clear a latched trip, or assert a maintenance bypass, because a
browser has nowhere safe to keep a signing key. Those actions come from here,
signed with an enrolled operator's ML-DSA-65 key.

    python -m app.nodes.operator setpoint 85
    python -m app.nodes.operator reset
    python -m app.nodes.operator bypass on

Run `make enroll` first; without an operator key this refuses to send anything,
rather than sending something the server would only reject.
"""

import argparse
import os
import sys
import time

import socketio

from app import identity
from app.config import SERVER_URL

OPERATOR_ID = os.environ.get("OPERATOR_ID", "operator-01")

_key_dir = identity.REGISTRY_PATH.parent / "identities"
_secret_path = _key_dir / f"{OPERATOR_ID}.key"
OPERATOR_SECRET = _secret_path.read_bytes() if _secret_path.exists() else None


def build_command(action, value=None):
    """Signs one control action over every field that gives it meaning."""
    nonce_hex = os.urandom(16).hex()
    timestamp = int(time.time())
    transcript = identity.operator_transcript(
        OPERATOR_ID, action, value, nonce_hex, timestamp
    )
    return {
        "operator_id": OPERATOR_ID,
        "action": action,
        "value": value,
        "nonce": nonce_hex,
        "timestamp": timestamp,
        "signature": identity.sign(OPERATOR_SECRET, transcript).hex(),
    }


def send(action, value=None):
    """Connects, sends one signed command, waits briefly for the server's reply.

    The server answers on the broadcast security log rather than to this client
    specifically, so the wait is what lets the acceptance or the refusal reach
    the terminal before the process exits.
    """
    client = socketio.Client()
    verdicts = []

    @client.on("security_log")
    def on_log(entry):
        msg = entry.get("msg", "")
        if "[SIS]" in msg:
            print(f"  {entry.get('type', ''):<8} {msg}")
            if "REFUSED" in msg or "Refused" in msg:
                verdicts.append(False)
            elif "signed by" in msg or "reset by" in msg or "bypass" in msg.lower():
                verdicts.append(True)

    client.connect(SERVER_URL)
    print(f"[OPERATOR] {OPERATOR_ID} sending {action}"
          f"{f' = {value}' if value is not None else ''}, signed with ML-DSA-65.")
    client.emit("operator_command", build_command(action, value))
    client.sleep(1.5)
    client.disconnect()

    # No verdict at all is a failure too — it means nothing on the server
    # recognised the command, which must not read as success.
    return 0 if verdicts and all(verdicts) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Signed operator console for the SIS")
    sub = parser.add_subparsers(dest="action", required=True)

    setpoint = sub.add_parser("setpoint", help="move the trip setpoint")
    setpoint.add_argument("value", type=float)
    sub.add_parser("reset", help="clear a latched trip")
    bypass = sub.add_parser("bypass", help="assert or clear the maintenance bypass")
    bypass.add_argument("state", choices=["on", "off"])

    args = parser.parse_args(argv)

    if OPERATOR_SECRET is None:
        print(f"No signing key for {OPERATOR_ID} at {_secret_path}.")
        print("Run: make enroll")
        return 2

    if args.action == "setpoint":
        return send("SET_SETPOINT", args.value)
    if args.action == "reset":
        return send("RESET")
    return send("BYPASS_ON" if args.state == "on" else "BYPASS_OFF")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
