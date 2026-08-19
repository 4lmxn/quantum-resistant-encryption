"""CLI runner for the quantum attack demonstration.

Stage 1 is narration; stages 2 and 3 are real. The stage logic lives in
attacks.py so the dashboard buttons run exactly the same code.
"""

import socketio

from app.attacks import attacks
from app.config import SERVER_URL

sio = socketio.Client()
intercepted = {}


def log(log_type, msg):
    sio.emit("relay_log", {"type": log_type, "msg": msg})
    print(f"[{log_type}] {msg}")


@sio.on("pqc_public_key")
def on_public_key(data):
    intercepted["encapsulation_key"] = bytes.fromhex(data["encapsulation_key"])


def obtain_public_key():
    """The server refuses unknown roles, so the attacker impersonates a sensor.
    Note what this does NOT give it: this is the attacker's own handshake, not
    the real sensor's session."""
    sio.emit("pqc_hello", {"role": "sensor"})
    for _ in range(50):
        if "encapsulation_key" in intercepted:
            return intercepted["encapsulation_key"]
        sio.sleep(0.1)
    return None


def launch_quantum_attack_sequence():
    sio.connect(SERVER_URL)
    def report(identifier, status, confidence, evidence, outcome):
        meta = attacks.describe(identifier)
        print(f"\n  {meta.get('name', identifier)}  [{meta.get('severity','-')}]")
        print(f"    status     : {status}  ({confidence})")
        print(f"    target     : {meta.get('target','-')}")
        print(f"    evidence   : {evidence}")
        print(f"    outcome    : {outcome}")
        print(f"    mitigation : {meta.get('mitigation','-')}\n")

    attacks.run_all(
        log=log,
        sleep=sio.sleep,
        report=report,
        obtain_public_key=obtain_public_key,
        deliver=lambda packet: sio.emit("mitm_inject", packet),
    )
    sio.disconnect()


if __name__ == "__main__":
    launch_quantum_attack_sequence()
