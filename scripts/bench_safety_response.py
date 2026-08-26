"""Cyber-physical safety-response latency: sensor event -> SIS-01 detection ->
trip decision -> actuator command -> XV-101 CLOSED.

Requires a live server (`make server`). Connects two real Socket.IO clients
-- one completing the sensor handshake, one completing the actuator handshake
-- over real TCP to that server process, exactly as `app/nodes/sensor.py` and
`app/nodes/actuator.py` do. This script does not import those modules
directly: both register an auto-streaming background task on handshake
completion (`stream_telemetry` / the watchdog loop), which would race with
this script's precisely-timed, one-reading-per-trial sends. So the handshake
logic is duplicated here in a minimal form, matching the same wire protocol
`app/server.py` expects (same functions from app.pqc / app.identity).

WHAT THIS MEASURES, EXACTLY: T_TOTAL = the wall-clock interval between this
script emitting one over-setpoint reading and this script's own actuator
handler finishing the CLOSED transition, using ONE process's perf_counter()
for both timestamps (both the sensor and actuator clients live in this one
script), so the number is a genuine, comparable duration -- not two
processes' independent clocks subtracted from each other.

WHAT THIS DOES NOT MEASURE: the parent research brief's T_sensor / T_network_in
/ T_crypto / T_logic / T_network_out / T_actuator breakdown. Splitting T_TOTAL
into those six components needs a timestamp injected partway through
app/server.py's own processing, which this phase deliberately does not add
(no changes to app/server.py in this pass). Reported as NOT MEASURED, not
estimated by assumption.

Run: python -m scripts.bench_safety_response [--trials N] [--load idle|cpu]
"""

import argparse
import json
import multiprocessing
import os
import threading
import time

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity
from app.config import SERVER_URL
from app.pqc import LINK_ACTUATOR, LINK_SENSOR, encapsulate, key_fingerprint
from scripts.bench_common import print_stats_table, stats, write_raw_csv, write_summary_json

TRIALS = 100
OVER_SETPOINT_C = 150.0  # above SETPOINT_MAX_C (120), trips regardless of current setpoint
TRIAL_TIMEOUT_S = 5.0

_KEY_DIR = identity.REGISTRY_PATH.parent / "identities"
OPERATOR_ID = os.environ.get("OPERATOR_ID", "operator-01")


def _load_secret(device_id):
    path = _KEY_DIR / f"{device_id}.key"
    return path.read_bytes() if path.exists() else None


def _require(path_bytes, what):
    if path_bytes is None:
        raise SystemExit(f"Missing {what}. Run: make enroll")
    return path_bytes


SERVER_PUBLIC = _require(
    (_KEY_DIR / "server.pub").read_bytes() if (_KEY_DIR / "server.pub").exists() else None,
    "identities/server.pub")


def handshake(role, device_id, link_label, timeout=5.0):
    """Completes the real ML-KEM-768 + ML-DSA-65 handshake. Returns
    (client, session_key). Raises on refusal or timeout."""
    client = socketio.Client()
    secret = _require(_load_secret(device_id), f"identities/{device_id}.key")
    state = {"key": None, "error": None}
    established = threading.Event()

    @client.on("pqc_public_key")
    def _on_pubkey(data):
        ek = bytes.fromhex(data["encapsulation_key"])
        if data.get("authenticated"):
            transcript = identity.handshake_transcript(role, ek)
            server_sig = bytes.fromhex(data.get("server_signature", "") or "")
            if not identity.verify(SERVER_PUBLIC, transcript, server_sig):
                state["error"] = "server signature invalid"
                established.set()
                return
        session_key, ct = encapsulate(ek, link_label)
        state["key"] = bytearray(session_key)
        client.emit("pqc_encapsulation", {
            "kem_ciphertext": ct.hex(),
            "key_fingerprint": key_fingerprint(session_key),
            "device_id": device_id,
            "device_signature": identity.sign(
                secret, identity.handshake_transcript(role, ek, ct)).hex(),
        })

    @client.on("pqc_refused")
    def _on_refused(data):
        state["error"] = data.get("reason", "refused")
        established.set()

    @client.on("pqc_established")
    def _on_established(_data):
        established.set()

    client.connect(SERVER_URL)
    client.emit("pqc_hello", {"role": role})
    if not established.wait(timeout):
        raise RuntimeError(f"{role} handshake timed out")
    if state["error"]:
        raise RuntimeError(f"{role} handshake refused: {state['error']}")
    return client, state["key"]


def seal_telemetry(session_key, temperature):
    nonce = os.urandom(12)
    payload = f'{{"temperature": {temperature}, "humidity": 50.0}}'.encode()
    ciphertext = AESGCM(bytes(session_key)).encrypt(nonce, payload, None)
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


def sign_operator(action, value=None):
    nonce_hex = os.urandom(16).hex()
    timestamp = int(time.time())
    secret = _require(_load_secret(OPERATOR_ID), f"identities/{OPERATOR_ID}.key")
    transcript = identity.operator_transcript(OPERATOR_ID, action, value, nonce_hex, timestamp)
    return {
        "operator_id": OPERATOR_ID, "action": action, "value": value,
        "nonce": nonce_hex, "timestamp": timestamp,
        "signature": identity.sign(secret, transcript).hex(),
    }


def _cpu_burn():
    x = 0
    while True:
        x = (x * 2654435761 + 1) & 0xFFFFFFFF


def run_trials(n, condition):
    sensor_client, sensor_key = handshake("sensor", "sensor-01", LINK_SENSOR)
    actuator_client, actuator_key = handshake("actuator", "actuator-01", LINK_ACTUATOR)
    operator_client = socketio.Client()
    operator_client.connect(SERVER_URL)

    healthy = threading.Event()

    @operator_client.on("sis_state")
    def _on_state(data):
        if data.get("trip_state") == "HEALTHY":
            healthy.set()
        else:
            healthy.clear()

    trial_closed = threading.Event()
    received_at = {}

    @actuator_client.on("execute_actuator_command")
    def _on_command(packet):
        aesgcm = AESGCM(bytes(actuator_key))
        body = json.loads(aesgcm.decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), None))
        t = time.perf_counter()
        if body.get("command") == "TRIP":
            received_at["t"] = t
            trial_closed.set()

    workers = []
    if condition == "cpu":
        for _ in range(multiprocessing.cpu_count()):
            p = multiprocessing.Process(target=_cpu_burn, daemon=True)
            p.start()
            workers.append(p)

    try:
        # Ensure a known-HEALTHY starting state before trial 1.
        healthy.clear()
        operator_client.emit("operator_command", sign_operator("RESET"))
        if not healthy.wait(TRIAL_TIMEOUT_S):
            raise RuntimeError("could not confirm HEALTHY before starting trials")

        samples = []
        misses = 0
        for i in range(n):
            trial_closed.clear()
            received_at.clear()
            start = time.perf_counter()
            sensor_client.emit("sensor_telemetry_event",
                                seal_telemetry(sensor_key, OVER_SETPOINT_C))
            if trial_closed.wait(TRIAL_TIMEOUT_S):
                samples.append((received_at["t"] - start) * 1000)
            else:
                misses += 1

            healthy.clear()
            operator_client.emit("operator_command", sign_operator("RESET"))
            if not healthy.wait(TRIAL_TIMEOUT_S):
                raise RuntimeError(f"trial {i}: RESET not confirmed within {TRIAL_TIMEOUT_S}s")

        return samples, misses
    finally:
        for p in workers:
            p.terminate()
        sensor_client.disconnect()
        actuator_client.disconnect()
        operator_client.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=TRIALS)
    parser.add_argument("--load", choices=["idle", "cpu"], default="idle",
                         help="idle: nothing competing for CPU. "
                              "cpu: cpu_count() busy-loop processes running throughout.")
    args = parser.parse_args()

    print(f"[bench_safety_response] {args.trials} trials, load={args.load}, "
          f"server={SERVER_URL} -- server must already be running (make server)")

    samples, misses = run_trials(args.trials, args.load)
    if not samples:
        raise SystemExit("every trial missed its timeout -- no data to report")

    s = stats(samples)
    print_stats_table([(f"safety-response T_TOTAL ({args.load})", s)])
    if misses:
        print(f"\n{misses}/{args.trials} trials MISSED (no TRIP observed within "
              f"{TRIAL_TIMEOUT_S}s) -- excluded from the statistics above, counted below.")

    write_raw_csv(
        f"safety_response_{args.load}",
        [{"trial": i, "ms": v} for i, v in enumerate(samples)],
        fieldnames=["trial", "ms"],
    )
    write_summary_json(f"safety_response_{args.load}_summary", {
        "condition": args.load,
        "trials_requested": args.trials,
        "trials_completed": len(samples),
        "trials_missed": misses,
        "over_setpoint_reading_c": OVER_SETPOINT_C,
        "t_total": s,
        "t_sensor": "NOT MEASURED",
        "t_network_in": "NOT MEASURED",
        "t_crypto": "NOT MEASURED",
        "t_logic": "NOT MEASURED",
        "t_network_out": "NOT MEASURED",
        "t_actuator": "NOT MEASURED",
        "note": "T_TOTAL only. The six-way breakdown needs a timestamp "
                "injected into app/server.py's own processing, not added "
                "this phase -- see the module docstring.",
    })
    print(f"\nraw samples -> results/raw/safety_response_{args.load}.csv")
    print(f"summary     -> results/processed/safety_response_{args.load}_summary.json")


if __name__ == "__main__":
    main()
