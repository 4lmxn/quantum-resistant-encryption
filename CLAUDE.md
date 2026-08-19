# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A demonstrator for a quantum-resistant IoT link: a Flask-SocketIO server, a
sensor node, an actuator node, a scripted attacker, a browser dashboard, and an
ESP32 firmware leg. Session keys are agreed with **real ML-KEM-768** (NIST FIPS
203, the standardised CRYSTALS-Kyber) via the `kyber-py` package; the data
channels are AES-256-GCM.

## Running it

```bash
pip install -r requirements.txt
make server     # terminal 1 — dashboard at http://127.0.0.1:5001
make sensor     # terminal 2 — handshake, then telemetry every 4s
make actuator   # terminal 3 — handshake, then waits for FAN_ON
make attack     # terminal 4 — one-shot 3-stage attack, then exits
make test         # crypto self-check, no server needed
make test-device  # ESP32 wire-format check, server must be running
```

**Port 5001, not 5000** — macOS AirPlay Receiver squats on 5000 and answers
handshakes with a 403 that looks like a CORS bug. Host/port/URL live in
`app/config.py` only; the dashboard uses same-origin `io()` and hardcodes nothing.

## Architecture

Star topology — nodes never talk to each other. Every node begins with an
ML-KEM-768 handshake and holds no key until it finishes:

1. Node → `pqc_hello` `{role: "sensor"|"actuator"}`
2. Server does `generate_keypair()` **per node**, keeps `dk` against the sid, returns `ek` (1184 B)
3. Node `encapsulate(ek, label)` → `(aes_key, ct)`, sends `ct` (1088 B)
4. Server `decapsulate(dk, ct, label)` → identical key
5. Both `HKDF-SHA256(shared_secret, info=<link label>)` → exactly 32 bytes

`LINK_SENSOR` and `LINK_ACTUATOR` are HKDF domain separators, so the two links
can never derive the same AES key. Fresh keypair per connection means
`zeroize_key()` is a real forward-secrecy measure, not a gesture.

Wire format on both AES legs: `{"nonce": <hex, 12 B>, "ciphertext": <hex, tag appended>}`,
no AAD, fresh `os.urandom(12)` per message. The tag-appended layout is what
Python's `AESGCM.encrypt` emits and what `sketch.ino` reproduces by hand.

Flow: sensor encrypts → `sensor_telemetry_event` → server decrypts with that
sid's key → `update_telemetry` + `security_log` to the browser → if over
`TEMP_THRESHOLD`, encrypt `FAN_ON` **separately per actuator sid** and emit
`to=` that sid → actuator verifies the GCM tag → `actuator_ack_event`.

The demo's point is the failure path: a bad tag raises inside `AESGCM.decrypt`
and becomes a red `security_log`. Never swallow those or add a plaintext
fallback — the visible rejection *is* the feature.

### Nodes cannot reach the dashboard directly

A Socket.IO client emit only reaches the server. Nodes therefore send
`relay_log` / `relay_actuator_ui`, and the server re-broadcasts them as
`security_log` / `update_actuator_ui`. **Any new dashboard control or node
message needs a matching `@socketio.on` handler in `app/server.py` or it vanishes
silently.** All current controls are wired: `set_threshold`, `trigger_attack`,
`toggle_actuator_override`.

The manual override sends a properly sealed `FAN_TOGGLE`, not a bare UI flip, so
the actuator authenticates it exactly like an automatic command. The actuator
owns `relay_state` and flips it itself, so no state sync with the server exists
to drift.

### Roles are validated, deliberately

`handle_pqc_hello` rejects any role that is not exactly `sensor` or `actuator`.
An earlier version defaulted unknown roles to `actuator`, which would enrol a
stranger in `actuator_keys` and post real encrypted commands to it. Do not
reintroduce a default branch here.

### attacks.py / attack.py

Stage logic lives in `app/attacks/attacks.py` and takes plumbing callables (`log`, `sleep`,
`obtain_public_key`, `deliver`) so the CLI runner and the dashboard buttons run
one implementation rather than two that drift. `app/attacks/attack.py` supplies Socket.IO
client plumbing; `app/server.py` supplies in-process plumbing and runs stages in a
background task so the stage sleeps never block the event loop.

Stage 1 is narration — there is no classical ECDH in this system to break, so
the Shor sequence is scripted for contrast. **Stages 2 and 3 are real.** Stage 2
captures a genuine 1184-byte encapsulation key off the wire and shows that
encapsulating against it twice yields two independent secrets, so replaying
captured traffic recovers nothing. It does not pretend to run BKZ. Stage 3 sends
a forged packet through the server's `mitm_inject` handler and lets the GCM tag
reject it.

## Showing the handshake

The dashboard's **Post-Quantum Key Establishment** table is fed by `pqc_status`,
which the server broadcasts on every handshake and disconnect. Nodes send a
`key_fingerprint` (SHA-256 of their derived key, truncated) alongside the KEM
ciphertext; the server compares it with its own and shows both. Fingerprints are
one-way, so this proves agreement without putting key material on the wire —
never replace them with the key itself.

`app/nodes/device_sim.py` is the ESP32 stand-in and shares the wire format with
`firmware/sketch.ino`. Changing one means changing the other.

## The ESP32 leg

`firmware/` holds firmware, wiring and instructions. The board does a real DHT22
read and real AES-256-GCM via mbedtls, then POSTs to `/telemetry` — one HTTP
route rather than teaching a microcontroller Socket.IO.

It does **not** run the handshake. It uses `DEVICE_PSK`, a provisioned key
duplicated in `app/config.py` and `sketch.ino`; the two must match byte for byte.
This is the one remaining pre-shared key in the system and the accepted
trade-off for keeping ML-KEM off the microcontroller.

## Conventions

- Session keys are never module constants. They come from `app/pqc.py` and live in
  per-sid dicts on the server, or in a node's `bytearray` so `zeroize_key()` can
  overwrite in place.
- Every `security_log` payload is `{"type": ..., "msg": ...}` with type in
  `SUCCESS` / `ERROR` / `ALERT` / `ATTACK`; the dashboard colour-codes on it.
- Use `sio.sleep()`, never `time.sleep()`, in node loops — blocking sleep kills
  the Socket.IO ping/pong and drops the connection.
- Long-running node loops go through `sio.start_background_task`, started only
  once `pqc_established` arrives.
