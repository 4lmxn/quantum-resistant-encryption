# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A demonstrator for **SIS-01**, a safety instrumented function on a process
plant: a high-temperature emergency shutdown that closes valve XV-101. It is
modelled on the 2017 TRITON/TRISIS attack on Schneider Triconex safety
controllers, so the interesting behaviour is what the system does when someone
is *inside* it, not merely listening to it.

The parts are a Flask-SocketIO server (the logic solver), a sensor node, an
actuator node holding XV-101, a signed operator console, a scripted attacker, a
browser dashboard, and an ESP32 firmware leg. Session keys are agreed with
**real ML-KEM-768** (NIST FIPS 203, the standardised CRYSTALS-Kyber) via
`kyber-py`; nodes and the server prove who they are with **real ML-DSA-65**
(FIPS 204) via `dilithium-py`; the data channels are AES-256-GCM.

This was previously a thermostat demo — temperature, fan, threshold 30 °C. The
vocabulary changed with it: `TEMP_THRESHOLD` → `TRIP_SETPOINT_C`,
`desired_relay` → `trip_state` (`HEALTHY`/`TRIPPED`), `relay_state` →
`valve_state` (`OPEN`/`CLOSED`), `FAN_ON`/`FAN_OFF` → `TRIP`/`RESET`,
`manual_mode` → `bypass`. `docs/SIS_CONTRACT.md` is the source of truth for the
refactor; if the code and that file disagree, the code is wrong.

## Running it

```bash
pip install -r requirements.txt
make enroll     # once — ML-DSA identities for server, nodes and operator-01
make server     # terminal 1 — dashboard at http://127.0.0.1:5001
make sensor     # terminal 2 — handshake, then telemetry every 4s
make actuator   # terminal 3 — handshake, then holds XV-101 OPEN
make attack     # terminal 4 — one-shot 3-stage attack, then exits

make operator ARGS="setpoint 85"   # signed setpoint move
make operator ARGS=reset           # signed clear of a latched trip
make operator ARGS="bypass on"     # signed maintenance bypass

make test         # crypto, trip logic, identity, operator auth, heartbeat — no server needed
make test-device  # ESP32 wire-format check, server must be running
```

`make enroll` is not optional any more. Without `identities.json` the server
runs `AUTHENTICATED = False`, logs the handshake as unauthenticated, and refuses
every operator command — deliberately, so the difference between the two modes
can be shown in one session. Re-running it enrols only what is missing;
`--force` regenerates everything and invalidates every device already in the
field.

**Port 5001, not 5000** — macOS AirPlay Receiver squats on 5000 and answers
handshakes with a 403 that looks like a CORS bug. Host/port/URL live in
`app/config.py` only; the dashboard uses same-origin `io()` and hardcodes nothing.

## Architecture

Star topology — nodes never talk to each other. Every node begins with an
ML-KEM-768 handshake and holds no key until it finishes:

1. Node → `pqc_hello` `{role: "sensor"|"actuator"}`
2. Server does `generate_keypair()` **per node**, keeps `dk` against the sid, returns `ek` (1184 B) plus an ML-DSA-65 signature over `handshake_transcript(role, ek)`
3. Node verifies that signature against `identities/server.pub` and aborts if it fails — an unverifiable offer is exactly what a man in the middle produces
4. Node `encapsulate(ek, label)` → `(aes_key, ct)`, sends `ct` (1088 B) with its `device_id` and its own signature over `handshake_transcript(role, ek, ct)`
5. Server checks the device is enrolled and the signature verifies, then `decapsulate(dk, ct, label)` → identical key
6. Both `HKDF-SHA256(shared_secret, info=<link label>)` → exactly 32 bytes

`LINK_SENSOR` and `LINK_ACTUATOR` are HKDF domain separators, so the two links
can never derive the same AES key. Fresh keypair per connection means
`zeroize_key()` is a real forward-secrecy measure, not a gesture. The transcript
binds the role and both halves of the exchange, so a signature captured from one
handshake cannot be replayed into another.

Wire format on every AES leg: `{"nonce": <hex, 12 B>, "ciphertext": <hex, tag appended>}`,
no AAD, fresh `os.urandom(12)` per message. The tag-appended layout is what
Python's `AESGCM.encrypt` emits and what `sketch.ino` reproduces by hand.

Flow: sensor encrypts → `sensor_telemetry_event` → server decrypts with that
sid's key → `process_telemetry(..., safety_relevant=True)` → `decide_trip()` →
`update_telemetry` + `security_log` to the browser → if at or above
`trip_setpoint`, seal `TRIP` **separately per actuator sid** and emit `to=` that
sid → actuator verifies the GCM tag, closes XV-101 → `actuator_ack_event` +
`relay_actuator_ui`.

The demo's point is the failure path: a bad tag raises inside `AESGCM.decrypt`
and becomes a red `security_log`. Never swallow those or add a plaintext
fallback — the visible rejection *is* the feature.

### Trips latch, and that is why there is no hysteresis

`decide_trip()` speaks on exactly one edge: the crossing into `TRIPPED`. Falling
back below the setpoint does **not** clear it. The plant cooling down is not
evidence that whatever caused the excursion has been dealt with, so clearing the
latch is an operator decision made through a signed `RESET`, handled by
`clear_trip()`.

The hysteresis band the thermostat carried is gone, and must not come back. It
existed to stop a two-edge controller chattering around the setpoint. A latch
has one edge and re-entry is a no-op, so the lower edge has nothing left to do —
adding a band back would only mean the trip fires late.

`decide_trip()` returns early when `bypass` is asserted. That is the maintenance
override, and it is operator-authenticated state, not a dashboard toggle.

### The dead-man heartbeat, and the fail-danger path it replaced

`heartbeat_loop()` in `app/server.py` seals a `HEARTBEAT` under each actuator's
own session key every `HEARTBEAT_PERIOD_S` (2 s) and emits `sis_heartbeat` to
that sid. It is started once, lazily, by `ensure_heartbeat_running()` on the
first actuator handshake — never at import time, so it never runs before there
is a session to seal it with, and a reconnect cannot start a second one.

`watchdog_loop()` in `app/nodes/actuator.py` closes XV-101 locally after
`HEARTBEAT_TIMEOUT_S` (6 s) of silence. Beats carry a `seq`; `accept_heartbeat()`
rejects any beat at or below the last one seen, so capturing one beat and
replaying it cannot hold the watchdog open indefinitely. `last_heartbeat` is
seeded at `pqc_established`, so a node that never hears a first beat still trips
on schedule.

**This replaced a fail-danger path.** The old `decide_relay()` logged a line and
dropped the command when no actuator was reachable, which meant severing the
network froze the final element wherever it happened to be — usually open. The
decision now lives on the node holding the valve, precisely so it survives the
case where the server cannot be reached. Silence means trip, not hold. Do not
move this decision back to the server, and do not make a missing heartbeat
recoverable by anything other than a fresh authenticated beat: a `RESET` reopens
the valve but leaves the watchdog running, so if the beat is still missing the
next pass trips again.

### Operator commands are signed, bounded, and single-use

`handle_operator_command` is the only path that can move the setpoint, clear a
trip, or change the bypass. The payload is
`{operator_id, action, value, nonce, timestamp, signature}` where `action` is one
of `SET_SETPOINT`, `RESET`, `BYPASS_ON`, `BYPASS_OFF`, and the signature is
ML-DSA-65 over `identity.operator_transcript(...)`:

```
b"quantum-iot/operator/v1|" + operator_id + b"|" + action + b"|" +
repr(value) + b"|" + nonce_hex + b"|" + str(int(timestamp))
```

Everything that changes the meaning of the command is inside the signature. An
operator is just another enrolled identity in `identities.json`; `make enroll`
creates `operator-01` and writes its secret to `identities/operator-01.key`.
`app/nodes/operator.py` is the console — it refuses to send at all without that
key, rather than sending something the server would only reject.

The server refuses, with a red `[SIS] Operator command REFUSED` log, when:

- no identities are enrolled on the server at all (`AUTHENTICATED` is false)
- `action` is not one of the four
- the operator id is not enrolled
- the timestamp is malformed, or more than `OPERATOR_MAX_SKEW_S` (30 s) from server time
- the nonce is missing, or already in `operator_nonces`
- the ML-DSA signature does not verify
- `SET_SETPOINT` only: the value is not a number, falls outside `SETPOINT_MIN_C`–`SETPOINT_MAX_C` (40–120 °C), or moves the setpoint by more than `SETPOINT_MAX_STEP_C` (15 °C) in one step

The clamp and the step limit apply **after** the signature verifies, and that
ordering is the lesson from Oldsmar: the intruder there used a legitimate
control path, so authentication is necessary and not sufficient. A correctly
signed command asking to move the trip setpoint sixty degrees is refused exactly
like an unsigned one.

The nonce is burned only once the signature checks out. Burning it earlier would
let an attacker spend a legitimate operator's nonce by sending garbage carrying
it.

### The refusing handlers are the demonstration — do not fix them

`set_threshold`, `toggle_actuator_override` and `resume_automatic` still exist
in `app/server.py` and **always refuse**, emitting a red `security_log`.

**Do not delete them, and do not make them work again.** They are how the demo
shows the unsigned path being turned away beside the signed one working. The
override in particular used to emit a properly sealed command, so the actuator
authenticated it correctly and obeyed — which proved the *server* had sent it,
and nothing about who had asked. That gap is the point. A future dashboard
control that needs to change safety state belongs on the signed
`operator_command` path, not restored here.

### Nodes cannot reach the dashboard directly

A Socket.IO client emit only reaches the server. Nodes therefore send
`relay_log` / `relay_actuator_ui`, and the server re-broadcasts them as
`security_log` / `update_actuator_ui`. **Any new dashboard control or node
message needs a matching `@socketio.on` handler in `app/server.py` or it vanishes
silently.** Currently wired: `trigger_attack`, `dashboard_ready`,
`operator_command`, plus the three refusing handlers above.

`handle_relay_actuator_ui` only speaks when the actuator's reported valve
position disagrees with `valve_position()`, and on disagreement it trusts the
actuator and adopts `TRIPPED`. A disagreement there is real news — usually the
node's own watchdog tripping locally because the heartbeat stopped arriving.

`broadcast_sis_state()` pushes setpoint, latch, valve, bypass and the clamp
bounds after any operator action, and `dashboard_ready` replays it, so a
dashboard that opens mid-run never shows a stale setpoint and never has to infer
state by parsing log text.

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

Stage 1 breaks the real classical channel — `make sensor-legacy` brings up an
RSA key-transport leg (`app/legacy.py`) with a deliberately small modulus so the
factoring completes in milliseconds; Shor's algorithm is what makes the
equivalent recovery feasible against RSA-2048, and that part is cited, not
simulated. **Stages 2 and 3 are real.** Stage 2 captures a genuine 1184-byte
encapsulation key off the wire and shows that encapsulating against it twice
yields two independent secrets, so replaying captured traffic recovers nothing.
It does not pretend to run BKZ. Stage 3 sends a forged packet through the
server's `mitm_inject` handler and lets the GCM tag reject it.

## Showing the handshake

The dashboard's **Post-Quantum Key Establishment** table is fed by `pqc_status`,
which the server broadcasts on every handshake and disconnect. Nodes send a
`key_fingerprint` (SHA-256 of their derived key, truncated) alongside the KEM
ciphertext; the server compares it with its own and shows both. Fingerprints are
one-way, so this proves agreement without putting key material on the wire —
never replace them with the key itself.

`app/nodes/device_sim.py` is the ESP32 stand-in and shares the wire format with
`firmware/sketch/sketch.ino`. Changing one means changing the other.

## The ESP32 leg is BPCS, not safety

`firmware/` holds firmware, wiring and instructions. The board does a real DHT22
read and real AES-256-GCM via mbedtls, then POSTs to `/telemetry` — one HTTP
route rather than teaching a microcontroller Socket.IO.

It does **not** run the handshake. It uses `DEVICE_PSK`, a provisioned key
duplicated in `app/config.py` and `sketch.ino`; the two must match byte for byte.
That key is committed to this repository, so anyone reading the source can forge
ESP32 telemetry. It is the one remaining pre-shared key in the system, the
accepted residual risk of keeping ML-KEM off the microcontroller, and overridable
with the `DEVICE_PSK` environment variable.

It is also exactly why the board sits on the basic process control lane rather
than the safety lane. `http_telemetry()` calls
`process_telemetry(..., safety_relevant=False)`, so ESP32 readings are decrypted,
displayed and logged (tagged `[SERVER/BPCS]`) but never reach `decide_trip()`.
A leg that cannot prove who it is must not be able to trip the plant. Do not
pass `safety_relevant=True` from that route, and do not give the ESP32 a path to
the trip decision without first giving it a real ML-DSA identity.

## Conventions

- Session keys are never module constants. They come from `app/pqc.py` and live in
  per-sid dicts on the server, or in a node's `bytearray` so `zeroize_key()` can
  overwrite in place.
- Long-term signing keys live in `identities.json` (mode 0600, contains the
  server secret) and `identities/*.key`. Both are gitignored; never commit them
  and never log key material.
- Every `security_log` payload is `{"type": ..., "msg": ...}` with type in
  `SUCCESS` / `ERROR` / `ALERT` / `ATTACK`; the dashboard colour-codes on it.
  Safety-function messages are prefixed `[SIS]` — `app/nodes/operator.py` reads
  the broadcast log for that prefix to decide its exit status.
- Use `sio.sleep()` / `socketio.sleep()`, never `time.sleep()`, in node and
  server loops — blocking sleep kills the Socket.IO ping/pong and drops the
  connection. That includes `heartbeat_loop()` and `watchdog_loop()`, where a
  dropped connection would trip the plant.
- Long-running loops go through `sio.start_background_task`, started only once
  `pqc_established` arrives (nodes) or on the first actuator handshake (server).
