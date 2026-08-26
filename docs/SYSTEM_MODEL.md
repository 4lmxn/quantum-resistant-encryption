<title>SYSTEM_MODEL.md</title>
# System model

Formal component and message model for SIS-01, using the entity tags from
`docs/THREAT_MODEL.md`. This is a description of what the code actually
does, cross-checked against `app/server.py`, `app/nodes/*.py`, `app/pqc.py`,
`app/identity.py`, and `docs/SIS_CONTRACT.md` — it is not an idealized or
aspirational architecture.

## Components

```
                    ┌─────────────────────────────────┐
                    │            SIS-01                │
                    │        (app/server.py)           │
                    │                                   │
                    │  ML-DSA-65 server identity        │
                    │  per-connection ML-KEM-768 dk     │
                    │  decide_trip() / clear_trip()     │
                    │  heartbeat_loop() (background)    │
                    └───┬──────────┬──────────┬─────────┘
                        │          │          │
          ML-KEM+ML-DSA │          │          │ ML-DSA (one-shot)
          handshake, then│         │          │
          AES-256-GCM   │          │          │
                        │          │          │
                ┌───────▼──┐  ┌────▼─────┐ ┌──▼────────┐
                │  TT-101   │  │  XV-101   │ │  OP-101    │
                │ (sensor)  │  │(actuator) │ │ (operator) │
                │           │  │           │ │            │
                │ telemetry │  │ watchdog_ │ │ signs one  │
                │ every 4s  │  │ loop()    │ │ command,   │
                │           │  │ (indep.)  │ │ exits      │
                └───────────┘  └───────────┘ └────────────┘

   Separate, lower-trust lane (never reaches decide_trip unless authenticated):

                ┌───────────────────────────┐
                │   Constrained node (BPCS)  │
                │  firmware/*.ino or         │
                │  app/nodes/device_sim.py   │
                │                             │
                │  /pqc/hello, /pqc/         │
                │  encapsulate, /telemetry   │
                │  (HTTP, not Socket.IO)     │
                └─────────────┬───────────────┘
                              │ DEVICE_PSK (static)
                              │  — or —
                              │ per-connection ML-KEM key
                              │ (if it completed /pqc)
                              ▼
                          SIS-01 (same server,
                          different code path:
                          http_telemetry())
```

Nodes never talk to each other — every arrow above terminates at SIS-01.
This is enforced structurally: `app/nodes/*.py` hold no listening socket,
only outbound Socket.IO/HTTP clients.

## Trust boundaries

1. **Network boundary**, around every arrow in the diagram. Everything
   crossing it is assumed attacker-visible and attacker-modifiable
   (Dolev-Yao), per `docs/THREAT_MODEL.md`.
2. **Enrollment boundary**, around `identities.json` / `identities/*.key`.
   Crossing *into* this trust domain (becoming an enrolled device) is
   assumed to happen only via `make enroll`, out of band from the runtime
   system. This audit does not model an attacker who can run `make enroll`
   themselves.
3. **Safety-relevance boundary**, inside `process_telemetry()`
   (`app/server.py:227`) via the `safety_relevant` flag. This is a boundary
   *within* the server process, not a network boundary — it is the single
   choke point that decides whether a reading, regardless of source, is
   even eligible to reach `decide_trip()`. Every telemetry entry point sets
   this flag explicitly: `handle_sensor_telemetry` implicitly `True`
   (default), `http_telemetry` sets it to `authenticated` (did this device
   complete `/pqc/hello`?), `handle_mitm_inject` sets it to `False`
   explicitly (`app/server.py:729`).

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Server ML-DSA-65 secret key | `identities.json` (or HSM, `app/keystore.py`) | Root of trust for every handshake offer |
| Per-device ML-DSA-65 secret keys | `identities/*.key` | Authenticates each node's identity |
| Per-connection ML-KEM-768 decapsulation key | Server memory, `server_engine.sensor_keys`/`actuator_keys`, keyed by sid | Recovers that connection's session key; zeroed on disconnect |
| Per-connection AES-256-GCM session key | Node's own `bytearray`, server's per-sid dict | Confidentiality/integrity of one session's traffic |
| `trip_setpoint`, `trip_state`, `bypass` | `server_engine` in-process state | The safety function's entire decision state |
| `DEVICE_PSK` | `identities/device.psk`, gitignored | BPCS-lane confidentiality only, explicitly not a safety asset |
| Nonce sets (`seen_nonces`, `operator_nonces`) | Server in-process memory | Replay defense; does not survive restart (`docs/RESEARCH_AUDIT.md` J-2) |

## Message flows

### 1. Handshake (every node, safety lane)

```
node -> server: pqc_hello {role}
server -> node: pqc_public_key {ek, signature over transcript(role, ek)}
node:  verify signature against server.pub; abort if it fails
node -> server: pqc_encapsulation {device_id, ct, signature over transcript(role, ek, ct)}
server: verify device is enrolled + signature verifies; decapsulate
both:  session_key = HKDF-SHA256(SHAKE-256(shared_secret || link_label))
```

Exact functions: `app/server.py:580` (`handle_pqc_hello`), `:602`
(`handle_pqc_encapsulation`); node side in `app/nodes/sensor.py` /
`actuator.py`; shared derivation in `app/pqc.py:44-55`.

### 2. Telemetry (safety lane)

```
TT-101 -> server: sensor_telemetry_event {nonce, ciphertext}
server: accept_nonce() -- reject if replayed
server: decrypt_sensor_data() -- reject if tag invalid
server: process_telemetry(data, source, packet, safety_relevant=True)
server: decide_trip(temperature)
server -> dashboard: update_telemetry, security_log
[if crossing setpoint] server -> XV-101 (per sid): TRIP, sealed under that
  actuator's own session key
```

`app/server.py:669-686`.

### 3. Command + heartbeat (SIS-01 → XV-101)

```
server (heartbeat_loop, every HEARTBEAT_PERIOD_S): 
  seq += 1; seal HEARTBEAT under actuator's session key -> sis_heartbeat
server (on trip edge or operator RESET):
  seal TRIP/RESET under actuator's session key -> execute_actuator_command
XV-101: verify GCM tag; if HEARTBEAT, accept_heartbeat() (rejects seq <= last_seq)
XV-101 (watchdog_loop, independent of the above): 
  if time since last accepted heartbeat > HEARTBEAT_TIMEOUT_S: close XV-101 locally
```

`app/server.py:342-` (`heartbeat_loop`), `app/nodes/actuator.py:92-115`
(`accept_heartbeat`), `:213-` (`watchdog_loop`).

### 4. Operator command

```
OP-101 (one-shot CLI): build {operator_id, action, value, nonce, timestamp}
OP-101: sign operator_transcript(...) with enrolled operator key
OP-101 -> server: operator_command {..., signature}
server: check AUTHENTICATED, action in allowed set, operator enrolled,
        timestamp within OPERATOR_MAX_SKEW_S, nonce unseen, signature valid
        -- burn nonce only after signature verifies
server: [SET_SETPOINT only] check clamp + max-step, independent of signature
server: apply action; broadcast_sis_state() to every dashboard
```

`app/server.py:831-909`, transcript format in `app/identity.py:62-77`.

### 5. Constrained-node (BPCS) lane

```
node -> server: POST /pqc/hello {role: "sensor"}         [optional — skipped
server -> node:  {ek, signature}                          if using DEVICE_PSK]
node -> server: POST /pqc/encapsulate {device_id, ct, signature}
server: same verification as the Socket.IO handshake; stores under
        server_engine.http_sessions[device_id]

node -> server: POST /telemetry {device_id, nonce, ciphertext, ...}
server: key = http_sessions[device_id] if present, else DEVICE_PSK
        authenticated = (session key was present)
server: process_telemetry(..., safety_relevant=authenticated)
```

`app/server.py:412-530`. This is the mechanism behind
`docs/THREAT_MODEL.md`'s "Elevation of privilege" row for the sensor
channel: `safety_relevant` is computed from *whether the PQC handshake
happened*, not from the device's claimed identity string, so a PSK-only
device cannot simply claim to be safety-relevant.

## Independent trust domains, formally

`K_sensor` and `K_actuator` are derived from the same shared-secret
generation machinery (`ML_KEM_768.encaps`/`decaps`) but different `info`
strings to HKDF (`app/pqc.py:20-21, 44-55`):

```
K_sensor   = HKDF-SHA256(SHAKE-256(ss_1 || LINK_SENSOR),   info=LINK_SENSOR)
K_actuator = HKDF-SHA256(SHAKE-256(ss_2 || LINK_ACTUATOR), info=LINK_ACTUATOR)
```

Even in the degenerate case `ss_1 == ss_2` (a fresh ML-KEM keypair per
connection makes this astronomically unlikely, not impossible by
construction), `K_sensor != K_actuator` because the HKDF `info` parameter
differs — this is what HKDF domain separation is for. This property is
exactly what `tests/test_pqc.py` is positioned to assert (file exists,
4 tests, not re-read line-by-line in this audit pass); formalizing it as
a named security property with its own test is carried into
`docs/SECURITY_PROPERTIES.md` (later phase) rather than duplicated here.

## What this model deliberately excludes

- Server-internal compute/thread model (Socket.IO event loop, background
  tasks via `sio.start_background_task`) — an implementation detail, not a
  system-model concern.
- MQTT transport internals (`app/transport/*.py`) — same message flows as
  above, different wire encoding; not modeled separately because it carries
  identical session-key material and identical trust boundaries, only a
  different transport. Flagged in `docs/RESEARCH_AUDIT.md` J-1 as
  under-documented, not because the model differs.
- Physical process dynamics (how fast a real plant's temperature actually
  changes) — out of scope for a system model of the *control and security*
  system; belongs to the cyber-physical testbed work (later phase).

---

*Companion documents: `docs/THREAT_MODEL.md` for what an adversary can do
to each flow above; `docs/SAFETY_MODEL.md` for the state machine
`decide_trip()`/`clear_trip()` implement and the invariants derived from
it.*
