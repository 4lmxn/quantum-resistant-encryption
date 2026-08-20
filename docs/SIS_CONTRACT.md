# SIS-01 refactor contract

Single source of truth for the emergency-shutdown refactor. Every phase-2 task
(firmware, dashboard, tests, docs) is written against this file. If code and this
file disagree, the code is wrong.

## Terminology

| Old | New | Meaning |
|---|---|---|
| `TEMP_THRESHOLD` | `TRIP_SETPOINT_C` | temperature at or above which the plant trips |
| `desired_relay` (`ON`/`OFF`) | `trip_state` (`HEALTHY`/`TRIPPED`) | server's view of the safety function |
| `relay_state` (`ON`/`OFF`) | `valve_state` (`OPEN`/`CLOSED`) | actuator's own view of XV-101 |
| `FAN_ON` / `FAN_OFF` / `FAN_TOGGLE` | `TRIP` / `RESET` | commands on the actuator link |
| `manual_mode` | `bypass` | maintenance bypass, operator-authenticated |

`OPEN` = process running. `CLOSED` = tripped, flow stopped.

## Behaviour changes

1. **Trips latch.** Crossing the setpoint sets `TRIPPED` and sends `TRIP`. Falling
   back below it does **not** reset. Only an authenticated operator `RESET` clears
   it. The hysteresis band is deleted — a latch does not chatter, so it is not needed.
2. **Fail-safe direction.** The actuator trips when the authenticated heartbeat
   stops. Silence means trip, not hold.
3. **ESP32 telemetry never drives the trip.** It is the BPCS transmitter. Its
   readings are displayed and logged; the safety decision runs only on telemetry
   from an ML-KEM/ML-DSA authenticated sensor node.

## Config (`app/config.py`)

```python
TRIP_SETPOINT_C      = 80.0   # default trip point
SETPOINT_MIN_C       = 40.0   # clamp, refuse below
SETPOINT_MAX_C       = 120.0  # clamp, refuse above
SETPOINT_MAX_STEP_C  = 15.0   # refuse a single change larger than this
HEARTBEAT_PERIOD_S   = 2.0    # server -> actuator
HEARTBEAT_TIMEOUT_S  = 6.0    # actuator trips after this much silence
```

## Socket.IO events

Unchanged: `pqc_hello`, `pqc_public_key`, `pqc_encapsulation`, `pqc_established`,
`sensor_telemetry_event`, `execute_actuator_command`, `actuator_ack_event`,
`relay_log`, `security_log`, `pqc_status`, `attack_result`, `attack_findings`,
`mitm_inject`, `trigger_attack`, `dashboard_ready`.

### Changed payloads

`update_telemetry`

```json
{"temp": 84.2, "humidity": 41.0, "source": "sensor node",
 "setpoint": 80.0, "trip_state": "TRIPPED", "valve": "CLOSED",
 "bypass": false, "over_setpoint": true, "safety_relevant": true,
 "status": "SECURE_ML_KEM_768", "wire": {}}
```

`safety_relevant` is `false` for ESP32/BPCS readings, and `status` follows it:
`SECURE_ML_KEM_768` on the safety lane, `SECURE_DEVICE_PSK` on the BPCS lane.
The BPCS leg must never be labelled with a KEM it does not use.

`update_actuator_ui` and `relay_actuator_ui` → `{"valve": "OPEN"|"CLOSED"}`

### New events

`sis_heartbeat` — server to one actuator sid, sealed with that actuator's session
key, same wire format as any command: `{"nonce": hex, "ciphertext": hex}`.
Plaintext: `{"command": "HEARTBEAT", "seq": n, "timestamp": t}` — the key is
`command`, not `type`, because a heartbeat rides the same encoder as every other
actuator command and the actuator reads `body["command"]`.

`sis_state` — server to every dashboard, after any operator action and on
`dashboard_ready`:
```json
{"setpoint": 80.0, "trip_state": "HEALTHY", "valve": "OPEN", "bypass": false,
 "setpoint_min": 40.0, "setpoint_max": 120.0, "max_step": 15.0}
```

`operator_command` — from the operator CLI only:

```json
{"operator_id": "operator-01", "action": "SET_SETPOINT",
 "value": 90.0, "nonce": "<hex 16B>", "timestamp": 1755000000, "signature": "<hex>"}
```

`action` is one of `SET_SETPOINT`, `RESET`, `BYPASS_ON`, `BYPASS_OFF`.

Signed transcript (ML-DSA-65, operator's enrolled key) — built by
`app.identity.operator_transcript(operator_id, action, value, nonce_hex, timestamp)`:

```
b"quantum-iot/operator/v1|" + operator_id + b"|" + action + b"|" +
repr(value) + b"|" + nonce_hex + b"|" + str(int(timestamp))
```

Server rejects when: operator not enrolled, signature invalid, nonce already
seen, timestamp more than 30 s from server time, value out of clamp, or step
larger than `SETPOINT_MAX_STEP_C`.

### Deliberately kept, now rejecting

`set_threshold`, `toggle_actuator_override` and `resume_automatic` still exist
and now **always refuse**, emitting a red `security_log`. They stay so the dashboard can show the
unsigned path being turned away next to the signed path working. Do not delete
them and do not make them work.

## HTTP

`POST /telemetry` (ESP32, BPCS) response:

```json
{"status": "accepted", "setpoint": 80.0, "trip_state": "HEALTHY", "valve": "OPEN"}
```

`compressor` / `excursion` / `threshold` keys are gone.

## Enrolment

`make enroll` now also creates `operator-01`, secret at
`identities/operator-01.key`. An operator is just another enrolled identity in
the registry's `devices` map.

Enrolment is incremental. With identities already present, `make enroll` adds
only the missing ones via `IdentityRegistry.enrol_additional()` and leaves the
server key and every existing device key alone. `--force` still regenerates
everything, which invalidates every device in the field.

## Operator CLI

`make operator` runs `python -m app.nodes.operator`, which signs and sends
`operator_command`. Subcommands: `setpoint <value>`, `reset`, `bypass on|off`.
