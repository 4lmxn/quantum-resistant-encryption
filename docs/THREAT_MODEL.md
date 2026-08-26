<title>THREAT_MODEL.md</title>
# Threat model

Companion to `docs/RESEARCH_AUDIT.md` and `docs/SYSTEM_MODEL.md`. This
document names the assets, trust boundaries, and attacker model, then
categorizes threats with STRIDE where that lens fits a cybersecurity
question — and explicitly stops using it where the question is really a
process-safety one (that boundary matters; see the note at the end of
each entity's threat table).

## Entities

| Tag | Role | Codebase |
|---|---|---|
| TT-101 | Sensor / process transmitter | `app/nodes/sensor.py` (safety lane), `firmware/sketch*.ino` + `app/nodes/device_sim.py` (BPCS lane) |
| SIS-01 | Safety logic solver | `app/server.py` |
| XV-101 | Final element (emergency shutdown valve) | `app/nodes/actuator.py` |
| OP-101 | Operator console | `app/nodes/operator.py` |
| DASH | Browser dashboard (HMI, not a safety component) | `app/templates/index.html` |
| ATTACKER | Adversarial network participant | `app/attacks/attack.py`, `app/attacks/attacks.py` |

## Trust anchors

- **Server identity key** (`identities.json`, `server.pub`/server secret,
  `app/identity.py:80-153`). Everything a node trusts about the server's
  key-exchange offer traces back to this one ML-DSA-65 keypair. Its
  compromise is a total break of the authenticity property on every link;
  it is not modeled as recoverable within this system (no revocation).
- **Device enrollment** (`identities/*.key`, entries in `identities.json`'s
  `devices` map). Each of TT-101 (safety lane), XV-101, and OP-101 has one.
  Enrollment is assumed to happen out-of-band and honestly
  (`docs/RESEARCH_AUDIT.md`, finding B) — this threat model does not cover
  compromise of the `make enroll` process itself, only compromise or misuse
  of an already-enrolled key.
- **`DEVICE_PSK`** (`app/config.py:9-55`) is a trust anchor **only for the
  BPCS lane**, deliberately excluded from `decide_trip()`. Compromising it
  is in scope as an attack (`psk` stage) but explicitly out of scope as a
  safety-relevant trust anchor.

## Security domains

Two cryptographically independent domains, both keyed off the server's
single ML-DSA-65 identity but never sharing AES session-key material:

- **Sensor domain** — `LINK_SENSOR` HKDF info string (`app/pqc.py:20`).
- **Actuator domain** — `LINK_ACTUATOR` HKDF info string (`app/pqc.py:21`).

A third, lower-trust domain exists off to the side: the **BPCS domain**
(constrained-node PSK lane), which never derives an ML-KEM session key at
all and is never consulted by `decide_trip()`.

## Communication channels

| Channel | Transport | Confidentiality/integrity | Authenticity |
|---|---|---|---|
| TT-101 → SIS-01 (safety lane) | Socket.IO or MQTT/TLS | AES-256-GCM, per-session key | ML-DSA-65 (node + server, both directions of the handshake) |
| SIS-01 → XV-101 | Socket.IO or MQTT/TLS | AES-256-GCM, per-session key | ML-DSA-65 at handshake; commands carry no per-message signature, only the session AEAD tag |
| SIS-01 → XV-101 heartbeat | Socket.IO | AES-256-GCM, per-session key, sequence number | Same session key as commands; freshness via `seq` |
| TT-101 → SIS-01 (BPCS lane) | HTTP POST `/telemetry` | AES-256-GCM under `DEVICE_PSK` | **None** — shared static key, not an enrolled identity |
| OP-101 → SIS-01 | Socket.IO, one-shot | Payload not encrypted; integrity via ML-DSA-65 signature over the transcript | ML-DSA-65, operator's enrolled key |
| DASH ↔ SIS-01 | Socket.IO | None (browser-local trust) | None — the dashboard is an HMI, not a safety-authenticated peer; `verify_pin` (`app/server.py:931`) gates the browser UI, not the safety function |

## Safety functions in scope

- Emergency shutdown on high-temperature/high-process-variable excursion
  (`decide_trip()`, `app/server.py:300-317`).
- Fail-safe on loss of communication (`watchdog_loop()`,
  `app/nodes/actuator.py:213-`).
- Authenticated, bounded operator override of setpoint, latch, and bypass
  (`handle_operator_command`, `app/server.py:831-909`).

## Attacker capabilities (assumed)

- Full network visibility on every channel above (passive).
- Ability to inject, modify, drop, delay, or replay packets on any channel
  (active, Dolev-Yao style) — this is what `mitm`, `replay`, `silence`, and
  `rogue` exercise.
- Possession of the constrained-node `DEVICE_PSK` in some scenarios
  (`psk` stage) — modeling a stolen board or leaked provisioning file, not a
  cryptanalytic recovery of it.
- Possession of one legitimately-enrolled operator's signing key in the
  `insider` scenario — modeling an authorized-but-malicious or coerced
  insider, not a stolen key (the signature is genuinely valid).
- A future large-scale quantum computer, for the `shor`/`kyber`/`grover`
  scenarios — modeled analytically/narratively per
  `docs/RESEARCH_AUDIT.md` finding E, not simulated.

## Attacker limitations (assumed)

- Cannot forge an ML-DSA-65 signature without the corresponding secret key
  (standard unforgeability assumption for FIPS 204 at category 3).
- Cannot recover an ML-KEM-768 shared secret from the public
  encapsulation key and observed ciphertexts alone (standard IND-CCA2
  assumption for FIPS 203 at category 3) — this is exactly what the
  `kyber` stage demonstrates rather than assumes; see
  `docs/RESEARCH_AUDIT.md` E for the honest scope of that demonstration.
- Cannot forge an AES-256-GCM tag without the session key (standard AEAD
  unforgeability assumption).
- Is not assumed to have compromised the server's own signing key or the
  machine it runs on — that is a different, out-of-scope threat class
  (server compromise), not covered by any current attack stage.
- Is not assumed to have physical access to XV-101 itself (only to the
  network channels reaching it).

## STRIDE-categorized threats, per channel

STRIDE is used here for the cybersecurity question ("can an adversary do X
to this channel") and deliberately **not** used as a substitute for the
process-safety question ("what happens to the plant if X succeeds or if
nothing is attacked at all") — that second question belongs to
`docs/SAFETY_MODEL.md`'s invariants, not to this table.

### TT-101 → SIS-01 (safety lane)

| STRIDE | Threat | Current control | Attack stage exercising it |
|---|---|---|---|
| Spoofing | Attacker claims to be TT-101 | ML-DSA-65 signature over the transcript, checked against the enrolled key (`app/identity.py:52-59`) | `rogue` |
| Tampering | Modify a reading in transit | AES-256-GCM tag | (no dedicated stage on this exact leg; `mitm` exercises the equivalent on the actuator leg — gap noted in `docs/RESEARCH_AUDIT.md` E) |
| Repudiation | Deny having sent a reading | Not a safety-relevant property for telemetry (see note below) | — |
| Information disclosure | Read plaintext temperature | AES-256-GCM confidentiality, ML-KEM-768 key secrecy | `shor` (against the classical fallback only), `harvest`, `kyber` |
| Denial of service | Stop TT-101 reaching SIS-01 | **Not directly defended** — silence on the sensor leg means no telemetry, not a forced trip. This is a real, currently-undemonstrated gap (the plant does not fail-safe on lost *sensor* input the way it does on lost *actuator* heartbeat). Recorded here rather than glossed over. | none |
| Elevation of privilege | A BPCS-lane reading reaching `decide_trip()` | Explicit `safety_relevant` flag, checked before `decide_trip()` is ever called (`app/server.py:227`, `http_telemetry` line ~516-530) | `psk` |

### SIS-01 → XV-101 (command + heartbeat)

| STRIDE | Threat | Current control | Attack stage |
|---|---|---|---|
| Spoofing | Forged command not from SIS-01 | AES-256-GCM tag under the actuator's session key | `mitm` |
| Tampering | Modify a genuine command in transit | AES-256-GCM tag | `mitm` |
| Repudiation | n/a — no multi-party audit requirement modeled | — | — |
| Information disclosure | Learn the command being sent | AES-256-GCM confidentiality | `harvest`, `kyber` |
| Denial of service | Cut the link to XV-101 | **Inverted by design**: DoS on this link causes the actuator's own watchdog to trip, which is the safe direction | `silence` |
| Elevation of privilege | A captured command reused later | Per-nonce single-use enforcement (`app/nodes/actuator.py`, replay set) | `replay` |

### OP-101 → SIS-01

| STRIDE | Threat | Current control | Attack stage |
|---|---|---|---|
| Spoofing | Command from an unenrolled operator | ML-DSA-65 signature, checked against enrolled operator identity | (covered by `tests/test_operator_auth.py`, no dashboard attack stage) |
| Tampering | Alter a signed command's value | Transcript binds `action`/`value`/`nonce`/`timestamp` (`app/identity.py:62-77`) | (covered by test, no attack stage) |
| Repudiation | Deny having issued a command | Signature is attributable to one enrolled operator identity — this is a genuine non-repudiation property, not exercised as an "attack" because it is not something an attacker defeats, it is something an operator cannot deny | — |
| Information disclosure | n/a — operator payload confidentiality not a stated goal | — | — |
| Denial of service | Flood with garbage-signed commands | **Not rate-limited.** `handle_operator_command` verifies every submitted signature; there is no throttle on submission rate. A real gap, recorded here. | none |
| Elevation of privilege | A genuine, correctly-signed command that is nonetheless unsafe | Bounds clamp (`SETPOINT_MIN_C`/`MAX_C`/`MAX_STEP_C`), independent of the signature check | `insider` |

## Safety-relevant vs. cybersecurity-relevant, explicitly

STRIDE's "Repudiation" and much of "Information disclosure" are
cybersecurity properties with no direct safety consequence in this system —
a leaked temperature reading does not, by itself, move a valve. Conflating
"we found a STRIDE category with a weak control" with "the plant is
unsafe" would be exactly the mistake this document is written to avoid.
The genuinely safety-relevant rows above are the Denial-of-Service and
Elevation-of-Privilege ones, because those are the categories that can
actually reach `decide_trip()` or XV-101's command path. That mapping —
STRIDE threat to safety consequence — is carried forward explicitly into
`docs/SAFETY_MODEL.md`'s invariants rather than left implicit here.

## New gaps this analysis surfaces (not previously logged in the audit)

- **Sensor-lane DoS has no fail-safe answer.** Cutting the *actuator* link
  causes a trip (by design). Cutting the *sensor* link causes silence with
  no equivalent forced response — the plant is left exactly where it was,
  with no watchdog on the input side. Whether this is acceptable (a real
  SIS often treats "loss of sensor signal" as itself an alarm/trip
  condition, distinct from "loss of final-element communication") is a
  genuine open question for `docs/SAFETY_MODEL.md`, not resolved here.
- **No rate limit on `operator_command` submissions.** Signature
  verification is real work (ML-DSA-65 verify, ~6ms per `RESEARCH.md`); a
  flood of garbage-signed submissions is a CPU-exhaustion vector on the
  server process, distinct from — and currently undefended against, unlike
  — the well-defended replay/forgery cases.

---

*Companion documents: `docs/SYSTEM_MODEL.md` for the formal component and
message model this threat model assumes; `docs/SAFETY_MODEL.md` for how
these threats map onto the safety state machine and its invariants.*
