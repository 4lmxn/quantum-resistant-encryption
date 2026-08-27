<title>RESEARCH_AUDIT.md</title>
# Research audit

Audit of the repository as it stands on branch `feat/sis-01-emergency-shutdown`,
before any research-track changes. Every claim below is anchored to a file and
line; nothing is inferred from the READMEs alone. Where the code and
`docs/SIS_CONTRACT.md` agree, the contract is cited; where they disagree, that
disagreement is logged in section J.

This document does not change behavior. It is the basis the rest of the
research track (`THREAT_MODEL.md`, `SYSTEM_MODEL.md`, `SAFETY_MODEL.md`,
later benchmark and paper work) is built on.

## A. Current architecture

Star topology, four Python roles plus one HTTP-only constrained-node
simulator, communicating through a single Flask-SocketIO server that is also
the trust anchor and the logic solver:

- **Server** (`app/server.py`, 988 lines) — holds the ML-DSA-65 server
  identity, runs one ML-KEM-768 keypair per connecting node, decrypts
  telemetry, evaluates `decide_trip()`, seals commands, and serves the
  dashboard.
- **Sensor** (`app/nodes/sensor.py`) — Socket.IO client, safety-relevant
  telemetry.
- **Actuator** (`app/nodes/actuator.py`, 336 lines) — Socket.IO client,
  holds XV-101, runs its own dead-man watchdog independent of the server.
- **Operator console** (`app/nodes/operator.py`) — one-shot signed CLI, not a
  persistent connection.
- **Constrained node simulator** (`app/nodes/device_sim.py`) — HTTP client
  standing in for the ESP32, exercises `/pqc/hello` and `/telemetry`
  (`app/server.py:412-530`).
- **Dashboard** (`app/templates/index.html`) — browser Socket.IO client.
- **Attacker** (`app/attacks/attack.py`, `app/attacks/attacks.py`, 572 lines)
  — both a CLI runner and in-process dashboard-triggered stages sharing one
  implementation (`app/attacks/attacks.py:1-10`).

A second transport exists and is **not** described in top-level docs: MQTT
over TLS 1.3 (`app/transport/broker.py`, `mqtt_bridge.py`, `mqtt_transport.py`,
223 lines total; `make broker` / `make server-mqtt` etc. in the Makefile).
It is a parallel wire format for the same session-key material, not a
different trust model. See finding J-1.

Firmware exists at three levels of completeness (`firmware/README.md`):

1. `firmware/sketch/sketch.ino` — real hardware target (MAX6675 thermocouple
   or a DHT22 Wokwi stand-in), telemetry sealed under a static provisioned
   `DEVICE_PSK`, `safety_relevant=False` by construction.
2. `firmware/pqc/` + `firmware/pqc_selftest/` — PQClean ML-KEM-768/ML-DSA-65
   ported to ESP32-Arduino, proven by cross-implementation known-answer tests
   against `kyber-py`/`dilithium-py` on the host (`make pqc-interop`,
   `tests/test_pqc_interop.py`), and measured at 287 KB / 21% flash.
3. `firmware/sketch_pqc/` — the full handshake wired into a sketch, proven
   against the live server's `/pqc/hello` and `/pqc/encapsulate` endpoints by
   `tests/test_firmware_e2e.py`, which drives the firmware's C crypto (not a
   Python re-implementation) through those endpoints and asserts `agreed:
   true`.

What (3) has **not** been shown is a physical ESP32 running that sketch over
real WiFi with measured timing, flash headroom under `USE_TLS`, or power
draw. `firmware/README.md:64-67` already states this precisely: "The only
thing left to a physical board is the WiFi/HTTP transport and the real timing
numbers." Per the phase-1 scoping decision for this research track, no
physical board is available this pass — every hardware number stays
`NOT MEASURED`, not estimated from the interop test.

## B. Current security assumptions

- A signature from `identities/server.pub` is the sole trust anchor for the
  key-exchange offer (`app/pqc.py`, `app/identity.py:52-59`); compromise of
  the server's ML-DSA-65 secret is not modeled or detected.
- Enrollment (`app/identity.py:80-153`, `make enroll`) is assumed out-of-band
  and honest — `IdentityRegistry.bootstrap()`/`enrol_additional()` trust
  whatever device IDs they are called with. There is no proof-of-possession
  step distinguishing a legitimately manufactured node from an attacker who
  can call `make enroll`.
- Long-term ML-DSA-65 keys have no forward secrecy and no revocation
  mechanism — stated already in `RESEARCH.md`'s "What still stands" section,
  not new to this audit.
- `DEVICE_PSK` (`app/config.py:9-55`) is a single shared secret for every
  un-provisioned constrained node; its compromise is explicitly out of the
  safety boundary by design (`safety_relevant=False`), not an oversight.
- Reference crypto implementations (`kyber-py`, `dilithium-py`) are pure
  Python and not constant-time; side-channel resistance is unaddressed
  (`RESEARCH.md`, "No side-channel resistance").
- Nonce/replay state (`server_engine.seen_nonces`,
  `server_engine.operator_nonces`) is in-process memory with no persistence
  across restart — a restarted server forgets every nonce it has seen,
  reopening the replay window for anything captured before the restart.
  **Not currently tested or documented as a gap; see J-2.**

## C. Current safety assumptions

- The trip function is a two-value latch, `HEALTHY`/`TRIPPED`
  (`app/server.py:49`), not the richer state machine a formal IEC 61511 model
  would draw (`ALARM`, `TRIP_PENDING`, `RESET_PENDING`, `FAULT`, ...). See
  `docs/SAFETY_MODEL.md` for the explicit mapping and gap analysis.
- `decide_trip()` (`app/server.py:300-317`) speaks only on the edge into
  `TRIPPED`; there is no de-latching path except an authenticated `RESET`.
  This is deliberately asymmetric — see `CLAUDE.md`'s "Trips latch" section.
- Bypass (`server_engine.bypass`, asserted only via a signed
  `BYPASS_ON`/`BYPASS_OFF` operator command, `app/server.py:884-891`) causes
  `decide_trip()` to return unconditionally
  (`app/server.py:309-310`). There is no bypass timeout, no audit reminder
  while bypass is asserted, and no limit on how long a bypass may stand —
  a real SIS would typically time-box a maintenance override. **Gap, see
  J-3.**
- The actuator's watchdog (`app/nodes/actuator.py:92-115, 213-`) is
  authoritative and independent: it trips on 6 seconds of heartbeat silence
  regardless of what the server believes, which is the documented answer to
  the fail-danger path the old thermostat code had. This is the single
  strongest safety property in the system and is well covered by
  `tests/test_heartbeat.py` (14 tests).
- A restarted server comes up `HEALTHY` (`app/server.py:49` — a fresh
  `CentralServer()` on process start) and reopens whatever valve reconnects
  to it (`app/server.py:660-666`, `sync_actuator_state`), documented in a
  comment at `app/server.py:368` but not covered by an automated test that a
  restart mid-trip is safely re-asserted. **Gap, see J-4.**

## D. Current cryptographic assumptions

- ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204), both NIST security category
  3, via `kyber-py>=1.2` / `dilithium-py>=1.1` (`requirements.txt`). Real
  standardized primitives, not toy implementations — confirmed by reading
  `app/pqc.py` and `app/identity.py` directly rather than trusting the
  package names.
- Session key derivation is `SHAKE-256(shared_secret || link_label)` then
  `HKDF-SHA256(..., info=link_label)` (`app/pqc.py:44-55`) — domain-separated
  per link (`LINK_SENSOR` vs `LINK_ACTUATOR`), which is what
  `tests/test_pqc.py` is positioned to verify (not read in this pass; flagged
  for the domain-separation test audit in `SECURITY_PROPERTIES.md` follow-up).
- AES-256-GCM with a fresh 12-byte nonce per message
  (`server_engine.decrypt_sensor_data`, `app/server.py:154-159`), tag
  appended, no AAD — matches `CLAUDE.md`'s documented wire format exactly.
- The claim in `RESEARCH.md` that "fresh keypair per connection = genuine
  forward secrecy" is **accurate for session-key material** — each
  `pqc_hello` gets its own `generate_keypair()` (`app/server.py`, per the
  `pqc_hello` handler at line 580) and `zeroize_key()` overwrites the node's
  copy on disconnect. It is **not** forward secrecy for the ML-DSA-65
  identity keys, which the same document already states plainly in "What
  still stands." The claim as written in `RESEARCH.md` is scoped correctly
  (it says "session keys," not "the system"); no correction needed, but
  `SECURITY_PROPERTIES.md` should state the scope explicitly rather than
  relying on the reader to notice.
- The bench numbers in `RESEARCH.md` (ML-KEM/ML-DSA/AES timings) are real,
  reproducible measurements from `bench.py` (median + p95 over 60 rounds),
  not fabricated — confirmed by reading `bench.py` directly. They predate
  this research track and are not superseded by anything here; the spec's
  requested benchmark harness (N≥100/1000, jitter, p50/p90/p95/p99/p99.9) is
  new work, not a redo of `bench.py`.

## E. Current attack surface

`app/attacks/attacks.py` implements **ten** attack stages
(`ATTACK_ORDER`, line 525-526: `silence, psk, insider, rogue, replay, mitm,
shor, kyber, harvest, grover`), each backed by a real mechanism against the
running system rather than a scripted log message — confirmed by reading
every `stage_*` function:

| Stage | Mechanism | Real or narrated |
|---|---|---|
| `silence` | stops server heartbeats, actuator watchdog trips locally | Real |
| `psk` | seals a forged reading with the real `DEVICE_PSK`, shows it never reaches `decide_trip` | Real |
| `insider` | submits a genuinely ML-DSA-signed `SET_SETPOINT 11100.0`, shows the clamp refuses it | Real |
| `rogue` | a second session claims an identity already holding one | Real |
| `replay` | recaptures a real sealed command and resends it | Real |
| `mitm` | posts a packet with an invalid GCM tag to the actuator | Real |
| `shor` | factors an intentionally small RSA modulus on the `sensor-legacy` leg | Real (reduced key size; cites Shor's algorithm rather than running it) |
| `kyber` | encapsulates twice against a captured public key, shows independence; does not run BKZ | Real capture, narrated infeasibility of key recovery |
| `harvest` | two live handshakes, shows unrelated keys | Real |
| `grover` | no live mechanism — pure narration of the AES-256 margin | **Narrated only** |

This is a materially larger and more honest attack surface than `CLAUDE.md`
currently describes ("a scripted attacker" with "one-shot 3-stage attack" in
the Makefile help text and the top-of-file summary). See J-1 for the
documentation mismatch this creates.

Against the spec's requested A01–A20 attack catalog (`RESEARCH-GRADE
TRANSFORMATION` prompt, section 8), current coverage:

- Covered, with a real mechanism: telemetry forgery (`psk`), telemetry
  replay (partially — `replay` covers command replay, not telemetry replay
  specifically; see gap below), command forgery (`mitm`), command replay
  (`replay`), rogue node (`rogue`), stolen credential (`psk`), legitimate
  malicious command (`insider`), network suppression (`silence`), heartbeat
  disruption (`silence`), duplicate identity (`rogue`).
- **Not covered by any stage, at the time this audit was written**: telemetry
  replay specifically (a captured sensor reading resent, as opposed to a
  captured actuator command), stale session, nonce reuse as its own scenario
  (distinct from the replay stage, which demonstrates the defense rather than
  probing the boundary), timestamp manipulation as its own scenario (covered
  only inside `tests/test_operator_auth.py::test_a_stale_command_is_refused`,
  not in the attack framework), invalid safety-state transition, malformed
  packet, downgrade attempt, oversized/resource-exhaustion message, server
  unavailable (from the actuator's perspective — `silence` covers loss of
  the actuator's heartbeat, not loss of the server process itself), actuator
  communication loss (same distinction).

**Post-audit update (research track, phase 3): closed.** All ten gaps listed
above now have a stage — `telemetry_replay`, `stale_session`, `nonce_probe`,
`timestamp_manip`, `downgrade`, `malformed_packet`, `oversized`,
`invalid_transition`, `actuator_absent`, `server_unavailable` — bringing
`ATTACK_ORDER` to twenty. Two of the ten are genuine, undefended findings
rather than demonstrations of a working control (`actuator_absent`:
`SUCCEEDED` when no actuator session exists, because the dead-man watchdog
lives on the actuator node and there is none to run it; `oversized`: a
multi-megabyte forged packet is rejected on the same GCM-tag failure any
forged packet hits, but no explicit request-size limit exists at the
application layer). This is left as an inline update, deliberately not a
silent rewrite of the paragraph above it, per this document's own closing
note about being a snapshot — the original finding is kept so the "what was
true when" record stays intact.

**Post-audit update (2026-08-26): `oversized` closed.** `MAX_CIPHERTEXT_HEX_CHARS`
(`app/config.py`) now rejects an oversized ciphertext field in
`decrypt_sensor_data` — the single choke point for every sensor-originated
packet (Socket.IO, the ESP32 HTTP leg, and the MQTT bridge) — before
`AESGCM.decrypt` is ever called, not after. `actuator_absent` remains open;
the dead-man watchdog is deliberately actuator-resident (`docs/SIS_CONTRACT.md`),
so no server-side fix closes it without moving that decision back to the
server, which the contract forbids.

## F. Current experimental capabilities

- `bench.py`: median/p95 timing for ML-KEM keygen/encapsulate/decapsulate,
  ML-DSA keygen/sign/verify, AES-GCM seal/open, RSA factorization — 60
  rounds, single machine, single run per invocation. No repeated-run
  statistics, no p99, no CSV/JSON export, no classical-vs-PQC side-by-side.
- 76 automated tests across 14 files (`tests/`), all fast (no `sio.sleep`
  waits longer than fractions of a second observed in the files read), all
  runnable without a live server (`make test`) except
  `tests/test_firmware_e2e.py` and device-leg tests, which need `make
  server` running (`make test-device`).
- No latency-under-load harness, no jitter measurement, no safety-response
  (sensor-event-to-valve-closed) timing harness, no packet-loss or
  concurrent-client simulation. **Post-audit update (research track, phase
  4): the safety-response and latency-under-load gaps are closed** —
  `scripts/bench_crypto.py` (N=1000/100, full percentile statistics, raw
  CSV + JSON summary) and `scripts/bench_safety_response.py` (real
  end-to-end T_TOTAL against a live server, idle and CPU-load conditions,
  100 trials each) now exist and have been run; see
  `docs/SAFETY_MODEL.md` INVARIANT-01. No jitter measurement or
  concurrent-client simulation exists yet — those remain open.
- No machine-readable attack-result output (`results/attacks/*.json` from
  the spec does not exist); attack outcomes currently live only as dashboard
  log lines and the `report(...)` calls' structured fields
  (`status`/`confidence`/`evidence`/`outcome`), which are real structured
  data already (`ATTACK_CATALOG`, `report()` calls throughout
  `attacks.py`) but are not persisted anywhere.

## G. Missing measurements

Everything the spec's benchmarking sections (10-13, 16) ask for is currently
absent and must be built, not retrofitted from existing numbers:

- Classical baseline (X25519 + Ed25519 + AES-256-GCM) — no code path exists
  for this today; `app/legacy.py` implements RSA key transport (used by the
  `shor` attack), not an X25519/Ed25519 baseline. These are different
  comparisons: RSA-vs-PQC-KEM demonstrates the Shor's-algorithm motivation;
  X25519/Ed25519-vs-PQC demonstrates the fair modern-classical-cost
  comparison the spec's section 9 wants. Both are legitimate; only the first
  exists.
- N≥100/1000 repeated-trial statistics with p50/p90/p95/p99/p99.9 and jitter
  — `bench.py` does p95 over 60 rounds only. **Closed this phase** for the
  N/percentile part by `scripts/bench_crypto.py`; jitter as its own reported
  statistic is still absent.
- End-to-end safety-response latency (`sensor event → SIS detection → trip
  decision → actuator command → physical state`) — **closed this phase** by
  `scripts/bench_safety_response.py`; see `docs/SAFETY_MODEL.md`
  INVARIANT-01 for the numbers. The six-way component breakdown the spec
  also asks for is still NOT MEASURED (would need instrumentation inside
  `app/server.py` itself, deliberately not added this phase).
- ESP32 hardware resource/timing numbers — **NOT MEASURED, physical hardware
  required**, per the phase-1 scoping decision (no board available this
  pass).
- Classical-vs-PQC-vs-PQC-optimized three-way comparison — does not exist.

## H. Potential novelty claims

Kept intentionally narrow pending the prior-art and patentability work
(spec sections 21-23, not in this phase):

- The combination of a **per-domain HKDF-separated post-quantum session
  key** (sensor link vs. actuator link, provably independent — testable via
  `LINK_SENSOR`/`LINK_ACTUATOR` in `app/pqc.py`) with an **actuator-resident,
  server-independent dead-man watchdog** that fails toward the safe
  direction on silence (`app/nodes/actuator.py:213-`) is not, on the current
  audit, something this codebase can claim as a first observation of — that
  determination needs the prior-art search in section 21 of the parent
  prompt, not this document.
- The `insider` attack stage's demonstration that a **correctly-signed,
  fully-authenticated command is independently rejected by a safety-policy
  clamp** (`app/server.py:903-909`) is a clean, reproducible illustration of
  "authentic ≠ safety-valid" and is a strong candidate for the paper's
  central experimental result (spec section 7) — but "clean illustration"
  is a claim about presentation quality, not novelty, and must not be
  conflated with one in `paper/SIS01_paper.md` when it is written.

## I. Claims that MUST NOT be made

Per the parent prompt's explicit prohibitions, restated here against what
this codebase specifically could tempt someone to overclaim:

- **Not** "the firmware runs the post-quantum handshake" without the
  qualifier "proven by host-side interop test against real ESP32 C code;
  not run on physical hardware." `firmware/README.md` already gets this
  right; any new doc referencing it must preserve that distinction.
  **Not** "the flash/RAM/timing numbers are measured on a real board" — the
  287 KB / 21% flash figure and the 79%-flash `sketch_pqc` figure are real
  compiler output (`arduino-cli` build artifacts), not simulated, but they
  are compile-time figures, not runtime-on-hardware figures. Runtime timing,
  power, and Wi-Fi behavior remain NOT MEASURED.
- **Not** "quantum-proof" or "unbreakable" — `RESEARCH.md` already avoids
  this; keep avoiding it in every new doc.
- **Not** "IEC 61511 / IEC 62443 certified" or "SIL-rated" — nothing in the
  codebase claims this today; do not introduce it.
- **Not** "novel" for ML-KEM+ML-DSA use, watchdog patterns, or authenticated
  safety messages generically, per the parent prompt's explicit instruction.
- **Not** "production-ready" — `server_engine.seen_nonces` is unbounded
  in-memory state with no restart persistence (finding B, last bullet), and
  the bypass mechanism has no timeout (finding C); both are reasonable for a
  research testbed and disqualifying for a production safety system.

## J. Reproducibility problems

- **J-1. `CLAUDE.md` understates the attack framework.** The top-level
  project description says "a scripted attacker" and the Makefile help text
  says "one-shot 3-stage attack" (`Makefile` help block, `make attack`
  entry). The actual `ATTACK_ORDER` has ten stages. This is a real
  documentation drift, not a fabrication — the code is simply ahead of the
  top-of-file docs. `CLAUDE.md` is the project's own instruction file: this
  audit does not correct it (out of scope for this phase), but any new
  research doc must describe the ten-stage reality, not the three-stage
  description.
- **J-2. Nonce/replay state does not survive a server restart.**
  `server_engine.seen_nonces` and `server_engine.operator_nonces`
  (`app/server.py:57` and the `CentralServer.__init__` block) are plain
  in-process sets. No test exercises "server restarts, previously-seen nonce
  is replayed" — this is a real, currently-untested reproducibility and
  security gap, not present in any of the 76 existing tests by name.
- **J-3. No bypass timeout or expiry.** `server_engine.bypass` stays asserted
  indefinitely once set; nothing times it out, reminds an operator it is
  still asserted, or logs periodically while it stands. No test covers this
  because there is no behavior to test — it is an absent feature, not a
  broken one.
- **J-4. No automated test for restart-during-trip re-assertion.** The
  comment at `app/server.py:368` documents the intended behavior (a
  reconnecting actuator is told the authoritative state); no test drives
  "server restarts while `trip_state == TRIPPED`, actuator reconnects,
  actuator ends up `CLOSED`."
- **J-5. `bench.py` has no seed control or repeated-run aggregation across
  invocations.** Running it twice gives two independent 60-round summaries
  with no combined record; making a benchmarking claim reproducible in the
  spec's sense (sections 17-18: N≥100, raw logs, no manually-copied numbers)
  needs a harness that does not exist yet.
- **J-6. `results/attacks/*.json` does not exist.** Attack outcomes are
  visible only in a running dashboard session; nothing is written to disk
  for later citation. **Closed in phase 3**: `report_attack()`
  (`app/server.py`) now writes each finding to `results/attacks/<id>.json`
  on every run, one file per attack identifier, overwritten with the latest
  result — gitignored (machine/run-specific), same as the benchmark output
  in `results/raw` and `results/processed`.

## K. Safety-standard gaps

Framed against IEC 61511 / ISA-84 concepts, without claiming compliance
(full mapping deferred to `docs/STANDARDS_MAPPING.md`, a later phase):

- **No SIL-relevant proof-test or diagnostic-coverage concept exists.** The
  system either has a live session or it doesn't; there is no periodic
  self-test of the trip path independent of live telemetry.
- **No documented safe-failure fraction or fault model.** A crashed sensor
  process simply stops sending telemetry; the system has no distinction
  between "no data because nothing to report" and "no data because the
  transmitter has failed," beyond the MAX6675 open-thermocouple `NAN` path
  in firmware (`firmware/README.md`, "the library returns `NAN` and the
  sketch refuses to publish") which is real but firmware-only, not mirrored
  in the Python sensor node.
- **Bypass has no time-box, dual-authorization, or automatic-reassertion
  requirement**, all of which IEC 61511 treats as important for maintenance
  overrides (finding C, J-3).
- **Proof of the "authenticated ≠ safety-valid" property exists only as a
  demonstration (`insider` stage), not as a documented, versioned safety
  requirement with a corresponding formal invariant** — this is exactly
  what `docs/SAFETY_MODEL.md` (this phase) closes.

## L. Patent-search questions

Deferred to a later phase's `docs/PATENTABILITY_RESEARCH.md`; recorded here
only as open questions this audit surfaces, not as answers:

1. Is per-link HKDF domain separation combined with an independent,
   server-unreachable dead-man watchdog (rather than a server-mediated
   fail-safe decision) previously described in ICS/OT security or SIS
   literature, and if so, at what level of specificity?
2. Is the specific combination of "signature verifies AND value fails a
   bounded safety-policy clamp AND the rejection is logged with a distinct
   security-event type" (as opposed to signature verification alone gating
   acceptance) described elsewhere as a named pattern, or only as general
   defense-in-depth advice?
3. Does prior art exist for transcript-binding a KEM ciphertext and a role
   claim together in one ML-DSA signature specifically to prevent
   role-reuse across sensor/actuator enrollment (`app/identity.py:52-59`),
   as opposed to transcript-binding for replay prevention generally?

---

*This audit describes the repository as read on 2026-08-25. It is a snapshot,
not a living document — re-run the audit rather than hand-editing this file
if the codebase changes materially.*
