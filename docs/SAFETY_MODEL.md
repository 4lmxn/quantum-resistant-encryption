<title>SAFETY_MODEL.md</title>
# Safety model

Two state machines appear in this document, and conflating them would be
the single easiest way to overclaim. **Model A** is the formal,
IEC-61511-flavored state machine a safety analyst would draw for a system
like this in the abstract. **Model B** is what `app/server.py` and
`app/nodes/actuator.py` actually implement today. The gap between them is
listed explicitly, not smoothed over — most of Model A's states collapse
into two implemented states plus one independent flag plus one independent
watchdog, and that collapse is a legitimate engineering choice for a
research testbed, not a bug, but it is not the same diagram.

## Model A — formal target state machine

```
                 process variable >= trip setpoint
      ┌─────────┐  ────────────────────────────►  ┌──────────┐
      │ NORMAL  │                                  │ TRIPPED  │
      └────┬────┘  ◄────────────────────────────┐  └────┬─────┘
           │         (no automatic path back)     │      │
           │ operator asserts bypass              │      │ authenticated RESET
           ▼                                       │      ▼
      ┌─────────┐                                  │  ┌──────────────┐
      │ BYPASS  │                                  │  │ RESET_PENDING │
      └────┬────┘                                  │  └──────┬────────┘
           │ operator clears bypass                │         │ RESET verified
           └───────────────────────────────────────┘         ▼
                                                          NORMAL

      NORMAL / BYPASS ──(comm timeout)──► COMMUNICATION_LOSS ──(fail-safe)──► TRIPPED
      any state ──(self-check failure)──► FAULT
```

`ALARM` and `TRIP_PENDING` (a pre-trip warning band and a debounce/confirm
step before latching) are part of the minimum state list the parent
research prompt asks for and are included in the diagram's vocabulary
below for completeness, even though — see Model B — neither exists as a
distinct implemented state.

## Model B — what is actually implemented

```
      trip_state: "HEALTHY" | "TRIPPED"     (app/server.py:49)
      bypass:      bool                      (app/server.py:52, independent flag)
      watchdog:     actuator-local, independent of trip_state entirely
                     (app/nodes/actuator.py:92-115, 213-)

      HEALTHY ──(temperature >= trip_setpoint, AND bypass == False)──► TRIPPED
                                                     (app/server.py:300-317)

      TRIPPED ──(authenticated operator RESET)──► HEALTHY
                                                     (app/server.py:331-336)

      [independent of trip_state:]
      actuator watchdog silent > HEARTBEAT_TIMEOUT_S ──► XV-101 CLOSED locally
                                                     (app/nodes/actuator.py:213-)
```

## Explicit mapping, Model A → Model B

| Model A state | Model B equivalent | Gap |
|---|---|---|
| `NORMAL` | `trip_state == "HEALTHY"` | None — direct correspondence |
| `ALARM` | **Does not exist.** There is no pre-trip warning band; `decide_trip()` only ever compares `temperature >= trip_setpoint`, a single threshold with no earlier alarm point. | Real gap. Adding one is a config/logic change (a second, lower threshold that only logs), not a rewrite — noted as a candidate for a later phase, not done here. |
| `TRIP_PENDING` | **Does not exist.** The edge into `TRIPPED` is instantaneous and unconditional on the reading alone (no debounce, no N-out-of-M voting, no confirm delay). | Real gap, and a deliberate one worth stating plainly: for a *research testbed* whose point is measuring authenticated-command and forged-command handling, debounce logic would only add noise to the latency benchmarks the later phase needs. Documented here so it is a decision, not an oversight. |
| `TRIPPED` | `trip_state == "TRIPPED"` | None — direct correspondence, and this is the best-tested state transition in the codebase (`tests/test_trip_logic.py`, 9 tests) |
| `BYPASS` | `bypass == True` | **Partial.** In Model A, `BYPASS` is drawn as a state the system *is in*, mutually exclusive with `NORMAL`/`TRIPPED`. In Model B, `bypass` is an orthogonal flag that can be `True` while `trip_state` is either value — `decide_trip()` just returns early when it's set (`app/server.py:309-310`), it does not transition `trip_state` anywhere. This is arguably more correct than Model A's mutual-exclusion drawing (a bypassed plant that is *already* tripped should stay `TRIPPED`, not silently become "BYPASS" and lose that fact), but it means Model A's diagram above is a simplification for readability, not literally what the code does. |
| `RESET_PENDING` | **Does not exist.** `clear_trip()` (`app/server.py:331-336`) is synchronous and unconditional once the operator-auth checks upstream in `handle_operator_command` pass — there is no intermediate state where a reset has been requested but not yet confirmed. | Real gap. A `RESET_PENDING` state would matter if reset needed a second confirmation or a field verification step (e.g., "process variable has actually returned below setpoint" — which, per `docs/SIS_CONTRACT.md`, is explicitly *not* required, since cooling is not evidence the cause was addressed). Given that design choice, `RESET_PENDING` may not even be the right target state for this system — flagged as a question for the safety-standards mapping phase, not resolved here. |
| `COMMUNICATION_LOSS` | **Does not exist as a `trip_state` value**, but its safety *consequence* is fully implemented via the independent actuator watchdog. | This is the most important entry in this table. Model A treats communication loss as a state the *system* enters, observable at the server. Model B never represents it at the server at all — `trip_state` on the server can stay `HEALTHY` indefinitely while XV-101 has already closed itself locally, because the watchdog is deliberately server-independent (`CLAUDE.md`, "The dead-man heartbeat, and the fail-danger path it replaced"). The physical outcome invariant-06 requires (fail-safe within watchdog timeout) is satisfied; the *server's own state variable reflecting it* is not. `handle_relay_actuator_ui` (`app/server.py:699-710`) does reconcile this when the actuator reports back — the server adopts `TRIPPED` on a disagreement — but only after the fact, not as a `COMMUNICATION_LOSS` transition in its own right. |
| `FAULT` | **Does not exist.** No self-check, no sensor-fault detection in the Python nodes (the MAX6675 open-thermocouple `NAN` path in firmware is the one real exception, and it only refuses to publish — it does not report a `FAULT` state to the server; see `docs/RESEARCH_AUDIT.md` K). | Real gap. |

**The honest summary**: Model B correctly implements the *safety-critical*
transitions of Model A (trip, latch, authenticated reset, fail-safe on
comm loss) but does not represent several of Model A's states as
first-class, observable server state. The system behaves safely in the
gaps (silence still fails toward `CLOSED`; there is no unsafe hidden
state), but an operator watching only `trip_state` cannot currently tell
"the plant is fine" apart from "the actuator has already fail-safed
locally and the server doesn't know yet." That is the single most
actionable finding in this document for a future phase.

## Invariants

Each invariant below states the requirement, its current test coverage
(file + test name where one exists), and, where no automated coverage
exists, what kind of coverage would close the gap.

### INVARIANT-01 — bounded trip response time

*If process pressure/temperature exceeds the configured trip threshold,
XV-101 must transition to CLOSED within a measured maximum response time.*

**Coverage, before this phase: NOT MEASURED.** No unit test can establish a
timing bound — this requires the statistical latency-benchmark harness
(parent prompt section 13, a later phase). `tests/test_trip_logic.py` proves
the *logical* edge fires correctly and exactly once; it says nothing about
wall-clock latency. Do not cite `test_trip_logic.py` as evidence for this
invariant in any later paper draft — it is not.

**Closed this phase** by `scripts/bench_safety_response.py`, run against a
live server with two real ML-KEM-768/ML-DSA-65-handshaked Socket.IO clients
(100 trials each condition, single-process `perf_counter()` for both
endpoints — see the module docstring for exactly what T_TOTAL does and does
not cover):

| Condition | n | median | p95 | p99 |
|---|---|---|---|---|
| idle | 100 | 1.012ms | 1.327ms | 1.412ms |
| host under `cpu_count()` busy-loop load | 100 | 2.208ms | 4.626ms | 8.895ms |

Raw samples: `results/raw/safety_response_{idle,cpu}.csv`. Summaries:
`results/processed/safety_response_{idle,cpu}_summary.json`. This is
`T_TOTAL` only — sensor event to this script's own actuator handler
observing `CLOSED`. The six-way `T_sensor`/`T_network_in`/`T_crypto`/
`T_logic`/`T_network_out`/`T_actuator` breakdown remains **NOT MEASURED**,
same as before: it needs a timestamp injected into `app/server.py`'s own
processing, which this phase deliberately did not add. Do not cite these
numbers as a breakdown — they are a single bound.

### INVARIANT-02 — forged telemetry never causes an unsafe command

*A forged telemetry message must never directly cause an unsafe actuator
command.*

**Coverage, before this phase: partial.**
`tests/test_device_leg.py::test_server_rejects_forged_device_packet`
covers the HTTP/constrained-node leg. Nothing previously drove
`handle_sensor_telemetry` — the primary Socket.IO safety-lane path — with
a forged or replayed packet directly. **Closed this phase** by
`tests/test_safety_invariants.py` (see below), which exercises exactly
that path.

### INVARIANT-03 — replayed command never changes safety state

*A replayed command must never change safety state.*

**Coverage: `tests/test_command_replay.py`** — 4 tests, covering a genuine
command obeyed once, an exact replay refused, a different command still
working, and a replayed `RESET` unable to reopen after a subsequent trip.

### INVARIANT-04 — unauthorized operator never modifies safety state

*An unauthorized operator must never modify safety state.*

**Coverage: `tests/test_operator_auth.py::test_an_unenrolled_operator_is_refused`**,
plus `test_a_tampered_signature_is_refused` and
`test_nothing_is_accepted_when_no_identities_are_enrolled` for the
adjacent failure modes (bad signature, unauthenticated mode entirely).

### INVARIANT-05 — authenticated but safety-invalid command is rejected

*An authenticated but safety-invalid command must be rejected.*

**Coverage: `tests/test_operator_auth.py::test_a_setpoint_outside_the_clamp_is_refused_even_when_signed`**
— this is, by a wide margin, the strongest single test in the repository
for this project's stated research question. It explicitly verifies the
signature is genuine (calls `identity.verify()` directly on the payload
before submitting it) specifically so the subsequent refusal can only be
attributed to the safety clamp, never to an accidentally-broken signature.
It is named in its own docstring as "the Oldsmar lesson." Also covered:
`test_an_oversized_step_is_refused_even_when_signed` (bounds the *rate* of
legitimate change, not just its absolute range).

### INVARIANT-06 — communication loss reaches fail-safe within watchdog timeout

*Loss of safety communication must result in the configured fail-safe
state within watchdog timeout.*

**Coverage: `tests/test_heartbeat.py`** — the watchdog-overdue tests
directly (`test_the_watchdog_is_overdue_after_the_timeout` /
`..._is_not_overdue_before_the_timeout`), plus
`tests/test_actuator_resync.py` for the reconnect-time reconciliation
behavior. This is the best-covered invariant in the codebase (14 tests in
`test_heartbeat.py` alone). Note the scope, precisely: these tests prove
the *logical* watchdog trips at the right threshold given a manipulated
clock; they do not prove the *real-time* silence-to-CLOSED latency under
load, which is INVARIANT-01's NOT MEASURED territory again.

### INVARIANT-07 — a latched trip cannot be cleared without a valid authorized reset

*A latched trip cannot be cleared without a valid authorized reset.*

**Coverage: `tests/test_trip_logic.py::test_the_latch_does_not_clear_when_it_cools`**
(no automatic clearing on any input) combined with
`tests/test_operator_auth.py::test_signed_reset_clears_a_latched_trip`
(the only path that does clear it, and it is authenticated). Together
these two tests from two different files are what jointly establish the
invariant — neither alone is sufficient, which is worth stating so a
future reader doesn't cite only one.

## Summary table

| Invariant | Status | Primary evidence |
|---|---|---|
| INV-01 bounded response time | Closed this phase | `scripts/bench_safety_response.py`, `results/processed/safety_response_*_summary.json` |
| INV-02 forged telemetry never unsafe | Closed this phase | `tests/test_safety_invariants.py` |
| INV-03 replay never changes state | Covered | `tests/test_command_replay.py` |
| INV-04 unauthorized operator refused | Covered | `tests/test_operator_auth.py` |
| INV-05 authentic-but-invalid rejected | Covered (strongest test in repo) | `tests/test_operator_auth.py::test_a_setpoint_outside_the_clamp_is_refused_even_when_signed` |
| INV-06 comm loss → fail-safe in time | Covered (logic), NOT MEASURED (real-time) | `tests/test_heartbeat.py` |
| INV-07 latch requires authorized reset | Covered (two files, jointly) | `tests/test_trip_logic.py` + `tests/test_operator_auth.py` |

---

*Companion documents: `docs/THREAT_MODEL.md` for the adversary each
invariant defends against; `docs/RESEARCH_AUDIT.md` finding C and K for
the broader safety-standard gaps (bypass now time-boxed — see finding C,
J-3; still no alarm band, no fault state) this document formalizes.*
