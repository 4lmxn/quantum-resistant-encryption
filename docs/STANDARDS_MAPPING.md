<title>STANDARDS_MAPPING.md</title>
# Standards mapping — IEC 61511 / IEC 62443

Maps this codebase against the *concepts* IEC 61511 (functional safety for
the process industry) and IEC 62443 (security for industrial automation and
control systems) use, so a reader who knows those standards can place SIS-01
correctly. This is a concept mapping, not a compliance claim.

**This system is not certified against, and does not claim conformance
with, IEC 61511, IEC 62443, or any SIL rating.** `docs/RESEARCH_AUDIT.md`
section I already forbids that claim; this document is the detailed version
of why — it walks every concept a certifier would check and states plainly,
per concept, whether the codebase has it, partially has it, or doesn't.
Nothing below should be read as a step toward certification; it is a
vocabulary bridge for a security/crypto audience to talk to a process-safety
audience about the same system.

## Why two standards, not one

IEC 61511 governs whether a safety instrumented function (SIF) does the
right physical thing under a *random or systematic hardware/software
fault*. IEC 62443 governs whether an industrial control system resists a
*deliberate adversary*. TRITON/TRISIS (the incident this project is modeled
on, `CLAUDE.md`) sits exactly at the seam: the attacker used a legitimate
engineering-workstation access path (a 62443 concern) to reprogram safety
logic (a 61511 concern). SIS-01's central experimental result — that a
correctly authenticated command is independently rejected by a
safety-policy clamp (`docs/RESEARCH_AUDIT.md` section H, second bullet) —
is the same seam, deliberately reproduced: authentication (62443) is
necessary but not sufficient for safety validity (61511).

## IEC 61511 concepts

| Concept | IEC 61511 meaning | This codebase | Evidence |
|---|---|---|---|
| Safety Instrumented Function (SIF) | The specific automated function that takes the process to a safe state | Present, one SIF: high-temperature trip closes XV-101 | `decide_trip()`, `app/server.py`; `docs/SIS_CONTRACT.md` |
| Safety Instrumented System (SIS) | The sensor + logic solver + final element chain implementing the SIF | Present, star topology | `docs/SYSTEM_MODEL.md` Components |
| SIL (Safety Integrity Level) | A quantified probability-of-failure-on-demand target (SIL 1–4), derived from hardware fault tolerance, proof-test interval, and architecture | **Absent.** No PFD calculation, no SIL target was set, no claim is made | `docs/RESEARCH_AUDIT.md` section I |
| Safe Failure Fraction (SFF) | Fraction of failures that fail toward the safe state rather than dangerously | **Not calculated.** Qualitatively, the design leans safe (silence closes the valve — INVARIANT-06), but no fault model or FMEDA exists to turn that into a number | `docs/RESEARCH_AUDIT.md` section K |
| Proof test | Periodic manual/automated test proving the SIF still works, independent of live process data | **Absent.** The system's only self-check is "does telemetry keep arriving" — there is no scheduled trip-path exercise that doesn't depend on a real or synthetic process excursion | `docs/RESEARCH_AUDIT.md` section K |
| Diagnostic coverage | Fraction of dangerous failures detected automatically (vs. only at proof test) | **Absent** at the server. Partial at the firmware edge: MAX6675 open-thermocouple returns `NAN` and the sketch refuses to publish rather than sending a false reading — a real diagnostic, but firmware-only, not mirrored in the Python sensor node and not surfaced to the server as a `FAULT` state | `firmware/README.md`; `docs/SAFETY_MODEL.md` Model A→B mapping, `FAULT` row |
| Bypass / maintenance override management | A time-boxed, logged, often dual-authorized suspension of the safety function for maintenance | **Partial.** The bypass is authenticated (signed `BYPASS_ON`/`BYPASS_OFF`, one of four operator actions) and logged, but has no timeout, no automatic re-assertion, and no second authorizer | `docs/RESEARCH_AUDIT.md` finding C, J-3; `docs/SAFETY_MODEL.md` `BYPASS` row |
| Voting / redundancy (1oo1, 2oo3, etc.) | Multiple sensors or final elements voting to tolerate a single failure | **Absent.** Single sensor, single final element (1oo1 by construction) — appropriate for a demonstrator, not evaluated against any SIL's hardware fault tolerance requirement | `docs/SYSTEM_MODEL.md` Components |
| Fail-safe state definition | The explicit safe state a SIF drives toward | Present and explicit: XV-101 `CLOSED` | `docs/SIS_CONTRACT.md` Terminology |
| Trip latching, no auto-reset | A trip must not clear itself when the triggering condition passes | Present and well-tested (INVARIANT-07) | `docs/SAFETY_MODEL.md` INVARIANT-07 |
| Independent final-element protection on comm loss | The final element must reach the safe state on loss of communication with the logic solver, without waiting for the logic solver | Present — the actuator-resident, server-independent dead-man watchdog is the strongest single piece of engineering in this codebase against this specific concept | `CLAUDE.md` "The dead-man heartbeat, and the fail-danger path it replaced"; `docs/SAFETY_MODEL.md` INVARIANT-06 |
| Alarm / pre-trip warning band | A lower threshold that warns before the trip threshold is reached | **Absent**, deliberately — see `docs/SAFETY_MODEL.md` `ALARM` row for the stated reason (avoiding debounce noise in the latency benchmark) | `docs/SAFETY_MODEL.md` Model A→B mapping |
| Trip confirmation / debounce (N-out-of-M) | Requiring the trip condition to persist across multiple samples before latching, to reject transient noise | **Absent**, deliberately, same reasoning as the alarm band | `docs/SAFETY_MODEL.md` `TRIP_PENDING` row |

## IEC 62443 concepts

| Concept | IEC 62443 meaning | This codebase | Evidence |
|---|---|---|---|
| Zone / conduit model | Partitioning a system into security zones connected by conduits with defined trust boundaries | Present, informally: server, sensor, actuator, operator, constrained node, dashboard, attacker are each a distinct trust domain communicating only through defined conduits (Socket.IO events, HTTP endpoints) — no node talks to another node directly | `docs/SYSTEM_MODEL.md` Trust boundaries, Independent trust domains |
| Security level (SL 1–4) | A target strength of security control against attacker capability tiers | **Not assigned.** The threat model states assumed attacker capabilities and limitations directly rather than mapping to a numbered SL | `docs/THREAT_MODEL.md` Attacker capabilities / limitations |
| Identification and authentication control (FR 1) | Every entity that can affect the system is uniquely identified and authenticated | Present for nodes (ML-DSA-65 identity per sensor/actuator/operator, verified in the handshake transcript) and for the constrained node (`/pqc/hello` + `/pqc/encapsulate`) | `CLAUDE.md` Architecture; `docs/SIS_CONTRACT.md` Enrolment |
| Use control (FR 2) | Authenticated identity is further checked against what that identity is permitted to do, not just who it is | Present — this is exactly `handle_operator_command`'s clamp/step-limit logic, applied *after* signature verification | `docs/SAFETY_MODEL.md` INVARIANT-05 |
| System integrity (FR 3) | Detecting and rejecting unauthorized modification of data/commands in transit | Present — AES-256-GCM authenticated encryption on every data leg; a bad tag is rejected, never silently accepted (`CLAUDE.md` "Never swallow those or add a plaintext fallback") | `CLAUDE.md` Architecture; `tests/test_safety_invariants.py` |
| Data confidentiality (FR 4) | Sensitive data is protected from disclosure | Present for session traffic (AES-256-GCM); long-term signing keys are file-permission-protected (mode 0600) and, per the HSM commit, can be held in a PKCS#11 HSM rather than on disk at all | `CLAUDE.md` Conventions; commit `b5f8949` |
| Restricted data flow (FR 5) | Network segmentation preventing lateral movement between zones | **Partial by topology, not by explicit control.** The star topology means nodes cannot reach each other directly (`docs/SYSTEM_MODEL.md`), which achieves the effect, but there is no firewall/ACL layer enforcing it — it is a property of what messages the server's own handlers accept, not of the network | `docs/SYSTEM_MODEL.md` Trust boundaries |
| Timely response to events (FR 6) | Security-relevant events are logged and can be acted on in time | Present for logging (`security_log`, typed `SUCCESS`/`ERROR`/`ALERT`/`ATTACK`; findings additionally persisted to `results/attacks/*.json`); **absent** for automated response — there is no alerting/SOAR-style reaction beyond the dashboard display | `CLAUDE.md` Conventions; commit `2c4e0ed` |
| Resource availability (FR 7) | The system resists denial-of-service and degrades gracefully under load | **Partial, and one confirmed gap.** No explicit request-size cap at the application layer — the `oversized` attack stage shows an oversized forged packet is still rejected correctly (the GCM tag fails), but only after the decrypt attempt, meaning a flood of oversized junk is a real, if narrow, CPU-cost DoS angle. No fix has been applied yet | `app/attacks/attacks.py` `oversized` catalog entry (`gap: True`); `docs/RESEARCH_AUDIT.md` |
| Least privilege | Each identity can only perform actions appropriate to its role | Present — role validation on handshake (`sensor`/`actuator` only, no default branch — `CLAUDE.md` "Roles are validated, deliberately"); a sensor's session key cannot be used to send actuator commands | `CLAUDE.md` "Roles are validated, deliberately" |
| Secure by default / no unauthenticated control path | A control system should not ship a data path that can change safety-relevant state without authentication | Present, and unusually explicit about it — the old unsigned handlers were deleted, not merely disabled, specifically so there is no handler left to even refuse a legacy call (`CLAUDE.md` "No unsigned control path exists — do not add one back"); the `invalid_transition` attack stage demonstrates this directly | `CLAUDE.md`; `app/attacks/attacks.py` `invalid_transition` |

## What this mapping does not attempt

- No PFD/PFH arithmetic, no SIL derivation. That requires a hardware fault
  model this project does not have (single relay/valve simulation, not a
  characterized field device).
- No formal FR-by-FR IEC 62443-4-2 component conformance table — the table
  above is concept coverage, not a certification worksheet with pass/fail
  test evidence per requirement ID.
- No claim about IEC 62443 zone/conduit *documentation* artifacts (a real
  62443 program produces a zone diagram, risk assessment per zone, and a
  security level target per zone as formal deliverables) — `docs/SYSTEM_MODEL.md`
  is the closest artifact this project has, and it was not written against
  the 62443 documentation template.

---

*Companion documents: `docs/SAFETY_MODEL.md` for the invariant-level detail
behind the IEC 61511 rows above; `docs/THREAT_MODEL.md` for the STRIDE
analysis behind the IEC 62443 rows; `docs/RESEARCH_AUDIT.md` section K for
the gap list this document was commissioned to formalize.*
