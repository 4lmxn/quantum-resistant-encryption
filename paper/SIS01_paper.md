<title>SIS01_paper.md</title>
# Authentication is not safety validity: a post-quantum safety-instrumented-system testbed modeled on TRITON/TRISIS

**Status: working draft.** Numbers are real, pulled from committed benchmark
output. Related work (Section 7) is grounded in a real, if limited,
prior-art search (`docs/PATENTABILITY_RESEARCH.md`) rather than asserted
from memory. Every claim in this draft must trace to a file in this
repository or a cited external source — see `docs/RESEARCH_AUDIT.md`
section I for the specific claims this paper must never make (SIL rating,
IEC certification, "quantum-proof," "novel" for the primitive combination
alone, "production-ready"). What's still missing before this could be a
submission-ready manuscript: a proper literature review beyond the ~10
prior-art queries in Section 7, full peer citations (not just search-result
links), and the still-open measurement gaps in Section 6.

## Abstract

Industrial safety instrumented systems (SIS) increasingly run on the same
Ethernet as the plant's ordinary control network, and the 2017
TRITON/TRISIS incident showed the consequence: an intruder who reaches a
safety controller's engineering path can reprogram the logic that is
supposed to be the plant's last line of defense. Separately, ML-KEM and
ML-DSA (NIST FIPS 203/204) close the "harvest now, decrypt later" exposure
that a future cryptanalytically relevant quantum computer creates for any
system whose safety-relevant channel confidentiality or authenticity relies
on classical public-key cryptography. This paper describes SIS-01, a
testbed combining both: a real ML-KEM-768 + ML-DSA-65 handshake protecting
every node-to-server link of a simulated high-temperature emergency
shutdown, exercised against ten reproducible attack scenarios plus two
forward-looking quantum ones. Its central experimental result is not about
cryptography: a correctly authenticated, validly signed operator command is
independently rejected by a bounded safety-policy clamp, demonstrating that
authentication and safety validity are two gates, not one — the specific
lesson of both TRITON/TRISIS and the 2021 Oldsmar water-treatment incident,
reproduced here as a controlled, measured experiment rather than an incident
report.

## 1. Introduction

### 1.1 Motivation

Two failure modes motivate this work, and they are independent of each
other:

1. **A legitimate control path used illegitimately.** In both TRITON/TRISIS
   (Schneider Triconex, 2017) and the Oldsmar, Florida water-treatment
   intrusion (2021), the attacker did not need to break cryptography — they
   reached a control path that already had the authority to do damage, and
   used it correctly. A defense that stops at "is this command
   authentically from an authorized party" does not stop this class of
   incident, because the answer was yes.
2. **Cryptographic exposure to a future quantum adversary.** Any SIS whose
   channel confidentiality or command authenticity rests on RSA or ECDSA is
   vulnerable to store-now/decrypt-later harvesting today and to real-time
   forgery once a cryptanalytically relevant quantum computer exists.
   FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), finalized August 2024, are
   NIST's standardized answer.

SIS-01 exists to make both failure modes demonstrable in one running
system, side by side, so the more important point — that closing (2) does
nothing about (1) — is not an abstract claim but something a reader can
watch happen.

### 1.2 What this paper is and is not

This is a testbed paper, not a cryptographic-scheme paper (ML-KEM and
ML-DSA are used as standardized, not modified) and not a certification
claim. `docs/RESEARCH_AUDIT.md` section I lists the specific claims this
project must not make; the strongest version of this paper's contribution
is: *a reproducible, measured, open demonstration that authenticated ≠
safety-valid, built on real post-quantum primitives rather than placeholder
cryptography.* Section 6 states plainly what is not yet measured or proven.

## 2. System design

SIS-01 models one safety instrumented function: a high-temperature
emergency shutdown that closes valve XV-101. The architecture is a star
topology — a sensor node, an actuator node holding XV-101, a signed
operator console, and a browser dashboard, all communicating only through a
central logic solver (`app/server.py`), never with each other directly. A
constrained-node simulator stands in for an ESP32-class device and speaks
the same handshake over three HTTP POSTs instead of Socket.IO.

Every node begins with an ML-KEM-768 handshake, authenticated by an
ML-DSA-65 signature over the transcript in both directions; a node holds no
session key until that signature verifies. `HKDF-SHA256` with a per-link
domain-separation label (`LINK_SENSOR` vs. `LINK_ACTUATOR`) derives
independent AES-256-GCM session keys from each node's own handshake, so the
sensor and actuator links can never share key material even though both
trace back to the same server identity. Full protocol detail is in
`docs/SYSTEM_MODEL.md`; the threat model behind each design choice is in
`docs/THREAT_MODEL.md`.

Two properties matter most for the safety argument in Section 4:

- **Trips latch.** Falling back below the setpoint does not clear a trip —
  only a signed operator `RESET` does. Cooling down is not evidence the
  cause was addressed (`docs/SIS_CONTRACT.md`).
- **The actuator's fail-safe decision is server-independent.** A dead-man
  watchdog on the actuator node itself closes XV-101 after
  `HEARTBEAT_TIMEOUT_S` of silence from the server, regardless of *why* the
  server went silent (crashed, network severed, or deliberately attacked).
  This replaced an earlier fail-danger design in which losing the server
  meant losing the ability to command a trip at all.

## 3. Threat model, summarized

Full detail in `docs/THREAT_MODEL.md`; the load-bearing assumptions:

- The attacker has full passive visibility and active inject/modify/drop/
  replay capability (Dolev-Yao) on every channel.
- The attacker may, in specific scenarios, possess a legitimately-enrolled
  operator's signing key (`insider`) or the constrained node's static
  provisioning key (`psk`) — modeling a coerced/malicious insider or a
  stolen board, not a cryptanalytic key-recovery.
- The attacker is not assumed to have compromised the server process or
  machine itself, and is not assumed to have physical access to XV-101.
- Standard unforgeability/IND-CCA2 assumptions hold for ML-DSA-65 and
  ML-KEM-768 at NIST category 3, and for AES-256-GCM.

Ten attack stages exercise this model against real running code (not
simulated outcomes): silence, a stolen PSK, an insider issuing an
out-of-bounds signed command, a rogue node attempting to enroll without a
valid identity, command replay, forged-command injection (MITM), telemetry
replay, replay into a closed session, a nonce-reuse probe, a stale-timestamp
operator command, a trust-downgrade attempt against an authenticated device,
malformed and oversized packets, the (removed) unsigned control path, and
two fail-safe-coverage questions (no actuator connected; server down). Two
further stages are narrated rather than executed — Shor's algorithm against
the RSA fallback and lattice reduction against ML-KEM — because they are
either cited (Shor's, against a deliberately small RSA modulus so the
demonstration completes in milliseconds) or bounded honestly as "not a BKZ
run" (Section 6). Catalog and per-attack evidence: `app/attacks/attacks.py`.

## 4. Central result: authenticated ≠ safety-valid

The `insider` attack stage is the paper's centerpiece. A legitimately
enrolled operator identity — key genuinely possessed, not stolen or
forged — signs a `SET_SETPOINT` command requesting a 60 °C move in one
step, an order of magnitude past `SETPOINT_MAX_STEP_C` (15 °C).
`handle_operator_command` verifies the ML-DSA-65 signature first — it is
valid — and only afterward checks the value against `SETPOINT_MIN_C`/
`SETPOINT_MAX_C`/`SETPOINT_MAX_STEP_C`. The command is refused, and logged
as a distinct `[SIS] Operator command REFUSED` event, separately from a
signature-failure refusal.

`tests/test_operator_auth.py::test_a_setpoint_outside_the_clamp_is_refused_even_when_signed`
is written specifically to isolate this property: it calls
`identity.verify()` directly on the payload before submitting it, so the
refusal that follows can only be attributed to the safety-policy clamp,
never to an accidentally-broken signature. Its docstring names it "the
Oldsmar lesson" — the 2021 incident in which a legitimate remote-access
path, not a cryptographic break, let an intruder attempt to move a sodium
hydroxide setpoint to a dangerous level.

The general property this instantiates: **signature verification and
safety-policy validation are independent, sequential gates over the same
command, and passing the first is necessary but not sufficient to pass the
second.** `docs/SAFETY_MODEL.md` INVARIANT-05 is the formal statement;
`docs/STANDARDS_MAPPING.md`'s IEC 62443 "Use control (FR 2)" row is the
standards vocabulary for the same idea. Whether this specific combination —
signature-then-clamp, with a distinct logged event type per rejection
reason — has been described elsewhere as a named pattern rather than
general defense-in-depth advice is an open prior-art question; see
`docs/PATENTABILITY_RESEARCH.md`.

## 5. Measured cost

### 5.1 Cryptographic primitives

`scripts/bench_crypto.py`, N=1000 (100 for keygen), pure-Python reference
implementations (`kyber-py`, `dilithium-py`), single laptop, no hardware
acceleration. Full percentile data: `results/processed/crypto_latency_summary.json`.

| Operation | median | p95 | p99 |
|---|---|---|---|
| ML-KEM-768 keygen | 1.961 ms | 2.043 ms | 2.153 ms |
| ML-KEM-768 encapsulate | 2.615 ms | 2.690 ms | 2.864 ms |
| ML-KEM-768 decapsulate | 3.522 ms | 3.611 ms | 3.739 ms |
| ML-DSA-65 keygen | 5.752 ms | 5.869 ms | 5.937 ms |
| ML-DSA-65 sign | 27.685 ms | 90.745 ms | 127.364 ms |
| ML-DSA-65 verify | 6.475 ms | 7.021 ms | 8.321 ms |
| AES-256-GCM seal | 0.0029 ms | 0.0031 ms | 0.0039 ms |
| AES-256-GCM open | 0.0020 ms | 0.0020 ms | 0.0026 ms |
| HKDF-SHA256 derive | 0.0046 ms | 0.0047 ms | 0.0049 ms |

ML-DSA-65 sign has by far the widest spread (median 27.7 ms vs. p99
127.4 ms) because ML-DSA uses rejection sampling — the number of attempts
to produce a valid signature varies per call. This is inherent to the
scheme, not measurement noise, and any paper citing a single "signing cost"
number without the percentile spread is misrepresenting it.

A full authenticated handshake (one ML-KEM keypair + encapsulate/decapsulate,
two ML-DSA sign/verify pairs) is dominated by signing cost: at the median,
roughly 1.96 + 2.62 + 3.52 + 2×27.69 + 2×6.48 ≈ **76 ms**; at p95, the
signing tail pushes it toward **200 ms**. These are pure-Python reference
figures — optimized C (liboqs, pqm4) is reported in the literature as
roughly two orders of magnitude faster — so treat this as an upper bound on
handshake cost, not a deployment estimate.

### 5.2 End-to-end safety-response latency

`scripts/bench_safety_response.py`, N=100 per condition, sensor event to
this script's own actuator-side handler observing `CLOSED`, both endpoints
timed in one process with `perf_counter()`. Full data:
`results/processed/safety_response_{idle,cpu}_summary.json`.

| Condition | n | median | p95 | p99 |
|---|---|---|---|---|
| idle | 100 | 1.012 ms | 1.327 ms | 1.412 ms |
| host under CPU load | 100 | 2.208 ms | 4.626 ms | 8.895 ms |

This is `T_TOTAL` only — a single end-to-end bound established once per
condition, not the six-way `T_sensor`/`T_network_in`/`T_crypto`/`T_logic`/
`T_network_out`/`T_actuator` breakdown a full latency characterization
would want. That breakdown needs a timestamp injected into `app/server.py`'s
own processing and remains **not measured** (`docs/SAFETY_MODEL.md`
INVARIANT-01). CPU load roughly doubles median latency and more than
sextuples p99, which is itself a finding worth stating plainly: this
system's response-time bound is not load-independent, and any deployment
claim would need a characterized worst-case host load, not just an idle
number.

## 6. Limitations — what this paper does not claim

Reproduced in full detail in `docs/RESEARCH_AUDIT.md`; summarized here so a
reader of this paper alone sees them without needing the companion
document:

- **No SIL rating, no IEC 61511/62443 certification, no claim of either.**
  `docs/STANDARDS_MAPPING.md` is a concept mapping, not a conformance
  worksheet — it states directly which IEC concepts (proof test, safe
  failure fraction, diagnostic coverage, security level) this codebase does
  not implement at all.
- **The `kyber` attack stage does not run BKZ.** It captures a real
  1184-byte encapsulation key off the wire and shows two independent
  encapsulations against it yield two independent secrets — proving replay
  recovers nothing, not attempting or bounding a lattice-reduction attack.
- **The firmware ML-KEM+ML-DSA handshake has not run on physical
  hardware.** It is proven by host-side interop test against real ESP32 C
  code (cross-checked against `kyber-py`/`dilithium-py` known-answer
  vectors), not by measured runtime, flash headroom under TLS, or power
  draw on a board. `firmware/README.md` documents the specific blockers.
- **No sensor-lane denial-of-service fail-safe.** Cutting the actuator link
  causes a trip by design; cutting the sensor link produces silence with no
  equivalent forced response (`docs/THREAT_MODEL.md`, "New gaps this
  analysis surfaces").
- **One gap found by this phase's own attack stages remains open, not
  fixed:** no actuator process running means no watchdog enforcing the
  fail-safe at all (`actuator_absent`, HIGH) — deliberately so, since the
  watchdog is actuator-resident by design (`docs/SIS_CONTRACT.md`) and a
  server-side fix would mean moving that decision back to the server. A
  second gap, an oversized forged packet reaching a full decrypt attempt
  before being rejected (`oversized`, LOW), is now closed: `app/config.py`'s
  `MAX_CIPHERTEXT_HEX_CHARS` rejects it on field length first, in
  `decrypt_sensor_data`, the single choke point every sensor-originated
  packet passes through regardless of transport.
- **Nonce/replay state does not survive a server restart** — `seen_nonces`
  and `operator_nonces` are in-process sets with no persistence
  (`docs/RESEARCH_AUDIT.md` J-2).
- **Bypass has no timeout, dual-authorization, or automatic
  reassertion** — asserted indefinitely once set (`docs/RESEARCH_AUDIT.md`
  finding C, J-3; `docs/STANDARDS_MAPPING.md` bypass row).
- **Single-family cryptographic risk.** ML-KEM and ML-DSA both rest on
  structured lattices; a break in that mathematical family removes key
  exchange and authentication together. A hybrid construction with a
  non-lattice backup (NIST selected HQC, code-based, as a backup KEM in
  March 2025; SLH-DSA, hash-based, is the equivalent hedge for signatures)
  is the natural next step and is not implemented here.
- **No side-channel resistance.** Reference implementations are not
  constant-time; this is a correctness/protocol testbed, not a
  side-channel-hardened one.

## 7. Related work and prior art

Full search detail and honest scope caveats: `docs/PATENTABILITY_RESEARCH.md`
(~10 web/patent queries, one session, not a professional clearance search).
Summarized here, not duplicated:

- **Watchdog independent of a central controller on comm loss** is
  decades-established ICS/OT practice (US4926158; US4598355) and, more
  generally, the textbook definition of a watchdog timer. SIS-01's
  actuator-resident dead-man watchdog is an application of this established
  pattern to a post-quantum-authenticated SIS, not a new mechanism.
- **HKDF domain separation for multiple independent keys off one shared
  secret** is standard KDF practice, and PQC-specific variants already
  exist in patent filings on multi-purpose PQC-KEM session derivation
  (US12301709). No source found combines this with a server-independent
  safety watchdog as one architectural principle applied twice — see
  `docs/PATENTABILITY_RESEARCH.md` Q1 for the full comparison.
- **A second, content-based gate after signature verification** has direct
  prior art in industrial control specifically: US10542007 (Bedrock
  Automation) checks a command against a whitelist after authentication,
  before forwarding it to the unit controller. SIS-01's clamp differs in
  mechanism (bounded numeric range plus an independent rate-of-change limit,
  vs. discrete whitelist membership) but is the same structural idea —
  authentication necessary, not sufficient. `docs/PATENTABILITY_RESEARCH.md`
  Q2 has the full comparison, including why 10542007 is prior art an
  examiner would cite regardless of how SIS-01's specific clamp is worded.
- **Transcript-binding a KEM ciphertext for session/downgrade integrity**
  is standard, TLS-1.3-lineage practice, and appears in at least one 2025
  paper using this project's exact primitive pairing: a Frontiers in
  Physics paper on an authenticated post-quantum session protocol using
  ML-KEM, ML-DSA, and AES-256-GCM, which uses a transcript-bound
  HKDF-SHA3-256 key schedule for downgrade resistance. That paper's
  transcript binding is session-scoped, not role-scoped. SIS-01's specific
  choice — binding the claimed enrollment role (`sensor` vs. `actuator`)
  into the same signed transcript as the KEM ciphertext, so a signature
  captured from one role's handshake cannot be replayed to claim the other
  role — was not found described elsewhere in this search, making it the
  narrowest and least-covered of the three claims investigated
  (`docs/PATENTABILITY_RESEARCH.md` Q3) — and also the least verified: two
  2025 papers using near-identical primitives (the Frontiers paper above,
  and a Nature Scientific Reports paper on lattice-based IIoT
  authentication) were found by search snippet only, not read in full.
- TRITON/TRISIS (Schneider Triconex, 2017) — the incident this testbed's
  topology and attack framing are modeled on.
- Oldsmar, Florida water-treatment intrusion (2021) — the incident
  `tests/test_operator_auth.py`'s central test is explicitly named after.
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), finalized
  August 2024.
- NIST selection of HQC as a backup key-encapsulation mechanism, March 2025.
- Energy consumption analysis of post-quantum key generation on embedded
  devices, arXiv:2505.16614.

None of the above should be read as a novelty claim for SIS-01. Section 6
and `docs/RESEARCH_AUDIT.md` section I already forbid that; this section
exists to place the work accurately against what a ten-query search
actually found, not to argue for a patent.

## 8. Reproducibility

Every number in Section 5 is regenerable: `make bench-crypto` and
`make bench-safety` / `make bench-safety-cpu` (the latter two need
`make server` running). Raw per-trial CSV and JSON summaries are written to
`results/raw/` and `results/processed/`, gitignored as machine- and
run-specific rather than committed as static evidence — this paper cites
the specific numbers produced on 2026-08-26 (`docs/RESEARCH_AUDIT.md`'s
snapshot date) as one reproducible run, not as a permanent constant. Attack
findings persist to `results/attacks/<id>.json` on every run via
`report_attack()`, one file per attack identifier, for citation without
needing a live dashboard session. `docs/RESEARCH_AUDIT.md` sections J and G
list what is still not reproducible or not yet measured at all — most
importantly the six-way latency breakdown and any ESP32-on-hardware number.

---

*This is a working draft, not a submission-ready manuscript. Any claim
added to this document must be checked against `docs/RESEARCH_AUDIT.md`
section I before being written down.*
