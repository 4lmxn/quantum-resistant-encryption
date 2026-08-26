<title>PATENTABILITY_RESEARCH.md</title>
# Patentability research

Answers the three prior-art questions logged in `docs/RESEARCH_AUDIT.md`
section L. This is a real web/patent search (~10 queries, one session,
2026-08-26), not a professional patent-clearance search — no USPTO/EPO
full-text boolean search, no IPC/CPC classification search, no non-English
literature. Treat every "no prior art found" verdict below as "not found in
this search," not as a cleared, defensible claim of novelty. Per
`docs/RESEARCH_AUDIT.md` section I, nothing in this document is grounds for
this project to claim "novel" anywhere else in its docs.

## Q1 — per-link HKDF domain separation + server-independent watchdog

*Is per-link HKDF domain separation combined with an independent,
server-unreachable dead-man watchdog previously described in ICS/OT
security or SIS literature, and if so, at what level of specificity?*

**Each half is independently well-established, decades deep, for the
watchdog side:**

- US4926158, "Powered communication link" — a remote substation watchdog
  resets or enters a safe mode when it stops hearing from the central
  controller; framed explicitly around comm loss between central controller
  and remote unit.
- US4598355, "Fault tolerant controller" — a watchdog interrupt detects
  comm failure between a central computer and a controller, then takes
  independent local action.
- Watchdog-timer literature generally (including nuclear control system
  usage) confirms "silence → local safe action, no central authority
  needed" is the textbook definition of a watchdog timer, not a novel
  observation on its own.

**The HKDF-domain-separation half is also well-established, and is starting
to appear in PQC-specific patent filings:**

- General practice: using a distinct `info`/context label per purpose to
  derive multiple cryptographically independent keys from one shared secret
  (Open Quantum Safe project discussion #1262; multiple public HKDF usage
  guides) — exactly the `LINK_SENSOR`/`LINK_ACTUATOR` pattern, described
  generically, no ICS framing.
- US12301709, "Multiple post-quantum cryptography key encapsulations with
  authentication and forward secrecy" (filed 2021) — derives session keys
  from PQC-KEM shared secrets with additional context data folded in for
  multiple sessions/purposes. Closer in *domain* (PQC-KEM-derived session
  keys, multi-purpose) than the general HKDF guides, but not phrased around
  a safety-instrumented actuator watchdog.

**Verdict: no source found combining both halves as one claim.** The
specific architectural choice this project makes — that the fail-safe
decision is deliberately kept off the server, so that a PQC session key's
cryptographic independence (via HKDF labels) and the watchdog's
operational independence from the server are the same design principle
applied twice, once to key material and once to control flow — was not
found stated together anywhere searched. This reads as an assembly of two
independently well-known primitives, applied to a specific documented
incident (TRISIS), not a novel primitive by itself. A patent examiner would
very likely combine 4926158/4598355-style watchdog art with
HKDF-domain-separation art under an obviousness rejection (a KSR-style
"combination of known elements according to known methods").

## Q2 — signature-then-clamp with distinctly-logged rejection

*Is the specific combination of "signature verifies AND value fails a
bounded safety-policy clamp AND the rejection is logged with a distinct
security-event type" described elsewhere as a named pattern, or only as
general defense-in-depth advice?*

**Closest single reference: US10542007, "Command authentication related to
the control of industrial systems"** (Bedrock Automation). A jump host
checks a command's syntax-string identifier against a **whitelist** before
forwarding it to the unit controller — authentication and command-content
validation are two structurally separate gates, same shape as SIS-01's
sign-then-clamp. Materially different in mechanism: 10542007 is a
**whitelist match/no-match** (discrete membership test), not a **bounded
numeric range clamp plus an independent rate-of-change limit** (SIS-01
checks `SETPOINT_MIN_C`/`SETPOINT_MAX_C` *and*, separately,
`SETPOINT_MAX_STEP_C` per command, both after the signature verifies). No
distinctly-typed logged event for "authentic-but-policy-rejected" vs.
"signature failed" was found described in 10542007's retrievable summary.

- US10834094B2, "Operator action authentication in an industrial control
  system" — signs and verifies operator action requests, gates execution on
  verification; no visible content-bounds-checking layer distinct from
  authentication in the summarized claims.
- "Defense in depth" as a named pattern is ubiquitous in general security
  writing, confirming it is treated as a broad principle, not a
  named-and-patented specific technique matching this triple.

**Verdict: no exact match.** US10542007 already establishes "authenticate,
then separately validate command content before acting" as patented
territory in ICS at the whitelist level, which weakens any claim to the
*general* shape of a second post-authentication gate — that examiner would
be cited regardless of what SIS-01 does specifically. What was not found
anywhere searched: the specific triple of (a) a continuous bounded-range
clamp rather than a discrete whitelist, (b) a rate-of-change limit layered
on top of the range limit, and (c) a distinctly-typed security-log event
for a policy rejection versus an authentication failure. Narrow claim
language around exactly that triple might fare better in a real
patentability review than the general "signed-but-rejected" framing would,
but US10542007 is prior art an examiner would cite regardless of how the
claim is narrowed.

## Q3 — transcript-binding a KEM ciphertext with a role claim

*Does prior art exist for transcript-binding a KEM ciphertext and a role
claim together in one ML-DSA signature specifically to prevent role-reuse
across sensor/actuator enrollment, as opposed to transcript-binding for
replay prevention generally?*

**Transcript-binding a KEM ciphertext for session/downgrade integrity is
standard, TLS-1.3-lineage practice, already present in at least one 2025
PQC paper using this project's exact primitive set:**

- Frontiers in Physics, "Design and implementation of an authenticated
  post-quantum session protocol using ML-KEM, ML-DSA, and AES-256-GCM"
  (2025) — uses a transcript-bound HKDF-SHA3-256 key schedule for
  downgrade resistance and integrity. Transcript binding for
  session/downgrade purposes, not role-specific.
- US12301709 and US12088706 ("Device securing communications using two
  post-quantum cryptography key encapsulation mechanisms") bind additional
  context data into PQC-KEM sessions, but their retrievable summaries
  describe purpose/session context, not an explicit enrollment-role claim
  (sensor vs. actuator) as the bound field.
- Nature Scientific Reports, "Post-quantum cryptographic authentication
  protocol for industrial IoT using lattice-based cryptography" (2025) —
  lattice-based IIoT authentication; role-binding specifics did not surface
  in the search-result summary. **Not cleared** — this paper needs a full
  read, not just a snippet read, before this verdict is trusted.

**Verdict: the narrowest and least-covered of the three claims, and also
the least-verified.** Binding an explicit *enrollment role claim* into the
same signed transcript as the KEM ciphertext, specifically to stop a
sensor's captured signature from being replayed to claim the actuator role
in a different handshake, was not found described anywhere in this search.
"Narrow and uncovered by roughly ten web queries" is a weak positive
signal, not a finding of novelty — the Nature and Frontiers 2025 papers in
particular, plus any non-English or non-indexed literature, remain
unchecked.

## Overall assessment

None of the three questions turned up a single source matching the full,
specific combination this project implements. Q1 and Q2 both have prior art
close enough that the *general shape* of the claim — watchdog independent
of a central controller; a second, content-based gate after
authentication — is well established and not novel by itself; only
narrowly worded claim language around the specific implementation details
might be defensible, and even then a real filing would need a professional
clearance search before any claim of novelty. Q3 is the most plausible
candidate for narrow novelty, but is also the one this search verified
least thoroughly — two 2025 papers using near-identical primitives were
found and not fully read.

**This document does not conclude that any part of SIS-01 is patentable.**
It answers the three questions the audit posed: where prior art was found
and how close it is, and where a ten-query search did not find a match
(distinct from "no such prior art exists"). Any future decision to pursue
IP protection on this work needs a professional search this document
explicitly is not.

---

*Companion documents: `docs/RESEARCH_AUDIT.md` section L for the original
questions; `docs/SAFETY_MODEL.md` INVARIANT-05 and `docs/STANDARDS_MAPPING.md`
"Use control (FR 2)" for the technical detail behind Q2's clamp mechanism;
`paper/SIS01_paper.md` section 7 for how this feeds the paper's related-work
section.*
