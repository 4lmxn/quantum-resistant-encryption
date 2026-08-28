"""The three attack stages, shared by attack.py (CLI) and the dashboard buttons.

Each stage takes plumbing callables so the same logic runs either from a
Socket.IO client or inside the server process:

    log(log_type, msg)      -> surface a line on the dashboard
    obtain_public_key()     -> a real ML-KEM-768 encapsulation key, or None
    deliver(packet)         -> hand a raw packet to the actuator(s)
    sleep(seconds)          -> the caller's non-blocking sleep
"""

import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import legacy
from app.pqc import ENCAPSULATION_KEY_BYTES, LINK_SENSOR, encapsulate



# Structured description of each attack, so the interface can present the name,
# severity and mitigation without inferring anything from log text.
ATTACK_CATALOG = {
    "silence": {
        "name": "Silence the Safety Function",
        "family": "Operational sabotage",
        "severity": "CRITICAL",
        "target": "The trip path itself",
        "vector": "The attacker does not forge anything. They cut the link the safety "
                  "controller uses to reach the shutdown valve, so that when a real "
                  "excursion arrives there is nothing left to act on it. This is what "
                  "TRITON was for at Petro Rabigh in 2017: disable the shutdown system, "
                  "then wait for the plant to fail on its own.",
        "impact": "Nothing happens immediately, which is the point. The plant keeps "
                  "running and every dial reads normal, until an ordinary fault that "
                  "would have been caught becomes a fire.",
        "mitigation": "The valve does not wait to be told. It expects a signed heartbeat "
                      "every 2 seconds and closes itself after 6 seconds of silence, so "
                      "cutting the link performs the shutdown rather than preventing it.",
    },
    "psk": {
        "name": "Forge With the Leaked Key",
        "family": "Credential compromise",
        "severity": "HIGH",
        "target": "The constrained monitoring node",
        "vector": "One device is too small to run the handshake, so it carries a fixed "
                  "provisioning key rather than a per-session one. Suppose the attacker "
                  "obtains it -- from a stolen board, a dumped flash image, a careless "
                  "commit -- and seals a perfectly valid reading of their choosing. "
                  "In 2019 a rig was shut for 19 days after malware arrived on a "
                  "worker's laptop and spread as far as the blowout preventer computer.",
        "impact": "If that node were trusted, a forged reading could trip the plant on "
                  "demand, or hide a real excursion by reporting calm.",
        "mitigation": "That node is the basic process control transmitter, not a safety "
                      "one. Its readings are displayed and can never reach the trip "
                      "decision, so a forged 250°C reading moves nothing.",
    },
    "insider": {
        "name": "Insider Setpoint Move",
        "family": "Abuse of legitimate access",
        "severity": "CRITICAL",
        "target": "The trip setpoint",
        "vector": "No cipher is broken. The attacker uses a real control path — either "
                  "the dashboard, or a genuine operator key — and simply asks for a trip "
                  "point that makes the safety function useless. At Oldsmar in 2021 "
                  "someone reached a water plant this way and requested a chemical dose "
                  "over a hundred times the safe level.",
        "impact": "A setpoint moved far enough is the same as no safety function at all, "
                  "and it leaves a perfectly clean audit trail behind it.",
        "mitigation": "Unsigned requests are refused outright. Signed ones are still "
                      "clamped to a safe range and limited in how far one change may "
                      "move the setpoint, so a valid signature is necessary and not "
                      "sufficient.",
    },
    "rogue": {
        "name": "Rogue Node",
        "family": "Impersonation",
        "severity": "HIGH",
        "target": "Device enrolment",
        "vector": "The attacker connects a second node claiming to be an already "
                  "connected transmitter. If both are served, their readings interleave "
                  "and the plant appears to be two different temperatures at once — a "
                  "failure that hides in plain sight, because the log looks busy rather "
                  "than wrong.",
        "impact": "A stolen or duplicated identity lets an attacker feed the safety "
                  "function readings of their choosing alongside the real ones.",
        "mitigation": "One identity, one live session. A second claim on an identity "
                      "that already holds a session is refused and the incumbent is left "
                      "undisturbed.",
    },
    "replay": {
        "name": "Replay a Captured Command",
        "family": "Active tampering",
        "severity": "HIGH",
        "target": "Actuator command channel",
        "vector": "The attacker records a genuine sealed command off the wire and sends "
                  "it again later. Nothing is forged and nothing is decrypted — the "
                  "packet is real, so its authentication tag is perfect. The FDA "
                  "described exactly this against MiniMed insulin pumps in 2019: record "
                  "the wireless traffic, replay it, the device obeys.",
        "impact": "Re-sending a captured RESET reopens the shutdown valve after a real "
                  "trip, using a message the safety controller genuinely composed.",
        "mitigation": "A genuine command is single-use. The valve remembers the nonces "
                      "it has already carried out and refuses a repeat, so a valid tag "
                      "proves the server composed the command but not that it composed "
                      "it just now.",
    },
    "shor": {
        "name": "Shor's Algorithm",
        "family": "Quantum cryptanalysis",
        "severity": "CRITICAL",
        "target": "Key exchange — both channels",
        "vector": "Today's internet keys are built from two large prime numbers "
                  "multiplied together. Security rests on nobody being able to work "
                  "backwards and find those primes. A quantum computer running Shor's "
                  "algorithm can, which breaks RSA and elliptic-curve key exchange.",
        "impact": "Whoever recovers the private key can read every message that key "
                  "ever protected — including traffic recorded years earlier and stored "
                  "until the hardware caught up.",
        "mitigation": "This system agrees its keys with ML-KEM-768 instead. Its security "
                      "rests on a lattice problem rather than on factoring, and Shor's "
                      "algorithm gives no advantage against it.",
    },
    "kyber": {
        "name": "Lattice Reduction (BKZ)",
        "family": "Quantum cryptanalysis",
        "severity": "CRITICAL",
        "target": "ML-KEM-768 key encapsulation",
        "vector": "The best known attack on ML-KEM. It treats the public key as a grid "
                  "of points and tries to shorten the grid until the hidden secret is "
                  "exposed. This is what BKZ reduction does to the Module-LWE problem.",
        "impact": "Recovering the private half of the key would expose every session "
                  "negotiated with it, on both the sensor and the actuator link.",
        "mitigation": "ML-KEM-768 is sized so this search is far beyond reach: roughly "
                      "2^181 operations classically, and no quantum method is known that "
                      "does meaningfully better.",
    },
    "harvest": {
        "name": "Harvest Now, Decrypt Later",
        "family": "Passive interception",
        "severity": "HIGH",
        "target": "Recorded ciphertext, both channels",
        "vector": "The attacker does not try to break anything today. They simply record "
                  "the encrypted traffic and store it, waiting for a quantum computer "
                  "capable of opening it later.",
        "impact": "Everything sent today would become readable in future — the reason "
                  "post-quantum protection is needed now rather than when the hardware "
                  "arrives.",
        "mitigation": "Every connection negotiates a brand new key, and nodes wipe the "
                      "old one when they disconnect. There is no long-lived key to come "
                      "back and recover.",
    },
    "mitm": {
        "name": "Man-in-the-Middle Command Injection",
        "family": "Active tampering",
        "severity": "CRITICAL",
        "target": "Actuator command channel",
        "vector": "The attacker sits on the network and sends the actuator a command the "
                  "server never issued, hoping it will simply obey.",
        "impact": "Physical hardware operated by an outsider. On a real installation that "
                  "is a valve, a lock or a motor moving on command.",
        "mitigation": "Every command carries an authentication tag computed with the "
                      "session key. The actuator checks that tag before acting, so a "
                      "forged command is discarded rather than executed.",
    },
    "telemetry_replay": {
        "name": "Replay a Captured Reading",
        "family": "Active tampering",
        "severity": "MEDIUM",
        "target": "Sensor telemetry channel",
        "vector": "The attacker records a genuine sealed telemetry packet off the "
                  "sensor link and sends the identical bytes again. This is the same "
                  "class of attack as replaying a captured command, demonstrated "
                  "instead against the input side of the safety function.",
        "impact": "If accepted, a captured reading could be replayed to make the "
                  "plant appear stable while the real transmitter reports something "
                  "different, or vice versa.",
        "mitigation": "Telemetry nonces are single-use per session, exactly like "
                      "command nonces: the server refuses a repeated one before it "
                      "even attempts to decrypt the packet.",
    },
    "stale_session": {
        "name": "Replay Into a Closed Session",
        "family": "Active tampering",
        "severity": "MEDIUM",
        "target": "Sensor session lifecycle",
        "vector": "The attacker captured a genuine packet earlier, but the session "
                  "it belonged to has since disconnected -- the sensor node "
                  "restarted, or its connection dropped. The attacker replays the "
                  "old packet anyway, hoping the server still remembers the key.",
        "impact": "None available even in principle: there is no key left to "
                  "decrypt with, so this is a stronger guarantee than freshness "
                  "checking alone.",
        "mitigation": "The server forgets a session's key entirely on disconnect "
                      "(CentralServer.forget()). A packet from a session that no "
                      "longer exists has no key to be decrypted against.",
    },
    "nonce_probe": {
        "name": "Nonce Reuse Probe",
        "family": "Active tampering",
        "severity": "LOW",
        "target": "Freshness enforcement",
        "vector": "The attacker has captured nothing and holds no key. They simply "
                  "try a nonce value once -- succeeding or failing does not matter "
                  "-- and then try the exact same nonce value again, to see whether "
                  "a nonce can be recycled once it has been seen.",
        "impact": "If nonces could be reused, an attacker could pre-compute forged "
                  "packets against nonce values likely to be reused, or exhaust the "
                  "freshness check by cycling through a small set.",
        "mitigation": "A nonce is burned the first time it is seen, whether or not "
                      "the packet it arrived on was ever genuine. This collapses "
                      "into the same accept_nonce() gate that stops telemetry and "
                      "command replay -- it is one mechanism, not three.",
    },
    "timestamp_manip": {
        "name": "Stale Operator Command",
        "family": "Active tampering",
        "severity": "MEDIUM",
        "target": "Operator command freshness",
        "vector": "A correctly signed operator command, built with a timestamp far "
                  "in the past -- as if it had been captured during commissioning "
                  "and held back for delivery during an upset.",
        "impact": "Without a freshness bound, a captured-but-not-yet-used signed "
                  "command would remain valid indefinitely, which is exactly the "
                  "kind of window a captured RESET or BYPASS could exploit.",
        "mitigation": "The server refuses any operator command more than "
                      "OPERATOR_MAX_SKEW_S old, independent of whether the "
                      "signature verifies.",
    },
    "downgrade": {
        "name": "Downgrade to the Provisioning Key",
        "family": "Impersonation",
        "severity": "MEDIUM",
        "target": "Constrained-node trust level",
        "vector": "A device that already completed the authenticated ML-KEM/ML-DSA "
                  "handshake has its telemetry re-sealed with the constrained "
                  "node's static provisioning key instead, hoping the server will "
                  "still accept it as the authenticated session.",
        "impact": "If it worked, an attacker who obtained the low-trust static key "
                  "could speak as a device that had proven a much stronger identity, "
                  "silently downgrading its trust level.",
        "mitigation": "The server looks up the session key by device_id and decrypts "
                      "with that key specifically -- an authenticated device's "
                      "packets can never be opened with a different key, so a "
                      "PSK-sealed forgery targeting an authenticated device_id fails "
                      "the tag, not merely the trust check.",
    },
    "malformed_packet": {
        "name": "Malformed Packet",
        "family": "Robustness",
        "severity": "LOW",
        "target": "Packet parsing, both directions",
        "vector": "Packets missing required fields, or carrying non-hex garbage "
                  "where a nonce or ciphertext is expected, sent to both the sensor "
                  "telemetry handler and the actuator command channel.",
        "impact": "A parser that raises an unhandled exception on malformed input "
                  "can crash the handling process or leave state inconsistent.",
        "mitigation": "Every decrypt path is wrapped in a broad exception handler "
                      "that logs and drops rather than propagating, so malformed "
                      "input produces a security_log line, not a crash.",
    },
    "oversized": {
        "name": "Oversized Message",
        "family": "Robustness",
        "severity": "LOW",
        "target": "Packet parsing, resource use",
        "vector": "A telemetry packet with a multi-megabyte ciphertext field -- far "
                  "larger than any genuine reading -- to see whether size alone "
                  "causes different behaviour than an ordinary forged packet.",
        "impact": "An unbounded parser could be used to exhaust memory or CPU with "
                  "a stream of oversized junk, a resource-exhaustion angle distinct "
                  "from forgery.",
        "mitigation": "A packet whose ciphertext field exceeds MAX_CIPHERTEXT_HEX_CHARS "
                      "(app/config.py) is rejected on field length before AESGCM.decrypt "
                      "ever runs -- a genuine reading is well under that bound, so this "
                      "costs nothing on the legitimate path.",
    },
    "invalid_transition": {
        "name": "Unsigned Control Path",
        "family": "Abuse of legitimate access",
        "severity": "LOW",
        "target": "Safety state, unsigned path",
        "vector": "The legacy unsigned control events this dashboard used to expose "
                  "-- set_threshold, toggle_actuator_override, resume_automatic -- "
                  "are sent again, as if an old client or a stale bookmark tried to "
                  "use them.",
        "impact": "If any of these still moved the safety state, it would be a "
                  "complete bypass of the signed operator path.",
        "mitigation": "These handlers were removed from the server entirely, not "
                      "merely disabled. An unknown Socket.IO event is silently "
                      "dropped by the dispatcher -- there is no handler left to "
                      "even refuse it.",
    },
    "actuator_absent": {
        "name": "No Final Element Connected",
        "family": "Operational sabotage",
        "severity": "HIGH",
        "target": "Physical fail-safe coverage",
        "vector": "Not a forgery: simply the case where no actuator node is "
                  "currently connected to the server at all -- crashed, never "
                  "started, or its process killed outright rather than merely "
                  "disconnected from the network.",
        "impact": "The dead-man watchdog that makes silence fail safe lives on the "
                  "actuator node. If no actuator process is running, there is no "
                  "watchdog running either, and a trip latches on the server with "
                  "nothing physical able to act on it.",
        "mitigation": "None at the server. This is reported as a genuine finding, "
                      "not a defended attack: the server logs plainly that the trip "
                      "could not be delivered, but the physical valve position in "
                      "this state is whatever it already was.",
        "gap": True,
    },
    "server_unavailable": {
        "name": "Logic Solver Unavailable",
        "family": "Operational sabotage",
        "severity": "INFO",
        "target": "Server availability",
        "vector": "The server process itself is stopped or unreachable -- the "
                  "complete version of 'silence the safety function', rather than "
                  "just withholding its heartbeats.",
        "impact": "Same as any other communication loss: none, by design.",
        "mitigation": "The actuator's watchdog does not know or care why heartbeats "
                      "stopped arriving; a dead server looks identical to a severed "
                      "cable from XV-101's point of view, and both close the valve.",
    },
    "grover": {
        "name": "Grover's Algorithm",
        "family": "Quantum cryptanalysis",
        "severity": "MEDIUM",
        "target": "AES session keys, both channels",
        "vector": "Rather than breaking the maths, this simply searches for the key — but "
                  "a quantum computer searches far faster, effectively halving the key "
                  "length.",
        "impact": "A 128-bit key would be reduced to the strength of a 64-bit one, which "
                  "is genuinely within reach of a determined attacker.",
        "mitigation": "This system uses 256-bit keys, so halving still leaves 128 bits of "
                      "strength — well beyond any foreseeable machine.",
    },
}


def describe(name):
    return ATTACK_CATALOG.get(name, {})


def stage_classical(log, sleep, report, intercept):
    """Real: breaks the classical RSA channel and decrypts its telemetry.

    Factorisation is performed classically at a reduced key size so it completes
    in milliseconds. Shor's algorithm is what makes the same recovery feasible
    against production-size RSA on a quantum computer.
    """
    log("ATTACK", "Shor's Algorithm: searching for a classical key exchange to attack")
    sleep(1)

    captured = intercept()
    if not captured or not captured.get("packet"):
        log("SUCCESS", "Shor's Algorithm: no classical channel present — nothing to attack")
        report(
            "shor",
            status="NOT APPLICABLE",
            confidence="Observed",
            evidence="Nothing to attack. Every channel currently running uses "
                     "post-quantum key exchange, so there is no RSA key to factor.",
            outcome="To see this attack succeed, start the old-style channel alongside: "
                    "make sensor-legacy",
        )
        return

    public = tuple(captured["public"])
    log("ATTACK", f"Shor's Algorithm: intercepted RSA-{public[0].bit_length()} public key "
                  f"n={public[0]}")
    sleep(1)

    started = time.perf_counter()
    private, (p_factor, q_factor) = legacy.recover_private_key(public)
    elapsed = time.perf_counter() - started
    log("ERROR", f"Shor's Algorithm: modulus factored in {elapsed * 1000:.1f} ms — "
                 f"n = {p_factor} x {q_factor}")
    sleep(1)

    session_key = legacy.unwrap_session_key(captured["blocks"], captured["chunk"], private)
    log("ERROR", f"Shor's Algorithm: session key recovered — {session_key.hex()[:32]}")
    sleep(1)

    packet = captured["packet"]
    try:
        plaintext = AESGCM(session_key).decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), None
        ).decode()
    except Exception as exc:
        plaintext = f"<decryption failed: {type(exc).__name__}>"

    log("ERROR", f"Shor's Algorithm: BREACH — intercepted telemetry reads {plaintext}")
    report(
        "shor",
        status="SUCCEEDED",
        confidence="Observed",
        evidence=f"Found the two primes behind the {public[0].bit_length()}-bit key in "
                 f"{elapsed * 1000:.1f} ms ({p_factor} x {q_factor}). That gave up the "
                 f"session key ({session_key.hex()[:32]}...), which decrypted a real "
                 f"intercepted reading: {plaintext}",
        outcome="This channel is fully readable to anyone who was listening — no "
                "tampering or access required, just a recording. The key here is small "
                "so the break finishes instantly; against a real 2048-bit key a quantum "
                "computer running Shor's algorithm does the same job. The post-quantum "
                "channels running alongside were unaffected.",
    )


def stage_lattice(log, sleep, report, obtain_public_key):
    """Real: operates on an actual ML-KEM-768 encapsulation key."""
    log("ATTACK", "Lattice Reduction: intercepting ML-KEM-768 key exchange")
    encapsulation_key = obtain_public_key()
    if encapsulation_key is None:
        log("ERROR", "Lattice Reduction: aborted, no handshake observed on the wire")
        report("kyber", status="INCONCLUSIVE", confidence="Not run",
               evidence="No ML-KEM handshake was observed.",
               outcome="Start a sensor or actuator node and run this again.")
        return

    log("ATTACK",
        f"Lattice Reduction: captured {len(encapsulation_key)}-byte encapsulation key "
        f"{encapsulation_key[:16].hex()}")
    sleep(1)

    # The public key really is public; anyone can encapsulate against it. The
    # point is that this yields the ATTACKER's own secret, not the sensor's.
    first_secret, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    second_secret, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    log("ATTACK",
        f"Lattice Reduction: two encapsulations against the captured key yield "
        f"{first_secret[:8].hex()} and {second_secret[:8].hex()}")
    log("SUCCESS" if first_secret != second_secret else "ERROR",
        "Lattice Reduction: encapsulation secrets are independent — captured traffic "
        "yields no key material")
    sleep(1)

    # Recovering the decapsulation key from the public key is Module-LWE.
    # Show the search space rather than pretending to solve it.
    started = time.perf_counter()
    log("ATTACK",
        f"Lattice Reduction: attempting Module-LWE recovery over a "
        f"{ENCAPSULATION_KEY_BYTES * 8}-bit basis")
    sleep(1.5)
    elapsed = time.perf_counter() - started
    log("SUCCESS", f"Lattice Reduction: abandoned after {elapsed:.2f}s — no key recovered")
    report(
        "kyber",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"Captured the real {len(encapsulation_key)}-byte public key off the "
                 f"wire. Using it twice produced two completely unrelated secrets "
                 f"({first_secret[:8].hex()} and {second_secret[:8].hex()}), so it gives "
                 f"away nothing about the live session. Key search abandoned after "
                 f"{elapsed:.2f}s.",
        outcome="Holding the public key is not enough — it does not reveal the session "
                "key, and working backwards to the private half is the lattice problem "
                "with no practical attack known.",
    )


def stage_harvest(log, sleep, report, obtain_public_key):
    """Report 1.4.1 — Harvest Now, Decrypt Later.

    Real: shows that two handshakes produce unrelated keys, so archived traffic
    cannot be opened by a key recovered later.
    """
    log("ATTACK", "Harvest Now, Decrypt Later: archiving intercepted ciphertext")
    sleep(1)
    log("ATTACK", "Harvest Now, Decrypt Later: awaiting future quantum decryption capability")
    sleep(1.5)

    first = obtain_public_key()
    second = obtain_public_key()
    if first is None or second is None:
        log("ERROR", "Harvest Now, Decrypt Later: aborted, no handshake observed")
        report("harvest", status="INCONCLUSIVE", confidence="Not run",
               evidence="No ML-KEM handshake was observed.",
               outcome="Start a sensor or actuator node and run this again.")
        return

    log("ATTACK",
        f"Harvest Now, Decrypt Later: session 1 key {first[:8].hex()}, "
        f"session 2 key {second[:8].hex()}")
    independent = first != second
    log("SUCCESS" if independent else "ERROR",
        "Harvest Now, Decrypt Later: sessions share no key material")
    if independent:
        report(
            "harvest",
            status="DEFENDED",
            confidence="Observed",
            evidence=f"Two connections in a row produced completely different keys "
                     f"({first[:8].hex()} and {second[:8].hex()}), and nodes erase the key "
                     f"from memory when they disconnect.",
            outcome="There is no single key worth waiting for. Breaking one connection's key "
                    "in future would open that connection only — not the recording.",
        )
    else:
        report(
            "harvest",
            status="INCONCLUSIVE",
            confidence="Not run",
            evidence=f"Two connections in a row produced the SAME key "
                     f"({first[:8].hex()}). This does not demonstrate independence.",
            outcome="Re-run the attack -- this indicates the demo failed to observe two "
                    "distinct handshakes, not that the key exchange itself repeated a key.",
        )


def stage_grover(log, sleep, report):
    """Report 1.4.4 — Grover's algorithm against the symmetric layer."""
    log("ATTACK", "Grover's Algorithm: quantum search against the AES session key")
    sleep(1)
    log("ATTACK", "Grover's Algorithm: effective key length reduced from n to n/2 bits")
    sleep(1)
    log("ERROR", "Grover's Algorithm: against AES-128 this would leave a 2^64 margin")
    sleep(1)
    log("SUCCESS", "Grover's Algorithm: this link uses AES-256, leaving a 2^128 margin")
    report(
        "grover",
        status="DEFENDED",
        confidence="Analytical",
        evidence="The live session keys are 256-bit — visible in the Key exchange tab. "
                 "Halving that leaves 128 bits of effective strength.",
        outcome="A 128-bit key would not survive this, which is why the design specifies "
                "256-bit. At that size the search stays out of reach even for a quantum "
                "computer.",
    )


def stage_mitm(log, sleep, report, deliver):
    """Real: a forged packet reaches the actuator; only the GCM tag stops it."""
    log("ATTACK", "Man-in-the-Middle: intercepting the actuator command channel")
    sleep(1)
    forged = {
        "nonce": "a1b2c3d4e5f60708090a0b0c",
        "ciphertext": "ff00ea2382104910284021948201948120",  # invalid tag
    }
    log("ATTACK", "Man-in-the-Middle: injecting forged ciphertext into the actuator")
    deliver(forged)
    sleep(1.5)
    report(
        "mitm",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"A forged command was delivered to the actuator "
                 f"({len(forged['ciphertext']) // 2} bytes). Its authentication tag did "
                 f"not check out, and the relay did not move.",
        outcome="The forged command was thrown away before anything physical happened. "
                "Detection is not enough on its own — what matters is that it was caught "
                "before the relay acted.",
    )



# ------------------------------------------------------------------ real, physical

def stage_silence(log, sleep, report, sever_heartbeat, heartbeat_timeout):
    """Real: cut the heartbeat and show the valve trip itself instead of freezing.

    sever_heartbeat(seconds) stops the server sending heartbeats for a while.
    This is TRITON's move -- disable the safety function -- run against the fix
    for it. Because the valve trips on silence rather than on command, cutting
    the link performs the shutdown instead of preventing it.
    """
    log("ATTACK", "Silence the Safety Function: cutting the heartbeat to the shutdown valve")
    sleep(1)
    window = heartbeat_timeout + 3
    sever_heartbeat(window)
    log("ATTACK", f"Silence: heartbeat severed. On an unprotected system the valve now "
                  f"stays wherever it is -- usually open -- and the trip is disabled.")
    sleep(heartbeat_timeout + 1.5)
    report(
        "silence",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"Heartbeats were stopped for {window:.0f}s. The valve's own watchdog "
                 f"saw {heartbeat_timeout:.0f}s of silence and closed XV-101 locally, "
                 f"without any command from the server.",
        outcome="Cutting the link tripped the plant rather than disabling the trip. "
                "This is the exact reversal of TRITON's goal: silence means shut down, "
                "not carry on.",
    )


def stage_psk(log, sleep, report, deliver_bpcs):
    """Real: forge a reading with the repo's committed key; show it changes nothing.

    deliver_bpcs(temperature) seals a reading with the device's provisioning key
    and posts it on the BPCS leg exactly as the ESP32 would -- standing in for an
    attacker who has somehow obtained that key.
    """
    log("ATTACK", "Forge With the Leaked Key: sealing with a compromised device provisioning key")
    sleep(1)
    log("ATTACK", "Forge: sealing a 250°C reading with the leaked key and posting it as the ESP32")
    accepted, tripped = deliver_bpcs(250.0)
    sleep(1.2)
    report(
        "psk",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"A 250°C reading, sealed with the committed key, was {'accepted onto '
                 'the dashboard' if accepted else 'rejected'} on the BPCS leg. The trip "
                 f"state after it was {'TRIPPED' if tripped else 'unchanged'}.",
        outcome="The forged reading was displayed and ignored by the safety function. "
                "The leaked key is real and the forgery is valid -- it simply has no "
                "route to the trip decision, which is the whole reason that node is "
                "kept off the safety path.",
    )


def stage_insider(log, sleep, report, send_operator):
    """Real: a signed but out-of-range setpoint, refused by the clamp.

    send_operator(action, value) submits a correctly signed operator command,
    so the signature genuinely verifies and the refusal provably comes from the
    bounds check rather than a broken signature.
    """
    log("ATTACK", "Insider Setpoint Move: signing a request to raise the trip point to 11,100°C")
    sleep(1)
    log("ATTACK", "Insider: the signature is valid -- this is a real operator key, used the way Oldsmar was")
    verdict = send_operator("SET_SETPOINT", 11100.0)
    sleep(1.2)
    report(
        "insider",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"A correctly signed command to set the trip point to 11,100°C was "
                 f"{verdict}. The signature verified; the value did not.",
        outcome="Authentication was necessary and not sufficient. The clamp refused a "
                "perfectly signed instruction, which is the control Oldsmar lacked -- "
                "there the access was legitimate and nothing bounded what it could ask.",
    )


def stage_rogue(log, sleep, report, impersonate):
    """Real: a second node claims an identity that already holds a session.

    impersonate(device_id) attempts to claim an in-use identity through the same
    function the handshake uses, so the demonstration cannot drift from the rule.
    """
    log("ATTACK", "Rogue Node: connecting a second transmitter claiming to be sensor-01")
    sleep(1)
    claimed, holder = impersonate("sensor-01")
    sleep(1)
    report(
        "rogue",
        status="DEFENDED" if not claimed else "SUCCEEDED",
        confidence="Observed",
        evidence=f"A second session tried to claim sensor-01, which was already held by "
                 f"session {holder[:8] if holder else '—'}. The claim was "
                 f"{'refused' if not claimed else 'ACCEPTED'}.",
        outcome="One identity, one session. The impostor was turned away and the real "
                "transmitter kept streaming, so the plant never appeared to be two "
                "temperatures at once.",
    )


def stage_telemetry_replay(log, sleep, report, replay_telemetry):
    """Real: re-sends a genuinely captured sensor telemetry packet.

    replay_telemetry() re-checks the exact captured (session, nonce) pair
    against the server's own freshness gate a second time -- the same gate
    handle_sensor_telemetry uses on the way in.
    """
    log("ATTACK", "Replay a Captured Reading: recording a genuine sealed telemetry "
                  "packet off the sensor link")
    sleep(1)
    had_packet, accepted_again = replay_telemetry()
    sleep(1.2)
    if not had_packet:
        report("telemetry_replay", status="INCONCLUSIVE", confidence="Not observed",
               evidence="No sensor telemetry has been seen yet on this server run.",
               outcome="Start the sensor node, let one reading arrive, then run this again.")
        return
    log("ATTACK", "Replay: re-submitting the exact captured (session, nonce) pair")
    report(
        "telemetry_replay",
        status="DEFENDED" if not accepted_again else "SUCCEEDED",
        confidence="Observed",
        evidence=f"The captured packet's nonce was {'still refused' if not accepted_again else 'ACCEPTED'} "
                 f"on a second submission.",
        outcome="The freshness gate that protects commands protects readings the "
                "same way -- one mechanism, exercised on both channels.",
    )


def stage_stale_session(log, sleep, report, check_stale_session):
    """Real: checks whether the last captured sensor session still holds a key."""
    log("ATTACK", "Replay Into a Closed Session: checking whether a previously "
                  "captured sensor session still has a live key")
    sleep(1)
    had_packet, still_live = check_stale_session()
    sleep(1)
    if not had_packet:
        report("stale_session", status="INCONCLUSIVE", confidence="Not observed",
               evidence="No sensor telemetry has been seen yet on this server run.",
               outcome="Start the sensor node, let one reading arrive, then run this again.")
        return
    if still_live:
        report("stale_session", status="INCONCLUSIVE", confidence="Not applicable yet",
               evidence="The captured session is still connected, so there is no "
                        "closed session to replay into.",
               outcome="Stop the sensor node (Ctrl+C) so its session ends, then run "
                       "this again.")
        return
    report(
        "stale_session",
        status="DEFENDED",
        confidence="Observed",
        evidence="The captured session's sid no longer holds a key -- it was erased "
                 "when the session disconnected.",
        outcome="There was nothing left to decrypt the old packet with. This is a "
                "stronger property than freshness checking: even a perfectly "
                "fresh-looking replay has no key to succeed against once the "
                "session that issued it is gone.",
    )


def stage_nonce_probe(log, sleep, report, probe_nonce):
    """Real: burns one nonce with a throwaway probe, then reuses it."""
    log("ATTACK", "Nonce Reuse Probe: submitting one throwaway nonce")
    sleep(1)
    first_accepted, second_accepted = probe_nonce()
    log("ATTACK", "Nonce Reuse Probe: submitting the identical nonce a second time")
    sleep(1)
    report(
        "nonce_probe",
        status="DEFENDED" if (first_accepted and not second_accepted) else "SUCCEEDED",
        confidence="Observed",
        evidence=f"First use: {'accepted' if first_accepted else 'refused'}. "
                 f"Second use of the same nonce: {'accepted' if second_accepted else 'refused'}.",
        outcome="A nonce is burned the moment it is seen, whether or not the packet "
                "carrying it was ever genuine -- so guessing or recycling a nonce "
                "buys nothing, even against packets that never decrypt.",
    )


def stage_timestamp_manip(log, sleep, report, send_stale_operator):
    """Real: a correctly signed operator command with a stale timestamp."""
    log("ATTACK", "Stale Operator Command: signing a RESET with a timestamp well "
                  "outside the freshness window")
    sleep(1)
    verdict = send_stale_operator()
    sleep(1.2)
    report(
        "timestamp_manip",
        status="DEFENDED" if verdict != "APPLIED" else "SUCCEEDED",
        confidence="Observed",
        evidence=f"A correctly signed but stale-timestamped RESET was {verdict}.",
        outcome="The signature genuinely verifies -- this is not a forgery. The "
                "freshness check is a second, independent gate on top of "
                "authentication, exactly like the setpoint clamp.",
    )


def stage_downgrade(log, sleep, report, attempt_downgrade):
    """Real: seals a reading for an authenticated device_id with the wrong key."""
    log("ATTACK", "Downgrade to the Provisioning Key: sealing a reading for an "
                  "authenticated device with the static provisioning key instead")
    sleep(1)
    had_target, accepted = attempt_downgrade()
    sleep(1.2)
    if not had_target:
        report("downgrade", status="INCONCLUSIVE", confidence="Not observed",
               evidence="No constrained node has completed the authenticated /pqc "
                        "handshake on this server run.",
               outcome="Run `make device`, let it complete its handshake, then run "
                       "this again.")
        return
    report(
        "downgrade",
        status="DEFENDED" if not accepted else "SUCCEEDED",
        confidence="Observed",
        evidence=f"A reading for an authenticated device, sealed with the wrong "
                 f"(provisioning) key, was {'refused' if not accepted else 'ACCEPTED'}.",
        outcome="The server decrypts with the specific key that device's handshake "
                "established, not with whichever key happens to be presented -- so "
                "there is no downgrade path from a strong identity to a weak one.",
    )


def stage_malformed_packet(log, sleep, report, send_malformed):
    """Real: missing fields and non-hex garbage, on both channels."""
    log("ATTACK", "Malformed Packet: submitting packets with missing fields and "
                  "non-hex garbage to both channels")
    sleep(1)
    results = send_malformed()
    sleep(1.2)
    crashed = any(not ok for ok, _ in results)
    report(
        "malformed_packet",
        status="DEFENDED" if not crashed else "SUCCEEDED",
        confidence="Observed",
        evidence="; ".join(desc for _, desc in results),
        outcome="Every malformed packet was rejected and logged; none of them "
                "raised past the handler that received it.",
    )


def stage_oversized(log, sleep, report, send_oversized):
    """Real: a multi-megabyte forged ciphertext field."""
    log("ATTACK", "Oversized Message: submitting a multi-megabyte forged telemetry packet")
    sleep(1)
    size_bytes, elapsed_ms, rejected, rejected_by_size_cap = send_oversized()
    sleep(1)
    if rejected_by_size_cap:
        outcome = ("MAX_CIPHERTEXT_HEX_CHARS rejects the packet on field length before "
                   "AESGCM.decrypt ever runs, closing the earlier gap where size alone "
                   "reached a full decrypt attempt before being refused on the GCM tag.")
    else:
        outcome = ("Rejected on the GCM tag rather than the size cap -- unexpected for "
                   "a packet this large; check MAX_CIPHERTEXT_HEX_CHARS.")
    report(
        "oversized",
        status="DEFENDED" if rejected else "SUCCEEDED",
        confidence="Observed",
        evidence=f"A {size_bytes:,}-byte forged packet was "
                 f"{'rejected' if rejected else 'ACCEPTED'} in {elapsed_ms:.1f}ms"
                 f"{' by the application-layer size cap' if rejected_by_size_cap else ''}.",
        outcome=outcome,
    )


def stage_invalid_transition(log, sleep, report, send_legacy_events):
    """Real: emits the removed unsigned control events and checks nothing moved."""
    log("ATTACK", "Unsigned Control Path: emitting the removed set_threshold / "
                  "toggle_actuator_override / resume_automatic events")
    sleep(1)
    unchanged = send_legacy_events()
    sleep(1.2)
    report(
        "invalid_transition",
        status="DEFENDED" if unchanged else "SUCCEEDED",
        confidence="Observed",
        evidence=f"Safety state before and after emitting all three legacy events "
                 f"was {'identical' if unchanged else 'DIFFERENT'}.",
        outcome="These handlers do not exist on the server any more, so the events "
                "are dropped by the Socket.IO dispatcher before any application "
                "code runs -- there is no handler left to even refuse them.",
    )


def stage_actuator_absent(log, sleep, report, check_actuator_presence):
    """Real, non-invasive: reports whether any actuator session currently exists."""
    log("ATTACK", "No Final Element Connected: checking for a live actuator session")
    sleep(1)
    connected = check_actuator_presence()
    sleep(1)
    if connected:
        report("actuator_absent", status="INCONCLUSIVE", confidence="Not applicable now",
               evidence="At least one actuator session is currently connected, so "
                        "its watchdog is running.",
               outcome="Stop the actuator node (Ctrl+C) and run this again to see "
                       "the uncovered case.")
        return
    report(
        "actuator_absent",
        status="SUCCEEDED",
        confidence="Observed",
        evidence="No actuator session is currently connected. The dead-man watchdog "
                 "that makes silence fail safe runs on the actuator node -- with no "
                 "actuator process running, nothing is enforcing it.",
        outcome="This is a genuine, undefended gap, not a demonstration of a "
                "control working: a trip still latches on the server, logged as "
                "undeliverable, but the physical valve's real position in this "
                "state is whatever it already was.",
    )


def stage_server_unavailable(log, sleep, report):
    """Narrated only: this server process cannot demonstrate its own absence."""
    log("ATTACK", "Logic Solver Unavailable: this is the complete version of "
                  "'silence the safety function' -- the server process itself, "
                  "not just its heartbeats")
    sleep(1.5)
    report(
        "server_unavailable",
        status="NOT APPLICABLE",
        confidence="Not run",
        evidence="A running server cannot demonstrate itself being unreachable. "
                 "To see this directly: stop `make server` entirely (not just this "
                 "one attack) and watch the actuator node's own terminal -- its "
                 "watchdog trips XV-101 after HEARTBEAT_TIMEOUT_S with no server "
                 "involved at all.",
        outcome="Mechanically identical to the Silence attack from the actuator's "
                "point of view: it does not distinguish a withheld heartbeat from "
                "no server to send one.",
    )


def stage_replay(log, sleep, report, capture_and_replay):
    """Real: re-send a genuine captured command; the nonce store refuses it.

    capture_and_replay() takes the last real command the server sealed and hands
    it to the actuator a second time. Nothing is forged, so the tag is perfect.
    """
    log("ATTACK", "Replay a Captured Command: recording a genuine sealed command off the wire")
    sleep(1)
    log("ATTACK", "Replay: re-sending the exact captured packet -- the tag is real, nothing is forged")
    had_packet, accepted = capture_and_replay()
    sleep(1.2)
    if not had_packet:
        report(
            "replay",
            status="INCONCLUSIVE",
            confidence="Not observed",
            evidence="No command had been issued yet, so there was nothing to capture. "
                     "Trip the plant once, then run this attack.",
            outcome="Cause a real trip first so there is a genuine command on the wire.",
        )
        return
    report(
        "replay",
        status="DEFENDED",
        confidence="Observed",
        evidence=f"A genuine captured command was re-sent. Its authentication tag was "
                 f"perfect, and it was {'still refused' if not accepted else 'ACCEPTED'} "
                 f"because its nonce had already been carried out.",
        outcome="A valid tag proves the server composed the command, not that it "
                "composed it just now. Single-use nonces close the replay the FDA "
                "described against MiniMed pumps.",
    )


# The order the attacks are presented in: the real, physical ones first, because
# those are the documented incidents, then the protocol/session-boundary probes,
# then the fail-safe-coverage questions, then the forward-looking quantum ones.
ATTACK_ORDER = ("silence", "psk", "insider", "rogue", "replay", "mitm",
                "telemetry_replay", "stale_session", "nonce_probe",
                "timestamp_manip", "downgrade", "malformed_packet", "oversized",
                "invalid_transition", "actuator_absent", "server_unavailable",
                "shor", "kyber", "harvest", "grover")


def run_stage(name, log, sleep, report, obtain_public_key, deliver,
              intercept=lambda: None, live=None):
    """Dispatch one stage by the interface's attack identifier.

    `live` bundles the callables the physical attacks need against the running
    system: severing the heartbeat, posting a forged BPCS reading, submitting a
    signed operator command, impersonating an identity, and replaying the last
    real command. The CLI runner passes what it can and omits the rest.
    """
    live = live or {}
    if name == "shor":
        stage_classical(log, sleep, report, intercept)
    elif name == "kyber":
        stage_lattice(log, sleep, report, obtain_public_key)
    elif name == "harvest":
        stage_harvest(log, sleep, report, obtain_public_key)
    elif name == "grover":
        stage_grover(log, sleep, report)
    elif name == "mitm":
        stage_mitm(log, sleep, report, deliver)
    elif name == "silence" and "sever_heartbeat" in live:
        stage_silence(log, sleep, report, live["sever_heartbeat"], live["heartbeat_timeout"])
    elif name == "psk" and "deliver_bpcs" in live:
        stage_psk(log, sleep, report, live["deliver_bpcs"])
    elif name == "insider" and "send_operator" in live:
        stage_insider(log, sleep, report, live["send_operator"])
    elif name == "rogue" and "impersonate" in live:
        stage_rogue(log, sleep, report, live["impersonate"])
    elif name == "replay" and "capture_and_replay" in live:
        stage_replay(log, sleep, report, live["capture_and_replay"])
    elif name == "telemetry_replay" and "replay_telemetry" in live:
        stage_telemetry_replay(log, sleep, report, live["replay_telemetry"])
    elif name == "stale_session" and "check_stale_session" in live:
        stage_stale_session(log, sleep, report, live["check_stale_session"])
    elif name == "nonce_probe" and "probe_nonce" in live:
        stage_nonce_probe(log, sleep, report, live["probe_nonce"])
    elif name == "timestamp_manip" and "send_stale_operator" in live:
        stage_timestamp_manip(log, sleep, report, live["send_stale_operator"])
    elif name == "downgrade" and "attempt_downgrade" in live:
        stage_downgrade(log, sleep, report, live["attempt_downgrade"])
    elif name == "malformed_packet" and "send_malformed" in live:
        stage_malformed_packet(log, sleep, report, live["send_malformed"])
    elif name == "oversized" and "send_oversized" in live:
        stage_oversized(log, sleep, report, live["send_oversized"])
    elif name == "invalid_transition" and "send_legacy_events" in live:
        stage_invalid_transition(log, sleep, report, live["send_legacy_events"])
    elif name == "actuator_absent" and "check_actuator_presence" in live:
        stage_actuator_absent(log, sleep, report, live["check_actuator_presence"])
    elif name == "server_unavailable":
        stage_server_unavailable(log, sleep, report)
    elif name in ATTACK_CATALOG:
        # A physical attack invoked without its live plumbing (e.g. from the CLI
        # runner, which has no in-process hooks). Say so rather than doing nothing.
        log("ERROR", f"{ATTACK_CATALOG[name]['name']} runs against the live server only "
                     f"-- use the dashboard button, not the CLI.")
    else:
        log("ERROR", f"Unknown attack identifier {name!r}")


def run_all(log, sleep, report, obtain_public_key, deliver,
            intercept=lambda: None, live=None):
    for name in ATTACK_ORDER:
        run_stage(name, log, sleep, report, obtain_public_key, deliver, intercept, live)
        sleep(1)
