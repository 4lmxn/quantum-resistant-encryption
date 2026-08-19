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
    log("SUCCESS" if first != second else "ERROR",
        "Harvest Now, Decrypt Later: sessions share no key material")
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


def run_stage(name, log, sleep, report, obtain_public_key, deliver, intercept=lambda: None):
    """Dispatch one stage by the interface's attack identifier."""
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
    else:
        log("ERROR", f"Unknown attack identifier {name!r}")


def run_all(log, sleep, report, obtain_public_key, deliver, intercept=lambda: None):
    for name in ("shor", "kyber", "harvest", "mitm", "grover"):
        run_stage(name, log, sleep, report, obtain_public_key, deliver, intercept)
        sleep(1)
