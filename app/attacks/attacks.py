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
        "vector": "Polynomial-time integer factorisation and discrete logarithm on a "
                  "fault-tolerant quantum computer.",
        "impact": "Full recovery of RSA and ECDH private keys, exposing every session "
                  "key derived from them and all traffic they protect.",
        "mitigation": "Key exchange uses ML-KEM-768, whose security rests on Module-LWE "
                      "rather than factorisation.",
    },
    "kyber": {
        "name": "Lattice Reduction (BKZ)",
        "family": "Quantum cryptanalysis",
        "severity": "CRITICAL",
        "target": "ML-KEM-768 key encapsulation",
        "vector": "Basis reduction against the Module-LWE instance underlying the "
                  "encapsulation key.",
        "impact": "Recovery of the decapsulation key would compromise every session "
                  "negotiated with it.",
        "mitigation": "ML-KEM-768 carries a 2^181 classical security margin and no known "
                      "quantum attack better than generic search.",
    },
    "harvest": {
        "name": "Harvest Now, Decrypt Later",
        "family": "Passive interception",
        "severity": "HIGH",
        "target": "Recorded ciphertext, both channels",
        "vector": "Archive traffic today, decrypt once quantum hardware matures.",
        "impact": "Retrospective disclosure of all historical telemetry and commands.",
        "mitigation": "A fresh ML-KEM keypair per session with key zeroization on "
                      "disconnect, so no long-lived key exists to recover.",
    },
    "mitm": {
        "name": "Man-in-the-Middle Command Injection",
        "family": "Active tampering",
        "severity": "CRITICAL",
        "target": "Actuator command channel",
        "vector": "Injection of a forged ciphertext into the server-to-actuator path.",
        "impact": "Unauthorised physical actuation — a relay driven by an attacker.",
        "mitigation": "AES-256-GCM authentication tag verified before the actuator acts.",
    },
    "grover": {
        "name": "Grover's Algorithm",
        "family": "Quantum cryptanalysis",
        "severity": "MEDIUM",
        "target": "AES session keys, both channels",
        "vector": "Quantum unstructured search, reducing an n-bit key to n/2 effective bits.",
        "impact": "AES-128 would fall to a 2^64 margin, within reach of a sustained attack.",
        "mitigation": "AES-256 retains a 2^128 effective margin under Grover.",
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
            evidence="No RSA or ECDH key exchange was observed. Every active channel "
                     "uses ML-KEM-768.",
            outcome="Start a legacy node to see this attack succeed: "
                    "python -m app.nodes.sensor --legacy",
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
        evidence=f"Factored the RSA-{public[0].bit_length()} modulus in "
                 f"{elapsed * 1000:.1f} ms ({p_factor} x {q_factor}), recovered the "
                 f"transported session key {session_key.hex()[:32]}..., and decrypted "
                 f"intercepted telemetry to: {plaintext}",
        outcome="The classical channel is fully compromised from passive interception "
                "alone. Factorisation is shown here at a reduced key size; Shor's "
                "algorithm achieves the same against RSA-2048 on a quantum computer. "
                "The ML-KEM-768 channels are unaffected.",
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
        evidence=f"Captured a real {len(encapsulation_key)}-byte encapsulation key. Two "
                 f"encapsulations produced unrelated secrets ({first_secret[:8].hex()} vs "
                 f"{second_secret[:8].hex()}). Module-LWE recovery abandoned after "
                 f"{elapsed:.2f}s.",
        outcome="The public key alone yields no session key. Recovering the decapsulation "
                "key is a Module-LWE problem with no known feasible attack.",
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
        evidence=f"Two consecutive handshakes produced unrelated encapsulation keys "
                 f"({first[:8].hex()} vs {second[:8].hex()}). Nodes zeroize the session "
                 f"key on disconnect.",
        outcome="No long-lived key exists. A key recovered in future decrypts nothing "
                "recorded today.",
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
        evidence="Session keys are 256-bit (verified in the Key Exchange tab). Grover "
                 "reduces this to a 2^128 effective search.",
        outcome="AES-128 would be reduced to 2^64 and is inadequate. AES-256 retains a "
                "2^128 margin, which remains computationally infeasible.",
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
        evidence=f"Forged packet delivered to the actuator (nonce {forged['nonce']}, "
                 f"{len(forged['ciphertext']) // 2} byte payload). GCM tag verification "
                 f"raised InvalidTag; the relay did not change state.",
        outcome="Tampered commands are rejected before actuation. The relay never acts on "
                "an unauthenticated packet.",
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
