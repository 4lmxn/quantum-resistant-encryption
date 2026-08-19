"""The three attack stages, shared by attack.py (CLI) and the dashboard buttons.

Each stage takes plumbing callables so the same logic runs either from a
Socket.IO client or inside the server process:

    log(log_type, msg)      -> surface a line on the dashboard
    obtain_public_key()     -> a real ML-KEM-768 encapsulation key, or None
    deliver(packet)         -> hand a raw packet to the actuator(s)
    sleep(seconds)          -> the caller's non-blocking sleep
"""

import time

from app.pqc import ENCAPSULATION_KEY_BYTES, LINK_SENSOR, encapsulate


def stage_classical(log, sleep):
    """Narration only: this system has no classical ECDH to break."""
    log("ATTACK", "[QUANTUM ATTACK 1] Intercepted Classical ECDH Key Exchange...")
    sleep(1)
    log("ATTACK", "[SHOR'S ALG] Solving Discrete Logarithm on Classical Curve...")
    sleep(1)
    log("ERROR", "[CLASSICAL BREACH] Key Cracked in 0.02s! Telemetry Decrypted.")


def stage_lattice(log, sleep, obtain_public_key):
    """Real: operates on an actual ML-KEM-768 encapsulation key."""
    log("ATTACK", "[QUANTUM ATTACK 2] Intercepting Kyber/ML-KEM-768 Key Exchange...")
    encapsulation_key = obtain_public_key()
    if encapsulation_key is None:
        log("ERROR", "[ATTACK ABORTED] No handshake observed on the wire.")
        return

    log(
        "ATTACK",
        f"[MITM] Captured {len(encapsulation_key)}-byte ML-KEM-768 public key: "
        f"{encapsulation_key[:16].hex()}...",
    )
    sleep(1)

    # The public key really is public; anyone can encapsulate against it. The
    # point is that this yields the ATTACKER's own secret, not the sensor's.
    first_secret, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    second_secret, _ = encapsulate(encapsulation_key, LINK_SENSOR)
    log(
        "ATTACK",
        f"[BKZ LATTICE REDUCTION] Encapsulated twice against the captured key: "
        f"{first_secret[:8].hex()}... vs {second_secret[:8].hex()}...",
    )
    log(
        "SUCCESS" if first_secret != second_secret else "ERROR",
        "[ATTACK FAILED] Each encapsulation yields an independent secret. "
        "Replaying captured traffic recovers nothing.",
    )
    sleep(1)

    # Recovering the decapsulation key from the public key is Module-LWE.
    # Show the search space rather than pretending to solve it.
    started = time.perf_counter()
    log(
        "ATTACK",
        f"[BKZ LATTICE REDUCTION] Attempting Module-LWE recovery over a "
        f"{ENCAPSULATION_KEY_BYTES * 8}-bit lattice basis (2^181 classical security)...",
    )
    sleep(1.5)
    log(
        "SUCCESS",
        f"[ATTACK FAILED] Abandoned after {time.perf_counter() - started:.2f}s. "
        f"Post-Quantum Lattice Unbroken! Kyber Math Intact.",
    )


def stage_harvest(log, sleep, obtain_public_key):
    """Report 1.4.1 — Harvest Now, Decrypt Later.

    Real: shows that two handshakes produce unrelated keys, so archived traffic
    cannot be opened by a key recovered later.
    """
    log("ATTACK", "[HARVEST NOW] Archiving encrypted telemetry for future decryption...")
    sleep(1)
    log("ATTACK", "[HARVEST NOW] Captured ciphertext stored. Waiting years for a quantum computer...")
    sleep(1.5)

    first = obtain_public_key()
    second = obtain_public_key()
    if first is None or second is None:
        log("ERROR", "[ATTACK ABORTED] No handshake observed on the wire.")
        return

    log(
        "ATTACK",
        f"[HARVEST NOW] Session 1 public key {first[:8].hex()}... "
        f"vs session 2 {second[:8].hex()}...",
    )
    log(
        "SUCCESS" if first != second else "ERROR",
        "[ATTACK FAILED] Every session negotiates a fresh keypair, and nodes wipe "
        "the old key. A key broken in 2040 opens nothing recorded today.",
    )


def stage_grover(log, sleep):
    """Report 1.4.4 — Grover's algorithm against the symmetric layer."""
    log("ATTACK", "[GROVER'S ALG] Quantum brute-force against the AES session key...")
    sleep(1)
    log("ATTACK", "[GROVER'S ALG] Grover halves the effective key length: sqrt(2^n) = 2^(n/2).")
    sleep(1)
    log(
        "ERROR",
        "[HYPOTHETICAL] Against AES-128 this leaves 2^64 — a real quantum margin failure.",
    )
    sleep(1)
    log(
        "SUCCESS",
        "[ATTACK FAILED] This link uses AES-256, so Grover leaves 2^128 effective "
        "security. Still computationally infeasible.",
    )


def stage_mitm(log, sleep, deliver):
    """Real: a forged packet reaches the actuator; only the GCM tag stops it."""
    log("ATTACK", "[QUANTUM ATTACK 3] Intercepting Actuator Command Payload...")
    sleep(1)
    log("ATTACK", "[MITM] Injecting Corrupted Ciphertext to Actuator...")
    deliver(
        {
            "nonce": "a1b2c3d4e5f60708090a0b0c",
            "ciphertext": "ff00ea2382104910284021948201948120",  # Invalid tag
        }
    )
    sleep(1.5)


def run_stage(name, log, sleep, obtain_public_key, deliver):
    """Dispatch one stage by the dashboard's button name."""
    if name == "shor":
        stage_classical(log, sleep)
    elif name == "kyber":
        stage_lattice(log, sleep, obtain_public_key)
    elif name == "harvest":
        stage_harvest(log, sleep, obtain_public_key)
    elif name == "grover":
        stage_grover(log, sleep)
    elif name == "mitm":
        stage_mitm(log, sleep, deliver)
    else:
        log("ERROR", f"[SERVER] Unknown attack type {name!r} requested.")


def run_all(log, sleep, obtain_public_key, deliver):
    stage_classical(log, sleep)
    sleep(1)
    stage_lattice(log, sleep, obtain_public_key)
    sleep(1)
    stage_mitm(log, sleep, deliver)
