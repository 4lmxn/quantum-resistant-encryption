import json
import time
import socketio

sio = socketio.Client()


def launch_quantum_attack_sequence():
    sio.connect("http://localhost:5000")

    # 1. Classical RSA/ECDH Attack Simulation
    sio.emit(
        "security_log",
        {
            "type": "ATTACK",
            "msg": "[QUANTUM ATTACK 1] Intercepted Classical ECDH Key Exchange...",
        },
    )
    time.sleep(1)
    sio.emit(
        "security_log",
        {
            "type": "ATTACK",
            "msg": "[SHOR'S ALG] Solving Discrete Logarithm on Classical Curve...",
        },
    )
    time.sleep(1)
    sio.emit(
        "security_log",
        {
            "type": "ERROR",
            "msg": "[CLASSICAL BREACH] Key Cracked in 0.02s! Telemetry Decrypted.",
        },
    )

    time.sleep(2)

    # 2. Post-Quantum Kyber Link Attack
    sio.emit(
        "security_log",
        {
            "type": "ATTACK",
            "msg": "[QUANTUM ATTACK 2] Intercepted Kyber-768 ML-KEM Key Exchange...",
        },
    )
    time.sleep(1)
    sio.emit(
        "security_log",
        {
            "type": "ATTACK",
            "msg": "[BKZ LATTICE REDUCTION] Attempting to solve Module-LWE Problem...",
        },
    )
    time.sleep(1.5)
    sio.emit(
        "security_log",
        {
            "type": "SUCCESS",
            "msg": "[ATTACK FAILED] Post-Quantum Lattice Unbroken! Kyber Math Intact.",
        },
    )

    time.sleep(2)

    # 3. Active Man-in-the-Middle Bit-Flipping Attack
    sio.emit(
        "security_log",
        {
            "type": "ATTACK",
            "msg": "[QUANTUM ATTACK 3] Intercepting Actuator Command Payload...",
        },
    )
    time.sleep(1)

    # Corrupted Payload Simulation
    corrupted_packet = {
        "nonce": "a1b2c3d4e5f60708090a0b0c",
        "ciphertext": "ff00ea2382104910284021948201948120",  # Invalid tag
    }
    sio.emit(
        "security_log",
        {"type": "ATTACK", "msg": "[MITM] Injecting Corrupted Ciphertext to Actuator..."},
    )
    sio.emit("execute_actuator_command", corrupted_packet)

    time.sleep(1)
    sio.disconnect()


if __name__ == "__main__":
    launch_quantum_attack_sequence()