import argparse
import json
import os
import time

import socketio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import identity
from app.config import (
    HEARTBEAT_TIMEOUT_S,
    SERVER_URL,
    TOPIC_COMMAND,
    TOPIC_ENCAPS,
    TOPIC_HELLO,
    TOPIC_PUBKEY,
)
from app.pqc import LINK_ACTUATOR, encapsulate, key_fingerprint

sio = socketio.Client()

# Device credentials, provisioned out of band by `make enroll`. Without them the
# node cannot prove who it is and the server will refuse the handshake.
DEVICE_ID = os.environ.get("DEVICE_ID", "actuator-01")
_key_dir = identity.REGISTRY_PATH.parent / "identities"
DEVICE_SECRET = (_key_dir / f"{DEVICE_ID}.key").read_bytes() if (
    _key_dir / f"{DEVICE_ID}.key").exists() else None
SERVER_PUBLIC = (_key_dir / "server.pub").read_bytes() if (
    _key_dir / "server.pub").exists() else None



class SimulatedActuatorNode:
    """Drives XV-101, the emergency shutdown valve.

    CLOSED is the safe state. The valve is held OPEN by an energised solenoid
    and by nothing else, so anything that stops the node from actively holding
    it open -- including this node losing contact with the server -- closes it.
    """

    def __init__(self):
        self.key_b = None
        self.valve_state = "OPEN"
        # Wall-clock of the last heartbeat whose GCM tag verified. Seeded at
        # handshake so a node that never hears one still trips on schedule.
        self.last_heartbeat = None
        self.last_seq = 0
        self.tripped_by_watchdog = False
        # Command nonces already obeyed. The server refuses a repeated nonce on
        # telemetry coming in, but nothing protected this direction: a captured
        # TRIP or RESET could simply be sent again and the valve would obey it,
        # which is the flaw the FDA described in the 2019 MiniMed insulin pump
        # recall -- record the wireless traffic, replay it, the device acts.
        self.seen_command_nonces = set()

    def establish_session(self, encapsulation_key):
        session_key, kem_ciphertext = encapsulate(encapsulation_key, LINK_ACTUATOR)
        self.key_b = bytearray(session_key)
        return kem_ciphertext

    def process_command(self, packet):
        """Decrypts command and verifies the AES-256-GCM authentication tag."""
        aesgcm = AESGCM(bytes(self.key_b))
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        # Decrypt & Validate GCM Tag
        cmd_data = json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8"))

        # A valid tag proves the server composed this command. It does not prove
        # the server composed it *just now*, so a genuine command is single-use.
        nonce_hex = packet["nonce"]
        if nonce_hex in self.seen_command_nonces:
            return False, "REPLAY REFUSED: this command was already carried out"
        self.seen_command_nonces.add(nonce_hex)

        command = cmd_data.get("command")
        if command == "TRIP":
            self.valve_state = "CLOSED"
        elif command == "RESET":
            # A reset only reopens the valve. It does not clear the watchdog --
            # if the heartbeat is still missing, the watchdog trips again on its
            # next pass, which is the behaviour we want.
            self.valve_state = "OPEN"
            self.tripped_by_watchdog = False
        else:
            return False, f"Unknown Command: {command!r}"

        flow = "flow stopped" if self.valve_state == "CLOSED" else "process running"
        return True, f"XV-101 {self.valve_state} ({flow})"

    def accept_heartbeat(self, packet):
        """Verifies one sealed heartbeat and records that we heard it.

        Returns False for a beat we have already counted. A replayed heartbeat
        must not be able to hold the watchdog open, or capturing a single beat
        would be enough to disable the trip indefinitely.
        """
        aesgcm = AESGCM(bytes(self.key_b))
        body = json.loads(aesgcm.decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), None
        ).decode("utf-8"))
        if body.get("command") != "HEARTBEAT":
            return False
        seq = int(body.get("seq", 0))
        if seq <= self.last_seq:
            return False
        self.last_seq = seq
        self.last_heartbeat = time.monotonic()
        return True

    def heartbeat_overdue(self):
        if self.last_heartbeat is None:
            return False
        return (time.monotonic() - self.last_heartbeat) > HEARTBEAT_TIMEOUT_S

    def zeroize_key(self):
        if self.key_b is None:
            return
        for i in range(len(self.key_b)):
            self.key_b[i] = 0
        print("\n[ACTUATOR] Session Key B zeroized from RAM.")


actuator = SimulatedActuatorNode()


@sio.on("connect")
def on_connect():
    print("[ACTUATOR NODE] Connected. Starting ML-KEM-768 handshake...")
    sio.emit("pqc_hello", {"role": "actuator"})


@sio.on("pqc_public_key")
def on_public_key(data):
    encapsulation_key = bytes.fromhex(data["encapsulation_key"])

    if data.get("authenticated"):
        if SERVER_PUBLIC is None:
            print("[ACTUATOR NODE] Server is authenticated but this device has no "
                  "server public key. Run: make enroll")
            sio.disconnect()
            return
        transcript = identity.handshake_transcript("actuator", encapsulation_key)
        if not identity.verify(SERVER_PUBLIC, transcript,
                               bytes.fromhex(data.get("server_signature", "") or "")):
            # An unverifiable offer is exactly what a man in the middle produces.
            print("[ACTUATOR NODE] ABORT: server signature invalid — refusing to continue.")
            sio.disconnect()
            return
        print("[ACTUATOR NODE] Server identity verified (ML-DSA-65).")

    kem_ciphertext = actuator.establish_session(encapsulation_key)
    # A hash of our derived key, so the server can prove agreement on the
    # dashboard without either side transmitting key material.
    sio.emit(
        "pqc_encapsulation",
        {
            "kem_ciphertext": kem_ciphertext.hex(),
            "key_fingerprint": key_fingerprint(bytes(actuator.key_b)),
            "device_id": DEVICE_ID,
            "device_signature": identity.sign(
                DEVICE_SECRET,
                identity.handshake_transcript("actuator", encapsulation_key, kem_ciphertext),
            ).hex() if DEVICE_SECRET else "",
        },
    )


@sio.on("pqc_refused")
def on_refused(data):
    """The server turned this handshake away. Say why and stop.

    Reconnecting would only produce the same refusal, and a node that silently
    retries a rejected identity is indistinguishable from one being used to
    brute-force a session.
    """
    reason = data.get("reason", "unknown")
    if reason == "duplicate_device_id":
        print(f"[ACTUATOR NODE] REFUSED: {data.get('device_id')} already has a live session "
              f"on this server. Another copy of this node is probably still running.")
    else:
        print(f"[ACTUATOR NODE] REFUSED by the server: {reason}")
    sio.disconnect()


@sio.on("pqc_established")
def on_established(data):
    print("[ACTUATOR NODE] Session Key B derived. Listening for server commands...")
    # Seed the deadline now. Without this the watchdog would wait for a first
    # heartbeat that may never arrive, which is precisely the failure it exists
    # to catch.
    actuator.last_heartbeat = time.monotonic()
    sio.start_background_task(watchdog_loop)


@sio.on("sis_heartbeat")
def on_heartbeat(packet):
    """A sealed proof that the safety controller is still there and still ours."""
    if actuator.key_b is None:
        return
    try:
        actuator.accept_heartbeat(packet)
    except Exception as exc:
        # A heartbeat that fails its tag is worse than a missing one: something
        # is injecting traffic. Say so, and let the watchdog run its course.
        sio.emit("relay_log", {
            "type": "ERROR",
            "msg": f"[ACTUATOR] Heartbeat REJECTED, tag mismatch ({type(exc).__name__}).",
        })


def watchdog_loop():
    """Trips XV-101 when the authenticated heartbeat stops.

    This is the fail-safe direction, and it is deliberately local: the decision
    is made here, by the node holding the valve, so it survives exactly the
    situation where the server can no longer be reached.
    """
    while sio.connected:
        sio.sleep(1.0)
        if actuator.key_b is None or actuator.tripped_by_watchdog:
            continue
        if not actuator.heartbeat_overdue():
            continue
        actuator.tripped_by_watchdog = True
        actuator.valve_state = "CLOSED"
        print(f"[ACTUATOR] Heartbeat lost for >{HEARTBEAT_TIMEOUT_S}s. TRIPPING XV-101.")
        sio.emit("relay_log", {
            "type": "ALERT",
            "msg": f"[ACTUATOR] Dead-man watchdog: no authenticated heartbeat for "
                   f"{HEARTBEAT_TIMEOUT_S}s. XV-101 CLOSED locally.",
        })
        sio.emit("relay_actuator_ui", {"valve": actuator.valve_state})


@sio.on("execute_actuator_command")
def on_actuator_command(packet):
    if actuator.key_b is None:
        sio.emit(
            "relay_log",
            {"type": "ERROR", "msg": "[ACTUATOR REJECTED] No session key established."},
        )
        return
    try:
        success, msg = actuator.process_command(packet)
        sio.emit("actuator_ack_event", f"ACTUATOR ACK: {msg}")
        # The tag verified either way; an unrecognised command is still a
        # failure and must not be logged as a success.
        sio.emit(
            "relay_log",
            {
                "type": "SUCCESS" if success else "ERROR",
                "msg": f"[ACTUATOR] {msg} (AES Tag Verified)",
            },
        )
        if success:
            sio.emit("relay_actuator_ui", {"valve": actuator.valve_state})
    except Exception as e:
        sio.emit(
            "relay_log",
            {
                "type": "ERROR",
                "msg": f"[ACTUATOR REJECTED] Tag Mismatch / Tampering Detected "
                       f"({type(e).__name__})",
            },
        )


def run_actuator_node():
    sio.connect(SERVER_URL)
    try:
        sio.wait()
    except KeyboardInterrupt:
        pass
    finally:
        actuator.zeroize_key()
        sio.disconnect()


def run_actuator_node_mqtt():
    """Same node, same GCM tag check — carried over MQTT with TLS 1.3."""
    from app.transport.mqtt_transport import MqttLink

    node_id = f"actuator-{os.getpid()}"
    link = MqttLink(node_id)

    def on_public_key(topic, payload):
        kem_ciphertext = actuator.establish_session(
            bytes.fromhex(payload["encapsulation_key"])
        )
        link.publish(
            f"{TOPIC_ENCAPS}/{node_id}",
            {
                "kem_ciphertext": kem_ciphertext.hex(),
                "key_fingerprint": key_fingerprint(bytes(actuator.key_b)),
            },
        )
        print("[ACTUATOR NODE] Session Key B derived (ML-KEM-768 over MQTT/TLS).")

    def on_command(topic, packet):
        if actuator.key_b is None:
            print("[ACTUATOR REJECTED] No session key established.")
            return
        try:
            success, msg = actuator.process_command(packet)
            print(f"[ACTUATOR] {msg} (AES Tag Verified)" if success
                  else f"[ACTUATOR REJECTED] {msg}")
        except Exception as exc:
            print(f"[ACTUATOR REJECTED] Tag Mismatch / Tampering Detected ({type(exc).__name__})")

    link.subscribe(f"{TOPIC_PUBKEY}/{node_id}", on_public_key)
    link.subscribe(f"{TOPIC_COMMAND}/{node_id}", on_command)
    link.connect()
    print(f"[ACTUATOR NODE] Connected over MQTT, TLS {link.tls_version()}.")
    link.publish(TOPIC_HELLO, {"node_id": node_id, "role": "actuator"})

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        actuator.zeroize_key()
        link.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post-quantum IoT actuator node")
    parser.add_argument("--transport", choices=["socketio", "mqtt"], default="socketio",
                        help="mqtt uses MQTT over TLS 1.3 and needs broker.py running")
    args = parser.parse_args()
    if args.transport == "mqtt":
        run_actuator_node_mqtt()
    else:
        run_actuator_node()
