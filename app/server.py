import argparse
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

from app.attacks import attacks
from app import identity, legacy
from app.config import (
    DEVICE_PSK,
    HEARTBEAT_PERIOD_S,
    HEARTBEAT_TIMEOUT_S,
    OPERATOR_MAX_SKEW_S,
    SERVER_HOST,
    SERVER_PORT,
    SETPOINT_MAX_C,
    SETPOINT_MAX_STEP_C,
    SETPOINT_MIN_C,
    TRIP_SETPOINT_C,
)
from app.pqc import (
    ENCAPSULATION_KEY_BYTES,
    KEM_CIPHERTEXT_BYTES,
    LINK_ACTUATOR,
    LINK_SENSOR,
    decapsulate,
    generate_keypair,
    key_fingerprint,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "quantum_safe_secret_key")
socketio = SocketIO(app, cors_allowed_origins="*")


class CentralServer:
    """Holds one ML-KEM session per connected node, keyed by Socket.IO sid."""

    def __init__(self):
        self.trip_setpoint = TRIP_SETPOINT_C
        # A safety trip latches. Falling back below the setpoint does not clear
        # it -- an operator has to look at the plant and reset it deliberately.
        # That is also why the thermostat's hysteresis band is gone: a latch
        # cannot chatter, so the lower edge it needed has nothing left to do.
        self.trip_state = "HEALTHY"
        # Maintenance bypass. An operator-authenticated state now, not a
        # dashboard toggle anyone could reach.
        self.bypass = False
        # Dead-man heartbeat sequence on the safety link.
        self.heartbeat_seq = 0
        # Operator command nonces, so a captured signed instruction is
        # single-use and cannot be delivered a second time during an upset.
        self.operator_nonces = set()
        # Which enrolled identity holds which live session. A safety transmitter
        # is a physical thing: there is exactly one TT-101 on the plant, so two
        # sessions claiming to be it means either a misconfigured second node or
        # someone using a stolen key, and both must be refused rather than
        # quietly averaged into the log.
        self.active_devices = {}  # device_id -> sid
        # An attack can cut the heartbeat to try to disable the safety function.
        # This is TRITON's actual goal: not to cause the accident, but to remove
        # the thing that would have stopped one.
        self.heartbeat_severed_until = 0.0
        # The last genuine command we sealed, kept so a replay attack has a real
        # packet to re-send rather than a made-up one.
        self.last_command_packet = None
        self.dispatched_command_nonces = set()
        self.findings = {}  # attack id -> last structured result
        # What a passive interceptor would hold for the legacy RSA channel:
        # the public key, the wrapped session key, and one captured packet.
        self.legacy_intercept = None
        self.offered_keys = {}  # sid -> the encapsulation key we sent, for the transcript
        self.pending_handshakes = {}  # sid -> (role, decapsulation_key)
        self.sensor_keys = {}  # sid -> aes key
        self.actuator_keys = {}  # sid -> aes key
        self.sessions = {}  # sid -> display record for the dashboard panel
        # A GCM nonce must never repeat under one key. Recording the nonces we
        # have already accepted turns a captured packet into a single-use token,
        # which is what stops a replay.
        self.seen_nonces = {}  # scope -> set of nonce hex
        self.replays_blocked = 0

    def begin_handshake(self, sid, role):
        encapsulation_key, decapsulation_key = generate_keypair()
        self.pending_handshakes[sid] = (role, decapsulation_key)
        self.offered_keys[sid] = encapsulation_key
        return encapsulation_key

    def complete_handshake(self, sid, kem_ciphertext, node_fingerprint, transport="socketio"):
        role, decapsulation_key = self.pending_handshakes.pop(sid)
        label = LINK_SENSOR if role == "sensor" else LINK_ACTUATOR
        session_key = decapsulate(decapsulation_key, kem_ciphertext, label)
        store = self.sensor_keys if role == "sensor" else self.actuator_keys
        store[sid] = session_key

        # The fingerprints are one-way hashes, so showing them proves both sides
        # reached the same key without putting any key material on the wire.
        server_fingerprint = key_fingerprint(session_key)
        self.sessions[sid] = {
            # MQTT node ids already carry the role; Socket.IO sids do not.
            "node": sid if transport == "mqtt" else f"{role}@{sid[:8]}",
            "role": role,
            "kem": "ML-KEM-768",
            "public_key_bytes": ENCAPSULATION_KEY_BYTES,
            "ciphertext_bytes": KEM_CIPHERTEXT_BYTES,
            "aes_key_bits": len(session_key) * 8,
            "server_fingerprint": server_fingerprint,
            "node_fingerprint": node_fingerprint,
            "agreed": node_fingerprint == server_fingerprint,
            "transport": transport,
            "authenticated": AUTHENTICATED,
        }
        return role

    def accept_nonce(self, scope, nonce_hex):
        """False if this nonce has already been used under this key."""
        seen = self.seen_nonces.setdefault(scope, set())
        if nonce_hex in seen:
            self.replays_blocked += 1
            return False
        # ponytail: unbounded per-session growth is fine for a demo lifetime;
        # a long-lived deployment wants a sliding window or a timestamp check.
        if len(seen) > 50000:
            seen.clear()
        seen.add(nonce_hex)
        return True

    def forget(self, sid):
        for device_id, held_by in list(self.active_devices.items()):
            if held_by == sid:
                del self.active_devices[device_id]
        self.pending_handshakes.pop(sid, None)
        self.seen_nonces.pop(sid, None)
        self.sensor_keys.pop(sid, None)
        self.actuator_keys.pop(sid, None)
        self.sessions.pop(sid, None)
        self.offered_keys.pop(sid, None)

    def decrypt_sensor_data(self, session_key, packet):
        """Decrypts sensor payload with the negotiated sensor session key."""
        aesgcm = AESGCM(session_key)
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        return json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode())

    def encrypt_actuator_command(self, session_key, command_str, seq=None):
        """Encrypts a command with one actuator's negotiated session key.

        Heartbeats carry a sequence number so the actuator can tell a fresh beat
        from one it has already counted; commands carry none.
        """
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        body = {"command": command_str, "timestamp": time.time()}
        if seq is not None:
            body["seq"] = seq
        ciphertext = aesgcm.encrypt(nonce, json.dumps(body).encode(), None)
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


server_engine = CentralServer()

# Device identities. Absent, the server runs unauthenticated and says so, so the
# difference between the two modes can be demonstrated in one session.
registry = identity.IdentityRegistry()
AUTHENTICATED = registry.server_public is not None
mqtt_bridge = None  # set by --mqtt at startup
_heartbeat_started = False


def ensure_heartbeat_running():
    """Starts the dead-man heartbeat once, on the first actuator handshake.

    Starting it here rather than at import time means it never runs before there
    is a session to seal it with, and never gets started twice by a reconnect.
    """
    global _heartbeat_started
    if _heartbeat_started:
        return
    _heartbeat_started = True
    socketio.start_background_task(heartbeat_loop)


def log(log_type, msg):
    socketio.emit("security_log", {"type": log_type, "msg": msg})


def report_attack(identifier, status, confidence, evidence, outcome):
    """Publishes a full finding: name, severity, target, evidence, mitigation."""
    record = dict(attacks.describe(identifier))
    record.update(
        id=identifier,
        status=status,
        confidence=confidence,
        evidence=evidence,
        outcome=outcome,
        detected_at=time.strftime("%H:%M:%S"),
    )
    server_engine.findings[identifier] = record
    socketio.emit("attack_result", record)


def broadcast_findings():
    socketio.emit("attack_findings", {"findings": list(server_engine.findings.values())})


def broadcast_pqc_status():
    """Pushes the live handshake table to the dashboard."""
    socketio.emit("pqc_status", {"sessions": list(server_engine.sessions.values())})


def process_telemetry(data, source, packet=None, safety_relevant=True):
    """Shared handling for the Socket.IO nodes and the ESP32 HTTP leg.

    `safety_relevant` is the whole point of the split. The ESP32 runs on a
    provisioned pre-shared key, not the ML-KEM handshake, so it is the basic
    process control transmitter and its readings are displayed but never allowed
    to move the safety function. Only telemetry from a node that completed an
    authenticated handshake can trip the plant.

    The trip decision runs first so the reading and the resulting state are
    reported together; reporting first would always show the previous state.
    """
    if safety_relevant:
        decide_trip(data["temperature"])

    # The raw packet goes to the dashboard too, so it can show side by side what
    # an eavesdropper captures against what the key holder recovers.
    wire = {}
    if packet:
        ciphertext = packet.get("ciphertext", "")
        wire = {
            "nonce": packet.get("nonce", ""),
            "ciphertext": ciphertext,
            "bytes_on_wire": len(ciphertext) // 2 + len(packet.get("nonce", "")) // 2,
        }
    socketio.emit(
        "update_telemetry",
        {
            "temp": data["temperature"],
            "humidity": data["humidity"],
            # Never label the BPCS leg with the KEM it does not use. That leg is
            # sealed with the provisioned DEVICE_PSK, and saying otherwise on the
            # dashboard would quietly undo the whole point of splitting the lanes.
            "status": "SECURE_ML_KEM_768" if safety_relevant else "SECURE_DEVICE_PSK",
            "source": source,
            # A dashboard that opens mid-run must not show a stale setpoint,
            # and must never have to infer state by parsing log messages.
            "setpoint": server_engine.trip_setpoint,
            "trip_state": server_engine.trip_state,
            "valve": valve_position(),
            "bypass": server_engine.bypass,
            "over_setpoint": data["temperature"] >= server_engine.trip_setpoint,
            "safety_relevant": safety_relevant,
            "wire": wire,
        },
    )
    lane = "SAFETY" if safety_relevant else "BPCS"
    log(
        "SUCCESS",
        f"[SERVER/{lane}] Decrypted telemetry from {source} "
        f"(AES-256-GCM): {data['temperature']}°C",
    )



def claim_identity(device_id, sid):
    """Claims an enrolled identity for one session. (False, holder) if taken.

    The rogue-node attack runs through this same function rather than a copy of
    the rule, so the demonstration can never drift away from the enforcement.
    """
    holder = server_engine.active_devices.get(device_id)
    if holder is not None and holder != sid:
        return False, holder
    server_engine.active_devices[device_id] = sid
    return True, sid


def valve_position():
    """XV-101 as the actuator holds it. CLOSED is the safe state."""
    return "CLOSED" if server_engine.trip_state == "TRIPPED" else "OPEN"


def decide_trip(temperature):
    """Latching trip. Speaks only on the edge into TRIPPED.

    A thermostat has two edges; a safety function has one. Once the process
    variable reaches the setpoint the trip latches and stays latched, because
    the plant cooling back down is not evidence that whatever caused the
    excursion has been dealt with. Clearing it is an operator decision, made
    through a signed RESET.
    """
    if server_engine.bypass:
        return  # maintenance bypass asserted; logged when it was asserted

    if temperature < server_engine.trip_setpoint:
        return
    if server_engine.trip_state == "TRIPPED":
        return  # already latched, nothing to say

    server_engine.trip_state = "TRIPPED"
    log("ALERT", f"[SIS] {temperature}°C reached setpoint "
                 f"{server_engine.trip_setpoint}°C. TRIP latched, closing XV-101.")

    if not server_engine.actuator_keys:
        # Still worth stating plainly: the latch is set on the server, but no
        # final element is listening, so nothing physical has actually moved.
        log("ERROR", "[SIS] No actuator holds a session. The trip command could "
                     "not be delivered — the heartbeat watchdog is the backstop.")
    else:
        send_actuator_command("TRIP")
    socketio.emit("update_actuator_ui", {"valve": valve_position()})


def clear_trip(operator_id):
    """Operator reset. Only reachable from a verified operator_command."""
    if server_engine.trip_state != "TRIPPED":
        log("ALERT", f"[SIS] RESET from {operator_id} ignored: not tripped.")
        return
    server_engine.trip_state = "HEALTHY"
    log("SUCCESS", f"[SIS] Trip reset by {operator_id}. Reopening XV-101.")
    send_actuator_command("RESET")
    socketio.emit("update_actuator_ui", {"valve": valve_position()})


def heartbeat_loop():
    """Sealed heartbeat to every actuator, forever.

    This is the fail-safe direction. The actuator trips when these stop, so
    severing the link closes the valve instead of freezing it open. Losing the
    network must never be a way to disable the safety function.
    """
    while True:
        socketio.sleep(HEARTBEAT_PERIOD_S)
        if time.time() < server_engine.heartbeat_severed_until:
            continue  # severed by an attack; the actuator's watchdog takes over
        if not server_engine.actuator_keys:
            continue
        server_engine.heartbeat_seq += 1
        for actuator_sid, actuator_key in list(server_engine.actuator_keys.items()):
            packet = server_engine.encrypt_actuator_command(
                actuator_key, "HEARTBEAT", seq=server_engine.heartbeat_seq
            )
            socketio.emit("sis_heartbeat", packet, to=actuator_sid)


def send_actuator_command(command_str):
    """Seals one command per actuator, each under that actuator's own session key."""
    for actuator_sid, actuator_key in list(server_engine.actuator_keys.items()):
        cmd_packet = server_engine.encrypt_actuator_command(actuator_key, command_str)
        server_engine.last_command_packet = cmd_packet
        _dispatch_to_actuator(actuator_sid, cmd_packet)


def _dispatch_to_actuator(actuator_sid, packet):
    server_engine.dispatched_command_nonces.add(packet.get("nonce", ""))
    record = server_engine.sessions.get(actuator_sid, {})
    if record.get("transport") == "mqtt" and mqtt_bridge is not None:
        mqtt_bridge.send_command(packet, actuator_sid)
    else:
        socketio.emit("execute_actuator_command", packet, to=actuator_sid)


def deliver_raw_to_actuators(packet):
    """Forwards an attacker-supplied packet verbatim, so the GCM tag is the only defence."""
    for actuator_sid in list(server_engine.actuator_keys):
        _dispatch_to_actuator(actuator_sid, packet)


def server_side_public_key():
    """A genuine ML-KEM-768 public key for the dashboard-triggered lattice demo."""
    encapsulation_key, _ = generate_keypair()
    return encapsulation_key


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/telemetry")
def http_telemetry():
    """Basic process control transmitter — the ESP32 leg.

    The board posts an AES-256-GCM packet sealed with its provisioned key,
    because it cannot run the ML-KEM handshake itself. That weaker key is
    exactly why this leg is not on the safety path: it reports, it is displayed,
    and it cannot trip the plant. The safety function listens only to nodes that
    proved who they were with ML-DSA-65.
    """
    packet = request.get_json(force=True, silent=True) or {}
    try:
        data = server_engine.decrypt_sensor_data(DEVICE_PSK, packet)
    except Exception as exc:
        log("ERROR", f"[SERVER ERROR] ESP32 packet rejected: {exc}")
        return {"status": "rejected"}, 400

    if not server_engine.accept_nonce("device-psk", packet.get("nonce", "")):
        log("ERROR", "[SERVER] REPLAY BLOCKED: this ESP32 packet was already accepted.")
        return {"status": "replay"}, 409
    process_telemetry(data, "ESP32 node (BPCS)", packet, safety_relevant=False)
    return {
        "status": "accepted",
        "setpoint": server_engine.trip_setpoint,
        "trip_state": server_engine.trip_state,
        "valve": valve_position(),
    }


@socketio.on("legacy_hello")
def handle_legacy_hello(data):
    """Classical RSA key transport, offered so the contrast can be demonstrated.

    This channel is deliberately weak and exists to be broken by attack 1.
    """
    public, private = legacy.generate_keypair()
    server_engine.pending_handshakes[request.sid] = ("legacy", private)
    log("ALERT", f"[LEGACY] RSA-{public[0].bit_length()} key transport offered — "
                 f"no post-quantum protection on this channel.")
    emit("legacy_public_key", {"n": public[0], "e": public[1]})


@socketio.on("legacy_key_transport")
def handle_legacy_key_transport(data):
    """The node encrypts a session key under the server's RSA public key."""
    entry = server_engine.pending_handshakes.pop(request.sid, None)
    if not entry or entry[0] != "legacy":
        log("ERROR", "[LEGACY] Key transport with no handshake in progress.")
        return
    private = entry[1]
    blocks, chunk = data["blocks"], data["chunk"]
    session_key = legacy.unwrap_session_key(blocks, chunk, private)

    server_engine.sensor_keys[request.sid] = session_key
    server_engine.sessions[request.sid] = {
        "node": f"legacy@{request.sid[:8]}", "role": "sensor", "kem": "RSA key transport",
        "public_key_bytes": (private[0].bit_length() + 7) // 8,
        "ciphertext_bytes": len(blocks) * ((private[0].bit_length() + 7) // 8),
        "aes_key_bits": len(session_key) * 8,
        "server_fingerprint": key_fingerprint(session_key),
        "node_fingerprint": str(data.get("key_fingerprint", "")),
        "agreed": str(data.get("key_fingerprint", "")) == key_fingerprint(session_key),
        "transport": "legacy",
    }
    # Exactly what an eavesdropper on this channel would have captured.
    server_engine.legacy_intercept = {
        "public": (private[0], legacy.PUBLIC_EXPONENT),
        "blocks": blocks, "chunk": chunk, "packet": None,
    }
    log("ERROR", f"[LEGACY] Session key established over RSA-{private[0].bit_length()}. "
                 f"This channel is breakable — run attack 1.")
    broadcast_pqc_status()
    emit("pqc_established", {"role": "sensor"})


@socketio.on("pqc_hello")
def handle_pqc_hello(data):
    role = data.get("role")
    if role not in ("sensor", "actuator"):
        # Never default an unknown role to "actuator": that would enrol a
        # stranger in actuator_keys and post real commands to it.
        log("ERROR", f"[PQC] Refused handshake for unknown role {role!r}.")
        return
    encapsulation_key = server_engine.begin_handshake(request.sid, role)

    payload = {"encapsulation_key": encapsulation_key.hex(), "authenticated": AUTHENTICATED}
    if AUTHENTICATED:
        # Signing the offer is what stops an attacker substituting their own
        # encapsulation key and sitting in the middle of the exchange.
        transcript = identity.handshake_transcript(role, encapsulation_key)
        payload["server_signature"] = identity.sign(registry.server_secret, transcript).hex()
        log("SUCCESS", f"[PQC] {role.upper()} offer signed with ML-DSA-65 (FIPS 204).")
    else:
        log("ALERT", f"[PQC] {role.upper()} handshake is UNAUTHENTICATED — run: make enroll")
    emit("pqc_public_key", payload)


@socketio.on("pqc_encapsulation")
def handle_pqc_encapsulation(data):
    if request.sid not in server_engine.pending_handshakes:
        log("ERROR", "[PQC] Encapsulation received with no handshake in progress.")
        return
    role_pending = server_engine.pending_handshakes[request.sid][0]
    kem_ciphertext = bytes.fromhex(data.get("kem_ciphertext", ""))

    if AUTHENTICATED:
        device_id = str(data.get("device_id", ""))
        signature = bytes.fromhex(data.get("device_signature", "") or "")
        if not registry.is_enrolled(device_id):
            server_engine.forget(request.sid)
            log("ERROR", f"[PQC] Handshake refused: {device_id or '<none>'} is not enrolled.")
            return
        # The transcript binds the exact encapsulation key the server offered.
        expected = identity.handshake_transcript(
            role_pending, server_engine.offered_keys.get(request.sid, b""), kem_ciphertext)
        if not identity.verify(registry.public_key_of(device_id), expected, signature):
            server_engine.forget(request.sid)
            log("ERROR", f"[PQC] Handshake refused: bad ML-DSA signature from {device_id}.")
            return

        # A valid signature proves the key, not that this is the only holder of
        # it. Refuse a second live session for an identity that already has one:
        # two nodes reporting as the same transmitter is a fault however it
        # happened, and on a safety loop it is one that hides in plain sight --
        # the readings interleave and the log looks busy rather than wrong.
        claimed, holder = claim_identity(device_id, request.sid)
        if not claimed:
            server_engine.forget(request.sid)
            log("ERROR", f"[PQC] Handshake refused: {device_id} already holds a live "
                         f"session on {holder[:8]}. One identity, one session.")
            emit("pqc_refused", {"reason": "duplicate_device_id", "device_id": device_id})
            return

    try:
        role = server_engine.complete_handshake(
            request.sid,
            kem_ciphertext,
            str(data.get("key_fingerprint", "")),
        )
    except Exception as exc:
        # Report the failure class only. The raw exception can carry the session
        # id, and this log is broadcast to every connected dashboard.
        server_engine.forget(request.sid)
        log("ERROR", f"[PQC] Handshake failed ({type(exc).__name__}).")
        return
    if role == "actuator":
        ensure_heartbeat_running()
    record = server_engine.sessions[request.sid]
    if record["agreed"]:
        log("SUCCESS", f"[PQC] {role.upper()} session key established via ML-KEM-768 + HKDF-SHA256.")
        log("SUCCESS", f"[PQC] Both sides derived key {record['server_fingerprint']} independently.")
    else:
        log("ERROR", f"[PQC] {role.upper()} key disagreement. Node and server derived different keys.")
    broadcast_pqc_status()
    emit("pqc_established", {"role": role})


@socketio.on("sensor_telemetry_event")
def handle_sensor_telemetry(packet):
    session_key = server_engine.sensor_keys.get(request.sid)
    if session_key is None:
        log("ERROR", "[SERVER] Telemetry from a node with no ML-KEM session. Dropped.")
        return
    if (server_engine.legacy_intercept is not None
            and server_engine.sessions.get(request.sid, {}).get("transport") == "legacy"):
        server_engine.legacy_intercept["packet"] = packet
    if not server_engine.accept_nonce(request.sid, packet.get("nonce", "")):
        log("ERROR", "[SERVER] REPLAY BLOCKED: this telemetry packet was already accepted.")
        return
    try:
        data = server_engine.decrypt_sensor_data(session_key, packet)
        process_telemetry(data, "sensor node", packet)
    except Exception as exc:
        log("ERROR", f"[SERVER ERROR] Decryption failed: {exc}")


@socketio.on("actuator_ack_event")
def handle_actuator_ack(data):
    log("SUCCESS", f"[SERVER] {data}")


@socketio.on("relay_log")
def handle_relay_log(data):
    """Nodes cannot reach the dashboard directly; the server relays their logs."""
    socketio.emit("security_log", data)


@socketio.on("relay_actuator_ui")
def handle_relay_actuator_ui(data):
    """The actuator confirms what it did. The server already emitted the
    intended state, so this only corrects a genuine disagreement."""
    reported = data.get("valve")
    if reported != valve_position():
        # A disagreement here is real news: the actuator's own watchdog may have
        # tripped locally because our heartbeat stopped reaching it.
        log("ALERT", f"[SIS] Actuator reports XV-101 {reported}, server expected "
                     f"{valve_position()}. Trusting the actuator.")
        if reported == "CLOSED":
            server_engine.trip_state = "TRIPPED"
        socketio.emit("update_actuator_ui", {"valve": reported})


@socketio.on("mitm_inject")
def handle_mitm_inject(packet):
    """Simulated man-in-the-middle on the server->actuator channel."""
    deliver_raw_to_actuators(packet)


def _attack_sever_heartbeat(seconds):
    server_engine.heartbeat_severed_until = time.time() + seconds


def _attack_deliver_bpcs(temperature):
    """Seals a reading with the committed DEVICE_PSK and runs it through the BPCS
    leg exactly as the ESP32 would, returning (accepted, tripped_after)."""
    before = server_engine.trip_state
    data = {"temperature": temperature, "humidity": 40.0}
    process_telemetry(data, "forged ESP32 (attack)", None, safety_relevant=False)
    return True, server_engine.trip_state != before


def _attack_send_operator(action, value):
    """Feeds a correctly signed operator command through the real handler and
    returns a short verdict string for the finding."""
    if not AUTHENTICATED:
        return "refused (no operator enrolled)"
    import os as _os
    from app.nodes.operator import OPERATOR_ID, OPERATOR_SECRET
    if OPERATOR_SECRET is None:
        return "refused (no operator key on this server)"
    nonce = _os.urandom(16).hex()
    ts = int(time.time())
    transcript = identity.operator_transcript(OPERATOR_ID, action, value, nonce, ts)
    before = server_engine.trip_setpoint
    handle_operator_command({
        "operator_id": OPERATOR_ID, "action": action, "value": value,
        "nonce": nonce, "timestamp": ts,
        "signature": identity.sign(OPERATOR_SECRET, transcript).hex(),
    })
    return "refused by the clamp" if server_engine.trip_setpoint == before else "APPLIED"


def _attack_impersonate(device_id):
    """Tests whether an identity can be claimed, WITHOUT taking it.

    Claiming it for real would evict nothing but would leave the attacker's sid
    holding the identity and lock the genuine device out, so this only reads the
    current holder. Returns (would_succeed, holder)."""
    holder = server_engine.active_devices.get(device_id)
    return holder is None, holder


def _attack_capture_and_replay():
    """Re-sends the last genuine command and reports whether it was fresh.

    The nonce was already dispatched once, so the server sees the repeat here and
    the actuator refuses it independently on arrival. Returns (had_packet,
    accepted_as_fresh)."""
    packet = server_engine.last_command_packet
    if packet is None:
        return False, False
    already_seen = packet.get("nonce", "") in server_engine.dispatched_command_nonces
    deliver_raw_to_actuators(packet)  # the actuator refuses it by its own nonce store
    return True, not already_seen


@socketio.on("trigger_attack")
def handle_trigger_attack(data):
    """Dashboard attack buttons. Runs in the background so the stage sleeps do
    not block the server's event loop."""
    attack_type = str(data.get("attack_type", ""))
    live = {
        "sever_heartbeat": _attack_sever_heartbeat,
        "heartbeat_timeout": HEARTBEAT_TIMEOUT_S,
        "deliver_bpcs": _attack_deliver_bpcs,
        "send_operator": _attack_send_operator,
        "impersonate": _attack_impersonate,
        "capture_and_replay": _attack_capture_and_replay,
    }

    def _run():
        attacks.run_stage(
            attack_type, log, socketio.sleep, report_attack,
            server_side_public_key, deliver_raw_to_actuators,
            lambda: server_engine.legacy_intercept, live,
        )
    socketio.start_background_task(_run)


@socketio.on("manual_trip")
def handle_manual_trip():
    """Manual emergency shutdown from the dashboard.

    Unlike every other control, this one genuinely works from anywhere, and that
    is correct: tripping is the fail-safe direction. Every real control room has
    a manual ESD button that any operator can hit without a second key, because
    moving the plant to its safe state is never the dangerous action. Clearing a
    trip is -- and that still needs a signed reset.
    """
    if server_engine.trip_state == "TRIPPED":
        log("ALERT", "[SIS] Manual ESD pressed, but the plant is already tripped.")
        return
    server_engine.trip_state = "TRIPPED"
    log("ALERT", "[SIS] MANUAL EMERGENCY SHUTDOWN. XV-101 closing. "
                 "A trip is always allowed; only a reset needs a signed operator command.")
    if server_engine.actuator_keys:
        send_actuator_command("TRIP")
    socketio.emit("update_actuator_ui", {"valve": valve_position()})
    broadcast_sis_state()


@socketio.on("toggle_actuator_override")
def handle_toggle_actuator_override():
    """Kept, and now always refused.

    This used to flip the final element on an unauthenticated dashboard message.
    The command it emitted was properly sealed, so the actuator authenticated it
    correctly and obeyed -- which proved the server had sent it, and nothing
    about who had asked. It stays here, refusing, so the demonstration can show
    the unsigned path being turned away beside the signed one working.
    """
    log("ERROR", "[SIS] Refused: unsigned override from the dashboard. "
                 "Safety actions need a signed operator command — run: make operator")


@socketio.on("set_threshold")
def handle_set_threshold(data):
    """Kept, and now always refused. See handle_toggle_actuator_override."""
    log("ERROR", "[SIS] Refused: unsigned setpoint change from the dashboard. "
                 "This is the Oldsmar path — a legitimate control channel with "
                 "nobody proving who used it.")


@socketio.on("resume_automatic")
def handle_resume_automatic():
    """Kept, and now always refused: clearing a bypass is an operator action."""
    log("ERROR", "[SIS] Refused: unsigned bypass change from the dashboard.")


OPERATOR_ACTIONS = ("SET_SETPOINT", "RESET", "BYPASS_ON", "BYPASS_OFF")


def _reject_operator(reason):
    log("ERROR", f"[SIS] Operator command REFUSED: {reason}")


@socketio.on("operator_command")
def handle_operator_command(data):
    """A control action carrying an ML-DSA-65 signature over everything that
    changes its meaning.

    Authentication alone is not the lesson from Oldsmar -- that intruder used a
    legitimate remote-access path. So a verified signature is necessary here but
    not sufficient: the value is still clamped, and the size of a single step is
    still limited. A correctly signed command asking to move the trip setpoint
    by sixty degrees is refused exactly like an unsigned one.
    """
    if not AUTHENTICATED:
        _reject_operator("no identities enrolled on this server — run: make enroll")
        return

    operator_id = str(data.get("operator_id", ""))
    action = str(data.get("action", ""))
    value = data.get("value")
    nonce_hex = str(data.get("nonce", ""))
    timestamp = data.get("timestamp")

    if action not in OPERATOR_ACTIONS:
        _reject_operator(f"unknown action {action!r}")
        return
    if not registry.is_enrolled(operator_id):
        _reject_operator(f"{operator_id or '<none>'} is not enrolled")
        return
    try:
        skew = abs(time.time() - float(timestamp))
    except (TypeError, ValueError):
        _reject_operator("malformed timestamp")
        return
    if skew > OPERATOR_MAX_SKEW_S:
        _reject_operator(f"stale by {skew:.0f}s — a captured command cannot be replayed later")
        return
    if not nonce_hex or nonce_hex in server_engine.operator_nonces:
        _reject_operator("nonce missing or already used")
        return

    transcript = identity.operator_transcript(operator_id, action, value, nonce_hex, timestamp)
    signature = bytes.fromhex(str(data.get("signature", "") or ""))
    if not identity.verify(registry.public_key_of(operator_id), transcript, signature):
        _reject_operator(f"bad ML-DSA signature for {operator_id}")
        return

    # Burn the nonce only once the signature checks out, so an attacker cannot
    # spend a legitimate operator's nonce by sending garbage that carries it.
    server_engine.operator_nonces.add(nonce_hex)
    _apply_operator_action(operator_id, action, value)


def _apply_operator_action(operator_id, action, value):
    """Runs a command whose signature has already been verified."""
    if action == "RESET":
        clear_trip(operator_id)
    elif action == "BYPASS_ON":
        server_engine.bypass = True
        log("ALERT", f"[SIS] Maintenance bypass ASSERTED by {operator_id}. "
                     f"The trip function is suspended.")
    elif action == "BYPASS_OFF":
        server_engine.bypass = False
        log("SUCCESS", f"[SIS] Maintenance bypass cleared by {operator_id}.")
    elif action == "SET_SETPOINT":
        _apply_setpoint(operator_id, value)
    broadcast_sis_state()


def _apply_setpoint(operator_id, value):
    try:
        wanted = float(value)
    except (TypeError, ValueError):
        _reject_operator("setpoint is not a number")
        return
    if not SETPOINT_MIN_C <= wanted <= SETPOINT_MAX_C:
        _reject_operator(f"setpoint {wanted}°C outside the safe range "
                         f"{SETPOINT_MIN_C}–{SETPOINT_MAX_C}°C")
        return
    step = abs(wanted - server_engine.trip_setpoint)
    if step > SETPOINT_MAX_STEP_C:
        _reject_operator(f"step of {step:.1f}°C exceeds the {SETPOINT_MAX_STEP_C}°C "
                         f"limit on a single change")
        return
    previous = server_engine.trip_setpoint
    server_engine.trip_setpoint = wanted
    log("SUCCESS", f"[SIS] Trip setpoint {previous}°C → {wanted}°C, "
                   f"signed by {operator_id} (ML-DSA-65).")


def broadcast_sis_state():
    """Pushes setpoint, latch and bypass to the dashboard after any change."""
    socketio.emit("sis_state", {
        "setpoint": server_engine.trip_setpoint,
        "trip_state": server_engine.trip_state,
        "valve": valve_position(),
        "bypass": server_engine.bypass,
        "setpoint_min": SETPOINT_MIN_C,
        "setpoint_max": SETPOINT_MAX_C,
        "max_step": SETPOINT_MAX_STEP_C,
    })


@socketio.on("dashboard_ready")
def handle_dashboard_ready():
    """A dashboard that connects mid-run still needs the current state."""
    broadcast_pqc_status()
    broadcast_findings()
    broadcast_sis_state()


@socketio.on("disconnect")
def handle_disconnect(reason=None):
    had_session = request.sid in server_engine.sessions
    server_engine.forget(request.sid)
    if had_session:
        broadcast_pqc_status()


def start_mqtt_bridge():
    """Brings up the MQTT over TLS leg alongside Socket.IO."""
    global mqtt_bridge
    from app.transport.mqtt_bridge import MqttBridge

    mqtt_bridge = MqttBridge(
        engine=server_engine,
        log=log,
        on_telemetry=process_telemetry,
        broadcast_status=broadcast_pqc_status,
    ).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Post-quantum IoT central server")
    parser.add_argument("--mqtt", action="store_true",
                        help="also accept nodes over MQTT/TLS 1.3 (needs broker.py)")
    args = parser.parse_args()

    if args.mqtt:
        try:
            start_mqtt_bridge()
            print(f"[SERVER] MQTT over TLS leg active.")
        except Exception as exc:
            # The Socket.IO demo must survive a missing broker.
            print(f"[SERVER] MQTT bridge unavailable ({exc}). Socket.IO only.")

    socketio.run(app, host=SERVER_HOST, port=SERVER_PORT, debug=False, allow_unsafe_werkzeug=True)
