import argparse
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

from app.attacks import attacks
from app.config import DEVICE_PSK, SERVER_HOST, SERVER_PORT, TEMP_THRESHOLD
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
        self.temp_threshold = TEMP_THRESHOLD
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
        self.pending_handshakes.pop(sid, None)
        self.seen_nonces.pop(sid, None)
        self.sensor_keys.pop(sid, None)
        self.actuator_keys.pop(sid, None)
        self.sessions.pop(sid, None)

    def decrypt_sensor_data(self, session_key, packet):
        """Decrypts sensor payload with the negotiated sensor session key."""
        aesgcm = AESGCM(session_key)
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        return json.loads(aesgcm.decrypt(nonce, ciphertext, None).decode())

    def encrypt_actuator_command(self, session_key, command_str):
        """Encrypts a command with one actuator's negotiated session key."""
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        payload = json.dumps(
            {"command": command_str, "timestamp": time.time()}
        ).encode()
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


server_engine = CentralServer()
mqtt_bridge = None  # set by --mqtt at startup


def log(log_type, msg):
    socketio.emit("security_log", {"type": log_type, "msg": msg})


def broadcast_pqc_status():
    """Pushes the live handshake table to the dashboard."""
    socketio.emit("pqc_status", {"sessions": list(server_engine.sessions.values())})


def process_telemetry(data, source, packet=None):
    """Shared decision logic for both the Socket.IO nodes and the ESP32 HTTP leg."""
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
            "status": "SECURE_ML_KEM_768",
            "source": source,
            # A dashboard that opens mid-run must not show a stale limit.
            "threshold": server_engine.temp_threshold,
            "wire": wire,
        },
    )
    log(
        "SUCCESS",
        f"[SERVER] Decrypted telemetry from {source} "
        f"(AES-256-GCM, key from ML-KEM-768): {data['temperature']}°C",
    )

    if data["temperature"] <= server_engine.temp_threshold:
        return

    log(
        "ALERT",
        f"[SERVER] ALERT: Temp {data['temperature']}°C > {server_engine.temp_threshold}°C. "
        f"Emitting FAN_ON command...",
    )
    if not server_engine.actuator_keys:
        log("ERROR", "[SERVER] No actuator has completed a handshake. Command dropped.")
        return
    send_actuator_command("FAN_ON")


def send_actuator_command(command_str):
    """Seals one command per actuator, each under that actuator's own session key."""
    for actuator_sid, actuator_key in list(server_engine.actuator_keys.items()):
        cmd_packet = server_engine.encrypt_actuator_command(actuator_key, command_str)
        _dispatch_to_actuator(actuator_sid, cmd_packet)


def _dispatch_to_actuator(actuator_sid, packet):
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
    """Constrained-device leg. The ESP32 posts an AES-256-GCM packet sealed with
    its provisioned key, because it cannot run the ML-KEM handshake itself."""
    packet = request.get_json(force=True, silent=True) or {}
    try:
        data = server_engine.decrypt_sensor_data(DEVICE_PSK, packet)
    except Exception as exc:
        log("ERROR", f"[SERVER ERROR] ESP32 packet rejected: {exc}")
        return {"status": "rejected"}, 400

    if not server_engine.accept_nonce("device-psk", packet.get("nonce", "")):
        log("ERROR", "[SERVER] REPLAY BLOCKED: this ESP32 packet was already accepted.")
        return {"status": "replay"}, 409
    process_telemetry(data, "ESP32 node", packet)
    return {"status": "accepted", "threshold": server_engine.temp_threshold}


@socketio.on("pqc_hello")
def handle_pqc_hello(data):
    role = data.get("role")
    if role not in ("sensor", "actuator"):
        # Never default an unknown role to "actuator": that would enrol a
        # stranger in actuator_keys and post real commands to it.
        log("ERROR", f"[PQC] Refused handshake for unknown role {role!r}.")
        return
    encapsulation_key = server_engine.begin_handshake(request.sid, role)
    log("ATTACK", f"[PQC] {role.upper()} handshake started. Sending ML-KEM-768 public key...")
    emit("pqc_public_key", {"encapsulation_key": encapsulation_key.hex()})


@socketio.on("pqc_encapsulation")
def handle_pqc_encapsulation(data):
    if request.sid not in server_engine.pending_handshakes:
        log("ERROR", "[PQC] Encapsulation received with no handshake in progress.")
        return
    try:
        role = server_engine.complete_handshake(
            request.sid,
            bytes.fromhex(data.get("kem_ciphertext", "")),
            str(data.get("key_fingerprint", "")),
        )
    except Exception as exc:
        # Report the failure class only. The raw exception can carry the session
        # id, and this log is broadcast to every connected dashboard.
        server_engine.forget(request.sid)
        log("ERROR", f"[PQC] Handshake failed ({type(exc).__name__}).")
        return
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
    socketio.emit("update_actuator_ui", data)


@socketio.on("mitm_inject")
def handle_mitm_inject(packet):
    """Simulated man-in-the-middle on the server->actuator channel."""
    deliver_raw_to_actuators(packet)


@socketio.on("trigger_attack")
def handle_trigger_attack(data):
    """Dashboard attack buttons. Runs in the background so the stage sleeps do
    not block the server's event loop."""
    attack_type = str(data.get("attack_type", ""))
    socketio.start_background_task(
        attacks.run_stage,
        attack_type,
        log,
        socketio.sleep,
        server_side_public_key,
        deliver_raw_to_actuators,
    )


@socketio.on("toggle_actuator_override")
def handle_toggle_actuator_override():
    """Manual relay override from the dashboard. Sent as a properly sealed
    command, so the actuator authenticates it exactly like an automatic one."""
    if not server_engine.actuator_keys:
        log("ERROR", "[SERVER] Override ignored: no actuator has completed a handshake.")
        return
    log("ALERT", "[SERVER] Operator override: dispatching sealed FAN_TOGGLE.")
    send_actuator_command("FAN_TOGGLE")


@socketio.on("set_threshold")
def handle_set_threshold(data):
    try:
        server_engine.temp_threshold = float(data["threshold"])
    except (KeyError, TypeError, ValueError):
        log("ERROR", "[SERVER] Rejected malformed threshold from dashboard.")
        return
    log("ALERT", f"[SERVER] Threshold set to {server_engine.temp_threshold}°C by operator.")


@socketio.on("dashboard_ready")
def handle_dashboard_ready():
    """A dashboard that connects mid-run still needs the current table."""
    broadcast_pqc_status()


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
