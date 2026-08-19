"""Server-side MQTT leg: runs the same handshake and telemetry logic as the
Socket.IO handlers, but over MQTT topics. Started by server.py --mqtt.
"""

from app.config import (
    TOPIC_COMMAND,
    TOPIC_ENCAPS,
    TOPIC_HELLO,
    TOPIC_PUBKEY,
    TOPIC_TELEMETRY,
)
from app.transport.mqtt_transport import MqttLink


class MqttBridge:
    """Bridges MQTT nodes into the server's existing session machinery.

    Node ids play the role Socket.IO session ids play elsewhere, so the same
    CentralServer methods work unchanged.
    """

    def __init__(self, engine, log, on_telemetry, broadcast_status):
        self.engine = engine
        self.log = log
        self.on_telemetry = on_telemetry
        self.broadcast_status = broadcast_status
        self.link = MqttLink("central-server")

    def start(self):
        self.link.subscribe(TOPIC_HELLO, self._handle_hello)
        self.link.subscribe(f"{TOPIC_ENCAPS}/+", self._handle_encaps)
        self.link.subscribe(f"{TOPIC_TELEMETRY}/+", self._handle_telemetry)
        self.link.connect()
        self.log("SUCCESS", f"[MQTT] Server bridge online over {self.link.tls_version()}.")
        return self

    def _handle_hello(self, topic, payload):
        node_id = str(payload.get("node_id", ""))
        role = payload.get("role")
        if not node_id or role not in ("sensor", "actuator"):
            self.log("ERROR", f"[MQTT] Refused handshake for role {role!r}.")
            return
        encapsulation_key = self.engine.begin_handshake(node_id, role)
        self.log("ATTACK", f"[MQTT] {role.upper()} handshake over TLS. Publishing ML-KEM-768 public key...")
        self.link.publish(
            f"{TOPIC_PUBKEY}/{node_id}",
            {"encapsulation_key": encapsulation_key.hex()},
        )

    def _handle_encaps(self, topic, payload):
        node_id = topic.rsplit("/", 1)[-1]
        if node_id not in self.engine.pending_handshakes:
            self.log("ERROR", "[MQTT] Encapsulation with no handshake in progress.")
            return
        try:
            role = self.engine.complete_handshake(
                node_id,
                bytes.fromhex(payload.get("kem_ciphertext", "")),
                str(payload.get("key_fingerprint", "")),
                transport="mqtt",
            )
        except Exception as exc:
            self.engine.forget(node_id)
            self.log("ERROR", f"[MQTT] Handshake failed ({type(exc).__name__}).")
            return
        record = self.engine.sessions[node_id]
        self.log("SUCCESS", f"[MQTT] {role.upper()} key {record['server_fingerprint']} agreed over MQTT/TLS.")
        self.broadcast_status()

    def _handle_telemetry(self, topic, packet):
        node_id = topic.rsplit("/", 1)[-1]
        session_key = self.engine.sensor_keys.get(node_id)
        if session_key is None:
            self.log("ERROR", "[MQTT] Telemetry from a node with no ML-KEM session. Dropped.")
            return
        if not self.engine.accept_nonce(node_id, packet.get("nonce", "")):
            self.log("ERROR", "[MQTT] REPLAY BLOCKED: packet already accepted.")
            return
        try:
            data = self.engine.decrypt_sensor_data(session_key, packet)
        except Exception as exc:
            self.log("ERROR", f"[MQTT] Decryption failed: {type(exc).__name__}")
            return
        self.on_telemetry(data, f"MQTT sensor {node_id}", packet)

    def send_command(self, packet, node_id):
        self.link.publish(f"{TOPIC_COMMAND}/{node_id}", packet)

    def actuator_ids(self):
        return [
            sid for sid in self.engine.actuator_keys
            if sid in self.engine.sessions and self.engine.sessions[sid].get("mqtt")
        ]
