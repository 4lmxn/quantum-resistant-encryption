"""MQTT over TLS 1.3 transport for the IoT nodes (report §3.1).

Wraps paho-mqtt so the sensor, actuator and server exchange the same JSON
messages they exchange over Socket.IO — only the carrier changes. The browser
dashboard stays on Socket.IO, since it is a UI client and not an IoT node.
"""

import json
import ssl
import threading

import paho.mqtt.client as mqtt

from config import MQTT_CA_CERT, MQTT_HOST, MQTT_TLS_PORT


class MqttLink:
    """One TLS-secured MQTT connection with topic handlers."""

    def __init__(self, client_id):
        self.client_id = client_id
        self._handlers = {}
        self._connected = threading.Event()
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=client_id
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            print(f"[MQTT] {self.client_id} connect failed: {reason_code}")
            return
        for topic in self._handlers:
            client.subscribe(topic)
        self._connected.set()

    def _on_message(self, client, userdata, message):
        try:
            payload = json.loads(message.payload.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            print(f"[MQTT] Dropped unparseable message on {message.topic}")
            return
        for topic, handler in self._handlers.items():
            if mqtt.topic_matches_sub(topic, message.topic):
                handler(message.topic, payload)

    def subscribe(self, topic, handler):
        """Register a handler. Wildcards (+ and #) are supported."""
        self._handlers[topic] = handler
        if self._connected.is_set():
            self._client.subscribe(topic)

    def publish(self, topic, payload):
        self._client.publish(topic, json.dumps(payload), qos=1)

    def connect(self, timeout=10):
        # TLS 1.3 is negotiated here; the broker presents the cert signed by our
        # local CA. The payloads inside are separately sealed with AES-256-GCM,
        # so this tunnel is defence in depth, not the only protection.
        self._client.tls_set(ca_certs=MQTT_CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        self._client.connect(MQTT_HOST, MQTT_TLS_PORT, keepalive=30)
        self._client.loop_start()
        if not self._connected.wait(timeout):
            raise ConnectionError(
                f"MQTT broker unreachable at {MQTT_HOST}:{MQTT_TLS_PORT}. "
                f"Start it with: python broker.py"
            )
        return self

    def tls_version(self):
        """The negotiated TLS version, for the dashboard and the demo."""
        sock = self._client.socket()
        return sock.version() if sock and hasattr(sock, "version") else "unknown"

    def disconnect(self):
        self._client.loop_stop()
        self._client.disconnect()
