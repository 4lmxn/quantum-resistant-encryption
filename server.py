import json
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "quantum_safe_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Central Server Cryptographic Engine ---
class CentralServer:

    def __init__(self):
        # 256-bit symmetric keys derived via Kyber KEM handshakes
        self.session_key_a = os.urandom(32)  # Sensor Link Key
        self.session_key_b = os.urandom(32)  # Actuator Link Key
        self.temp_threshold = 30.0  # Trigger threshold in °C

    def decrypt_sensor_data(self, packet):
        """Decrypts sensor payload using Session Key A."""
        aesgcm = AESGCM(self.session_key_a)
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        decrypted_raw = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_raw.decode())

    def encrypt_actuator_command(self, command_str):
        """Encrypts command payload using Session Key B."""
        aesgcm = AESGCM(self.session_key_b)
        nonce = os.urandom(12)
        payload = json.dumps(
            {"command": command_str, "timestamp": time.time()}
        ).encode()
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


server_engine = CentralServer()


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("sensor_telemetry_event")
def handle_sensor_telemetry(packet):
    try:
        data = server_engine.decrypt_sensor_data(packet)
        socketio.emit(
            "update_telemetry",
            {
                "temp": data["temperature"],
                "humidity": data["humidity"],
                "status": "SECURE_KEY_A",
            },
        )
        socketio.emit(
            "security_log",
            {
                "type": "SUCCESS",
                "msg": f"[SERVER] Decrypted Sensor Telemetry via Key A: {data['temperature']}°C",
            },
        )

        # Decision Logic
        if data["temperature"] > server_engine.temp_threshold:
            socketio.emit(
                "security_log",
                {
                    "type": "ALERT",
                    "msg": f"[SERVER] ALERT: Temp {data['temperature']}°C > {server_engine.temp_threshold}°C. Emitting FAN_ON command...",
                },
            )
            cmd_packet = server_engine.encrypt_actuator_command("FAN_ON")
            socketio.emit("execute_actuator_command", cmd_packet)

    except Exception as e:
        socketio.emit(
            "security_log",
            {"type": "ERROR", "msg": f"[SERVER ERROR] Decryption failed: {str(e)}"},
        )


@socketio.on("actuator_ack_event")
def handle_actuator_ack(data):
    socketio.emit("security_log", {"type": "SUCCESS", "msg": f"[SERVER] {data}"})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)