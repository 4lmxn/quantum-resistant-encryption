"""Local MQTT broker with TLS, so the nodes can speak MQTT over TLS 1.3.

Pure Python (amqtt) — no mosquitto install. Run this before the nodes when
using the MQTT transport:

    ./make_certs.sh     # once
    python broker.py
"""

import asyncio
import logging
import os

from amqtt.broker import Broker

from config import MQTT_HOST, MQTT_TLS_PORT

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

# amqtt 0.12 field names: snake_case, ssl is a bool, no "default" listener needed.
CONFIG = {
    "listeners": {
        "default": {
            "type": "tcp",
            "bind": f"{MQTT_HOST}:{MQTT_TLS_PORT}",
            "max_connections": 50,
            "ssl": True,
            "certfile": os.path.join(CERT_DIR, "broker.crt"),
            "keyfile": os.path.join(CERT_DIR, "broker.key"),
        },
    },
    "sys_interval": 0,
    "auth": {"allow-anonymous": True},
    "topic_check": {"enabled": False},
}


async def serve():
    if not os.path.exists(os.path.join(CERT_DIR, "broker.crt")):
        raise SystemExit("Certificates missing. Run ./make_certs.sh first.")

    broker = Broker(CONFIG)
    await broker.start()
    print(f"[BROKER] MQTT over TLS listening on {MQTT_HOST}:{MQTT_TLS_PORT}")
    print("[BROKER] Ctrl-C to stop.")
    await asyncio.Event().wait()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        print("\n[BROKER] Stopped.")
