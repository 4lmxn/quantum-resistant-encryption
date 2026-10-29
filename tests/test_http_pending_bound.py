"""Unauthenticated /pqc/hello cannot grow server memory. Run: python -m tests.test_http_pending_bound

Every hello leaves a decapsulation key behind before the caller has proved
anything, so the table must expire and stay bounded.
"""

from app import server


def hello(client):
    reply = client.post("/pqc/hello", json={"device_id": "esp32-01", "role": "sensor"})
    assert reply.status_code == 200, reply.status_code
    return reply.get_json()["handshake_id"]


def test_pending_handshakes_are_capped():
    server.server_engine.http_pending.clear()
    client = server.app.test_client()
    for _ in range(server.HTTP_PENDING_MAX + 20):
        hello(client)
    assert len(server.server_engine.http_pending) <= server.HTTP_PENDING_MAX


def test_expired_handshake_is_refused_and_pruned():
    server.server_engine.http_pending.clear()
    client = server.app.test_client()
    stale = hello(client)
    role, dk, ek, device, issued = server.server_engine.http_pending[stale]
    server.server_engine.http_pending[stale] = (role, dk, ek, device,
                                                issued - server.HTTP_HANDSHAKE_TTL_S - 1)
    reply = client.post("/pqc/encapsulate", json={"handshake_id": stale, "device_id": "esp32-01",
                                                  "kem_ciphertext": "00"})
    assert reply.status_code == 400, reply.status_code
    assert stale not in server.server_engine.http_pending


def test_fresh_handshake_still_completes_lookup():
    server.server_engine.http_pending.clear()
    client = server.app.test_client()
    fresh = hello(client)
    assert fresh in server.server_engine.http_pending


if __name__ == "__main__":
    for name, check in sorted(globals().items()):
        if name.startswith("test_"):
            check()
            print(f"PASS {name}")
