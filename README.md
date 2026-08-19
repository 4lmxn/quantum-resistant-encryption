# Quantum-Resistant IoT Encryption

A working demonstrator of a post-quantum secured IoT control loop. A temperature
sensor streams encrypted telemetry to a central server, the server decides
whether to run a fan, and the fan relay only obeys commands it can
cryptographically authenticate.

Session keys are established with **ML-KEM-768** (NIST FIPS 203, the
standardised form of CRYSTALS-Kyber). The data channels are **AES-256-GCM**.

![status](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-blue) ![status](https://img.shields.io/badge/AES--256--GCM-authenticated-green)

## Why this is quantum-resistant

| Layer | Algorithm | Quantum threat | Status |
|---|---|---|---|
| Key exchange | ML-KEM-768 | Shor's algorithm breaks RSA/ECDH outright | Module-LWE has no known quantum attack |
| Bulk encryption | AES-256-GCM | Grover's algorithm halves the search space | 256-bit key → 128-bit effective, still infeasible |
| Message integrity | GCM authentication tag | — | Forged packets rejected before they reach the relay |

Classical ECDH would be recoverable by a sufficiently large quantum computer.
Lattice-based ML-KEM is not, which is the entire point of the comparison the
attack demo draws.

## Architecture

```
   sensor.py ──┐                         ┌── actuator.py
  (ML-KEM +    │                         │   (ML-KEM +
   AES-GCM)    │                         │    AES-GCM)
               ▼                         ▲
          ┌─────────────────────────────────┐
          │        server.py (Flask)        │──── dashboard (browser)
          │  per-node ML-KEM handshake      │
          │  threshold decision logic       │
          └─────────────────────────────────┘
               ▲                         ▲
   ESP32 ──────┘                         └────── attack.py
  (AES-GCM,                                     (3-stage demo)
   HTTP POST)
```

Nodes never talk to each other; everything routes through the server. The two
links use **independently negotiated keys**, so compromising one leg does not
expose the other.

### The handshake

Every node starts with no key at all:

1. Node sends `pqc_hello` with its role
2. Server generates a **fresh ML-KEM-768 keypair per node**, returns the 1184-byte encapsulation key
3. Node encapsulates → derives a shared secret, returns the 1088-byte KEM ciphertext
4. Server decapsulates → arrives at the identical secret
5. Both run `HKDF-SHA256(secret, info=<link label>)` → a 32-byte AES-256 key

Because the keypair is fresh per connection, wiping the key on shutdown is
genuine forward secrecy. HKDF domain separation guarantees the sensor and
actuator links can never derive the same key.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python server.py     # terminal 1 — dashboard at http://127.0.0.1:5001
python sensor.py     # terminal 2
python actuator.py   # terminal 3
python attack.py     # terminal 4 (optional — dashboard has buttons for this)
```

Open <http://127.0.0.1:5001> for the live dashboard: telemetry chart, relay
state, threshold slider, manual override, and a colour-coded security log.

> **Port 5001, not 5000.** On macOS the AirPlay Receiver occupies port 5000 and
> answers with a 403 that looks convincingly like a CORS failure.

## Tests

```bash
python test_pqc.py         # handshake agreement, domain separation, freshness, tamper rejection
python test_device_leg.py  # ESP32 wire format (server must be running)
```

## The attack demonstration

Three stages, from the dashboard buttons or `attack.py`:

1. **Classical break** — *scripted narration.* There is no classical ECDH in
   this system to break; the stage exists to contrast with stage 2.
2. **Lattice attack** — *real.* Captures a genuine 1184-byte ML-KEM public key
   off the wire, then shows that encapsulating against it twice produces two
   unrelated secrets, so recorded traffic yields nothing. It reports the
   Module-LWE search space rather than pretending to solve it.
3. **Man-in-the-middle bit-flip** — *real.* Injects a forged ciphertext at the
   actuator. The GCM tag check rejects it and the relay never moves.

Stage 3 is the payoff: tampering is not merely detected, it is detected *before*
a physical actuator acts on it.

## Hardware

`wokwi/` contains ESP32 firmware, wiring, and setup notes. The board performs a
real DHT22 read and real AES-256-GCM through the ESP32's mbedtls hardware
crypto, then POSTs to the server's `/telemetry` route.

Runs in the browser on [Wokwi](https://wokwi.com) or on a physical ESP32 —
identical sketch, two lines changed. See [`wokwi/README.md`](wokwi/README.md).

**The ESP32 does not run the handshake.** It uses a provisioned pre-shared key
(`DEVICE_PSK`), duplicated in `config.py` and `sketch.ino`. Keeping ML-KEM off
the microcontroller was a deliberate scope decision; this is the one remaining
pre-shared key in the system.

## Files

| File | Role |
|---|---|
| `pqc.py` | ML-KEM-768 keygen / encapsulation / HKDF derivation |
| `server.py` | Flask-SocketIO server, handshake state, threshold logic |
| `sensor.py` / `actuator.py` | Simulated nodes |
| `attacks.py` | Attack stages, shared by the CLI and the dashboard buttons |
| `attack.py` | CLI runner for the attack sequence |
| `config.py` | Threshold, network config, ESP32 pre-shared key |
| `templates/index.html` | Dashboard |
| `wokwi/` | ESP32 firmware and wiring |

## Honest limitations

- Stage 1 of the attack demo is narration, not a real cryptanalysis.
- No certificate or signature layer: the ML-KEM handshake is unauthenticated, so
  it resists eavesdropping but not an active impersonator who can sit in the
  middle from the very first packet. Production use would add ML-DSA signatures.
- `DEVICE_PSK` is a hardcoded key for the constrained node.
- Nonces come from `os.urandom` / `esp_random`; there is no nonce-reuse counter.

## Built with

Python 3.14 · Flask · Flask-SocketIO · [`kyber-py`](https://pypi.org/project/kyber-py/) · `cryptography` · Chart.js · Tailwind · ESP32/mbedtls
