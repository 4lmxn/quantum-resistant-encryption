# SIS-01 — A Post-Quantum Safety Instrumented System

> A working **emergency shutdown system** for industrial plant, protected end to
> end with **post-quantum cryptography** — and attackable live from the dashboard.

A temperature transmitter streams **authenticated** telemetry to a logic solver.
Crossing the trip setpoint **latches** a trip and slams valve **XV-101** shut.
The valve obeys **only** commands it can cryptographically authenticate, from a
server it has cryptographically identified.

Modelled on the **2017 TRITON/TRISIS** attack on Schneider Triconex safety
controllers — so the design question throughout is not *"can an eavesdropper
read this"* but **"what happens when someone is already inside."**

![ML-KEM-768](https://img.shields.io/badge/ML--KEM--768-FIPS%20203-blue) ![ML-DSA-65](https://img.shields.io/badge/ML--DSA--65-FIPS%20204-blueviolet) ![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-authenticated-green) ![tests](https://img.shields.io/badge/tests-69%20passing-brightgreen)

![Dashboard](docs/dashboard.png)

---

## The one-paragraph version

- **Sensor → server → valve.** Three parts, each a real node.
- **Every link is post-quantum.** Keys agreed with ML-KEM-768, identities and
  commands signed with ML-DSA-65, data sealed with AES-256-GCM.
- **It behaves like a real safety system**, not a thermostat: trips **latch**,
  losing the network **closes** the valve, and even a validly-signed command is
  **bounded**.
- **You can attack it live.** Ten dashboard scenarios, six drawn from documented
  real-world incidents, each reporting what actually happened.

---

## Why post-quantum

| Layer | Algorithm | The quantum threat | Why this survives it |
|---|---|---|---|
| **Key exchange** | ML-KEM-768 | Shor's algorithm breaks RSA/ECDH outright | Built on Module-LWE — **no known quantum attack** |
| **Identity & commands** | ML-DSA-65 | Shor's algorithm breaks RSA/ECDSA signatures | Lattice signatures — **the authentication survives too** |
| **Bulk encryption** | AES-256-GCM | Grover's algorithm halves the key search | 256-bit → 128-bit effective — **still infeasible** |
| **Message integrity** | GCM tag | — | Forged packets **rejected before XV-101 moves** |

> **Key point:** signing a post-quantum handshake with a *classical* signature
> would reintroduce exactly the weakness ML-KEM removes. That is why the
> signature layer is **ML-DSA, not RSA or ECDSA**.

---

## Architecture

```
   sensor ──┐                             ┌── actuator  (XV-101)
  (ML-KEM + │                             │   (ML-KEM + ML-DSA
   ML-DSA + ▼                             ▲    + AES-GCM +
   AES-GCM)                               │     dead-man watchdog)
        ┌───────────────────────────────────┐
        │     server — the logic solver     │──► dashboard (browser · PIN-gated · view only)
        │  • per-node ML-KEM handshake      │
        │  • latching trip decision         │◄── operator console (ML-DSA signed)
        │  • sealed heartbeat every 2s ─────┼──►
        └───────────────────────────────────┘
              ▲                             ▲
   ESP32 ─────┘                             └── attacker
 (real ML-KEM handshake, or                    (10 live scenarios)
  PSK fallback if unprovisioned)
```

- **Nodes never talk to each other** — everything routes through the server.
- **The two safety links use independently negotiated keys.** Breaking one leg
  gives you **nothing** on the other.
- **The dashboard holds no key.** It is a view; every safety action is signed
  elsewhere.

### The handshake, step by step

Every node starts with **no key at all**:

1. **Node** → `hello` with its role.
2. **Server** → a **fresh ML-KEM-768 keypair per node**, returns the 1184-byte
   encapsulation key **signed with ML-DSA-65**.
3. **Node** verifies that signature, and **aborts** if it fails (that is the
   man-in-the-middle defence).
4. **Node** encapsulates → returns the 1088-byte ciphertext **signed with its own
   enrolled key**.
5. **Server** checks the node is enrolled and the signature covers the exact keys
   exchanged, then decapsulates → **same secret**.
6. **Both** run `HKDF-SHA256` → an identical 32-byte AES-256 key.

- **Fresh keypair per connection** → wiping the key on disconnect is **genuine
  forward secrecy**.
- **Domain separation** → the sensor and valve links can **never** derive the
  same key.
- **The signed transcript binds the role and both halves** → a captured
  signature can't be replayed into another handshake.

---

## What makes it a safety system, not a thermostat

- **Trips latch.** Reaching the setpoint sends `TRIP` and stays tripped. Cooling
  back down does **not** clear it — a plant getting colder is not proof the fault
  is gone. **Only a signed operator `RESET` clears it.**
- **Losing the network closes the valve.** The server seals a **heartbeat every
  2 s**; the valve trips itself after **6 s of silence**. Cutting the cable
  *performs* the shutdown instead of disabling it — the exact reversal of what
  TRITON tried. *(This replaced a fail-danger path that used to freeze the valve
  open.)*
- **Safety actions require a signed operator command.** Setpoint, reset, and
  bypass all go through `make operator`, signed with an enrolled ML-DSA-65 key.
- **A valid signature is necessary but not sufficient.** Oldsmar's intruder used
  a *legitimate* control path, so the server also refuses a command when:
  - the operator is **not enrolled**, or the signature doesn't verify
  - the **nonce** is missing or already used (single-use)
  - the **timestamp** is more than 30 s off
  - the setpoint is **outside 40–120 °C**
  - one change moves it **more than 15 °C**

  > A correctly signed request for **11,100 °C is refused exactly like an
  > unsigned one.**
- **The dashboard is PIN-gated.** A 4-digit operator PIN, **new every server
  run**, printed in the console — so dashboard access follows console access.
- **There is no unsigned control path.** The one thing the dashboard *can* do is
  a **manual emergency stop** — because tripping is the fail-safe direction, and
  every control room has that red button.

---

## Post-quantum on the microcontroller

The constrained ESP32 node is **not** a permanent weak-link exception. It runs
the **real** handshake primitives, and this was proven — not asserted:

- **✅ Interoperates with the server, byte-for-byte.** The vendored PQClean C
  encapsulates against a `kyber-py` key and `kyber-py` recovers the **identical
  secret**; `dilithium-py` and the C verify each other's signatures. Reproducible:
  `make pqc-interop`.
- **✅ Fits the chip.** ML-KEM-768 + ML-DSA-65 compile for the ESP32 at **287 KB
  (21% of flash), 11% RAM**. `make firmware-pqc`.
- **The Python ESP32 stand-in does the full handshake today** over HTTP and
  becomes a full safety transmitter — no pre-shared key.

> **Remaining:** wiring the on-device handshake into the networked telemetry
> sketch (a 64 KB task for ML-DSA signing + on-hardware timing). Integration, not
> unknowns. Until then the firmware uses a **runtime-provisioned** key that is
> **never committed** — `make enroll` generates and prints it.

---

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

make enroll     # once — ML-DSA identities + a random device key (prints the PIN-less secrets)
make server     # terminal 1 — dashboard at http://127.0.0.1:5001, PIN printed here
make sensor     # terminal 2
make actuator   # terminal 3
make device     # terminal 4 (optional) — the ESP32 stand-in, real handshake
```

**Signed operator actions**, from any terminal:

```bash
make operator ARGS="setpoint 85"   # move the trip setpoint
make operator ARGS=reset           # clear a latched trip
make operator ARGS="bypass on"     # assert the maintenance bypass
```

- **Open** <http://127.0.0.1:5001>, then **enter the PIN** from the server
  console to unlock the HMI.
- **Skip `make enroll`** and the server runs unauthenticated, says so, and
  refuses every operator command — worth showing once.
- **Full walkthrough:** [`docs/DEMO.md`](docs/DEMO.md) has a 10-beat demo script
  with the expected output for each step.

> **⚠️ Port 5001, not 5000.** On macOS the AirPlay Receiver squats on 5000 and
> answers with a 403 that looks exactly like a CORS failure.

---

## Attacks you can run

Ten dashboard scenarios, **documented incidents first**, quantum second — each
runs against the **live** system and reports what actually happened:

| Attack | Based on | What you see |
|---|---|---|
| **Silence the safety function** | TRITON, 2017 | valve trips itself |
| **Forge with a leaked key** | 19-day rig shutdown | forged reading **ignored** |
| **Insider setpoint move** | Oldsmar, 2021 | clamp **refuses** a signed absurd value |
| **Rogue node** | Aliquippa, 2023 | duplicate identity **refused** |
| **Replay a captured command** | Medtronic, 2019 | single-use nonce **refuses** it |
| **Forged command injection** | — | GCM tag **rejects** it before XV-101 moves |
| **Shor / Lattice / Harvest / Grover** | forward-looking | the reason for post-quantum keys |

> The payoff is that tampering is not merely *detected* — it is detected
> **before a physical final element acts on it.**

Background on the incidents: **[Killing the Kill Switch](docs/)** explainer.

---

## Tests

```bash
make test         # 69 checks — crypto, latching trip, identity, operator auth,
                  # heartbeat watchdog, duplicate-identity, command replay,
                  # actuator resync, HTTP handshake, C↔Python interop
make pqc-interop  # cross-implementation known-answer test on its own
make test-device  # ESP32 wire format (server must be running)
```

---

## Hardware

- `firmware/` holds the ESP32 sketch, wiring, and setup notes.
- Runs in the browser on **[Wokwi](https://wokwi.com)** or on a **physical
  ESP32** — identical sketch.
- `firmware/pqc/` vendors the **real ML-KEM-768 + ML-DSA-65** (PQClean, CC0);
  `firmware/pqc_selftest/` runs them on the board.
- Step-by-step, including the free-Wokwi tunnel route:
  [`firmware/README.md`](firmware/README.md).

---

## Layout

```
app/           server, crypto, dashboard, identity
  nodes/       sensor, actuator, operator console, ESP32 stand-in
  transport/   MQTT over TLS + broker
  attacks/     the attack stages
firmware/
  sketch/      the ESP32 telemetry sketch
  pqc/         vendored ML-KEM-768 + ML-DSA-65 (interop-proven)
  pqc_selftest/  on-device crypto self-test
tests/         crypto, identity, handshake, interop checks
docs/          demo script, SIS contract, architecture diagrams
```

| File | Role |
|---|---|
| `app/pqc.py` | ML-KEM-768 keygen / encapsulation / HKDF derivation |
| `app/identity.py` | ML-DSA-65 keys, signed transcripts, enrolment registry |
| `app/server.py` | Logic solver — handshake, latching trip, heartbeat, operator auth, PIN |
| `app/nodes/actuator.py` | XV-101 and its dead-man watchdog |
| `app/nodes/operator.py` | Signed console — the only path to safety state |
| `app/nodes/device_sim.py` | ESP32 stand-in — runs the real HTTP handshake |
| `app/attacks/attacks.py` | The ten attack stages |
| `firmware/pqc/` | Vendored post-quantum C, ESP32 + host, interop-tested |
| `docs/DEMO.md` | 10-beat demo script |

Run `make` on its own to list every command.

---

## Honest limitations

Found by **attacking the running system**, not by reasoning about it.

**Fixed after testing** ✅

- **Device authentication** — nodes prove identity with ML-DSA-65; a client that
  merely *claims* to be the actuator is refused.
- **Man-in-the-middle** — the server signs the key it offers, so an attacker
  can't substitute their own from the first packet.
- **Unauthenticated safety actions** — removed entirely; the signed operator path
  replaced them.
- **Fail-danger on link loss** — the dead-man heartbeat now closes the valve.
- **Replay** — single-use nonces on both telemetry and commands.
- **The committed device key** — now **generated at runtime** by `make enroll`,
  stored in gitignored `identities/`, never in the source.
- **No dashboard auth** — now a rotating 4-digit operator PIN.
- **Constrained node's crypto** — ML-KEM-768 + ML-DSA-65 now run on the ESP32
  (proven to compile and to interoperate with the server).

**Still open** 🔶

- **On-hardware handshake integration.** The firmware crypto is proven; wiring it
  into the networked telemetry sketch (FreeRTOS task + timing) is the remaining
  work. The runtime PSK is the fallback until then.
- **Server signing key at rest.** `identities/` is mode 0600 and gitignored, but
  a real deployment puts the ML-DSA key in an **HSM or secure element** — not yet
  wired.
- **Attack 1's quantum step is cited, not simulated** — it factors a deliberately
  small RSA modulus so the classical break completes in milliseconds.

---

## Built with

Python 3.14 · Flask · Flask-SocketIO ·
[`kyber-py`](https://pypi.org/project/kyber-py/) ·
[`dilithium-py`](https://pypi.org/project/dilithium-py/) · `cryptography` ·
[PQClean](https://github.com/PQClean/PQClean) (ESP32) · Chart.js · ESP32/mbedtls
