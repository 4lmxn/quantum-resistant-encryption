# Demo script

A 5-minute walkthrough. No hardware, no simulator, no internet.

## Setup (before the audience arrives)

Four terminals, all with the venv active:

```bash
source .venv/bin/activate
```

| Terminal | Command | Purpose |
|---|---|---|
| 1 | `python server.py` | Central server + dashboard |
| 2 | `python sensor.py` | Sensor node |
| 3 | `python actuator.py` | Fan relay node |
| 4 | *(kept free)* | For the device and attack demos |

Open <http://127.0.0.1:5001> full-screen. That page is the entire demo.

---

## 1. "The key exchange is real" — 60 seconds

Point at the **Post-Quantum Key Establishment** table.

> Each node runs its own ML-KEM-768 handshake. The server generates a fresh
> keypair per connection, so this is not a shared password baked into the code.

What to draw attention to, in order:

- **1184 B public key, 1088 B KEM ciphertext** — the real FIPS 203 parameter sizes
- **The two fingerprints on each row match** — the node and the server each derived the same 256-bit AES key independently. The key itself was never transmitted; those are SHA-256 digests
- **The sensor and actuator rows have *different* fingerprints** — separate keys per link, so breaking one leg gives you nothing on the other

Then, for the strongest point: **stop `sensor.py` (Ctrl-C) and restart it.**
The row disappears and returns with a completely different fingerprint.

> Every connection negotiates a brand new key. Recording today's traffic is
> worthless tomorrow — that is forward secrecy, and it is why the "harvest now,
> decrypt later" attack fails here.

---

## 2. "The control loop works" — 30 seconds

Drag the **threshold slider** below the current temperature.

The log turns yellow with an ALERT, the server seals a `FAN_ON` command under
the actuator's own key, and the relay flips to **ON**.

> The command is encrypted and authenticated. The actuator obeys it only because
> the GCM tag verified.

Press **Manual Relay Override** to show operator control uses the same sealed path.

---

## 3. "Classical crypto dies, lattice crypto does not" — 90 seconds

Threat Simulation Panel, buttons in order.

**Button 1 — Classical RSA Crack (Shor's).** Be honest here:

> This stage is narration. There is no classical ECDH in my system to break —
> it's here for contrast, to show what Shor's algorithm would do to RSA or
> elliptic-curve key exchange.

**Button 2 — Kyber-768 Lattice Test.** This one is real:

> It captures an actual 1184-byte ML-KEM public key off the wire and encapsulates
> against it twice. The two secrets are completely different, which is the point:
> an eavesdropper who records the whole handshake still learns nothing, because
> the secret is never derived from the public key alone.
>
> It reports the Module-LWE search space rather than pretending to solve it.
> Nobody can run BKZ on a 9472-bit lattice in a demo.

**Button 3 — Inject MITM Packet Tamper.** The payoff:

> A forged command is delivered to the actuator. The GCM tag fails, the log turns
> red, and — this is the important part — **the relay does not move.** Tampering
> isn't just detected, it's rejected before a physical actuator acts on it.

---

## 4. "It works on constrained hardware too" — 45 seconds

Terminal 4:

```bash
python device_sim.py
```

> This is the ESP32 leg. A microcontroller can't run the handshake, so it uses a
> provisioned key and posts over plain HTTP. Same AES-256-GCM, same wire format
> as the firmware in `wokwi/sketch.ino`.

Then Ctrl-C and:

```bash
python device_sim.py --forge
```

> Every packet rejected with HTTP 400. Even on the constrained leg, an attacker
> without the key cannot inject a reading.

---

## 5. Tests — 30 seconds

```bash
python test_pqc.py
python test_device_leg.py
```

> Handshake agreement, domain separation between the two links, a fresh key per
> session, and tamper rejection — all asserted, not claimed.

---

## Questions you should expect

**"Is the handshake authenticated?"**
No. It resists eavesdropping, not an active attacker sitting in the middle from
the first packet. Production would add ML-DSA signatures. *(Say this before they
ask — volunteering it reads as understanding, not oversight.)*

**"Why is AES-256 quantum-safe?"**
Grover's algorithm halves the effective key length: 256-bit becomes 128-bit
effective, still far beyond reach. Shor's algorithm is the one that destroys
RSA and ECDH, and it does not apply to symmetric ciphers or to lattices.

**"Why ML-KEM-768 and not 512 or 1024?"**
768 is NIST security category 3, the recommended general-purpose parameter set.

**"Did you implement Kyber yourself?"**
No — `kyber-py`, an implementation of the FIPS 203 standard. Rolling your own
primitive is how you get a broken one.

**"What's still hardcoded?"**
`DEVICE_PSK`, for the constrained node only. It's the trade-off for keeping
ML-KEM off the microcontroller, and it's documented in both places it appears.

---

## If something breaks

| Problem | Fix |
|---|---|
| Port 5001 in use | `pkill -f server.py` |
| Handshake table empty | Nodes not started, or started before the server |
| No FAN_ON firing | Drag the threshold below the current temperature |
| Dashboard blank | Restart `server.py` — templates are cached when debug is off |
