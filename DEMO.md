# Demo script

A 5-minute walkthrough. No hardware, no simulator, no internet.

## Setup (before the audience arrives)

Four terminals, all with the venv active:

```bash
source .venv/bin/activate
```

| Terminal | Command | Purpose |
|---|---|---|
| 1 | `make server` | Central server + dashboard |
| 2 | `make sensor` | Sensor node |
| 3 | `make actuator` | Fan relay node |
| 4 | *(kept free)* | For the device and attack demos |

Open <http://127.0.0.1:5001> full-screen. That page is the entire demo.

---

## 1. "Why this needs encrypting at all" — 30 seconds

Start at the top strip and the **Wire View**, before any crypto talk.

> This is one telemetry packet, shown twice. On the left is what anyone tapping
> the network captures — 69 bytes indistinguishable from random. On the right is
> what the server recovers, because it is the only party holding the key.
>
> On an unencrypted IoT link the left panel would read exactly like the right
> one. That is the whole problem: telemetry leaks occupancy and process data, and
> the command leg moves physical hardware, so a forged packet opens a valve.

Point out that the nonce changes on every single message — the same reading
encrypts to completely different bytes each time.

---

## 2. "The key exchange is real" — 60 seconds

Point at the **Post-Quantum Key Establishment** table.

> Each node runs its own ML-KEM-768 handshake. The server generates a fresh
> keypair per connection, so this is not a shared password baked into the code.

What to draw attention to, in order:

- **1184 B public key, 1088 B KEM ciphertext** — the real FIPS 203 parameter sizes
- **The two fingerprints on each row match** — the node and the server each derived the same 256-bit AES key independently. The key itself was never transmitted; those are SHA-256 digests
- **The sensor and actuator rows have *different* fingerprints** — separate keys per link, so breaking one leg gives you nothing on the other

Then, for the strongest point: **stop `app/nodes/sensor.py` (Ctrl-C) and restart it.**
The row disappears and returns with a completely different fingerprint.

> Every connection negotiates a brand new key. Recording today's traffic is
> worthless tomorrow — that is forward secrecy, and it is why the "harvest now,
> decrypt later" attack fails here.

---

## 3. "The control loop works" — 30 seconds

Drag the **threshold slider** below the current temperature.

The log turns yellow with an ALERT, the server seals a `FAN_ON` command under
the actuator's own key, and the relay flips to **ON**.

> The command is encrypted and authenticated. The actuator obeys it only because
> the GCM tag verified.

Press **Manual Relay Override** to show operator control uses the same sealed path.

---

## 4. "Every threat in Chapter 1.4, answered" — 2 minutes

The **Quantum Threat Model** table maps one-to-one onto §1.4 of your report.
Walk the rows top to bottom, pressing Run on each.

**Shor's algorithm.** Be honest here:

> This stage is narration. There is no classical ECDH in my system to break —
> it's here for contrast, to show what Shor's algorithm would do to RSA or
> elliptic-curve key exchange.

**Lattice cryptanalysis.** This one is real:

> It captures an actual 1184-byte ML-KEM public key off the wire and encapsulates
> against it twice. The two secrets are completely different, which is the point:
> an eavesdropper who records the whole handshake still learns nothing, because
> the secret is never derived from the public key alone.
>
> It reports the Module-LWE search space rather than pretending to solve it.
> Nobody can run BKZ on a 9472-bit lattice in a demo.

**Harvest now, decrypt later.** The row your abstract leads with:

> Two handshakes, two unrelated keys. Archived traffic cannot be opened by a key
> recovered later, because that key never existed when the traffic was recorded.

**Grover's algorithm.** The symmetric side:

> Grover halves effective key length. AES-128 would drop to 2^64 — genuinely
> weak. This link uses AES-256, so the margin is 2^128. That is exactly why the
> report specifies 256 and not 128.

**MitM / device impersonation.** The payoff:

> A forged command is delivered to the actuator. The GCM tag fails, the log turns
> red, and — this is the important part — **the relay does not move.** Tampering
> isn't just detected, it's rejected before a physical actuator acts on it.

---

## 5. "It works on constrained hardware too" — 45 seconds

Terminal 4:

```bash
make device
```

> This is the ESP32 leg. A microcontroller can't run the handshake, so it uses a
> provisioned key and posts over plain HTTP. Same AES-256-GCM, same wire format
> as the firmware in `firmware/sketch.ino`.

Then Ctrl-C and:

```bash
make device ARGS=--forge
```

> Every packet rejected with HTTP 400. Even on the constrained leg, an attacker
> without the key cannot inject a reading.

---

## 6. Tests — 30 seconds

```bash
make test
make test-device
```

> Handshake agreement, domain separation between the two links, a fresh key per
> session, and tamper rejection — all asserted, not claimed.

---

## 7. "And here is what it does not stop" — 45 seconds

**Do not skip this.** Scroll to the honest-limits panel and walk it yourself.

> Three things get through. Anything can claim to be the fan and receive real
> orders, because nothing proves device identity. An attacker present from the
> very first packet can sit in the middle of the key agreement. And the dashboard
> controls have no login.
>
> All three have the same fix — signed device identities, ML-DSA — which is the
> future work in Chapter 6.
>
> Replay was on that list until we tested for it. A captured packet is now
> accepted exactly once; `test_replayed_device_packet_is_rejected` proves it.

Volunteering this is worth more than any demo. It shows you know where your
threat model ends, which is the difference between a project that works and a
project you understand.

---

## Questions you should expect

**"Is the handshake authenticated?"**
No, and that is the single biggest limitation. It resists eavesdropping, not an
active attacker present from the first packet. ML-DSA signatures are the fix and
are named as future work. *(Say this before they ask.)*

**"Can I replay a captured packet?"**
No. The server records the nonce of every packet it accepts under a given key, so
a captured packet is accepted exactly once. The second copy gets HTTP 409.

**"Could I pretend to be the actuator?"**
Yes. That is a real gap — we tested it. Role is claimed, not proved, so a rogue
client completes a handshake and receives decryptable commands. It needs device
authentication, which is the same ML-DSA work.

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
| Dashboard blank | Restart `app/server.py` — templates are cached when debug is off |
