# SIS-01 demo runbook

Roughly eight minutes. Every line of output below was produced by an actual run,
not written from memory — if yours differs, something is wrong.

The story: a process plant with an emergency shutdown function. TT-101 watches a
vessel, and when it reaches the trip setpoint the safety system closes XV-101.
The 2017 TRITON attack on Schneider Triconex controllers targeted exactly this
kind of system — the one whose only job is preventing people from dying.

## Setup, once

```bash
pip install -r requirements.txt
make enroll          # creates the ML-DSA identities, including operator-01
```

## Terminals

| | Command | What it is |
|---|---|---|
| 1 | `make server` | logic solver + dashboard on <http://127.0.0.1:5001> |
| 2 | `make actuator` | XV-101, the shutdown valve |
| 3 | `make sensor` | TT-101, the safety transmitter |
| 4 | `make device` | ESP32 stand-in on the BPCS lane (optional) |
| 5 | — | spare, for operator commands |

Open the dashboard before starting the nodes so you see the handshakes happen.

---

## Beat 1 — the handshake

Nodes hold no key until this finishes.

```
[PQC] ACTUATOR offer signed with ML-DSA-65 (FIPS 204).
[PQC] ACTUATOR session key established via ML-KEM-768 + HKDF-SHA256.
[PQC] Both sides derived key 09585d9ea8feea44 independently.
```

Point at the **Post-Quantum Key Establishment** table. Both fingerprints match
and neither side ever transmitted key material — they are SHA-256 digests, so
agreement is provable without exposure.

Say: the signature is the part that matters. ML-KEM alone proves nobody is
watching, not who you are talking to.

## Beat 2 — normal operation

Plant idles near 67 °C against an 80 °C setpoint. State `HEALTHY`, XV-101 `OPEN`.

## Beat 3 — the unsigned path is refused

Drag the trip setpoint slider on the dashboard. It snaps back, and the log says:

```
ERROR [SIS] Refused: unsigned setpoint change from the dashboard.
            This is the Oldsmar path — a legitimate control channel
            with nobody proving who used it.
```

Say: in February 2021 an intruder reached the Oldsmar water plant through
legitimate remote access and moved a chemical setpoint from about 100 ppm to
11,100 ppm. No cipher was broken. The control path was real; nobody was proving
who used it. That control still exists on this dashboard, and it now refuses.

## Beat 4 — the signed path works

Terminal 5:

```bash
make operator ARGS="setpoint 75"
```

```
SUCCESS [SIS] Trip setpoint 80.0°C → 75.0°C, signed by operator-01 (ML-DSA-65).
```

## Beat 5 — a valid signature is not enough

```bash
make operator ARGS="setpoint 200"
```

```
ERROR [SIS] Operator command REFUSED: setpoint 200.0°C outside the safe range 40.0–120.0°C
```

```bash
make operator ARGS="setpoint 115"
```

```
ERROR [SIS] Operator command REFUSED: step of 40.0°C exceeds the 15.0°C limit on a single change
```

Say: the signature verified. It was refused anyway. Authentication was never the
whole lesson from Oldsmar — a correctly signed instruction to do something insane
is still insane, so the value is clamped and the size of one step is limited.

## Beat 6 — the trip

Press **ENTER** in terminal 3. The process starts climbing 2.5 °C per reading.

```
t+ 4s  69.6C  HEALTHY
t+ 8s  72.1C  HEALTHY
t+12s  74.6C  HEALTHY
tripped at 77.1C after ~16s

ALERT [SIS] 77.07°C reached setpoint 75.0°C. TRIP latched, closing XV-101.
```

XV-101 goes `CLOSED` on the dashboard.

## Beat 7 — the latch holds

Press **ENTER** again to stop the upset. The plant cools:

```
t+ 4s  74.7C  TRIPPED  valve=CLOSED
t+10s  72.8C  TRIPPED  valve=CLOSED
```

**72.8 °C is below the 75 °C setpoint and it is still tripped.** This is the
behaviour change. The old thermostat would have reset itself here. A safety trip
latches, because the plant cooling down is not evidence that whatever caused the
excursion has been dealt with. Only a person clears it:

```bash
make operator ARGS=reset
```

```
SUCCESS [SIS] Trip reset by operator-01. Reopening XV-101.
```

## Beat 8 — cut the network

With everything healthy, kill terminal 1 (the server) with `Ctrl-C`. Watch
terminal 2:

```
[ACTUATOR] Heartbeat lost for >6.0s. TRIPPING XV-101.
```

Say: the safety decision lives on the node holding the valve, precisely so it
survives the case where the server cannot be reached. Silence means trip. Before
this change, losing the network froze the valve wherever it was — usually open —
which handed an attacker a way to disable the shutdown function by doing nothing
more than cutting a cable.

This mirrors the hardware. XV-101 is a normally-closed solenoid: it is held open
by an energised coil and by nothing else, so pulling its power closes it too.
Both the firmware and the software now fail in the same direction.

## Beat 9 — the BPCS lane cannot trip the plant

Restart the server, then in terminal 5:

```bash
.venv/bin/python - <<'EOF'
import os, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import DEVICE_PSK, SERVER_URL
plaintext = '{"unit": "TT-101", "temperature": 250.00, "humidity": 40.00}'
nonce = os.urandom(12)
sealed = AESGCM(DEVICE_PSK).encrypt(nonce, plaintext.encode(), None)
print(requests.post(f"{SERVER_URL}/telemetry",
      json={"nonce": nonce.hex(), "ciphertext": sealed.hex()}).json())
EOF
```

The dashboard shows 250 °C on an amber hazard-striped card marked
**BPCS — NOT SAFETY RATED**, and the plant does not move.

Say: `DEVICE_PSK` is committed to this repository, so anyone who can read the
source can forge that packet — and I just did. It says 250 °C against a 75 °C
setpoint and it changed nothing, because the ESP32 runs on a provisioned
pre-shared key rather than the ML-KEM handshake, so it is the basic process
control transmitter and is not allowed to reach the safety function. That split
is the containment for the one weak key left in the system.

## Beat 10 — the attacks

Run the three attack stages from the dashboard.

- **Stage 1** breaks the classical RSA channel. Start `make sensor-legacy` first,
  or it has nothing to break.
- **Stage 2** captures a real 1184-byte encapsulation key off the wire and shows
  that encapsulating against it twice gives two unrelated secrets, so replaying
  captured traffic recovers nothing.
- **Stage 3** injects a forged command and the GCM tag rejects it.

The red rejection line is the feature. Never treat it as a bug to be smoothed
over.

## If something misbehaves

| Symptom | Cause |
|---|---|
| Handshake refused, `not enrolled` | run `make enroll` |
| `Address already in use` | an old server is still running — check `lsof -nP -iTCP:5001` |
| Dashboard looks like the old thermostat | the browser or the server is serving a cached template; restart the server and hard-reload |
| Plant never trips | you are not in terminal 3, or stdin is not a TTY — the ENTER watcher only arms on a real terminal |
| Trip fires immediately on start | the upset toggle is still on from a previous run; press ENTER to stop it |
