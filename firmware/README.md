# ESP32 hardware leg — TT-101, the BPCS transmitter

## Why this board is not the safety transmitter

The ESP32 is **TT-101, the basic process control system transmitter**. It reads
the process temperature, seals it with AES-256-GCM, and posts it. The server
displays it, logs it, and stores it in the audit trail — and it can never trip
the plant. The server marks this leg `safety_relevant: false` on purpose.

The reason is the key. Every Python node negotiates a fresh session key with
ML-KEM-768 and proves who it is with ML-DSA-65, so the server knows a specific
enrolled identity produced that reading. This board does neither. It holds
`DEVICE_PSK`, a 32-byte key **generated at runtime by `make enroll`** (never
committed) and provisioned into
`app/config.py` and `sketch.ino`. Anyone who can read the repo can seal a
packet that this leg would accept.

A valid GCM tag under a shared, committed key proves the packet was not
tampered with in transit. It does not prove **who sent it**, and it gives no
forward secrecy — one leak retroactively opens every packet ever sent. A safety
instrumented function cannot be armed by a sender you cannot identify, so the
trip decision runs only on telemetry from a node that completed the
authenticated handshake, and XV-101 is driven only by the actuator node, which
obeys nothing that is not sealed under its own session key.

Keeping ML-KEM off the microcontroller is the accepted trade-off. Being honest
about what that costs — and putting this leg outside the safety path because of
it — is the point of the split.

## On-hardware post-quantum handshake — status and roadmap

The **simulator** (`app/nodes/device_sim.py`) already runs the full ML-KEM-768 +
ML-DSA-65 handshake over HTTP and becomes a full safety transmitter with a
per-connection key — no pre-shared key. That is the verifiable proof the
constrained leg *can* be a real post-quantum node.

Porting that handshake onto the ESP32 firmware is a genuine sub-project. It was
scoped empirically, not hand-waved, and these are the concrete blockers found:

- **No ML-KEM-768 Arduino library exists.** The Library Manager has only
  `PQCMicro` (ML-KEM-512 / ML-DSA-44). ML-KEM-768 would have to be vendored from
  PQClean into the sketch.
- **The ML-DSA-65 library does not link under Arduino.** `mldsa` (NeuraiProject)
  provides ML-DSA-65 for ESP32, but it is a CMake *unity-build* design: compiled
  flat by `arduino-cli` it leaves `PQCP_MLDSA_NATIVE_*` symbols undefined at link
  time. It needs a precompiled `.a` or real build-system integration.
- **Stack.** ML-DSA-65 signing needs ~45 KB of working memory; on ESP32 that is a
  dedicated FreeRTOS task with a 64 KB stack, not the default 8 KB.
- **Flash.** This sketch is already at 78% of program flash. ML-KEM-768 +
  ML-DSA-65 code has to fit in what remains, or move to a board with more.
- **Interop.** The C implementations must produce byte-identical results to
  `kyber-py` and `dilithium-py` on the server. That has to be proven against
  shared known-answer vectors on the bench before it is trusted.

Until those are closed, the firmware seals telemetry with the provisioned
`DEVICE_PSK` and the server keeps that leg off the safety lane. The protocol
itself is done and tested; the microcontroller port is the remaining work.

## Build status

Both sensor paths compile clean against **ESP32 Arduino core 3.3.11**, with
`--warnings all` and zero warnings from `sketch.ino`.

Default build (`SIM_DHT22_STANDIN 0`, `USE_TLS 0`) — MAX6675, real hardware:

```
Sketch uses 1031560 bytes (78%) of program storage space. Maximum is 1310720 bytes.
Global variables use 48592 bytes (14%) of dynamic memory, leaving 279088 bytes.
```

Wokwi stand-in build (`SIM_DHT22_STANDIN 1`):

```
Sketch uses 1029108 bytes (78%) of program storage space. Maximum is 1310720 bytes.
Global variables use 48520 bytes (14%) of dynamic memory, leaving 279160 bytes.
```

Reproduce it yourself:

```bash
make firmware-setup   # once — arduino-cli, the ESP32 core, and both libraries
make firmware
```

`firmware-setup` installs `MAX6675` (RobTillaart) and `DHT sensor library for
ESPx`. Both have empty `depends=` lines, so a clean machine fetches exactly two
libraries and nothing else.

Adafruit's `MAX6675 library` was the obvious first choice and is the wrong one
here: it declares `LiquidCrystal` as a dependency for its bundled examples, so
every build — including every cold Wokwi build — fetched an LCD driver this
sketch never includes. RobTillaart's costs 3008 bytes more flash (1031560 vs
1028552) and is worth it, because on a 78%-full image three kilobytes is noise
and a spurious dependency on every build is not.

The two APIs are not interchangeable. Adafruit's constructor is
`(clock, select, miso)`; RobTillaart's is `(select, miso, clock)`, and its
`read()` returns a status byte rather than folding a fault into the temperature.
Swapping back without reversing those three pins would read a dead bus and
publish a plausible constant — the worst failure mode a transmitter has.

If Wokwi refuses to run this, the problem is Wokwi, not the firmware.

### On `USE_TLS`

It saves nothing. `HTTPClient.h` drags `WiFiClientSecure` and the whole mbedtls
TLS stack into the image whether the switch is 0 or 1 — measured on this sketch
at **1031560 B with `USE_TLS 0`** against **1032116 B with `USE_TLS 1`**, 556
bytes apart. Choose it on reachability (the free-Wokwi tunnel is https-only),
never on size. The only real size win is dropping `HTTPClient` for a raw
`WiFiClient` and hand-rolling the request: that measured **890316 B**.

## The sensor: MAX6675, and the Wokwi stand-in

Real TT-101 is a **MAX6675 K-type thermocouple amplifier** on SPI. A
thermocouple is what a process plant actually puts in a hot line, and its open-
circuit fault bit gives a real sensor-failure path — the library returns `NAN`
and the sketch refuses to publish, because a burnt-out probe must never be
reported as 0 °C.

**Wokwi has no MAX6675 part.** The stock catalogue has no thermocouple at all;
the MAX6675 projects you find on wokwi.com ship a community *custom chip*
(`chip-max6675`), which needs its own `chip.json` and wasm binary in the
project. Rather than vendor that, `diagram.json` keeps a **DHT22 as a visual
stand-in** for TT-101, and the sketch has a switch:

```c
#define SIM_DHT22_STANDIN 0   // 0 = MAX6675 (real hardware), 1 = DHT22 (Wokwi)
```

Set it to `1` before running the Wokwi simulation, so you can drag the sensor's
temperature past the setpoint and watch the reading flow through. Leave it at
`0` for real hardware. The sealed payload is byte-for-byte the same shape either
way.

## Wiring

| ESP32 pin | Component | Role |
|---|---|---|
| 3V3 / GND | MAX6675 VCC / GND | thermocouple amplifier power |
| GPIO 18 | MAX6675 SCK | SPI clock |
| GPIO 19 | MAX6675 SO | SPI data out (read-only device, no MOSI) |
| GPIO 5 | MAX6675 CS | chip select |
| GPIO 4 | Slide switch to GND | **BYPASS REQ** — `INPUT_PULLUP`, LOW = asserted |
| VIN / GND / GPIO 26 | Relay module VCC / GND / IN | **RUNNING** local lamp |
| GPIO 27 → 220Ω → LED anode | LED (cathode to GND) | **TRIPPED** local lamp |
| 3V3 / GND / GPIO 15 | DHT22 | Wokwi stand-in only, `SIM_DHT22_STANDIN 1` |

`diagram.json` contains the switch, both lamps and the DHT22 stand-in. The
MAX6675 is not in it, for the reason above.

### The bypass switch is a request, not an authorisation

The board reads the switch and reports `bypass_request` in the sealed payload.
That is all it does. It never bypasses anything locally. Per the SIS contract a
maintenance bypass is an **operator-authenticated server action**, signed with
ML-DSA-65 against an enrolled operator identity and checked for replay. A
switch on a transmitter housing is an operator asking for a bypass; granting it
is the server's decision.

### Both outputs are local indication only

This board does **not** drive XV-101 and has no path to it. The shutdown valve
is driven by the actuator node, which only executes commands sealed under its
own ML-KEM session key. The relay and the LED mirror the `trip_state` and
`valve` the server reported, so a fitter standing at the transmitter sees the
same state as the control room — without this board being able to cause it.

---

## Which route to take

The simulated ESP32 needs to reach your Flask server. How depends on your account:

| | Free Wokwi | Wokwi Club (paid) |
|---|---|---|
| Route | Public gateway + a tunnel | Private gateway (`wokwigw`) |
| Server URL | your `https://…` tunnel address | `http://host.wokwi.internal:5001` |
| Extra software | `cloudflared` or `ngrok` | `wokwigw` |

**The private gateway is a paid feature.** On a free account
`host.wokwi.internal` will not resolve, so use Route A.

---

## Route A — free account (tunnel + public gateway)

**1. Start the server.** It already binds `0.0.0.0`, so it accepts outside traffic.

```bash
make server
```

**2. Open a tunnel** in a second terminal. Cloudflared needs no signup:

```bash
brew install cloudflared
cloudflared tunnel --url http://localhost:5001
```

It prints a URL like `https://random-words-here.trycloudflare.com`. Keep this
terminal open — closing it kills the tunnel and the URL changes each run.

**3. Create the Wokwi project.** Go to [wokwi.com](https://wokwi.com) → New Project
→ **ESP32 (Arduino / C++)**. Check the tab bar shows `sketch.ino` and NOT
`main.py` — a `main.py` tab means you picked the MicroPython template, which
ignores `sketch.ino` entirely and will simply never run your code.

**4. Paste the files:**
- `sketch/sketch.ino` → the sketch tab
- `diagram.json` → the diagram tab (click the tab, paste over everything)
- `libraries.txt` → the libraries tab

**5. Switch to the stand-in sensor and set your URL.** In `sketch.ino`:

```c
#define SIM_DHT22_STANDIN 1
#define USE_TLS 1
static const char *TELEMETRY_URL = "https://random-words-here.trycloudflare.com/telemetry";
```

**6. Press play.** The serial monitor should show:

```
[BOOT] SIS-01 BPCS transmitter TT-101
[BOOT] Sensor: DHT22 stand-in (Wokwi)
[BOOT] Not on the safety path: PSK-sealed, reported only.
[NODE] Connecting to WiFi....
[NODE] Online as 10.13.37.2
[NODE] Sealed 72.00C (bypass req clear) -> accepted (setpoint 80.0C, HEALTHY, XV-101 OPEN)
```

**7. Watch the dashboard** at <http://127.0.0.1:5001>. Every POST logs a green
`[SERVER/BPCS] Decrypted telemetry from ESP32 node (BPCS)` line.

**8. Drive the demo.** Click the stand-in sensor in the Wokwi canvas and drag
its temperature above the setpoint. The dashboard shows the reading and flags it
over-setpoint — and the plant does **not** trip, because this leg is not on the
safety path. Flip the BYPASS REQ switch and the request is reported, and
likewise ignored. To actually trip the plant, drive the Python sensor node.

That "nothing happened" is the demonstration, not a bug.

---

## Route B — Wokwi Club (private gateway)

Same steps, except:

1. Install and run the gateway (leave it open):
   ```bash
   go install github.com/wokwi/wokwigw@latest
   wokwigw
   ```
2. Set `TELEMETRY_URL` to `http://host.wokwi.internal:5001/telemetry` and `USE_TLS 0`
3. No tunnel needed.

---

## Real hardware

Same sketch, `SIM_DHT22_STANDIN` left at `0`. Three edits:

- `WIFI_SSID` / `WIFI_PASS` → your network (drop the trailing `, 6` channel argument)
- `TELEMETRY_URL` → your machine's LAN IP, e.g. `http://192.168.1.7:5001/telemetry`
- Nothing else changes — the crypto path is identical

Parts: ESP32 DevKit v1, MAX6675 breakout, K-type thermocouple probe, slide
switch, 1-channel 5V relay module, LED, 220Ω resistor. Flash from Arduino IDE
(board: **ESP32 Dev Module**) or PlatformIO.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `POST failed, HTTP -1` | Tunnel died, or wrong URL. Re-check the cloudflared output. |
| `POST failed, HTTP 400` | Server rejected the packet — `DEVICE_PSK` mismatch — run `make enroll`, copy the printed hex into `sketch.ino`. |
| `POST failed, HTTP 409` | Replay blocked. The server already accepted that nonce. |
| `TT-101 fault: open thermocouple` | Probe not connected, or MAX6675 miswired on GPIO 18/19/5. In Wokwi this is expected — set `SIM_DHT22_STANDIN 1`. |
| `DHT22 stand-in read failed` | Stand-in not wired to GPIO 15 in the diagram. |
| Trip state never changes | Correct. This leg cannot trip the plant. Use the Python sensor node. |
| `host.wokwi.internal` unreachable | You are on a free account — use Route A. |

## If you change the key

`DEVICE_PSK` is generated by `make enroll`, stored in the gitignored
`identities/device.psk`, and printed as hex. Paste those 32 bytes into
`sketch.ino`. The server reads the file; the board must be flashed with the same
value. They must match byte for byte or every packet is rejected with an `InvalidTag`. That duplication is
the cost of the board not running its own handshake, and the reason this leg is
BPCS rather than safety.
