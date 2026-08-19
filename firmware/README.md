# ESP32 hardware leg — step by step

Real DHT22 read, real AES-256-GCM on the ESP32's hardware crypto, real HTTP POST
to the Flask server. The ML-KEM-768 handshake runs on the Python nodes; this
board uses the provisioned `DEVICE_PSK`.

## Wiring

| ESP32 pin | Component |
|---|---|
| 3V3 / GND / GPIO 15 | DHT22 VCC / GND / SDA |
| VIN / GND / GPIO 26 | Relay module VCC / GND / IN |
| GPIO 27 → 220Ω → LED anode | Fan indicator (cathode to GND) |

`diagram.json` already contains this wiring.

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
python server.py
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
- `sketch.ino` → the sketch tab
- `diagram.json` → the diagram tab (click the tab, paste over everything)

There is no `libraries.txt` and nothing to install. The DHT22 is read with its
raw single-wire protocol and every include ships with the ESP32 Arduino core.

**5. Set your URL.** In `sketch.ino`, edit `TELEMETRY_URL` to your tunnel address,
keeping the `/telemetry` path:

```c
static const char *TELEMETRY_URL = "https://random-words-here.trycloudflare.com/telemetry";
```

**6. Press play.** The serial monitor should show:

```
[NODE] Connecting to WiFi....
[NODE] Online as 10.13.37.2
[NODE] Sealed 24.00C / 40.00% -> server accepted
```

**7. Watch the dashboard** at <http://127.0.0.1:5001>. Every POST logs a green
`Decrypted telemetry from ESP32 node` line.

**8. Drive the demo.** Click the DHT22 in the Wokwi canvas and drag its
temperature above 30°C. The relay flips, the LED lights, and the dashboard logs
the threshold alert.

---

## Route B — Wokwi Club (private gateway)

Same steps, except:

1. Install and run the gateway (leave it open):
   ```bash
   go install github.com/wokwi/wokwigw@latest
   wokwigw
   ```
2. Set `TELEMETRY_URL` to `http://host.wokwi.internal:5001/telemetry`
3. No tunnel needed.

---

## Real hardware

Same sketch. Three edits:

- `WIFI_SSID` / `WIFI_PASS` → your network (drop the trailing `, 6` channel argument)
- `TELEMETRY_URL` → your machine's LAN IP, e.g. `http://192.168.1.7:5001/telemetry`
- Nothing else changes — the crypto path is identical

Parts: ESP32 DevKit v1, DHT22, 1-channel 5V relay module, LED, 220Ω resistor.
Flash from Arduino IDE (board: **ESP32 Dev Module**) or PlatformIO.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `POST failed, HTTP -1` | Tunnel died, or wrong URL. Re-check the cloudflared output. |
| `POST failed, HTTP 400` | Server rejected the packet — `DEVICE_PSK` mismatch between `config.py` and `sketch.ino`. |
| `DHT22 error: TIMEOUT` | Wrong pin, or the DHT22 is not wired in the diagram. |
| `DHT22 read failed` | Sensor not wired to GPIO 15 in the diagram. |
| `host.wokwi.internal` unreachable | You are on a free account — use Route A. |

## If you change the key

`DEVICE_PSK` appears twice — `config.py` and `sketch.ino`. They must match byte
for byte or every packet is rejected with an `InvalidTag`. That duplication is
the cost of the board not running its own handshake.
