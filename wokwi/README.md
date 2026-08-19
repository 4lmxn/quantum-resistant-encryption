# ESP32 hardware leg (Wokwi)

Real DHT22 read, real AES-256-GCM on the ESP32's hardware crypto, real HTTP POST
to the Flask server. The ML-KEM handshake stays on the Python nodes; this board
uses the provisioned `DEVICE_PSK`.

## Wiring

| ESP32 | Component |
|---|---|
| 3V3 / GND / GPIO 15 | DHT22 VCC / GND / SDA |
| VIN / GND / GPIO 26 | Relay module VCC / GND / IN |
| GPIO 27 → 220Ω | LED anode (fan indicator), cathode to GND |

## Run it in the browser

1. Start the Python server: `python server.py` (listens on `0.0.0.0:5001`).
2. Install the Wokwi IoT Gateway once — it is what lets the simulated ESP32
   reach your laptop: https://docs.wokwi.com/guides/iot-gateway
3. Run `wokwigw` in a terminal and leave it open.
4. Go to wokwi.com, create a new ESP32 project, and paste in `sketch.ino`,
   `diagram.json`, and `libraries.txt` from this folder.
5. Hit play. Click the DHT22 in the canvas to drag its temperature above 30°C
   and watch the relay flip and the dashboard log the decryption.

Without the gateway the sketch still compiles and runs, but every POST fails
with a connection error — that is expected, not a bug.

## Run it on real hardware

Same sketch. Two edits:

- `WIFI_SSID` / `WIFI_PASS` → your actual network (drop the `, 6` channel arg).
- `TELEMETRY_URL` → your machine's LAN IP, e.g. `http://192.168.1.7:5001/telemetry`.

Parts: ESP32 DevKit v1, DHT22, 1-channel 5V relay module, LED, 220Ω resistor.
Flash with Arduino IDE (board: "ESP32 Dev Module") or PlatformIO.

## If you change the key

`DEVICE_PSK` appears twice — `config.py` and `sketch.ino`. They must match byte
for byte or every packet is rejected with an InvalidTag. This duplication is the
cost of the board not doing its own handshake.
