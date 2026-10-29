# SIS-01 mini plant — build guide

A tabletop process plant that shows every property the project claims, with
real water, a real valve and a real trip. The story: a pump feeds a reactor
vessel. If the reactor overheats, the safety function cuts the feed. That
means XV-101 closes and P-101 stops.

```
                 ┌───────────── TT-101 (K-type probe, in V-101)
                 │                    │ MAX6675 → ESP32
                 ▼                    │ ML-KEM-768 + ML-DSA-65 over WiFi
   ┌──────────────────────────┐       ▼
   │ T-100 reservoir (clear)  │   make server  (logic solver, dashboard)
   │                          │       │ TRIP sealed under actuator session key
   │  ┌─────┐       ┌──────┐  │       ▼
   │  │V-101│◄──────│XV-101│◄─┼── make actuator ── USB ── Nano/Uno ── relay
   │  │ jar │ feed  │valve │  │                                  CH1 │ CH2
   │  └──┬──┘       └──▲───┘  │                                      │
   │     │ overflow    │      │                         XV-101 ◄─────┘
   │     ▼             │      │                         P-101  ◄───────
   │  water      P-101 pump ──┘
   └──────────────────────────┘
```

- **T-100** is the reservoir. **P-101** sits submerged in it and pumps water up
  through **XV-101** into **V-101**, a small jar standing inside T-100.
- V-101 overflows back into T-100, so the loop runs indefinitely.
- **TT-101** sits in V-101. To create the "runaway", pour kettle water into
  V-101.

## Which sensor the code reads

`firmware/sketch_pqc/sketch_pqc.ino` is the ESP32 safety transmitter. The line
`#define TT101_MAX6675` near the top picks its sensor:

| Value | Sensor | Pins |
|---|---|---|
| `1` (default) | MAX6675 + K-type thermocouple | SCK 18, SO 19, CS 5 |
| `0` | DHT22, for the bench before the MAX6675 arrives | data 15 |

Use the MAX6675 for the plant. A DHT22 is not waterproof and stops at 80 °C,
which is exactly the default setpoint, so it can never be dunked in V-101.

## Bill of materials

| # | Item | Spec that matters | Have? |
|---|---|---|---|
| 1 | ESP32 DevKit + USB cable | any 30/38-pin, USB-C or micro | ✅ |
| 2 | Arduino Nano **or** Uno + USB cable | same sketch runs on both | ✅ Uno |
| 3 | Breadboards ×2, jumpers M-M + M-F | | ✅ |
| 4 | MAX6675 module + K-type probe | **stainless sheathed probe** if you can. The M6-screw probe that ships with most kits is fine only if just the metal tip goes in water. Its braided lead wicks water | buy |
| 5 | 12 V solenoid valve | **Normally Closed**, **direct-acting / 0 MPa minimum pressure**, plastic body, barbs that match your tube | ✅ check spec |
| 6 | 12 V DC submersible pump | brushless DC, ~200–300 L/h, **DC not mains**: an aquarium pump with a 230 V plug is the wrong part | buy |
| 7 | Clear tubing ~1.5 m | inner diameter = the pump outlet and valve barbs (usually 8 mm). Zip ties for clamps | buy |
| 8 | **2-channel** 5 V relay module | opto-isolated. One channel for the valve, one for the pump | ✅ if 2-ch, else buy |
| 9 | 12 V DC adapter, **≥ 2 A** | pump ~0.5 A + valve ~0.5 A + headroom | ✅ check rating |
| 10 | DC barrel jack → screw terminal adapter | so you never cut the adapter lead | buy |
| 11 | 1N4007 diodes ×2 | flyback across the valve coil and the pump | buy |
| 12 | LEDs green / yellow / red + 220 Ω ×3 | status lamps on the ESP32 | buy 2 + 2 resistors |
| 13 | T-100: clear plastic box, 2–3 L | wide enough for the pump and V-101 side by side | buy |
| 14 | V-101: small clear jar, ~250 ml | stands inside T-100, lower than its rim | buy |
| 15 | Drip tray or baking tray | the whole plant stands in it | buy |
| 16 | Kettle + mug | heat source for the trip | home |
| 17 | *Optional:* inline flow indicator (impeller window) | makes flow vs. no-flow obvious from the back of a room | nice to have |
| 18 | *Optional:* printed tags T-100, P-101, XV-101, V-101, TT-101 | sells "plant", not "breadboard" | 5 minutes |

**Why the valve spec matters.** Most cheap ½" 12 V valves are pilot-operated.
They need about 0.02 MPa of line pressure to seal, and a small submersible pump
barely makes that. The valve then clicks but water keeps dribbling through, and
your trip looks broken. Buy a **direct-acting, zero-pressure** valve. Before
building, test the one you have: with no power, water from the pump must not
pass.

## Wiring

### ESP32: TT-101 and status lamps

| ESP32 | To |
|---|---|
| 3V3 | MAX6675 VCC |
| GND | MAX6675 GND, all LED cathodes |
| GPIO 18 | MAX6675 SCK |
| GPIO 19 | MAX6675 SO |
| GPIO 5 | MAX6675 CS |
| GPIO 25 → 220 Ω → | green LED anode: **HEALTHY** |
| GPIO 26 → 220 Ω → | yellow LED anode: **FAULT** (no session, server down, probe failed) |
| GPIO 27 → 220 Ω → | red LED anode: **TRIPPED** (stays on until signed reset) |

Power it over USB from the laptop or a power bank. The ESP32 has no wired link
to the Nano: its only path to the valve is through the server and the actuator
node, which is the point of the architecture.

### Nano / Uno: interposing relay for XV-101 and P-101

| Nano/Uno | Relay module |
|---|---|
| 5V | VCC |
| GND | GND |
| D2 | IN1: XV-101 |
| D3 | IN2: P-101 |

USB goes to the Mac running `make actuator`. Upload
`firmware/nano_relay/nano_relay.ino` (board: Arduino Uno or Nano).

### 12 V side: keep it off the breadboard

```
adapter +12V ── barrel terminal + ──┬── relay CH1 COM
                                    └── relay CH2 COM
relay CH1 NO ── XV-101 (+)     XV-101 (−) ── adapter −
relay CH2 NO ── P-101  (+)     P-101  (−) ── adapter −
1N4007 across XV-101: stripe to (+)
1N4007 across P-101:  stripe to (+)
```

- Use **NO** contacts, not NC. A dead Nano, a pulled USB cable or a dead 12 V
  supply then leaves both outputs de-energised, so the valve is spring-closed
  and the pump is off. This fails safe with no code involved.
- 12 V never touches an ESP32 or Nano pin.
- **Relay polarity check:** most cheap relay boards switch on when the input is
  pulled LOW. If the relays click ON at power-up, set `RELAY_ACTIVE_LOW = true`
  in `nano_relay.ino` and re-upload. Change nothing else.

### Physical layout

- Put the electronics on a board **beside** the tray, never above or below the
  water.
- Mount the valve above the waterline, with its outlet tube running down into
  V-101.
- Fill T-100 so the pump is fully covered. Running dry kills it in minutes.

## Fail-safe layers you can show

| Layer | Trigger | What closes XV-101 | Time |
|---|---|---|---|
| Logic solver | TT-101 ≥ setpoint | server → sealed TRIP → actuator | one reading |
| Manual ESD | dashboard ESD button | same path, no signature (tripping is the safe direction) | instant |
| Dead-man heartbeat | server dies, network cut | actuator's own watchdog | 6 s |
| Link watchdog | actuator crashes, USB pulled while powered | Nano on its own | 3 s |
| De-energise to trip | 12 V or Nano power lost | spring in the NC valve | instant |

## Bring-up, in this order

Test each stage on its own before connecting the next. That way a fault is
always in the last thing you added.

1. **12 V only:** jumper the pump straight to 12 V with the tube into V-101.
   Water should flow. Then add the valve unpowered: flow must stop. Power the
   valve: flow resumes.
2. **Relay + Nano:** upload `nano_relay.ino` with no 12 V connected. Open the
   Serial Monitor at 9600 and send `1`: both relays click, then click off again
   3 s later. That is the link watchdog working. Send `0`: they stay off.
3. **Relay + 12 V:** connect the 12 V side and repeat step 2. Water starts,
   then stops by itself 3 s later.
4. **ESP32:** run `make enroll && make firmware-keys` once. Set `WIFI_SSID`,
   `WIFI_PASS` and `SERVER` in `sketch_pqc.ino`, then upload. With
   `make server` running, the Serial Monitor shows
   `[PQC] Session established`, and the yellow LED goes off and green comes on.
5. **Everything:**
   ```bash
   make server                                            # terminal 1
   .venv/bin/pip install pyserial                         # once
   ls /dev/cu.usbmodem* /dev/cu.usbserial*                # find the Nano/Uno
   RELAY_SERIAL_PORT=/dev/cu.usbmodemXXXX make actuator   # terminal 2
   ```
   The relays click and water flows. **Do not run `make sensor`.** The ESP32
   is TT-101 now, and a second simulated transmitter on the safety lane would
   trip the plant on numbers nobody is measuring.

## Demo beats on the hardware

The full narration is in `docs/DEMO.md`. This is what the audience sees on
the table at each beat.

| Beat | You do | Table | Dashboard |
|---|---|---|---|
| Handshake | power the ESP32 | yellow → green | esp32-01 in the PQC table, fingerprints agree |
| Normal running | nothing | water circulating | live TT-101 ≈ room temperature |
| Signed setpoint | `make operator ARGS="setpoint 65"`, then `"setpoint 50"` | nothing moves | setpoint 80 → 65 → 50, green logs |
| Signature is not enough | `make operator ARGS="setpoint 120"` | nothing moves | REFUSED: step > 15 °C, despite a valid signature |
| **Trip** | pour kettle water into V-101 | **red on, relay click, flow stops** | TRIPPED, XV-101 CLOSED |
| Latch | wait for V-101 to cool below 50 °C | flow stays off | still TRIPPED |
| Signed reset | `make operator ARGS=reset` | green on, flow resumes | HEALTHY, XV-101 OPEN |
| Bypass | `make operator ARGS="bypass on"`, pour hot water | flow keeps running, no trip | BYPASS banner, time-boxed |
| Manual ESD | ESD button on dashboard | flow stops | TRIPPED by operator |
| Attacks | `make attack` | **nothing moves** | forged packets rejected in red |
| Cut the network | Ctrl-C the server | flow stops within 6 s, yellow on | — |
| Kill the actuator | Ctrl-C terminal 2 | flow stops within 3 s | — |
| Probe failure | unplug the thermocouple | yellow on, green off | readings stop, never a fake value |

Before the bypass beat, run `make operator ARGS="bypass off"` and `reset` if
the latch is set, so each beat starts from HEALTHY.

## Safety

- 12 V DC only. No mains anywhere near the water.
- Electronics beside the tray, not above or in it.
- Kettle water is about 90 °C. Pour it into V-101 from the side, not over the
  wiring.
- Unplug the 12 V supply before reaching into the tank.
