# One command per terminal. Run everything from the repo root.
PY := .venv/bin/python

.PHONY: help install certs server sensor actuator device attack broker \
        server-mqtt sensor-mqtt actuator-mqtt test clean

help:
	@echo "Setup:"
	@echo "  make install        install dependencies"
	@echo "  make certs          generate TLS certificates (once, for MQTT)"
	@echo ""
	@echo "Run the demo (one per terminal):"
	@echo "  make server         central server + dashboard on :5001"
	@echo "  make sensor         thermometer node"
	@echo "  make actuator       fan node"
	@echo "  make device         ESP32 stand-in (no hardware needed)"
	@echo "  make sensor-legacy  classical RSA node — attack 1 breaks this one"
	@echo "  make attack         run the full attack sequence"
	@echo ""
	@echo "MQTT over TLS 1.3 instead of WebSocket:"
	@echo "  make broker         then server-mqtt / sensor-mqtt / actuator-mqtt"
	@echo ""
	@echo "  make test           run the test suite"

install:
	$(PY) -m pip install -r requirements.txt

certs:
	./scripts/make_certs.sh

server:
	$(PY) -m app.server

sensor:
	$(PY) -m app.nodes.sensor

sensor-legacy:      ## classical RSA channel, so attack 1 has something to break
	$(PY) -m app.nodes.sensor --legacy

actuator:
	$(PY) -m app.nodes.actuator

device:
	$(PY) -m app.nodes.device_sim

attack:
	$(PY) -m app.attacks.attack

broker:
	$(PY) -m app.transport.broker

server-mqtt:
	$(PY) -m app.server --mqtt

sensor-mqtt:
	$(PY) -m app.nodes.sensor --transport mqtt

actuator-mqtt:
	$(PY) -m app.nodes.actuator --transport mqtt

test:
	$(PY) -m tests.test_pqc
	$(PY) -m tests.test_thermostat
	@echo "(test_device_leg needs a running server: make server, then make test-device)"

test-device:
	$(PY) -m tests.test_device_leg

clean:
	find . -path ./.venv -prune -o -name __pycache__ -type d -print0 | xargs -0 rm -rf
