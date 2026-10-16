# AirTell

### Exposing the digital body language of Bluetooth Low Energy.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)]()

Modern mobile operating systems treat Bluetooth Low Energy (BLE) privacy as an address-randomization problem. It isn't. Across advertising intervals, scan request timings, and proprietary payload structures, devices broadcast a continuous, identifiable "body language" long before a connection is ever established.

Standard single-dongle sniffers periodically hop across advertising channels (37, 38, and 39), leaving predictable blind spots during channel transitions. **AirTell** eliminates this blindness. Built on top of [NCC Group's Sniffle](https://github.com/nccgroup/Sniffle) firmware, AirTell orchestrates multiple CC2652-based radio dongles over UART or an in-memory virtual radio bus. It pairs active stimulators with synchronized passive observers to evaluate, benchmark, and expose the BLE tracking mechanisms documented across [Privacy Enhancing Technologies Symposium (PETS)](https://petsymposium.org/) research.

A public Google Notebook containing architectural notes, research references, and packet dissection logs is available at [Google NotebookLM](https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6).

---

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Operational Topologies](#operational-topologies)
  - [Topology A: Stimulator + Observer](#topology-a-stimulator--observer)
  - [Topology B: Dual-Channel Passive Observer](#topology-b-dual-channel-passive-observer)
  - [Topology C: Master / Slave Link Layer Traffic Relay](#topology-c-master--slave-link-layer-traffic-relay)
- [Hardware Requirements](#hardware-requirements)
  - [Supported Dongles & Bridge Limits](#supported-dongles--bridge-limits)
  - [Port Auto-Discovery & In-Use Verification](#port-auto-discovery--in-use-verification)
- [Centralized Documentation](#centralized-documentation)
- [Mock Simulation & Offline Harness](#mock-simulation--offline-harness)
- [Wire Protocol & Line Framing](#wire-protocol--line-framing)
- [Installation & Quick Start](#installation--quick-start)
- [Running Tests](#running-tests)
- [Project Layout](#project-layout)

---

## Architecture Overview

The testbed coordinates two Sniffle radio dongles over UART or an in-memory virtual radio bus:

```
                        ┌───────────────────────────┐
                        │   Testbed Orchestration   │
                        │   (Topology A / B / CLI)  │
                        └──────┬─────────────┬──────┘
                               │             │
                    ┌──────────┴───┐     ┌───┴────────────┐
                    │ Device 1 Ctrl│     │ Device 2 Ctrl  │
                    └────────┬─────┘     └───┬────────────┘
                             │               │
               ┌─────────────┴─────┐     ┌─────┴─────────────┐
               │  SerialPort /     │     │  SerialPort /     │
               │  MockSerial (Dev1)│     │  MockSerial (Dev2)│
               └─────────────┬─────┘     └─────┬─────────────┘
                             │               │
                        ▲    ▼               ▲    ▼
               ╔════════════════════════════════════════════╗
               ║   Physical BLE Air / VirtualRadioBus       ║
               ║   (Channels 37, 38, 39, 1 us Timestamps)   ║
               ╚════════════════════════════════════════════╝
```

Key subsystems include:
1. **`protocol`**:
   - `wire`: Base64+CRLF line framing with word-count prefix, command opcodes, and binary message parsing (`PacketMessage`, `MarkerMessage`, `StateMessage`, `MeasurementMessage`).
   - `mac`: Synthetic palindromic MAC address generator ensuring endianness invariance ($B_0 \dots B_5 = B_5 \dots B_0$) across LE radio bytes and network logs, with full support for Static Random, NRPA, RPA, and Public address types.
   - `beacons`: Standardized bit-for-bit AD encoders for Apple iBeacon, AltBeacon, Google Eddystone (UID, URL, TLM), and Google/Apple Exposure Notification (GAEN `0xFD6F`).
   - `probing`: Active probe constructors (`SCAN_REQ`) and response frames (`SCAN_RSP`) eliciting Complete Local Names and service UUIDs.
2. **`device`**:
   - `serial_port`: Hardware autodetection (Sonoff Zigbee Dongle Plus, TI XDS110, CatSniffer), non-conflicting dual port allocation, CP2102 baud rate capping (921,600 baud), and serial synchronization (`mark_and_flush`).
   - `mock`: In-memory `MockSerialInterface` and `VirtualRadioBus` for deterministic, offline testing without hardware dongles.
   - `controller`: High-level controller (`SniffleDeviceController`) managing advertising injection, active scanning, passive sniffing, and queued packet retrieval.
3. **`topology`**:
   - `topology_a`: Stimulator (Device 1) broadcasts synthesized beacons or burst sequences while Observer (Device 2) captures over-the-air packets.
   - `topology_b`: Dual-Channel Passive Observer locking Device 1 to Ch 37 and Device 2 to Ch 38, merging captures into a single timestamp-ordered stream to eliminate channel-hop blindness.
   - `lifecycle`: Graceful shutdown coordinator handling `SIGINT`/`SIGTERM`, safely terminating reader threads, and releasing serial ports.

---

## Operational Topologies

### Topology A: Stimulator + Observer
- **Device 1 (Stimulator)**: Configured as an active transmitter broadcasting parameterized beacon profiles (e.g., iBeacon, AltBeacon, Eddystone, GAEN) or replaying recorded advertisement sequences with custom transmission intervals (20 ms to 1000 ms) and palindromic MAC addresses.
- **Device 2 (Observer)**: Concurrently sniffs primary advertising channels (37, 38, 39) to capture peripheral advertisements, mobile device scan requests (`SCAN_REQ`), and connection attempts elicited by the stimulator.

### Topology B: Dual-Channel Passive Observer
Standard single-dongle sniffers periodically hop across channels 37, 38, and 39, causing blind spots during channel transitions. Topology B coordinates two devices simultaneously locked to fixed primary advertising channels:
- **Device 1**: Locked to Channel 37 (`hop3=False`).
- **Device 2**: Locked to Channel 38 (`hop3=False`) or Channel 39.
Captured packets from both dongles are merged in real time into a strictly timestamp-ordered queue, providing continuous multi-channel visibility.

### Topology C: Master / Slave Link Layer Traffic Relay
Sniffle performs [link-layer relaying](https://hardwear.io/netherlands-2022/presentation/bluetooth-LE-link-layer-relay-attacks.pdf) of Bluetooth LE traffic:
- **Device 1 (`/dev/ttyUSB0`)**: Acts as BLE central using `relay_master.py` positioned near genuine peripheral. Captures peripheral advertisements and binds TCP socket 7352 on `0.0.0.0`.
- **Device 2 (`/dev/ttyUSB1`)**: Acts as BLE peripheral using `relay_slave.py` positioned near genuine central. Clones advertising payload, accepts connections, and tunnels link-layer packets bidirectionally over TCP.
- See [`docs/relay_specifications.md`](docs/relay_specifications.md) for complete specifications, timing parameters, and security advisories.

---

## Hardware Requirements

### Supported Dongles & Bridge Limits
- **Sonoff Zigbee 3.0 USB Dongle Plus** (TI CC2652P, USB VID: `0x10C4`, PID: `0xEA60`).
  - *Note*: Older Sonoff dongles use Silicon Labs CP2102 (non-N) bridge chips limited to **921,600 baud**. The framework automatically caps the baud rate to 921,600 baud when CP2102 bridges are detected. Newer CP2102N revisions operate at **2,000,000 baud**.
- **Texas Instruments CC26x2 LaunchPad** (CC2652R / CC2652RB / CC1352P with XDS110 Debug Probe, VID: `0x0451`, PID: `0xBEF3`). Default: **2,000,000 baud**.
- **Electronic Cats CatSniffer V3** (VID: `0x2E8A`, PID: `0x00C0`).

### Port Auto-Discovery & In-Use Verification
The `discover_sniffle_ports()` and `allocate_dual_ports()` utilities automatically scan available serial interfaces, match hardware descriptors, and assign two distinct ports (`port1 != port2`) to Device 1 and Device 2 without manual configuration.

**Device Usage Validation (`lsof`):**
To determine at all times whether a Sniffle device is open and being used:
```bash
lsof /dev/ttyUSB0  # Return code 0 = OPEN and IN USE; Non-zero = IDLE / NOT OPEN
lsof /dev/ttyUSB1
```
The application checks this status continuously via `airtell.device.serial_port.check_device_usage()`, displaying real-time telemetry badges in the top app bar, sidebar, and radio controls view. See [`docs/device_status.md`](docs/device_status.md).

---

## Centralized Documentation

Full technical documentation is centralized in [`docs/`](docs/):
- [**Documentation Index**](docs/index.md): Central navigation hub.
- [**Link Layer Traffic Relay Specifications**](docs/relay_specifications.md): Master/Slave topology on USB0/USB1.
- [**Device Status & LSOF Validation**](docs/device_status.md): In-use determination mechanics.
- [**Scripts Directory Reference**](docs/scripts_reference.md): Complete guide to all scripts in `scripts/`.
- [**Sniffle CLI Operations Guide (HOWTO)**](docs/howto.md): Advanced operational scenarios.
- [**Apple AirDrop Analysis**](docs/airdrop.md): Byte-level Continuity protocol dissection.
- [**Crackle PCAP Analysis**](docs/crackle_pcap_analysis.md): Long-term device tracking across RPAs.
- [**Filtering BLE JSON with JQ**](docs/json_jq.md): Recipes for structured log processing.
- [**TShark & PCAP Dissection**](docs/tshark.md): Native vs. extcap capture guide.
- [**Hardware Setup & Flashing**](docs/hardware_setup.md): Bootloader flashing and configuration.

---

## Mock Simulation & Offline Harness

The testbed includes a full in-memory simulation subsystem:
- **`MockSerialInterface`**: Emulates PySerial `Serial` operations (`read`, `readline`, `write`, `cancel_read`, `close`, `in_waiting`) in pure Python with thread-safe non-blocking buffers.
- **`VirtualRadioBus`**: Routes link-layer packets between simulated dongles. When Device 1 transmits an advertisement (`COMMAND_ADVERTISE`), the bus wraps the payload into a standard `PacketMessage` with microsecond timestamps, RF channel, RSSI (-60 dBm), and valid CRC, delivering it to any listening device locked to that channel.
- Enables 100% automated test coverage in CI/CD environments without physical hardware dongles.

---

## Wire Protocol & Line Framing

Sniffle communicates over UART using **Base64 ASCII records** terminated by `\r\n`:

```
Host to Dongle:
  b0 = (len(cmd_bytes) + 3) // 3
  wire_line = base64_encode(bytes([b0, *cmd_bytes])) + "\r\n"

Dongle to Host:
  data = base64_decode(raw_line)
  word_cnt = data[0]
  msg_type = data[1]
  msg_body = data[2:]
```

### PacketMessage Header Format (Message Type `0x10`)
Packets received by the radio unpack a 10-byte header:
- `ts` (4 bytes, uint32 LE): Microsecond timestamp ($1\ \mu\text{s}$ resolution).
- `l` (2 bytes, uint16 LE): Flags bitfield:
  - Bit 15: Direction (`0` = Central -> Peripheral, `1` = Peripheral -> Central).
  - Bit 14: CRC Error flag (`1` = CRC error, `0` = Valid CRC).
  - Bits 13..0: Link Layer PDU length in bytes.
- `event` (2 bytes, uint16 LE): Connection event counter.
- `rssi` (1 byte, signed int8): Signal strength in dBm (-128 to 0 dBm).
- `chan` (1 byte, uint8): Bits 5..0 = RF channel (0–39); Bits 7..6 = PHY mode (0=1M, 1=2M, 2=Coded S8, 3=Coded S2).
- Followed by the raw Link Layer PDU body.

---

## Installation & Quick Start

```bash
# Clone the repository
git clone https://github.com/example/airtell.git
cd airtell

# Install in editable mode with development dependencies
pip install -e .[test]
```

---

## Running Tests

Execute the automated test suite with strict warning trapping:

```bash
# Run all unit tests
pytest -v -W error tests/

# Run with coverage report
pytest --cov=airtell --cov-report=term-missing tests/

# Run linter
ruff check src tests
```

---

## Project Layout

```
airtell/
├── README.md
├── pyproject.toml
├── app/                        # Material Design v3 Tactical Streamlit Dashboard
│   ├── components/             # Navigation rail, top app bar, PWA assets
│   ├── views/                  # Telemetry, RSSI trends, alerts, radio controls
│   └── streamlit_app.py        # Dashboard application entrypoint
├── docs/                       # Centralized documentation hub
│   ├── index.md                # Documentation navigation index
│   ├── relay_specifications.md # Master/Slave link layer relay specification
│   ├── device_status.md        # Device in-use validation via lsof
│   ├── scripts_reference.md    # Comprehensive scripts directory guide
│   ├── howto.md                # Sniffle CLI operations guide
│   ├── airdrop.md              # Apple AirDrop advertisement dissection
│   ├── crackle_pcap_analysis.md # Crackle analysis & longitudinal tracking
│   ├── json_jq.md              # Parsing Wireshark JSON with JQ
│   ├── tshark.md               # TShark & PCAP dissection guide
│   └── hardware_setup.md       # Hardware flashing & multi-dongle guide
├── scripts/                    # Standalone CLI tools, relays, & decoders
│   ├── advertiser.py           # Connectable peripheral emulator
│   ├── ble_antistalking_tracker.py # SQLite logger & heuristic alert dispatcher
│   ├── ble_parser.py           # Standalone offline finding key parser
│   ├── crackle                 # BLE encryption cracking ELF binary
│   ├── initiator.py            # Active central connection tester
│   ├── pcap_decoder.py         # Offline PCAP AD structure parser
│   ├── radar_tomography.py     # 2D radio tomographic sensing engine
│   ├── relay_master.py         # Central relay forwarder (TCP 7352)
│   ├── relay_slave.py          # Peripheral relay emulator
│   ├── reset.py                # Firmware reset utility
│   ├── scanner.py              # Active discovery scanner & RSSI aggregator
│   ├── sniff_receiver.py       # Core packet sniffer & connection follower
│   ├── sniffle_extcap.py       # Wireshark extcap live capture plugin
│   ├── uart_test.py            # Serial round-trip latency benchmark
│   └── version_check.py        # Firmware version & API validator
├── src/
│   ├── airtell/                # Modular testbed framework (`import airtell`)
│   │   ├── adversarial/        # Deanonymizer, relay bridge, rogue beacons
│   │   ├── device/             # Serial port lifecycle, lsof check, mock bus
│   │   ├── extcap/             # Asynchronous Tshark runner & stream parser
│   │   ├── protocol/           # Wire protocol, beacons, probing, MAC generator
│   │   └── topology/           # Topologies A & B, graceful shutdown
│   └── sniffle/                # Embedded Sniffle C firmware & CLI library
└── tests/                      # Unit, integration, and E2E test suites
```

