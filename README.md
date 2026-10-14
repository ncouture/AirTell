# Bluetooth-Sniffle Testbed Framework

A modular Python testbed framework that orchestrates dual Sniffle-enabled radio dongles for active beacon injection, link-layer probing, and multi-channel passive sniffing. Designed to evaluate the Bluetooth Low Energy (BLE) tracking and fingerprinting attack surfaces documented in **PoPETs 2025-0103**: *"Your Signal, Their Data: An Empirical Privacy Analysis of Wireless-scanning SDKs in Android"*.

---

## Table of Contents

* [Key Features](https://www.google.com/search?q=%23key-features)
* [Architecture](https://www.google.com/search?q=%23architecture)
* [Operational Topologies](https://www.google.com/search?q=%23operational-topologies)
* [Topology A: Stimulator + Observer](https://www.google.com/search?q=%23topology-a-stimulator--observer)
* [Topology B: Dual-Channel Passive Observer](https://www.google.com/search?q=%23topology-b-dual-channel-passive-observer)


* [Supported Hardware & Bridge Constraints](https://www.google.com/search?q=%23supported-hardware--bridge-constraints)
* [Wire Protocol & Framing Specification](https://www.google.com/search?q=%23wire-protocol--framing-specification)
* [Installation](https://www.google.com/search?q=%23installation)
* [Quick Start & Usage](https://www.google.com/search?q=%23quick-start--usage)
* [1. Port Auto-Discovery](https://www.google.com/search?q=%231-port-auto-discovery)
* [2. Running Topology A (Stimulate & Observe)](https://www.google.com/search?q=%232-running-topology-a-stimulate--observe)
* [3. Running Topology B (Continuous Multi-Channel Capture)](https://www.google.com/search?q=%233-running-topology-b-continuous-multi-channel-capture)


* [In-Memory Mock Simulation (CI/CD)](https://www.google.com/search?q=%23in-memory-mock-simulation-cicd)
* [Development & Testing](https://www.google.com/search?q=%23development--testing)
* [Project Layout](https://www.google.com/search?q=%23project-layout)
* [Citation](https://www.google.com/search?q=%23citation)

---

## Key Features

* **Eliminate Channel-Hop Blindness:** Merges streams from two dedicated hardware sniffers locked to distinct primary advertising channels (37, 38, or 39), capturing connection requests (`CONNECT_IND`) and scan responses without hop-loss.
* **Endianness-Invariant MAC Generation:** Synthetic palindromic address generators ($B_0..B_5 = B_5..B_0$) guarantee consistent byte-order representations across link-layer radio captures and upper-layer network logs.
* **Bit-for-Bit AD Payload Synthesizers:** Ready-to-inject encoders for Apple iBeacon, AltBeacon, Google Eddystone (UID, URL, TLM), and COVID-19 Exposure Notification (GAEN `0xFD6F`).
* **Hardware-Aware Serial Driver:** Dynamic port auto-discovery with auto-baud negotiation and automatic CP2102 baud-rate clamping to prevent serial buffer overflow.
* **Zero-Hardware CI/CD Testing:** Full virtual radio bus and mock serial harness for deterministic, offline testing of link-layer logic and topologies.

---

## Architecture

The framework controls two hardware radios over high-speed UART or directs simulated frames through an in-memory virtual radio bus:

```
                           ┌───────────────────────────┐
                           │   Testbed Orchestration   │
                           │   (Topology A / B / CLI)  │
                           └──────┬─────────────┬──────┘
                                  │             │
                     ┌────────────┴───┐     ┌───┴────────────┐
                     │ Device 1 Ctrl  │     │ Device 2 Ctrl  │
                     └────────┬───────┘     └───┬────────────┘
                              │                 │
                ┌─────────────┴─────┐     ┌─────┴─────────────┐
                │  SerialPort /     │     │  SerialPort /     │
                │  MockSerial (Dev1)│     │  MockSerial (Dev2)│
                └─────────────┬─────┘     └─────┬─────────────┘
                              │                 │
                      ▲       ▼                 ▲       ▼
                ╔═════════════════════════════════════════════╗
                ║    Physical BLE Air / VirtualRadioBus       ║
                ║    (Channels 37, 38, 39, 1 µs Timestamps)   ║
                ╚═════════════════════════════════════════════╝

```

---

## Operational Topologies

### Topology A: Stimulator + Observer

Evaluates how mobile operating systems and third-party scanning SDKs react to synthesized RF beacons and link-layer probes.

```
 [Device 1: Stimulator]  ──(TX: iBeacon / Eddystone / SCAN_RSP)──▶  [Mobile Device / SDK Target]
                                                                               │ (Scan / Connect)
 [Device 2: Observer]    ◀──(RX: SCAN_REQ / CONNECT_IND on Ch 37/38/39)────────┘

```

* **Device 1 (Stimulator):** Broadcasts configurable advertising profiles with parameterized advertising intervals (20 ms – 1000 ms), rotating or static palindromic MACs, and custom transmit powers.
* **Device 2 (Observer):** Simultaneously monitors primary advertising channels to intercept probe requests (`SCAN_REQ`) and connection negotiations triggered by the stimulus.

### Topology B: Dual-Channel Passive Observer

Standard single-radio sniffers hop between channels 37, 38, and 39, missing up to 66% of transient packets. Topology B locks two radios to separate channels to ensure uninterrupted coverage.

```
 Channel 37 ──────▶ [Device 1 (Ch 37 Lock)] ──┐
                                              ├──▶ [Timestamp-Ordered Real-Time Merge] ──▶ PCAP / Log
 Channel 38 ──────▶ [Device 2 (Ch 38 Lock)] ──┘

```

* **Device 1:** Locked to Channel 37 (`hop3=False`).
* **Device 2:** Locked to Channel 38 or Channel 39 (`hop3=False`).
* **Synchronizer:** Merges incoming packet queues using 1 µs hardware timestamps into a single, strictly chronological output stream.

---

## Supported Hardware & Bridge Constraints

| Hardware Target | MCU / Radio | USB VID:PID | Default Baud | Bridge Quirks & Capping |
| --- | --- | --- | --- | --- |
| **Sonoff Zigbee 3.0 Dongle Plus** | TI CC2652P | `0x10C4:0xEA60` | **921,600** or **2,000,000** | Early models feature CP2102 chips limited to 921,600 baud. The framework automatically detects CP2102 and caps baud rates. CP2102N revisions support 2M baud. |
| **TI CC26x2 LaunchPad** | CC2652R / CC1352P | `0x0451:0xBEF3` | **2,000,000** | XDS110 Application/User UART. Native 2M baud support. |
| **CatSniffer V3** | TI CC1352P + RP2040 | `0x2E8A:0x00C0` | **2,000,000** | Electronic Cats multi-protocol sniffer platform. |

> **Flashing Note:** To install Sniffle on the Sonoff ZBDongle-P, put the board into bootloader mode (hold the internal `BOOT` button while plugging in USB) and flash the CC2652P Sniffle `.hex` firmware using `cc2538-bsl.py`.

---

## Wire Protocol & Framing Specification

Sniffle communicates over UART using Base64-encoded records terminated by standard CRLF (`\r\n`):

$$\text{Wire Line} = \text{Base64}\Big(\big[\text{word\_count}, \text{command\_opcode}, \dots\big]\Big) + \texttt{"\textbackslash r\textbackslash n"}$$

### PacketMessage Header Format (`0x10`)

Every packet captured over the air returns a **10-byte binary header** prior to the raw Link Layer PDU payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      ts (uint32_t, LE)                        |  Microsecond Timestamp
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|D|C|      length (14 bits)     |       event (uint16_t, LE)    |  Flags / PDU Len / Event
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  rssi (int8)  |   chan/phy    |      ... Raw PDU Payload ...  |  Signal / RF Channel & PHY
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

| Field | Type | Offset | Description |
| --- | --- | --- | --- |
| `ts` | `uint32` (LE) | 0..3 | Free-running hardware timer with 1 µs resolution. |
| `flags_len` | `uint16` (LE) | 4..5 | **Bit 15:** Direction (`0` = Central $\to$ Peripheral, `1` = Peripheral $\to$ Central)<br>

<br>**Bit 14:** CRC status (`0` = Valid, `1` = Error)<br>

<br>**Bits 13..0:** Link Layer PDU length (bytes). |
| `event` | `uint16` (LE) | 6..7 | Connection event counter. |
| `rssi` | `int8` | 8 | Received signal strength in dBm (-128 to 0 dBm). |
| `chan_phy` | `uint8` | 9 | **Bits 5..0:** RF Channel index (0–39)<br>

<br>**Bits 7..6:** PHY Mode (`0`=1M, `1`=2M, `2`=Coded S8, `3`=Coded S2). |

---

## Installation

### Prerequisites

* Python 3.10 or higher
* Two compatible USB dongles flashed with NCC Group's Sniffle firmware

```bash
# Clone the repository
git clone https://github.com/ncouture/bluetooth-sniffle.git
cd bluetooth-sniffle

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode with development/test dependencies
pip install -e ".[test]"

```

---

## Quick Start & Usage

### 1. Port Auto-Discovery

Scan and verify connected Sniffle hardware without opening device manager:

```python
from bluetooth_sniffle.device.serial_port import discover_sniffle_ports, allocate_dual_ports

# Discover all connected Sniffle-compatible radios
ports = discover_sniffle_ports()
for p in ports:
    print(f"Found: {p.device} | Description: {p.description} | Max Baud: {p.max_baud}")

# Auto-allocate two distinct ports for Device 1 and Device 2
port_dev1, port_dev2 = allocate_dual_ports()
print(f"Allocated: Dev1={port_dev1.device}, Dev2={port_dev2.device}")

```

### 2. Running Topology A (Stimulate & Observe)

Broadcast synthetic iBeacons with palindromic MACs on Device 1 while sniffing capture metrics on Device 2:

```python
import time
from bluetooth_sniffle.topology.topology_a import TopologyA
from bluetooth_sniffle.protocol.beacons import create_ibeacon_payload
from bluetooth_sniffle.protocol.mac import generate_palindromic_mac, AddressType

# Generate a synthetic palindromic address (endian-safe across all logs)
sender_mac = generate_palindromic_mac(AddressType.RANDOM_STATIC)

# Assemble an iBeacon advertisement payload
adv_payload = create_ibeacon_payload(
    uuid="FDA50693-A4E2-4FB1-AFCF-C6EB07647825",
    major=1001,
    minor=1,
    tx_power=-59
)

# Initialize Topology A with auto-allocated hardware ports
with TopologyA() as testbed:
    # Configure Device 1 as an active beacon transmitter (100 ms interval)
    testbed.stimulator.start_advertising(
        payload=adv_payload,
        adv_interval_ms=100,
        mac_address=sender_mac
    )

    # Configure Device 2 to observe channels 37, 38, and 39
    testbed.observer.start_sniffing()

    print("Running stimulation & capture for 10 seconds...")
    time.sleep(10)

    # Retrieve captured link-layer frames
    captured_packets = testbed.observer.get_captured_packets()
    print(f"Captured {len(captured_packets)} packets.")

```

### 3. Running Topology B (Continuous Multi-Channel Capture)

Capture across both Channel 37 and Channel 38 simultaneously to eliminate hop transitions:

```python
import time
from bluetooth_sniffle.topology.topology_b import TopologyB

# Initialize dual-channel observer
with TopologyB(chan_primary=37, chan_secondary=38) as testbed:
    testbed.start()
    time.sleep(5)
    testbed.stop()

    # Stream merged packets ordered by microsecond hardware timestamps
    for pkt in testbed.get_merged_stream():
        print(f"[{pkt.timestamp_us} µs] Ch:{pkt.channel} RSSI:{pkt.rssi}dBm Len:{pkt.length}")

```

---

## In-Memory Mock Simulation (CI/CD)

The framework can run completely decoupled from physical USB hardware using the built-in virtual radio bus:

```python
from bluetooth_sniffle.device.mock import MockSerialInterface, VirtualRadioBus
from bluetooth_sniffle.device.controller import SniffleDeviceController

# Instantiate a shared virtual 2.4 GHz RF medium
radio_bus = VirtualRadioBus()

# Create two mock serial interfaces bound to the bus
dev1_serial = MockSerialInterface(name="VDev1", bus=radio_bus)
dev2_serial = MockSerialInterface(name="VDev2", bus=radio_bus)

ctrl_stim = SniffleDeviceController(serial_interface=dev1_serial)
ctrl_obs = SniffleDeviceController(serial_interface=dev2_serial)

# Lock observer to Channel 37
ctrl_obs.set_channel(37)
ctrl_obs.start_sniffing()

# Transmit simulated packet on Channel 37
ctrl_stim.transmit_raw(channel=37, pdu=b"\x02\x01\x06\x03\x03\xAA\xFE")

# Observer receives frame with valid CRC, RSSI (-60 dBm), and 1 µs timestamp
rx_pkt = ctrl_obs.read_packet(timeout=1.0)
assert rx_pkt is not None
assert rx_pkt.channel == 37

```

---

## Development & Testing

Run the test suite under strict error checking (ensuring deprecation and runtime warnings fail the build):

```bash
# Execute unit and topology integration tests
pytest -v -W error tests/

# Generate terminal code coverage report
pytest --cov=bluetooth_sniffle --cov-report=term-missing tests/

# Execute static code analysis and linting
ruff check src tests

# Check PEP 484 type annotations
mypy src

```

---

## Project Layout

```
bluetooth-sniffle/
├── README.md
├── pyproject.toml
├── src/
│   └── bluetooth_sniffle/
│       ├── __init__.py
│       ├── protocol/
│       │   ├── __init__.py
│       │   ├── wire.py          # Sniffle Base64 line framing & opcode parsing
│       │   ├── mac.py           # Palindromic MAC address generators
│       │   ├── beacons.py       # iBeacon, AltBeacon, Eddystone, GAEN AD encoders
│       │   └── probing.py       # SCAN_REQ and SCAN_RSP frame builders
│       ├── device/
│       │   ├── __init__.py
│       │   ├── serial_port.py   # Port discovery, auto-baud, and CP2102 rate clamping
│       │   ├── mock.py          # MockSerialInterface & VirtualRadioBus simulator
│       │   └── controller.py    # SniffleDeviceController command engine
│       └── topology/
│           ├── __init__.py
│           ├── base.py          # Abstract Base Topology interface
│           ├── topology_a.py    # Stimulator + Observer dual-dongle runner
│           ├── topology_b.py    # Dual-Channel continuous passive capture
│           └── lifecycle.py     # Signal coordinator (SIGINT/SIGTERM teardown)
└── tests/
    ├── conftest.py
    ├── test_beacons.py
    ├── test_palindromic_mac.py
    ├── test_probing.py
    ├── test_wire_protocol.py
    ├── test_mock_device.py
    └── test_topologies.py

```

---

## Citation

If you use this framework in academic research or privacy benchmarking, please cite the underlying study:

```bibtex
@article{popets2025_wireless_scanning_sdk,
  title     = {Your Signal, Their Data: An Empirical Privacy Analysis of Wireless-scanning SDKs in Android},
  author    = {PoPETs Research Collective},
  journal   = {Proceedings on Privacy Enhancing Technologies (PoPETs)},
  volume    = {2025},
  number    = {1},
  pages     = {103},
  year      = {2025}
}

```

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](https://www.google.com/search?q=LICENSE) for details.
