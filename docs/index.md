# Sniffle & Bluetooth-Sniffle Central Documentation

Welcome to the centralized documentation hub for **Sniffle** and the **Bluetooth-Sniffle Testbed Framework**.

This repository pairs firmware for Texas Instruments CC1352 / CC26x2 wireless microcontrollers (and Sonoff Zigbee 3.0 Dongle Plus CC2652P adapters) with Python host-side tools, Streamlit operations dashboards, and dual-dongle coordination testbeds.

---

## Documentation Directory

### 1. Specifications & Topologies
* [**Link Layer Traffic Relay Specifications**](relay_specifications.md)
  Full architectural and protocol specifications to implement Link Layer Traffic Relay using a master/slave topology (`/dev/ttyUSB0` and `/dev/ttyUSB1`) across two Sniffle devices (`relay_master.py` and `relay_slave.py`). Includes PDU sequencing, fast connection interval tuning, XDS110 DMA latency workarounds, and security warnings.
* [**Device Status & LSOF Validation**](device_status.md)
  Specification and operations guide for runtime detection of Sniffle device availability. Explains validation via `lsof /dev/ttyUSB0` and `lsof /dev/ttyUSB1` (exit code 0 = open/in use, non-zero = idle/not open) and real-time dashboard telemetry.

### 2. Scripts & CLI Reference
* [**Scripts Directory Reference**](scripts_reference.md)
  Comprehensive technical documentation of all utilities and tools located in `scripts/`, including `sniff_receiver.py`, `scanner.py`, `advertiser.py`, `initiator.py`, `relay_master.py`, `relay_slave.py`, `ble_parser.py`, `ble_antistalking_tracker.py`, `crackle`, `pcap_decoder.py`, `reset.py`, `uart_test.py`, `version_check.py`, and `radar_tomography.py`.
* [**Sniffle CLI Operations Guide (HOWTO)**](howto.md)
  End-to-end user guide for hardware diagnostics, 3-channel advertising hopping, connection following, encrypted parameter preloading, Wireshark extcap integration, and active link-layer transmission.
* [**Quickstart Commands & Dual-Dongle Playbook**](quickstart_commands.md)
  Centralized quickstart recipes, multi-dongle topology configurations, serial device permissions, and Wireshark streaming setup.

### 3. Protocol Dissection & Analysis
* [**Apple AirDrop Advertisement Analysis**](airdrop.md)
  Byte-level packet breakdown of Apple Continuity Nearby Info advertisements indicating "AirDrop receive enabled", with live TShark and Sniffle filters.
* [**Crackle PCAP Analysis & Long-Term Device Attribution**](crackle_pcap_analysis.md)
  In-depth analysis of captured BLE PCAPs with `crackle`, tracing Resolvable Private Addresses (RPAs) against fixed peripheral anchors across multi-hour sessions.
* [**Filtering BLE JSON with JQ**](json_jq.md)
  Techniques and recipes for processing Wireshark/TShark JSON streams (`tshark -T json`), handling dotted key syntax, hierarchical scan response trees, and extracting unique device identities.
* [**Using TShark with Sniffle & PCAP Handling**](tshark.md)
  Differences between live extcap streaming and native PCAP dissection (DLT 256 / `DLT_BLUETOOTH_LE_LL_WITH_PHDR`), display filters, and multi-dongle parallel capture configurations.

### 4. Hardware Deployment
* [**Hardware Setup & Dongle Flashing**](hardware_setup.md)
  Step-by-step firmware flashing instructions for Sonoff CC2652P USB Dongle Plus, TI LaunchPad (XDS110), and CatSniffer v3, Linux `dialout` permission configuration, and CP2102 baud rate constraints.

---

## Repository Architecture

```text
bluetooth-sniffle/
├── app/                      # Material Design v3 Dark Tactical Streamlit Dashboard
│   ├── components/           # M3 Top App Bar, Navigation Rail, PWA Service Worker
│   └── views/                # Live Telemetry, RSSI Trends, Threat Alerts, Radio Controls
├── conductor/                # Conductor workflow tracks, plans, and specifications
├── docs/                     # Centralized technical documentation hub
├── scripts/                  # Standalone CLI tools, parsers, relays, and decoders
├── src/
│   ├── bluetooth_sniffle/    # Core Python testbed framework (protocols, devices, topologies)
│   └── sniffle/              # Embedded Sniffle firmware sources and python_cli library
└── tests/                    # Unit, integration, and end-to-end test suites
```
