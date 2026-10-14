# Specification: Live Bluetooth JSON Streaming via Tshark & Sniffle Extcap

## 1. Overview
This track integrates live real-time Bluetooth Low Energy (BLE) packet capture and non-blocking JSON streaming into the Streamlit web application. By wrapping the `sniffle_extcap.py` Wireshark extcap plugin using `tshark` (`-T ek` line-delimited JSON and `-T json`), the testbed streams live dissected BLE frames directly into the application's shared `EventQueue`. This empowers all operational views (Live Telemetry, RSSI Signal Trends, Packet Inspector, and Radio Controls) with real-time Link Layer data without interfering with or replacing existing background Sniffle topology processes and their database logging.

## 2. Functional Requirements

### FR1: Asynchronous Tshark Extcap Process Manager & Stream Engine
- **Process Spawning & Execution**: Programmatically construct and spawn `tshark` subprocesses utilizing `sniffle` extcap configuration options (`extcap.sniffle.<option>:<value>`) with line-buffered stdout (`-l`), passing user parameters: `serport`, `mode`, `advchan`, `rssi`, `mac`, `irk`, `string`, `extadv`, `longrange`, `crcerr`.
- **Dual Output Format Support**: Primary parser targeting high-throughput line-delimited Elasticsearch JSON (`-T ek`), with robust fallback parser for streaming JSON arrays (`-T json`).
- **Thread-Safe Ring Buffer & Bridge**: Dedicated background worker reading stdout lines into a thread-safe ring buffer (`collections.deque(maxlen=N)`), normalizing extracted frames into the standardized observation schema and pushing them into the singleton `EventQueue`.
- **Graceful Lifecycle Management**: Clean process termination (`SIGTERM` followed by timeout-escalated `SIGKILL`), ensuring serial port release, zombie process cleanup, and zero orphaned child processes on shutdown or configuration changes.

### FR2: Topology Execution & Multi-Dongle Orchestration
- **Device Availability & Non-Interference Guard**:
  - Non-destructive serial port probing (`/dev/ttyUSB0`, `/dev/ttyUSB1`, etc.) to detect whether a radio is currently held by active Sniffle processes or external tools before launching `tshark`.
  - Strict preservation of existing background sniffing and database logging workflows (`ble_antistalking_tracker.py`, `TopologyA`, `TopologyB`).
- **Topology A (Dual-Channel Tshark Pipeline)**: Concurrently orchestrate two `tshark` worker instances—one targeting radio 1 (e.g., Channel 37) and radio 2 (e.g., Channel 38)—aggregating dissected frames into a synchronized unified stream.
- **Topology B (Cross-Band & Single Radio Mode)**: Single `tshark` worker streaming on an available radio while preserving the alternate radio for auxiliary stimulus, pairing relay, or cellular/SDR synchronization.

### FR3: High-Performance JSON Dissector & Field Normalization
- **BLE Field Extraction**:
  - Timestamp: `_source.layers.frame["frame.time_epoch"]` or `_source.layers.frame["frame.time"]` normalized to monotonic epoch float.
  - MAC Address: `_source.layers.btle["btle.advertising_address"]` or `_source.layers.btcommon["btcommon.eir_ad.entry.device_address"]`.
  - RSSI: `_source.layers.btle["btle.rssi"]` (integer dBm).
  - Channel: `_source.layers.btle["btle.channel"]` or command-line extcap override parameter.
  - PDU Type: `_source.layers.btle["btle.advertising_header.pdu_type"]` (ADV_IND, SCAN_REQ, SCAN_RSP, ADV_NONCONN_IND, etc.).
  - Company ID / Manufacturer Data: `_source.layers.btcommon["btcommon.eir_ad.entry.company_id"]` and raw payload hex extraction.
  - Public Key Fragment / Tracking Network: Detection of Apple Find My (`0x004C`/`0x12`), Google Find Hub (`0xFE9F`), Samsung SmartThings Find (`0x0075`), and Tile (`0xFEED`).
- **Memory & Resource Control**: Bounded ring buffers and pruning to guarantee constant memory footprint during extended multi-hour captures.

### FR4: Streamlit UI Integration & Radio Controls View
- **Parameter Control Panel**: Map UI input widgets (sliders for RSSI floor cutoff, port select dropdowns, channel radios, filter inputs for MAC/IRK/string, checkboxes for Extended Adv, Coded PHY, CRC errors) to `tshark` command-line extcap flags.
- **Real-Time Visualizations**:
  - Live packet stream table with auto-scroll and freeze capabilities (`st.dataframe`).
  - Real-time throughput metrics (packets/sec, dropped frames, active channels) via `st.metric`.
  - Dynamic Plotly signal strength trends (`st.plotly_chart`) updated from the live stream.
- **Hardware Conflict & Preflight Diagnostics**: Visual indicators displaying whether dongles are `AVAILABLE`, `ACTIVE (TSHARK)`, or `BUSY (EXISTING TOPOLOGY)`, with actionable guidance if `tshark` or `sniffle_extcap.py` are missing or lack permissions.

## 3. Non-Functional Requirements
- **Latency**: Inter-process JSON extraction and queue propagation latency $< 20\text{ ms}$ under sustained loads of 200 packets/second.
- **Stability**: Zero memory leakage in continuous 60-minute benchmark stress tests.
- **Compatibility**: 100% offline unit/integration testability with mock `tshark` JSON output streams without requiring hardware dongles.
- **Standards & Lint**: Adherence to Google Python Style Guide, M3 Tactical design tokens, and zero `ruff` errors.

## 4. Acceptance Criteria
- [ ] `TsharkExtcapRunner` starts, monitors, and cleanly terminates `tshark` subprocesses across single and dual dongle modes.
- [ ] Live JSON extractor parses both `-T ek` and `-T json` streams, extracting timestamp, MAC address, RSSI, channel, PDU type, and company identifiers.
- [ ] Packets from `tshark` workers flow directly into `EventQueue` and render in real-time across Streamlit views.
- [ ] Active port contention detection prevents collisions with already-running Sniffle/database logging processes.
- [ ] Unit and integration test suite verifies parsing, process lifecycle, and UI controls in mock mode.
- [ ] Full test suite passes (`uv run pytest`) and `ruff check .` reports zero violations.

## 5. Out of Scope
- Modifying `sniffle_extcap.py` source code or altering Wireshark extcap protocol interfaces.
- Replacing existing background sniffing processes or altering `ble_antistalking_tracker.py` database schema.
