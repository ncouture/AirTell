# Implementation Plan: Live Bluetooth JSON Streaming via Tshark & Sniffle Extcap

## Phase 1: Asynchronous Tshark Extcap Process Manager & Stream Engine
- [x] Task: Write unit tests for command construction, extcap option formatting, and process lifecycle in `tests/test_tshark_runner.py` 79656aa
  - [x] Test formatting of `tshark -i sniffle -o "extcap.sniffle.<option>:<value>"` parameters
  - [x] Test line-buffered streaming, stderr capture, and non-blocking stdout reading
  - [x] Test graceful shutdown (`SIGTERM` followed by timeout-escalated `SIGKILL`)
- [x] Task: Implement `TsharkConfig` and `TsharkExtcapRunner` in `src/bluetooth_sniffle/extcap/runner.py` 8c402a4
  - [x] Support parameter mapping: `serport`, `mode`, `advchan`, `rssi`, `mac`, `irk`, `string`, `extadv`, `longrange`, `crcerr`
  - [x] Implement background worker thread reading stdout into thread-safe ring buffer (`collections.deque`)
  - [x] Implement robust process lifecycle and signal management
- [x] Task: Phase Verification & Checkpoint (Refer to workflow.md) [checkpoint: 8c402a4]

## Phase 2: Live BLE JSON Dissector & Field Normalization
- [ ] Task: Write unit tests for JSON stream parsing in `tests/test_tshark_parser.py`
  - [ ] Test extraction from Elasticsearch line-delimited JSON (`-T ek`)
  - [ ] Test extraction from standard streaming JSON arrays (`-T json`)
  - [ ] Test extraction of timestamp, MAC, RSSI, channel, PDU type, and company ID
  - [ ] Test identification of tracking networks (Apple Find My, Google Find Hub, SmartThings, Tile)
- [ ] Task: Implement `TsharkBleJsonParser` in `src/bluetooth_sniffle/extcap/parser.py`
  - [ ] Extract and normalize Link Layer fields into standard observation schema
  - [ ] Implement `EventQueue` bridge pushing normalized observations to application singleton queue
  - [ ] Enforce memory bounds and drop-oldest retention
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 3: Multi-Dongle Topology Orchestration & Contention Guard
- [ ] Task: Write unit tests for port conflict detection and dual-channel aggregation in `tests/test_tshark_topology.py`
  - [ ] Test non-destructive device locking checks preventing collisions with active Sniffle processes
  - [ ] Test concurrent dual-dongle aggregation across separate primary advertising channels
- [ ] Task: Implement `TsharkTopologyManager` in `src/bluetooth_sniffle/extcap/topology.py`
  - [ ] Implement non-interfering device probe (`check_port_availability`) guarding existing DB logging
  - [ ] Implement Topology A (Dual-Channel: Ch 37 on Radio 1, Ch 38 on Radio 2)
  - [ ] Implement Topology B (Single-Channel / Cross-Band with cellular/SDR coexistence)
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 4: Streamlit UI Integration & Radio Controls View
- [ ] Task: Write integration tests for Radio Controls live streaming UI in `tests/test_tshark_ui.py`
  - [ ] Test widget parameter binding to extcap command configuration
  - [ ] Test live packet table and metric counter updates
  - [ ] Test hardware preflight diagnostics and missing dependency alerts
- [ ] Task: Extend `app/views/radio_controls.py` with Live Tshark Extcap Streaming Panel
  - [ ] Add extcap parameter controls (channel selector, RSSI floor slider, MAC/IRK/string filters, toggles)
  - [ ] Add live packet stream table (`st.dataframe`), throughput counters (`st.metric`), and dynamic Plotly chart
  - [ ] Add device conflict and preflight status badges (`AVAILABLE`, `BUSY`, `MISSING DEPENDENCIES`)
- [ ] Task: Full System End-to-End Verification
  - [ ] Run full test suite (`pytest -v -W error tests/`)
  - [ ] Verify `ruff check .` lint cleanliness
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)
