# Product Definition: AirTell

## Vision
AirTell is a modular security and privacy testbed coordinating two Sniffle-enabled USB dongles (SONOFF Zigbee 3.0 Plus TI CC2652P) to evaluate, exercise, and monitor Bluetooth Low Energy (BLE) tracking networks, rotating identifiers, and identification methods documented in empirical research (such as PoPETs 2025-0103).

## Operational Focus
- **Dual-Track Deployment**:
  - **Laboratory & CI Evaluation**: 100% offline verification using the in-memory `VirtualRadioBus`, asserting bit-for-bit frame compliance, timing monotonicity, and state machine resilience without requiring physical radios.
  - **Live Field Deployment**: Hardware-in-the-loop multi-channel packet capture, real-time identifier parsing, and anti-stalking threat detection against real-world commercial tracking tags (Apple Find My / AirTags, Google Find Hub, Samsung SmartThings Find, Tile).

## Target Personas
- **Security & Privacy Researchers**: Investigating crowdsourced offline finding networks and testing tracking countermeasures.
- **Wireless Security Auditors**: Analyzing BLE Link Layer advertising traffic, testing device re-identification risks, address rotation synchronicity, and active scanning side-effects.
- **Embedded & RF Engineers**: Developing and validating BLE radio firmware, sniffer bridges, and dual-channel synchronization mechanisms.

## Core Capabilities
1. **Dual-Device Orchestration**:
   - **Topology A (Stimulator + Observer)**: Device 1 broadcasts synthesized beacon streams and replay sequences, while Device 2 captures scan requests, connection attempts, and peripheral advertisements.
   - **Topology B (Dual-Channel Passive Observer)**: Both devices sniff simultaneously on separate primary advertising channels (Ch 37 and Ch 38/39) with microsecond timestamp-monotonic watermark sorting to eliminate channel-hop blindness.
2. **Beacon Synthesis & Active Probing**:
   - Bit-for-bit frame builders for Apple iBeacon, AltBeacon, Google Eddystone (UID/URL/TLM), and Google/Apple Exposure Notification (GAEN `0xFD6F`).
   - Endianness-invariant palindromic MAC address generator across all BLE address types (Public, Random Static, NRPA, RPA).
   - Active probe generation (`SCAN_REQ`) and response dissection (`SCAN_RSP`) for eliciting Complete Local Names and service UUIDs.
3. **Passive Sniffing & Anti-Stalking Telemetry**:
   - Real-time Link Layer PDU dissector extracting manufacturer-specific data (Apple Continuity, Microsoft CDP, generic), service UUIDs, and crowdsourced tracking public keys.
   - Database-backed anti-stalking tracker (`ble_antistalking_tracker.py`) with sliding-window correlation heuristics (15-minute window, observation thresholds, persistence span) and Twilio SMS alert dispatching. Currently supporting SQLite, with a future roadmap to include support for other database engines.
   - Full PCAP export (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`, DLT 256) compatible with Wireshark and `crackle`.
4. **Interactive Visualization & Simulation**:
   - **Material Design v3 Dark Tactical PWA Dashboard** (`app/streamlit_dashboard.py`, `app/streamlit_app.py`): Progressive Web Application with standalone manifest (`app/static/manifest.json`), service worker caching (`app/static/service-worker.js`), persistent M3 Top App Bar, and expanding Navigation Rail spanning operational views (Telemetry Overview, RSSI Signal Trends, Alert Feed with incident triage and whitelisting, Deep Packet Inspector with AD structure dissection, Radio Controls with auto-discovery, synthetic burst injection, and offline PCAP/JSON replay, and Adversarial Testbed).
   - **Event-Driven Queue Bridge**: Thread-safe singleton `EventQueue` with bounded capacity, drop-oldest overflow protection, and non-blocking draining linking background Sniffle topology threads to Streamlit UI state.
   - In-memory `VirtualRadioBus` for 100% offline unit, integration, and E2E simulation testing without physical hardware.
5. **Adversarial Security Testbed & Identifier Deanonymization**:
   - **Multi-Signal Rotating Identifier Deanonymizer** (`airtell.adversarial.deanonymizer`): Static MAC leakage detection, constant OUI prefix identification, payload-to-address rotation desynchronization ($\Delta t$), and trajectory reconstruction across address cycles.
   - **Two-Ended Pairing Relay Testbed** (`airtell.adversarial.relay`): Inter-dongle pairing relay across a microsecond timestamp-preserving IPC queue with Link Layer connection tracking and SMP handshake failure error extraction (`SMP_PAIRING_FAILED`).
   - **Synthetic Rogue Beacon Generator & Evasion Benchmark** (`airtell.adversarial.rogue_beacon`): Parameterized rogue beacon generation for Apple Find My (`0x004C`/`0x12`), Google Find Hub (`0xFE9F`), Samsung SmartThings Find (`0x0075`), and Tile (`0xFEED`), and automated evasion benchmarking against `BLETrackerDB` heuristics.
   - **CLI Subcommands & Streamlit Integration**: Dedicated CLI tools (`airtell relay`, `deanonymize`, `rogue-inject`) and integrated Adversarial Testbed view in the Streamlit M3 dashboard.
6. **Live Tshark & Sniffle Extcap JSON Streaming Pipeline**:
   - **Asynchronous Extcap Subprocess Runner** (`airtell.extcap.runner`): Programmatic construction and lifecycle execution of `tshark -i sniffle -o "extcap.sniffle.<option>:<value>"` with line-buffered stdout (`-l`), graceful shutdown (`SIGTERM`/`SIGKILL`), and ring buffer queuing.
   - **High-Performance BLE JSON Stream Dissector** (`airtell.extcap.parser`): Dual-mode parsing for Elasticsearch line-delimited JSON (`-T ek`) and streaming array JSON (`-T json`) with multiline brace-depth assembly, ISO 8601 timestamps, nested EIR/AD structure unpacking, and tracking network classification (Apple Find My, Google Find Hub, Samsung SmartThings, Tile).
   - **Multi-Dongle Topology Orchestration & Contention Guard** (`airtell.extcap.topology`): Non-interfering serial port probing preventing collisions with active background Sniffle logging processes; Topology A (Dual-Channel aggregation) and Topology B (Single Radio / Cross-Band).
7. **Exclusive-Use BLE Side-Channel Suite & Streamlit Visualizer**:
   - **Link-Layer Differential Encryption Initiation Analysis** (`airtell.sidechannel.differential_encryption`): Identifies shared Long Term Key (LTK) possession via positive `LL_START_ENC_RSP` (0x06) vs unbonded / untrusted rejection `LL_REJECT_IND` (0x0D) or `LL_REJECT_EXT_IND` (0x11) with error code `0x06` (`PIN_OR_KEY_MISSING`).
   - **CSRK 32-bit SignCounter Monotonicity & Tracking** (`airtell.sidechannel.csrk_counter`): Inspects ATT Signed Write commands (Opcode `0xD2`), tracks strictly monotonic 32-bit counter progression, verifies truncated AES-CMAC signatures, detects replay/rollback/jump anomalies, and establishes cross-RPA device re-identification linking persistent identities across address rotation boundaries.
   - **Bluetooth Address Tracking (BAT) Allowlist Timing Oracle** (`airtell.sidechannel.bat_allowlist`): Analyzes inter-frame space timing ($T_{IFS} = 150\,\mu\text{s} \pm 2\,\mu\text{s}$) to detect selective allowlist probe responses vs silent drops ($> 1000\,\mu\text{s}$), flags directed advertising bursts (`ADV_DIRECT_IND`), and fingerprints connection parameter 4-tuples `<Interval, Latency, Timeout, Hop>`.
   - **Unified Multi-Source Runner & Analysis Engine** (`airtell.sidechannel.runner`): Executes across offline PCAP/PCAPNG capture files, live streaming queues, and synthetic simulation testbeds, outputting structured JSON, human-readable text summaries, and audit-grade Markdown reports.
   - **Material Design v3 Side-Channel Visualizer Tab** (`app/views/adversarial_evaluation.py`): Interactive Streamlit visualizer featuring Plotly Timing Oracle scatter plots, CSRK trajectory progression charts, encryption handshake status classification tables with Link-Layer control hex payload inspectors, and PoPETs empirical research metrics cards.

## Future Roadmap (Multi-Radio & Infrastructure Extensions)
- **Pluggable Database Backends**: Abstracting telemetry storage to support additional engines (e.g., PostgreSQL, TimescaleDB, DuckDB) alongside SQLite.
- **SDR Physical-Layer Fingerprinting**: Interfacing wideband SDRs (e.g. HackRF One) to correlate IQ signal imperfections (frequency offset, phase noise) with BLE MAC rotation cycles.
- **Cross-Layer Radio Correlation**: Correlating BLE peripheral actions with Wi-Fi and Sub-GHz IoT uplink bursts to analyze side-channel privacy leakage.
