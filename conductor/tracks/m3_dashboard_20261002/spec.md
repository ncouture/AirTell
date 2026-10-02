# Specification: Material Design v3 Dark Tactical PWA Dashboard

## 1. Overview
Build a high-performance Progressive Web Application (PWA) dashboard adhering to Material Design v3 (M3) Dark Tactical styling for the dual-dongle Bluetooth-Sniffle testbed. The dashboard provides real-time telemetry streaming from active Sniffle topologies via a thread-safe singleton queue, an M3 Top App Bar, an expanding side Navigation Rail with 5 primary operational views, a multi-level anti-stalking threat triage interface, full radio orchestration and beacon injection controls, and offline PCAP/telemetry replay via a PWA service worker.

## 2. Functional Requirements

### FR1: M3 Dark Tactical PWA Architecture
- **Web App Manifest (`app/static/manifest.json`)**: Standalone display mode, tactical dark theme `#0F141C`, background color, app identity, and responsive icon assets.
- **Service Worker (`app/static/service-worker.js`)**:
  - Cache-first strategy for app shell, static CSS, icons, and JavaScript.
  - Offline fallback caching for historical telemetry records and offline PCAP uploads.
- **M3 Dark Tactical UI**: Configured via `.streamlit/config.toml` and scoped `st.html()` CSS utilizing M3 dark tokens (Surface `#0F141C`, Primary `#A8C7FA`, Error/Alert `#F2B8B5`, Surface Container `#1B2028`).
- **M3 Layout**: Persistent Top App Bar showing hardware status and quick actions, expanding Navigation Rail on the side, and responsive bottom bar on compact screens.
- **Component Constraint**: Exclusively use components developed and shipped by the official Streamlit project.

### FR2: Event-Driven Queue & Topology Bridge
- Implement a thread-safe singleton queue via `@st.cache_resource` bridging background Sniffle topology threads (Topologies A and B) to Streamlit UI state.
- Support low-latency queue draining on UI cycles without thread deadlocks or UI blocking.

### FR3: 5 Core Operational Views
1. **Live Telemetry Overview**: Real-time packet throughput, channel distribution (37, 38, 39), active tracking network counts (Apple, Google, Tile, Samsung), and hardware bridge indicators.
2. **RSSI Signal Trends**: Interactive Plotly time-series graphing signal strength (dBm) over time, color-coded by ephemeral public key, with proximity threshold indicators.
3. **Multi-Level Alert Feed**: Chronological threat timeline categorizing alerts into:
   - *Suspicious*: Persistent beaconing over time windows ($\ge 5$ packets in $\ge 5$ min).
   - *High Proximity*: Strong signal levels ($\text{RSSI} > -55\text{ dBm}$).
   - *Unlinkability Hazard*: Static MAC address leakage or un-rotated payload keys.
   - *Analyst Actions*: Acknowledge alert, Whitelist key/device, Tag custom incident notes, Export incident report to JSON/CSV.
4. **Deep Packet Inspector**: Filterable data table with multi-protocol filtering, Link Layer PDU dissection, AD structure inspection, and payload hex dumps.
5. **Testbed & Radio Controls**: Interactive hardware orchestrator allowing analysts to toggle Topologies (A/B), trigger synthetic beacon injection bursts (iBeacon, AltBeacon, Eddystone, GAEN), and download live PCAP captures.

### FR4: Persistent Whitelists & Analyst Notes
- Persist whitelisted tracker IDs, alert acknowledgments, and analyst notes in dedicated SQLite tables (`whitelists`, `alert_actions`) in `ble_tracker.db`.

### FR5: Offline Inspection & PCAP Replay
- When disconnected from live radio dongles, enable analysts to upload and inspect saved PCAP files and JSON session captures directly in the browser via service worker caching.

## 3. Non-Functional Requirements
- **Performance**: Queue ingestion and UI drain overhead $<100\text{ ms}$ per cycle.
- **Testability**: Comprehensive unit and integration test coverage for all views, PWA assets, queue bridges, and database actions.
- **Safety**: Thread-safe lifecycle handling with zero port locking collisions or unclosed file descriptors on shutdown.

## 4. Out of Scope
- Firmware compilation for CC2652P (assumes dongles are pre-flashed with Sniffle).
- Cloud-hosted external database synchronization.
