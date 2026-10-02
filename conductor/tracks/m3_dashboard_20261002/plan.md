# Implementation Plan: Material Design v3 Dark Tactical PWA Dashboard

## Phase 1: PWA Infrastructure, Design Tokens & Layout Shell [checkpoint: 6562275]
- [x] Task: Write tests for PWA static assets, manifest structure, and M3 design token configuration [e816b77]
  - [x] Write unit test in `tests/test_pwa_assets.py` validating `manifest.json` required fields and mime types
  - [x] Write unit test verifying service worker caching headers and asset lists
- [x] Task: Implement M3 Dark Tactical configuration and PWA assets [e90707d]
  - [x] Create `.streamlit/config.toml` with dark tactical theme tokens (Surface `#0F141C`, Primary `#A8C7FA`, On-Surface `#E1E2E8`)
  - [x] Create `app/static/manifest.json` with standalone display, app icons, and tactical color schemes
  - [x] Create `app/static/service-worker.js` with static shell cache-first and telemetry network-first strategy
- [x] Task: Implement M3 Top App Bar and expanding Navigation Rail component [6562275]
  - [x] Create navigation component in `app/components/navigation.py` using official Streamlit layout primitives
  - [x] Inject M3 typography and styled app bar header via scoped `st.html()`
- [x] Task: Phase Verification & Checkpoint (Refer to workflow.md) [6562275]

## Phase 2: Event-Driven Queue & Database Schema Extension [checkpoint: aa839cc]
- [x] Task: Write unit tests for singleton queue bridge and extended database tables [88f0c2b]
  - [x] Write unit test in `tests/test_queue_bridge.py` validating thread-safe push/drain and overflow protection
  - [x] Write unit test in `tests/test_tracker_db_extensions.py` for whitelisting and alert acknowledgment schema
- [x] Task: Implement thread-safe singleton queue bridge [673e396]
  - [x] Implement `EventQueue` in `app/queue_bridge.py` cached via `@st.cache_resource`
  - [x] Add non-blocking drain and batching logic for live UI cycles
- [x] Task: Extend database schema for whitelisting and analyst actions [aa839cc]
  - [x] Add `whitelists` and `alert_actions` tables to `ble_antistalking_tracker.py`
  - [x] Implement CRUD helper functions for whitelisting ephemeral keys/MACs and recording incident notes
- [x] Task: Phase Verification & Checkpoint (Refer to workflow.md) [aa839cc]

## Phase 3: Core Dashboard Views & Multi-Level Alert Triage
- [x] Task: Write component tests for telemetry views and alert categorization [20d1da2]
  - [x] Write test in `tests/test_dashboard_views.py` testing live metrics rendering and Plotly RSSI figure generation
  - [x] Write test validating multi-level alert categorization (Suspicious, High Proximity, Unlinkability Hazard)
- [x] Task: Implement Live Telemetry Overview & RSSI Trends views [54cda00]
  - [x] Implement `app/views/telemetry_overview.py` with metric cards and channel distributions
  - [x] Implement `app/views/rssi_trends.py` generating interactive Plotly time series grouped by ephemeral keys
- [ ] Task: Implement Multi-Level Alert Feed with Analyst Actions
  - [ ] Implement `app/views/alert_feed.py` displaying categorized threat cards with severity badges
  - [ ] Implement interactive buttons for Acknowledge Alert, Whitelist Identifier, Tag Custom Note, and Export Incident CSV
- [ ] Task: Implement Deep Packet Inspector view
  - [ ] Implement `app/views/packet_inspector.py` with multi-protocol filtering, AD structure decoding, and raw hex views
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 4: Testbed & Radio Controls, Offline PCAP Replay & E2E Validation
- [ ] Task: Write integration tests for radio orchestration and offline PCAP parsing
  - [ ] Write integration test in `tests/test_dashboard_orchestration.py` testing topology triggers from UI
  - [ ] Write test verifying offline PCAP file upload and in-browser parsing
- [ ] Task: Implement Testbed & Radio Controls view
  - [ ] Implement `app/views/radio_controls.py` allowing analysts to toggle Topologies (A/B) and trigger beacon injection bursts (iBeacon, AltBeacon, Eddystone, GAEN)
  - [ ] Add live PCAP capture download button
- [ ] Task: Implement Offline PCAP & Session Replay view
  - [ ] Implement `app/views/offline_replay.py` enabling file upload and offline dissection of PCAP and JSON session captures
- [ ] Task: Assemble main dashboard entrypoint
  - [ ] Refactor `app/streamlit_dashboard.py` to route between the 5 views via the M3 navigation rail
- [ ] Task: Full System End-to-End Verification
  - [ ] Run full test suite (`pytest -v -W error tests/`)
  - [ ] Verify `ruff check src tests app` lint cleanliness
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)
