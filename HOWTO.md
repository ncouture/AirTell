# AirTell: Python BLE Offline Finding Parser & Anti-Stalking Tracker Suite

All requested components have been created and validated in `/home/self/git/bluetooth-sniffle`:

### Standalone Offline Finding Parser (`ble_parser.py`)

- **Interfaces directly** with `sniffle_receiver` on the specified serial port and advertising channel (37, 38, or 39).
- **Unpacks and parses** raw 31-byte advertising payloads.
- **Detects and extracts** public key fragments for Apple Find My (`0x004C` / `0x12`), Google Fast Pair / Find Hub (`0xFE9F`), Tile (`0xFEED`), and Samsung SmartThings Find (`0x0075`).

### BLE Anti-Stalking Tracker & SQLite Logger (`ble_antistalking_tracker.py`)

- **Database Management**: Manages SQLite database schema with `observations` and `alerts` tables and performance indexes on `timestamp` and `ephemeral_key`.
- **Heuristic Correlation**: Implements sliding-window heuristics (15-minute evaluation window, minimum observation threshold, minimum persistence span) to flag persistent rogue beacons even across randomized Bluetooth MAC addresses.
- **Alert Dispatching**: Integrated with alert notification dispatching via Twilio SMS (`--twilio-sid`, `--twilio-token`, `--twilio-from`, `--twilio-to` or corresponding environment variables) to automatically push alerts when a rogue tag threshold is breached.

### Streamlit Real-Time Dashboard (`streamlit_dashboard.py`)

- **Shared State**: Connects to the shared SQLite database (`ble_tracker.db`).
- **Telemetry Visualizer**: Visualizes live summary metrics (Total Packets, Identified Trackers, Active 15m Threats).
- **Interactive Trajectories**: Generates interactive Plotly RSSI time-series trends grouped by tracker ephemeral keys.
- **Threat Feed**: Provides an interactive security alert feed and filtered raw packet inspector table.

---

## Deployment & Execution Guide

### 1. Dual-Dongle Parallel Capture

Deploy both SONOFF CC2652P dongles concurrently across different primary advertising channels to write simultaneously into the shared database:

```bash
# Terminal 1: Monitor Channel 37 via Dongle 1
python3 ble_antistalking_tracker.py -p /dev/ttyUSB0 -c 37 -db ble_tracker.db

# Terminal 2: Monitor Channel 38 via Dongle 2
python3 ble_antistalking_tracker.py -p /dev/ttyUSB1 -c 38 -db ble_tracker.db
```

### 2. Launch the Streamlit Web Dashboard

Launch the web interface to visualize real-time RSSI trajectories and security alerts:

```bash
streamlit run app/streamlit_dashboard.py
```

The dashboard will open at `http://localhost:8501`.
