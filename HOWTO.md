# AirTell Quickstart Guide

This document provides a concise quickstart for running AirTell and links to authoritative documentation guides.

## Canonical Documentation Hub

For exhaustive technical guides, parameter manuals, and hardware setups, refer to the canonical files in `docs/`:

- **Sniffle CLI Operations Guide**: [`docs/howto.md`](docs/howto.md) (Hardware detection, packet sniffing, connection following, radar tomography, and PCAP decoding).
- **AirTell Unified CLI Manual**: [`docs/CLI.md`](docs/CLI.md) (Subcommands: `sidechannel`, `topology-a`, `topology-b`, `deanonymize`, `verify-hardware`, `mock-simulate`).
- **Scripts Reference**: [`docs/scripts_reference.md`](docs/scripts_reference.md) (Standalone utility directory reference).
- **Documentation Index**: [`docs/index.md`](docs/index.md) (Central navigation index).

---

## Quickstart Commands

### 1. Offline PCAP Analysis & Simulation (Zero-Hardware)
```bash
# Analyze side-channels (differential encryption, CSRK counters, BAT allowlist)
airtell sidechannel -i captures/trace_session.pcap

# Replay simulated 2D radio tomographic sensing
python3 src/airtell/scripts/radar_tomography.py --simulate --headless --max-frames 25
```

### 2. Dual-Dongle Monitoring & Anti-Stalking Tracker
```bash
# Monitor Channel 37 via Dongle 1
python3 src/airtell/scripts/ble_antistalking_tracker.py -s /dev/ttyUSB0 -c 37 --db ble_tracker.db

# Monitor Channel 38 via Dongle 2
python3 src/airtell/scripts/ble_antistalking_tracker.py -s /dev/ttyUSB1 -c 38 --db ble_tracker.db
```

### 3. Launch the Streamlit Web Dashboard
```bash
streamlit run app/streamlit_app.py
```
