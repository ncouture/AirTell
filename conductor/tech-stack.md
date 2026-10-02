# Technology Stack: Bluetooth-Sniffle

## Core Language & Runtime
- **Python**: `>=3.10`
- **Build & Packaging**: `setuptools>=61.0`, configured via `pyproject.toml`
- **Package & Environment Management**: `uv` first (`uv sync`, `uv run`) with full standard `pip` / `virtualenv` PEP 517/621 fallback

## Hardware & Communications
- **Serial Interface**: `pyserial>=3.5` (UART communication with TI CC2652P Sniffle radios, baud rates up to 921,600)
- **Firmware Base**: Sniffle BLE5 sniffer firmware (Texas Instruments CC2652 / CC1352)
- **Hardware Discovery**: Automatic USB serial port discovery for Sonoff CC2652P (CH340 / CP2102) and TI XDS110 debug probes with mock hardware fallback

## Cryptography & Data Integrity
- **Cryptographic Primitives**: `cryptography>=40.0.0` (AES-128, key derivation, and token evaluation)
- **CRC & Whitening**: Custom vectorized BLE whitening and CRC24 reverse implementations

## Modeling & Storage
- **Data Modeling & Validation**: `pydantic>=2.0.0` (Packet headers, dissected PDU records, and telemetry session schemas)
- **Database Abstraction**: `SQLAlchemy` / `SQLModel` ORM layer providing a unified abstraction across storage backends
- **Current Primary Engine**: `sqlite3` (Thread-safe observations & alerts logging, indexed query windows, plus persistent `whitelists` and `alert_actions` tables for triage)
- **Roadmap Engines**: PostgreSQL, TimescaleDB, and DuckDB supported via SQLAlchemy dialect drivers

## Frontend, Dashboard & Visualization
- **Application Framework**: `streamlit>=1.64.0` (Strictly utilizing official Streamlit components)
- **Plotting & Charts**: `plotly>=7.1.0` (Interactive real-time RSSI signal trends)
- **Progressive Web App**: Native Service Worker caching and Web App Manifest (`manifest.json`) for offline asset loading

## Optional Integration Extras
- **Notifications Extra (`[notifications]`)**: `twilio>=8.0.0` for SMS alerting, kept optional to preserve a lean core installation

## Testing, Tooling & Code Quality
- **Test Framework**: `pytest>=9.1.1` with `anyio`, `pytest-cov` (591 multi-tier E2E, unit, and integration tests across 28 test modules)
- **Static Analysis & Formatting**: `ruff` (targeting Python 3.10+, line length 120)
