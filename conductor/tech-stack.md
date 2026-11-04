# Technology Stack: AirTell

## Core Language & Runtime
- **Python**: `>=3.10`
- **Build & Packaging**: `setuptools>=61.0`, configured via `pyproject.toml`
- **Package & Environment Management**: `uv` first (`uv sync`, `uv run`) with full standard `pip` / `virtualenv` PEP 517/621 fallback

## Hardware & Communications
- **Serial Interface**: `pyserial>=3.5` (UART communication with TI CC2652P / CC1352 Sniffle radios, default 2,000,000 baud with automatic capping to 921,600 baud on legacy CP2102 bridges)
- **Firmware Base**: Sniffle BLE5 sniffer firmware (Texas Instruments CC2652 / CC1352)
- **Hardware Discovery**: Automatic USB serial port discovery for Sonoff CC2652P (CP2102 / CP2102N) and TI XDS110 debug probes with mock hardware fallback

## Cryptography & Data Integrity
- **Cryptographic Primitives**: `cryptography>=40.0.0` (AES-128, key derivation, and token evaluation)
- **CRC & Whitening**: Custom vectorized BLE whitening and CRC24 reverse implementations

## Modeling & Storage
- **Data Modeling & Validation**: `pydantic>=2.0.0` (Packet headers, dissected PDU records, and telemetry session schemas)
- **Database Abstraction**: `DatabaseBackend(ABC)` architecture (`src/airtell/telemetry/storage.py`) providing a lean, high-throughput abstraction over native DB-API connections without third-party ORM overhead
- **Production Storage Engines**:
  - `SQLiteBackend`: Thread-safe observations & alerts logging via standard library `sqlite3`, thread-local connection management, indexed query windows, and persistent `whitelists` and `alert_actions` tables
  - `DuckDBBackend`: High-throughput columnar analytical engine (`duckdb>=1.5.6`) with zero-copy vectorized aggregation, parity-compatible schema, and read-through SQLite attachment
- **Roadmap Engines**: PostgreSQL and TimescaleDB planned via native DB-API drivers implementing `DatabaseBackend`

## Frontend, Dashboard & Visualization
- **Application Framework**: `streamlit>=1.64.0` (Strictly utilizing official Streamlit components)
- **Plotting & Charts**: `plotly>=7.1.0` (Interactive real-time RSSI signal trends)
- **Progressive Web App**: Native Service Worker caching and Web App Manifest (`manifest.json`) for offline asset loading

## Optional Integration Extras
- **Notifications Extra (`[notifications]`)**: `twilio>=8.0.0` for SMS alerting, kept optional to preserve a lean core installation

## Testing, Tooling & Code Quality
- **Packet Dissection & Streaming Engine**: `tshark` (Wireshark CLI engine with Sniffle extcap plugin wrapper, supporting line-delimited `-T ek` and `-T json` streaming)
- **Test Framework**: `pytest>=9.1.1` with `anyio`, `pytest-cov` (1,267+ passing multi-tier E2E, unit, and integration tests across 60+ test modules)
- **Static Analysis & Formatting**: `ruff` (targeting Python 3.10+, line length 120)
