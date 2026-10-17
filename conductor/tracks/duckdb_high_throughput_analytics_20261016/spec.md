# Specification: Embedded DuckDB High-Throughput Analytics Engine

## 1. Overview
Integrate an embedded DuckDB columnar analytics engine alongside SQLite in AirTell to accelerate analytical queries, RSSI trends, channel distribution histograms, and sliding-window anti-stalking heuristic evaluations over multi-million packet PCAP telemetry datasets (5M+ observations).
This track introduces a unified `DatabaseBackend` abstraction layer supporting both SQLite and DuckDB, equips `BLETrackerDB` with vectorized execution, enables sub-second filtering in Streamlit views (Packet Inspector, RSSI Trends, Threat Alerts), and provides performance benchmark validation.

## 2. Functional Requirements

### FR1: Pluggable DatabaseBackend Abstraction (Issue #45)
- In `src/airtell/telemetry/storage.py` and `src/airtell/telemetry/__init__.py`:
  - Define `DatabaseBackend` abstract base class defining common database methods:
    `connect()`, `close()`, `init_db()`, `insert_observation()`, `insert_alert()`, `get_observations()`, `get_rssi_timeseries()`, `get_channel_distribution()`, `get_tracker_frequencies()`, `check_stalking_heuristics()`, `query_df()`.
  - Implement `SQLiteBackend` wrapping standard `sqlite3` connections and queries.
  - Implement `DuckDBBackend` supporting direct attachment to existing `.db` / SQLite files via `ATTACH '...' AS sqlite_db (TYPE SQLITE); USE sqlite_db;` or native `.duckdb` / in-memory files.
  - Implement factory helper `get_database_backend(backend_type="sqlite"|"duckdb", db_path=...)` with graceful fallback to `SQLiteBackend` when DuckDB is unavailable or encounters attachment errors.

### FR2: Embedded DuckDB Vectorized Analytics in BLETrackerDB (Issues #18, #35, #36)
- In `src/airtell/scripts/ble_antistalking_tracker.py` (and `BLETrackerDB`):
  - Add support for attaching DuckDB engine to accelerate sliding-window anti-stalking heuristic checks, aggregation queries, RSSI trends, and channel histograms on large datasets (5M+ observations).
  - Ensure seamless fallback to standard SQLite if DuckDB is unavailable or disabled.
  - Expose high-level aggregation methods on `BLETrackerDB`: `get_observations()`, `get_rssi_timeseries()`, `get_channel_distribution()`, `get_tracker_frequencies()`.

### FR3: Streamlit Dashboard Integration (Issue #46)
- In `app/streamlit_app.py` and views (`views/packet_inspector.py`, `views/rssi_trends.py`, `views/alert_feed.py`, `views/telemetry_overview.py`):
  - Cache the DuckDB analytical connection/backend in Streamlit session state or resource cache.
  - Accelerate packet search and filtering in Deep Packet Inspector, RSSI Trends time-series, and Threat Alerts views using vectorized queries.
  - Preserve backwards compatibility for callers passing standard SQLite connections or mock connections.

### FR4: Storage Performance Benchmarks (Issue #51)
- In `tests/benchmarks/test_storage_benchmarks.py`:
  - Implement automated benchmarks comparing SQLite vs DuckDB execution times for sliding-window queries and aggregations across synthetic datasets (10,000 to 100,000+ packets in automated tests, with scalable fixtures for 1M/5M).
  - Assert that DuckDB execution is fast and produces identical analytical results to SQLite.

### FR5: Technical Documentation & Migration Guide (Issue #53)
- In `docs/howto.md`:
  - Document DuckDB setup, configuration options (`DATABASE_BACKEND`, `DUCKDB_THREADS`, `DUCKDB_MEMORY_LIMIT`), memory limits, and migration guide for running high-throughput analytics on large PCAP files.
  - Document performance characteristics and schema compatibility between DuckDB and SQLite.

## 3. Non-Functional Requirements
- **Performance**: Sub-second query latency (< 200ms) for aggregations and sliding-window heuristics over multi-million packet datasets.
- **Reliability & Resilience**: Clean error handling; graceful automatic fallback to SQLite if DuckDB attachment fails or DuckDB is disabled.
- **Code Quality**: Zero `ruff` lint warnings (`line-length = 120`, target Python 3.10+).
- **Test Coverage**: 100% test pass rate across all unit, integration, and benchmark tests.
- **Backwards Compatibility**: All 1,197+ existing repository tests must continue passing.

## 4. Acceptance Criteria
- [x] `DatabaseBackend` abstraction protocol implemented with `SQLiteBackend` and `DuckDBBackend` concrete classes.
- [x] `DuckDBBackend` attaches SQLite database files via `ATTACH ... (TYPE SQLITE)` and executes vectorized SQL queries.
- [x] Factory function `get_database_backend()` returns appropriate backend with graceful fallback.
- [x] `BLETrackerDB` supports DuckDB acceleration for sliding-window heuristics and aggregations.
- [x] Streamlit dashboard views utilize cached DuckDB backend for sub-second packet filtering.
- [x] Automated benchmark test suite verifies query performance and 100% result parity between SQLite and DuckDB.
- [x] Technical documentation and migration guide added to `docs/howto.md`.
- [x] All repository tests pass (`uv run pytest`) and lint checks pass (`uv run ruff check .`).
