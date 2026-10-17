# Implementation Plan: Embedded DuckDB High-Throughput Analytics Engine

## Phase 1: Conductor Track Scaffolding & Registry Indexing
- [x] Task: Scaffold Track 5 Conductor track directory and documentation (Issue #11)
  - [x] Create `conductor/tracks/duckdb_high_throughput_analytics_20261016/`
  - [x] Create `metadata.json`, `index.md`, `spec.md`, and `plan.md`
- [x] Task: Update `conductor/tracks.md` registry with Track 5 entry

## Phase 2: Pluggable DatabaseBackend Abstraction
- [x] Task: Define `DatabaseBackend` ABC in `src/airtell/telemetry/storage.py` and `__init__.py` (Issue #45)
  - [x] Declare common interface methods: `connect()`, `close()`, `init_db()`, `insert_observation()`, `insert_alert()`, `get_observations()`, `get_rssi_timeseries()`, `get_channel_distribution()`, `get_tracker_frequencies()`, `check_stalking_heuristics()`, `query_df()`
  - [x] Implement `SQLiteBackend` wrapping standard SQLite connections
  - [x] Implement `DuckDBBackend` with direct attachment to existing `.db` / SQLite files via `ATTACH ... (TYPE SQLITE)` or native DuckDB files
  - [x] Provide factory function `get_database_backend(backend_type="sqlite"|"duckdb", db_path=...)` with fallback to SQLite

## Phase 3: DuckDB Vectorized Query Acceleration in BLETrackerDB
- [x] Task: Integrate DuckDB engine into `BLETrackerDB` in `src/airtell/scripts/ble_antistalking_tracker.py` (Issues #18, #35, #36)
  - [x] Support DuckDB backend attachment for sliding-window anti-stalking heuristic checks
  - [x] Implement high-throughput aggregation queries for tracker frequencies, RSSI trends, and channel histograms
  - [x] Ensure seamless fallback to standard SQLite if DuckDB is disabled or encounters attachment errors

## Phase 4: Streamlit Dashboard Integration
- [x] Task: Integrate DuckDB analytical backend into Streamlit application (Issue #46)
  - [x] Cache DuckDB backend in `app/streamlit_app.py` via `get_analytics_backend()` / session state
  - [x] Accelerate packet inspection filtering in `app/views/packet_inspector.py`
  - [x] Accelerate signal trend charts in `app/views/rssi_trends.py`
  - [x] Accelerate alert feed queries in `app/views/alert_feed.py`
  - [x] Accelerate telemetry overview metrics in `app/views/telemetry_overview.py`

## Phase 5: Storage Performance Benchmarks
- [x] Task: Implement benchmark test suite in `tests/benchmarks/test_storage_benchmarks.py` (Issue #51)
  - [x] Generate synthetic observation datasets (10,000 to 100,000+ packets, with scalable fixtures for 1M/5M)
  - [x] Benchmark execution times comparing SQLite vs DuckDB for sliding-window heuristics and aggregations
  - [x] Assert 100% analytical result parity between SQLite and DuckDB

## Phase 6: Documentation Reconciliation
- [x] Task: Document DuckDB configuration, tuning, and migration guide in `docs/howto.md` (Issue #53)
  - [x] Document installation and environment configuration options (`DATABASE_BACKEND`, `DUCKDB_THREADS`, `DUCKDB_MEMORY_LIMIT`)
  - [x] Document performance characteristics and schema compatibility

## Phase 7: Verification & Issue Closures
- [x] Task: Run complete repository test suite (`uv run pytest`) and linter (`uv run ruff check .`)
- [x] Task: Close resolved GitHub issues (#18, #35, #36, #45, #46, #51, #53, #11)
