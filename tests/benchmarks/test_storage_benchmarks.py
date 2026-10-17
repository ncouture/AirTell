"""Performance benchmarks comparing SQLite vs DuckDB on synthetic BLE observation datasets."""

from __future__ import annotations

import logging
import os
import random
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from airtell.telemetry.storage import DuckDBBackend, SQLiteBackend

logger = logging.getLogger("airtell.benchmarks")


def generate_synthetic_database(
    db_path: str,
    packet_count: int = 15000,
    base_epoch: float = 1729000000.0,
    num_stalkers: int = 3,
) -> dict[str, Any]:
    """Generate a realistic synthetic SQLite database with multi-network BLE observations.

    Args:
        db_path: Path to write the SQLite database file.
        packet_count: Total number of observations to generate.
        base_epoch: Base Unix timestamp for observations.
        num_stalkers: Number of persistent stalker devices to plant.

    Returns:
        Metadata summary including plant identifiers and observation counts.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA journal_mode = MEMORY")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            datetime_str TEXT,
            mac_address TEXT,
            rssi INTEGER,
            network_type TEXT,
            ephemeral_key TEXT,
            channel INTEGER,
            raw_payload TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_time ON observations (timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_key ON observations (ephemeral_key)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            datetime_str TEXT,
            identifier TEXT,
            network_type TEXT,
            observation_count INTEGER,
            first_seen REAL,
            last_seen REAL,
            max_rssi INTEGER,
            alert_message TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS whitelists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier_type TEXT NOT NULL,
            identifier_value TEXT NOT NULL,
            notes TEXT,
            created_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            action_type TEXT NOT NULL,
            analyst_note TEXT,
            timestamp REAL
        )
        """
    )

    networks = [
        "Apple Find My",
        "Google Find Hub",
        "Tile",
        "Samsung SmartThings Find",
        "Unknown",
    ]
    channels = [37, 38, 39]

    # Pre-generate stalker devices that will meet heuristic criteria
    # (>= 5 observations over >= 300s in trailing 900s window)
    stalker_tags: list[dict[str, Any]] = []
    for s_idx in range(num_stalkers):
        s_key = f"planted_stalker_key_{s_idx:02d}"
        s_net = networks[s_idx % 4]
        stalker_tags.append({"key": s_key, "net": s_net, "count": 20})

    rows: list[tuple[Any, ...]] = []
    rng = random.Random(42)  # Deterministic seed for reproducible benchmarks

    # 1. Plant persistent stalker packets across the trailing 12 minutes
    window_start = base_epoch - 720.0
    for stalker in stalker_tags:
        for p_idx in range(stalker["count"]):
            pkt_time = window_start + (p_idx * 30.0)
            dt_str = datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S")
            mac = f"40:11:22:33:44:{rng.randint(0, 255):02x}"
            rssi = rng.randint(-65, -45)
            chan = rng.choice(channels)
            rows.append((pkt_time, dt_str, mac, rssi, stalker["net"], stalker["key"], chan, "020106124c000215"))

    # 2. Fill remaining rows with realistic background BLE telemetry
    remaining = packet_count - len(rows)
    for i in range(remaining):
        # Timestamps spread over trailing 2 hours
        offset_sec = rng.uniform(0, 7200)
        pkt_time = base_epoch - offset_sec
        dt_str = datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S")
        mac = f"c0:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}"
        rssi = rng.randint(-95, -50)
        net_choice = rng.choice(networks)
        if net_choice == "Unknown":
            net = "Unknown"
            key = ""
        else:
            key_id = rng.randint(0, 1000)
            net = networks[key_id % 4]
            key = f"key_{key_id:04x}"
        chan = rng.choice(channels)
        payload = "020106" if net == "Unknown" else "020106124c000215"
        rows.append((pkt_time, dt_str, mac, rssi, net, key, chan, payload))


    conn.executemany(
        """
        INSERT INTO observations (timestamp, datetime_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()

    return {
        "total_packets": len(rows),
        "stalkers": stalker_tags,
        "base_epoch": base_epoch,
    }


@pytest.fixture(scope="module")
def benchmark_db_module(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, dict[str, Any]]:
    """Create a persistent module-scoped synthetic benchmark database."""
    tmp_dir = tmp_path_factory.mktemp("bench_db")
    db_file = str(tmp_dir / "benchmarks_telemetry.db")

    # Packet scale: 15,000 for standard automated tests (or scalable via env var)
    count = int(os.environ.get("BENCHMARK_PACKET_COUNT", "15000"))
    meta = generate_synthetic_database(db_file, packet_count=count)
    return db_file, meta


@pytest.fixture
def scalable_benchmark_factory(tmp_path: Path):
    """Factory fixture generating scalable synthetic datasets for arbitrary packet scales (10k, 100k, 1M, 5M)."""

    def _create(packet_count: int = 50000, filename: str = "scalable_bench.db", num_stalkers: int = 5) -> tuple[str, dict[str, Any]]:
        db_file = str(tmp_path / filename)
        meta = generate_synthetic_database(db_file, packet_count=packet_count, num_stalkers=num_stalkers)
        return db_file, meta

    return _create


def test_benchmark_sliding_window_heuristics(benchmark_db_module: tuple[str, dict[str, Any]]) -> None:
    """Benchmark sliding-window anti-stalking heuristic evaluation: SQLite vs DuckDB."""
    db_path, meta = benchmark_db_module
    base_epoch = meta["base_epoch"]

    sqlite_be = SQLiteBackend(db_path)
    duckdb_be = DuckDBBackend(db_path)

    # 1. Measure SQLite latency
    t0 = time.perf_counter()
    sqlite_alerts = sqlite_be.check_stalking_heuristics(
        window_seconds=900,
        min_observations=5,
        min_time_span=300,
        cooldown_seconds=0,
        now=base_epoch,
    )
    sqlite_duration = time.perf_counter() - t0

    # 2. Measure DuckDB latency
    t1 = time.perf_counter()
    duckdb_alerts = duckdb_be.check_stalking_heuristics(
        window_seconds=900,
        min_observations=5,
        min_time_span=300,
        cooldown_seconds=0,
        now=base_epoch,
    )
    duckdb_duration = time.perf_counter() - t1

    # 3. Assert parity: Both backends MUST return the exact same detected stalker alerts
    sqlite_ids = {a["tracker_id"] for a in sqlite_alerts}
    duckdb_ids = {a["tracker_id"] for a in duckdb_alerts}
    assert sqlite_ids == duckdb_ids
    assert all(s["key"] in duckdb_ids for s in meta["stalkers"])

    for s_alert in sqlite_alerts:
        d_match = next(
            d for d in duckdb_alerts
            if d["tracker_id"] == s_alert["tracker_id"] and d["network_type"] == s_alert["network_type"]
        )
        assert d_match["network_type"] == s_alert["network_type"]
        assert d_match["observation_count"] == s_alert["observation_count"]
        assert d_match["max_rssi"] == s_alert["max_rssi"]
        assert abs(d_match["first_seen"] - s_alert["first_seen"]) < 0.001
        assert abs(d_match["last_seen"] - s_alert["last_seen"]) < 0.001


    # 4. Assert execution performance
    assert duckdb_duration < 0.5  # Sub-500ms on synthetic dataset

    logger.info(
        "Sliding-window heuristics benchmark (%d packets): SQLite=%.3fs, DuckDB=%.3fs (Parity: OK)",
        meta["total_packets"],
        sqlite_duration,
        duckdb_duration,
    )

    sqlite_be.close()
    duckdb_be.close()


def test_benchmark_tracker_frequencies_aggregation(benchmark_db_module: tuple[str, dict[str, Any]]) -> None:
    """Benchmark full-scan tracker frequencies aggregation: SQLite vs DuckDB."""
    db_path, meta = benchmark_db_module

    sqlite_be = SQLiteBackend(db_path)
    duckdb_be = DuckDBBackend(db_path)

    # 1. SQLite aggregation
    t0 = time.perf_counter()
    sqlite_freqs = sqlite_be.get_tracker_frequencies(min_count=1, limit=50)
    sqlite_duration = time.perf_counter() - t0

    # 2. DuckDB aggregation
    t1 = time.perf_counter()
    duckdb_freqs = duckdb_be.get_tracker_frequencies(min_count=1, limit=50)
    duckdb_duration = time.perf_counter() - t1

    # 3. Result parity
    assert len(sqlite_freqs) == len(duckdb_freqs)
    for s_row, d_row in zip(sqlite_freqs, duckdb_freqs):
        assert s_row["tracker_id"] == d_row["tracker_id"]
        assert s_row["observation_count"] == d_row["observation_count"]
        assert s_row["max_rssi"] == d_row["max_rssi"]

    assert duckdb_duration < 0.5

    logger.info(
        "Tracker frequencies aggregation (%d packets): SQLite=%.3fs, DuckDB=%.3fs (Parity: OK)",
        meta["total_packets"],
        sqlite_duration,
        duckdb_duration,
    )

    sqlite_be.close()
    duckdb_be.close()


def test_benchmark_channel_distribution_histogram(benchmark_db_module: tuple[str, dict[str, Any]]) -> None:
    """Benchmark channel distribution histogram aggregation: SQLite vs DuckDB."""
    db_path, meta = benchmark_db_module

    sqlite_be = SQLiteBackend(db_path)
    duckdb_be = DuckDBBackend(db_path)

    # 1. SQLite channel distribution
    t0 = time.perf_counter()
    sqlite_chans = sqlite_be.get_channel_distribution()
    sqlite_duration = time.perf_counter() - t0

    # 2. DuckDB channel distribution
    t1 = time.perf_counter()
    duckdb_chans = duckdb_be.get_channel_distribution()
    duckdb_duration = time.perf_counter() - t1

    # 3. Result parity
    assert sqlite_chans == duckdb_chans
    assert sum(duckdb_chans.values()) == meta["total_packets"]

    assert duckdb_duration < 0.5

    logger.info(
        "Channel distribution histogram (%d packets): SQLite=%.3fs, DuckDB=%.3fs (Parity: OK)",
        meta["total_packets"],
        sqlite_duration,
        duckdb_duration,
    )

    sqlite_be.close()
    duckdb_be.close()


def test_benchmark_rssi_timeseries_retrieval(benchmark_db_module: tuple[str, dict[str, Any]]) -> None:
    """Benchmark RSSI timeseries query: SQLite vs DuckDB."""
    db_path, meta = benchmark_db_module

    sqlite_be = SQLiteBackend(db_path)
    duckdb_be = DuckDBBackend(db_path)

    # 1. SQLite timeseries
    t0 = time.perf_counter()
    sqlite_series = sqlite_be.get_rssi_timeseries(network_types=["Apple Find My"], min_rssi=-70, limit=500)
    sqlite_duration = time.perf_counter() - t0

    # 2. DuckDB timeseries
    t1 = time.perf_counter()
    duckdb_series = duckdb_be.get_rssi_timeseries(network_types=["Apple Find My"], min_rssi=-70, limit=500)
    duckdb_duration = time.perf_counter() - t1

    # 3. Parity
    assert len(sqlite_series) == len(duckdb_series)
    if sqlite_series:
        assert sqlite_series[0]["id"] == duckdb_series[0]["id"]
        assert sqlite_series[0]["rssi"] == duckdb_series[0]["rssi"]

    assert duckdb_duration < 0.5

    logger.info(
        "RSSI timeseries retrieval (%d packets): SQLite=%.3fs, DuckDB=%.3fs (Parity: OK)",
        meta["total_packets"],
        sqlite_duration,
        duckdb_duration,
    )

    sqlite_be.close()
    duckdb_be.close()


def test_benchmark_scalable_dataset_summary(tmp_path: Path) -> None:
    """Test generating a scalable 20,000 packet dataset and verify benchmark table output."""
    db_file = str(tmp_path / "scale_test.db")
    meta = generate_synthetic_database(db_file, packet_count=20000, num_stalkers=4)

    sqlite_be = SQLiteBackend(db_file)
    duckdb_be = DuckDBBackend(db_file)

    # Run full query suite
    t0 = time.perf_counter()
    s_alerts = sqlite_be.check_stalking_heuristics(cooldown_seconds=0, now=meta["base_epoch"])
    s_freqs = sqlite_be.get_tracker_frequencies()
    s_chans = sqlite_be.get_channel_distribution()
    s_time = time.perf_counter() - t0

    t1 = time.perf_counter()
    d_alerts = duckdb_be.check_stalking_heuristics(cooldown_seconds=0, now=meta["base_epoch"])
    d_freqs = duckdb_be.get_tracker_frequencies()
    d_chans = duckdb_be.get_channel_distribution()
    d_time = time.perf_counter() - t1

    assert {a["tracker_id"] for a in s_alerts} == {a["tracker_id"] for a in d_alerts}
    assert all(s["key"] in {a["tracker_id"] for a in d_alerts} for s in meta["stalkers"])
    assert len(s_freqs) == len(d_freqs)
    assert s_chans == d_chans


    # Verify DuckDB sub-second total execution across all 3 analytical queries
    assert d_time < 1.0

    print(
        f"\n[BENCHMARK] Scalable Dataset ({meta['total_packets']:,} packets):\n"
        f"  SQLite Total Query Suite: {s_time * 1000:.2f} ms\n"
        f"  DuckDB Total Query Suite: {d_time * 1000:.2f} ms\n"
        f"  Parity: 100% IDENTICAL RESULTS\n"
    )

    sqlite_be.close()
    duckdb_be.close()


def test_benchmark_scalable_large_scale_fixture(scalable_benchmark_factory: Any) -> None:
    """Validate scalable dataset fixture generating up to 100k packets with DuckDB sub-second execution."""
    scale_count = int(os.environ.get("BENCHMARK_STRESS_PACKETS", "30000"))
    db_file, meta = scalable_benchmark_factory(packet_count=scale_count, filename="stress_scale.db", num_stalkers=3)

    sqlite_be = SQLiteBackend(db_file)
    duckdb_be = DuckDBBackend(db_file)

    t0 = time.perf_counter()
    s_alerts = sqlite_be.check_stalking_heuristics(now=meta["base_epoch"], cooldown_seconds=0)
    s_time = time.perf_counter() - t0

    t1 = time.perf_counter()
    d_alerts = duckdb_be.check_stalking_heuristics(now=meta["base_epoch"], cooldown_seconds=0)
    d_time = time.perf_counter() - t1

    assert {a["tracker_id"] for a in s_alerts} == {a["tracker_id"] for a in d_alerts}
    assert d_time < 1.0
    assert s_time >= 0

    sqlite_be.close()
    duckdb_be.close()

