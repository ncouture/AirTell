"""Unit and integration tests for pluggable DatabaseBackend abstraction (SQLite & DuckDB)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from airtell.telemetry.storage import (
    DuckDBBackend,
    SQLiteBackend,
    get_database_backend,
)


@pytest.fixture
def temp_sqlite_path(tmp_path: Path) -> str:
    """Return a temporary file path for a SQLite database."""
    return str(tmp_path / "telemetry_test.db")


@pytest.fixture
def temp_duckdb_path(tmp_path: Path) -> str:
    """Return a temporary file path for a native DuckDB database."""
    return str(tmp_path / "telemetry_test.duckdb")


def test_factory_get_database_backend(temp_sqlite_path: str) -> None:
    """Validate factory function returns proper backend types and falls back gracefully."""
    sqlite_be = get_database_backend(backend_type="sqlite", db_path=temp_sqlite_path)
    assert isinstance(sqlite_be, SQLiteBackend)

    duckdb_be = get_database_backend(backend_type="duckdb", db_path=temp_sqlite_path)
    assert isinstance(duckdb_be, DuckDBBackend)

    auto_be = get_database_backend(backend_type="auto", db_path=temp_sqlite_path)
    assert isinstance(auto_be, (DuckDBBackend, SQLiteBackend))

    # Fallback test with invalid/unsupported backend
    fallback_be = get_database_backend(backend_type="unknown_engine", db_path=temp_sqlite_path)
    assert isinstance(fallback_be, SQLiteBackend)


def test_sqlite_backend_crud_and_queries(temp_sqlite_path: str) -> None:
    """Validate SQLiteBackend observation insertion, alert recording, and queries."""
    backend = SQLiteBackend(temp_sqlite_path)

    # Insert observations
    now = time.time()
    id1 = backend.insert_observation(
        mac_address="c0:11:22:33:44:01",
        rssi=-50,
        network_type="Apple Find My",
        ephemeral_key="apple_key_01",
        channel=37,
        raw_payload="020106",
        timestamp=now - 100,
    )
    id2 = backend.insert_observation(
        mac_address="c0:11:22:33:44:02",
        rssi=-70,
        network_type="Google Find Hub",
        ephemeral_key="google_key_02",
        channel=38,
        raw_payload="020106",
        timestamp=now - 50,
    )
    assert id1 > 0
    assert id2 > id1

    # Query observations
    obs = backend.get_observations(limit=10)
    assert len(obs) == 2
    assert obs[0]["id"] == id2
    assert obs[1]["id"] == id1

    # Filter by network_type
    apple_obs = backend.get_observations(network_type="Apple Find My")
    assert len(apple_obs) == 1
    assert apple_obs[0]["mac_address"] == "c0:11:22:33:44:01"

    # Filter by search_query
    search_res = backend.get_observations(search_query="google_key")
    assert len(search_res) == 1
    assert search_res[0]["network_type"] == "Google Find Hub"

    # Channel distribution
    ch_dist = backend.get_channel_distribution()
    assert ch_dist.get(37) == 1
    assert ch_dist.get(38) == 1

    # Tracker frequencies
    freqs = backend.get_tracker_frequencies()
    assert len(freqs) == 2

    # Query DataFrame
    df = backend.query_df("SELECT count(*) as total FROM observations")
    assert isinstance(df, pd.DataFrame)
    assert df["total"].iloc[0] == 2

    backend.close()


def test_duckdb_backend_attached_to_sqlite(temp_sqlite_path: str) -> None:
    """Validate DuckDBBackend direct attachment to SQLite file with vectorized execution."""
    # First seed data via SQLiteBackend
    sqlite_be = SQLiteBackend(temp_sqlite_path)
    now = time.time()
    for i in range(10):
        sqlite_be.insert_observation(
            mac_address=f"c0:11:22:33:44:{i:02x}",
            rssi=-50 - i,
            network_type="Apple Find My" if i % 2 == 0 else "Tile",
            ephemeral_key=f"key_{i:02x}",
            channel=37 + (i % 3),
            timestamp=now - (10 - i) * 60,
        )
    sqlite_be.close()

    # Attach via DuckDBBackend
    duck_be = DuckDBBackend(temp_sqlite_path, threads=2, memory_limit="512MB")

    # Verify DuckDB reads SQLite observations
    obs = duck_be.get_observations(limit=50)
    assert len(obs) == 10

    # Test vectorized filtering
    apple_obs = duck_be.get_observations(network_type="Apple Find My", as_df=True)
    assert isinstance(apple_obs, pd.DataFrame)
    assert len(apple_obs) == 5

    # Test RSSI timeseries
    rssi_df = duck_be.get_rssi_timeseries(network_types=["Apple Find My"], as_df=True)
    assert isinstance(rssi_df, pd.DataFrame)
    assert len(rssi_df) == 5

    # Test channel distribution
    chans = duck_be.get_channel_distribution()
    assert sum(chans.values()) == 10

    # Test tracker frequencies
    freqs = duck_be.get_tracker_frequencies(min_count=1, as_df=True)
    assert isinstance(freqs, pd.DataFrame)
    assert len(freqs) == 10

    duck_be.close()


def test_duckdb_backend_native_file(temp_duckdb_path: str) -> None:
    """Validate DuckDBBackend operating on a native .duckdb database file."""
    backend = DuckDBBackend(temp_duckdb_path)

    now = time.time()
    id1 = backend.insert_observation(
        mac_address="c0:11:22:33:44:55",
        rssi=-52,
        network_type="Samsung SmartThings Find",
        ephemeral_key="samsung_key_01",
        channel=39,
        timestamp=now,
    )
    assert id1 > 0

    obs = backend.get_observations()
    assert len(obs) == 1
    assert obs[0]["mac_address"] == "c0:11:22:33:44:55"
    assert obs[0]["network_type"] == "Samsung SmartThings Find"

    backend.close()


def test_duckdb_in_memory_backend() -> None:
    """Validate DuckDBBackend operating in-memory (:memory:)."""
    backend = DuckDBBackend(":memory:")

    now = time.time()
    id1 = backend.insert_observation(
        mac_address="aa:bb:cc:dd:ee:ff",
        rssi=-48,
        network_type="Tile",
        ephemeral_key="tile_key_01",
        channel=37,
        timestamp=now,
    )
    assert id1 > 0

    obs = backend.get_observations(limit=10)
    assert len(obs) == 1
    assert obs[0]["network_type"] == "Tile"

    backend.close()


def test_backend_whitelist_and_alert_actions(temp_sqlite_path: str) -> None:
    """Validate whitelists and alert action logging across SQLite and DuckDB."""
    backend = get_database_backend("duckdb", db_path=temp_sqlite_path)

    # Whitelist operations
    w_id = backend.add_whitelist("ephemeral_key", "test_key_123", notes="Authorized beacon")
    assert w_id > 0
    assert backend.is_whitelisted("ephemeral_key", "test_key_123")
    assert backend.is_whitelisted("ephemeral_key", "TEST_KEY_123")
    assert not backend.is_whitelisted("ephemeral_key", "unknown_key")

    w_list = backend.get_whitelists()
    assert len(w_list) == 1
    assert w_list[0]["identifier_value"] == "test_key_123"

    # Alert action operations
    alert_id = backend.insert_alert(
        identifier="threat_tag_99",
        network_type="Apple Find My",
        observation_count=10,
        first_seen=100.0,
        last_seen=500.0,
        max_rssi=-45,
        alert_message="High proximity threat",
    )
    assert alert_id > 0

    action_id = backend.record_alert_action(
        alert_id=alert_id,
        action_type="investigating",
        analyst_note="Security team dispatched to sweep room.",
    )
    assert action_id > 0

    actions = backend.get_alert_actions(alert_id=alert_id)
    assert len(actions) == 1
    assert actions[0]["action_type"] == "investigating"

    # Remove whitelist
    assert backend.remove_whitelist(w_id)
    assert not backend.is_whitelisted("ephemeral_key", "test_key_123")

    backend.close()


def test_sliding_window_heuristics_parity(temp_sqlite_path: str) -> None:
    """Validate that sliding-window heuristics produce identical alerts on SQLite and DuckDB."""
    sqlite_be = SQLiteBackend(temp_sqlite_path)
    now = time.time()
    stalker_key = "stalker_beacon_par_01"

    # Insert 8 packets for stalker_key over 12 minutes
    for i in range(8):
        t = now - 720 + (i * 90)
        sqlite_be.insert_observation(
            mac_address=f"40:11:22:33:44:{i:02x}",
            rssi=-45 if i == 7 else -55,
            network_type="Apple Find My",
            ephemeral_key=stalker_key,
            channel=37,
            timestamp=t,
        )

    # Insert random single-packet background devices (should not trigger alert)
    for i in range(5):
        sqlite_be.insert_observation(
            mac_address=f"50:11:22:33:44:{i:02x}",
            rssi=-80,
            network_type="Google Find Hub",
            ephemeral_key=f"benign_{i}",
            channel=38,
            timestamp=now - 50,
        )

    # Run heuristics on SQLite
    sqlite_alerts = sqlite_be.check_stalking_heuristics(
        window_seconds=900,
        min_observations=5,
        min_time_span=300,
        cooldown_seconds=0,
        now=now,
    )
    assert len(sqlite_alerts) == 1
    assert sqlite_alerts[0]["tracker_id"] == stalker_key
    assert sqlite_alerts[0]["alert_level"] == "CRITICAL"

    # Attach DuckDB to the exact same database
    duck_be = DuckDBBackend(temp_sqlite_path)
    duck_alerts = duck_be.check_stalking_heuristics(
        window_seconds=900,
        min_observations=5,
        min_time_span=300,
        cooldown_seconds=0,
        now=now,
    )
    assert len(duck_alerts) == 1
    assert duck_alerts[0]["tracker_id"] == stalker_key
    assert duck_alerts[0]["alert_level"] == "CRITICAL"
    assert duck_alerts[0]["observation_count"] == sqlite_alerts[0]["observation_count"]
    assert duck_alerts[0]["max_rssi"] == sqlite_alerts[0]["max_rssi"]

    sqlite_be.close()
    duck_be.close()


def test_sqlite_in_memory_backend() -> None:
    """Validate SQLiteBackend operating in-memory (:memory:) with shared state across calls."""
    backend = SQLiteBackend(":memory:")

    now = time.time()
    id1 = backend.insert_observation(
        mac_address="c0:11:22:33:44:01",
        rssi=-52,
        network_type="Apple Find My",
        ephemeral_key="mem_key_01",
        channel=37,
        timestamp=now,
    )
    assert id1 > 0

    obs = backend.get_observations()
    assert len(obs) == 1
    assert obs[0]["ephemeral_key"] == "mem_key_01"

    # Test whitelist operations on in-memory SQLite
    w_id = backend.add_whitelist("ephemeral_key", "mem_key_01", notes="Authorized")
    assert w_id > 0
    assert backend.is_whitelisted("ephemeral_key", "mem_key_01")
    assert not backend.remove_whitelist(9999)  # Non-existent ID returns False
    assert backend.remove_whitelist(w_id)  # Existent ID returns True
    assert not backend.is_whitelisted("ephemeral_key", "mem_key_01")

    # Test alert recording and heuristics
    a_id = backend.insert_alert(
        identifier="mem_key_01",
        network_type="Apple Find My",
        observation_count=5,
        first_seen=now - 400,
        last_seen=now,
        max_rssi=-50,
        alert_message="Test alert",
        timestamp=now,
    )
    assert a_id > 0
    alerts = backend.get_alerts()
    assert len(alerts) == 1

    backend.close()


def test_duckdb_remove_whitelist_nonexistent() -> None:
    """Validate DuckDBBackend.remove_whitelist returns False when ID does not exist."""
    backend = DuckDBBackend(":memory:")

    w_id = backend.add_whitelist("ephemeral_key", "safe_key_01", notes="Safe tag")
    assert w_id > 0
    assert backend.is_whitelisted("ephemeral_key", "safe_key_01")

    # Removing non-existent ID must return False
    assert not backend.remove_whitelist(99999)

    # Removing existent ID must return True
    assert backend.remove_whitelist(w_id)
    assert not backend.is_whitelisted("ephemeral_key", "safe_key_01")

    backend.close()


def test_duckdb_fallback_to_sqlite_on_error(temp_sqlite_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate that DuckDBBackend gracefully falls back to SQLite when DuckDB query execution fails."""
    # Seed data into SQLite file
    sqlite_be = SQLiteBackend(temp_sqlite_path)
    now = time.time()
    sqlite_be.insert_observation(
        mac_address="c0:11:22:33:44:99",
        rssi=-55,
        network_type="Tile",
        ephemeral_key="tile_fallback_key",
        channel=37,
        timestamp=now,
    )
    sqlite_be.close()

    duck_be = DuckDBBackend(temp_sqlite_path)
    # Verify normal read
    assert len(duck_be.get_observations()) == 1

    class BrokenCon:
        def execute(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("Simulated DuckDB lock / failure")

        def close(self) -> None:
            pass

    monkeypatch.setattr(duck_be, "con", BrokenCon())

    # All analytical methods must seamlessly fall back to SQLiteBackend rather than crashing
    obs = duck_be.get_observations()
    assert len(obs) == 1
    assert obs[0]["mac_address"] == "c0:11:22:33:44:99"

    rssi_df = duck_be.get_rssi_timeseries(as_df=True)
    assert isinstance(rssi_df, pd.DataFrame)
    assert len(rssi_df) == 1

    chans = duck_be.get_channel_distribution()
    assert chans.get(37) == 1

    freqs = duck_be.get_tracker_frequencies()
    assert len(freqs) == 1

    alerts = duck_be.get_alerts()
    assert isinstance(alerts, list)

    duck_be.close()


def test_ble_tracker_db_backend_caching_and_close(temp_sqlite_path: str) -> None:
    """Validate BLETrackerDB backend caching, close lifecycle, and query parity."""
    from airtell.scripts.ble_antistalking_tracker import BLETrackerDB

    tracker = BLETrackerDB(db_path=temp_sqlite_path, enable_duckdb=False)
    be1 = tracker.backend
    be2 = tracker.backend
    # When DuckDB is disabled, backend must be cached, not re-created on every property access
    assert be1 is be2

    tracker.insert_observation("AA:BB:CC:DD:EE:FF", -58, "Apple Find My", "test_caching_key")
    obs = tracker.get_observations()
    assert len(obs) == 1

    # Toggle DuckDB attachment
    attached = tracker.attach_duckdb()
    assert attached
    assert tracker.enable_duckdb
    assert tracker.backend is tracker.duckdb_backend

    # Test close lifecycle
    tracker.close()
    assert tracker.duckdb_backend is None
    assert tracker._sqlite_backend is None


def test_factory_environment_variables(temp_sqlite_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate that get_database_backend respects DATABASE_BACKEND, DUCKDB_THREADS, and DUCKDB_MEMORY_LIMIT."""
    monkeypatch.setenv("DATABASE_BACKEND", "duckdb")
    monkeypatch.setenv("DUCKDB_THREADS", "2")
    monkeypatch.setenv("DUCKDB_MEMORY_LIMIT", "1GB")

    be = get_database_backend(db_path=temp_sqlite_path)
    assert isinstance(be, DuckDBBackend)
    assert be.threads == 2
    assert be.memory_limit == "1GB"
    be.close()

