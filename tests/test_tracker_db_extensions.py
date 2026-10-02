"""Unit tests for BLETrackerDB extended schema: whitelists and alert_actions."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from scripts.ble_antistalking_tracker import BLETrackerDB


@pytest.fixture
def temp_db(tmp_path: Path) -> BLETrackerDB:
    """Create a fresh temporary SQLite tracker database."""
    db_file = tmp_path / "test_tracker.db"
    return BLETrackerDB(str(db_file))


def test_db_schema_initialization(temp_db: BLETrackerDB) -> None:
    """Validate that observations, alerts, whitelists, and alert_actions tables are created."""
    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

    assert "observations" in tables
    assert "alerts" in tables
    assert "whitelists" in tables
    assert "alert_actions" in tables


def test_whitelist_crud_operations(temp_db: BLETrackerDB) -> None:
    """Validate adding, querying, checking, and deleting whitelisted identifiers."""
    # Check non-existent
    assert not temp_db.is_whitelisted("ephemeral_key", "deadbeef01020304")
    assert not temp_db.is_whitelisted("mac_address", "AA:BB:CC:DD:EE:FF")

    # Add whitelist entries
    w_id1 = temp_db.add_whitelist("ephemeral_key", "deadbeef01020304", notes="Lab Beacon #1")
    assert w_id1 > 0
    w_id2 = temp_db.add_whitelist("mac_address", "AA:BB:CC:DD:EE:FF", notes="Research laptop")
    assert w_id2 > 0

    # Verify is_whitelisted
    assert temp_db.is_whitelisted("ephemeral_key", "deadbeef01020304")
    assert temp_db.is_whitelisted("mac_address", "AA:BB:CC:DD:EE:FF")
    # Case-insensitive checks
    assert temp_db.is_whitelisted("ephemeral_key", "DEADBEEF01020304")
    assert temp_db.is_whitelisted("mac_address", "aa:bb:cc:dd:ee:ff")

    # Fetch list
    all_whitelists = temp_db.get_whitelists()
    assert len(all_whitelists) == 2
    assert any(w["identifier_value"].lower() == "deadbeef01020304" for w in all_whitelists)

    # Delete
    assert temp_db.remove_whitelist(w_id1)
    assert not temp_db.is_whitelisted("ephemeral_key", "deadbeef01020304")
    assert temp_db.is_whitelisted("mac_address", "AA:BB:CC:DD:EE:FF")


def test_alert_actions_recording_and_retrieval(temp_db: BLETrackerDB) -> None:
    """Validate analyst alert acknowledgment and incident tagging."""
    # Record an observation and alert first
    obs_id = temp_db.insert_observation(
        mac_address="c0:11:22:33:44:55",
        rssi=-50,
        network_type="Apple Find My",
        ephemeral_key="key1234567890",
        channel=37,
        raw_payload="020106124c000215",
    )
    assert obs_id > 0

    alert_id = temp_db.log_alert(
        identifier="key1234567890",
        network_type="Apple Find My",
        count=8,
        max_rssi=-48,
        message="Persistent tracker detected",
    )
    assert alert_id > 0

    # Record action
    action_id = temp_db.record_alert_action(
        alert_id=alert_id,
        action_type="acknowledged",
        analyst_note="Authorized research device tested in Faraday cage.",
    )
    assert action_id > 0

    actions = temp_db.get_alert_actions(alert_id=alert_id)
    assert len(actions) == 1
    assert actions[0]["action_type"] == "acknowledged"
    assert "Faraday cage" in actions[0]["analyst_note"]


def test_stalking_heuristics_suppress_whitelisted_trackers(temp_db: BLETrackerDB) -> None:
    """Validate that whitelisted trackers do not trigger anti-stalking alerts."""
    now = time.time()
    key = "safe_beacon_key_999"

    # Insert 6 observations over 10 minutes (would normally trigger alert)
    for i in range(6):
        obs_time = now - (6 - i) * 100
        temp_db.insert_observation(
            mac_address=f"c0:11:22:33:44:{i:02x}",
            rssi=-60,
            network_type="Apple Find My",
            ephemeral_key=key,
            channel=37,
            raw_payload="020106",
            timestamp=obs_time,
        )

    # Before whitelisting, heuristics should find alert
    alerts = temp_db.check_stalking_heuristics(window_minutes=15, min_observations=5, min_duration_minutes=5)
    assert len(alerts) >= 1
    assert any(a["identifier"] == key for a in alerts)

    # Now whitelist the key
    temp_db.add_whitelist("ephemeral_key", key, notes="Whitelisted safe beacon")

    # Re-evaluate heuristics
    alerts_after = temp_db.check_stalking_heuristics(window_minutes=15, min_observations=5, min_duration_minutes=5)
    assert not any(a["identifier"] == key for a in alerts_after)
