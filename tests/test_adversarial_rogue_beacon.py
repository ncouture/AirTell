"""Unit tests for synthetic rogue beacon generator and anti-stalking evasion benchmark."""

from __future__ import annotations

import tempfile

from airtell.adversarial.rogue_beacon import (
    AntiStalkingEvasionEvaluator,
    EvasionBenchmarkResult,
    RogueBeaconGenerator,
    SyntheticBeaconSpec,
)

try:
    from airtell.scripts.ble_antistalking_tracker import BLETrackerDB, classify_payload
except ImportError:
    from scripts.ble_antistalking_tracker import BLETrackerDB, classify_payload


def test_rogue_beacon_generator_payload_construction():
    """Verify bit-for-bit structure of generated rogue beacon advertising payloads."""
    generator = RogueBeaconGenerator()

    # 1. Apple Find My payload
    apple_spec = SyntheticBeaconSpec(
        network_type="Apple Find My",
        ephemeral_key="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
        mac_address="40:11:22:33:44:55",
        rssi=-65,
    )
    apple_pdu = generator.build_payload(apple_spec)
    assert len(apple_pdu) <= 31
    net, key = classify_payload(apple_pdu.hex())
    assert net == "Apple Find My"
    assert key == apple_spec.ephemeral_key[:44]

    # 2. Google Find Hub payload
    google_spec = SyntheticBeaconSpec(
        network_type="Google Find Hub",
        ephemeral_key="aabbccddeeff00112233445566778899",
        mac_address="50:99:88:77:66:55",
        rssi=-68,
    )
    google_pdu = generator.build_payload(google_spec)
    assert len(google_pdu) <= 31
    net, key = classify_payload(google_pdu.hex())
    assert net == "Google Find Hub"
    assert key.startswith("fe9f")
    assert google_spec.ephemeral_key[:32] in key

    # 3. Samsung SmartThings Find payload
    samsung_spec = SyntheticBeaconSpec(
        network_type="Samsung SmartThings Find",
        ephemeral_key="99887766554433221100",
        mac_address="60:AA:BB:CC:DD:EE",
        rssi=-70,
    )
    samsung_pdu = generator.build_payload(samsung_spec)
    assert len(samsung_pdu) <= 31
    net, key = classify_payload(samsung_pdu.hex())
    assert net == "Samsung SmartThings Find"

    # 4. Tile payload
    tile_spec = SyntheticBeaconSpec(
        network_type="Tile",
        ephemeral_key="feed11223344",
        mac_address="70:12:34:56:78:90",
        rssi=-72,
    )
    tile_pdu = generator.build_payload(tile_spec)
    assert len(tile_pdu) <= 31
    net, key = classify_payload(tile_pdu.hex())
    assert net == "Tile Tracker"


def test_rogue_beacon_generator_burst_sequence():
    """Verify generation of parameterized burst sequences with interval jitter."""
    generator = RogueBeaconGenerator()
    spec = SyntheticBeaconSpec(
        network_type="Apple Find My",
        ephemeral_key="0102030405060708090a0b0c0d0e0f10",
        mac_address="40:AA:BB:CC:DD:EE",
    )
    burst = generator.generate_burst(spec, count=5, interval_seconds=1.0, jitter_seconds=0.1)
    assert len(burst) == 5
    # Timestamps should be strictly monotonically increasing
    timestamps = [pkt.timestamp for pkt in burst]
    assert all(t2 > t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:]))


def test_anti_stalking_evasion_evaluator_benchmarks():
    """Verify that evasion evaluator tests both detection triggers and evasion strategies."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db = BLETrackerDB(tmp_db.name)
        evaluator = AntiStalkingEvasionEvaluator(db)

        # Scenario 1: Standard persistent tracking (should be detected)
        result_standard: EvasionBenchmarkResult = evaluator.evaluate_scenario(
            scenario_name="standard_persistence",
            packets_count=10,
            duration_minutes=8,
            rotation_interval_minutes=30,  # Slow rotation -> persists
        )
        assert result_standard.is_detected is True
        assert result_standard.alert_count >= 1

        # Scenario 2: Burst & Sleep evasion (few packets under threshold -> should evade)
        result_evasion: EvasionBenchmarkResult = evaluator.evaluate_scenario(
            scenario_name="burst_and_sleep",
            packets_count=4,  # Under the 5 packet threshold
            duration_minutes=2,  # Under the 5 minute threshold
            rotation_interval_minutes=30,
        )
        assert result_evasion.is_detected is False
        assert result_evasion.alert_count == 0
