"""Unit tests for rotating identifier deanonymization and rotation desynchronization analysis."""

from __future__ import annotations

from bluetooth_sniffle.adversarial.deanonymizer import (
    LinkabilityObservation,
    RotationDesyncAnalyzer,
    StaticLeakageDetector,
    TrajectoryReconstructor,
)


def test_static_leakage_detector_flags_public_mac():
    """Public or static random MAC addresses with rotating keys should trigger static leakage alert."""
    detector = StaticLeakageDetector()

    # Observation 1: Public MAC address, ephemeral key 1
    obs1 = LinkabilityObservation(
        mac_address="AA:BB:CC:11:22:33",
        mac_type="Public",
        ephemeral_key="4c00120102030405060708090a0b0c0d",
        timestamp=1000.0,
        rssi=-65,
        network_type="Apple Find My",
    )
    result1 = detector.analyze(obs1)
    assert result1.has_static_leakage is True
    assert "Public/Static MAC" in result1.reason

    # Observation 2: Same Public MAC, rotated ephemeral key
    obs2 = LinkabilityObservation(
        mac_address="AA:BB:CC:11:22:33",
        mac_type="Public",
        ephemeral_key="4c00120908070605040302010f0e0d0c",
        timestamp=1900.0,
        rssi=-66,
        network_type="Apple Find My",
    )
    result2 = detector.analyze(obs2)
    assert result2.has_static_leakage is True
    assert result2.leakage_category == "STATIC_MAC"


def test_static_leakage_detector_flags_constant_oui_prefix():
    """Randomized addresses preserving a static 24-bit OUI vendor prefix should be flagged."""
    detector = StaticLeakageDetector()

    # Series of RPA addresses that all share the exact same OUI prefix
    macs = [
        "F0:F5:BD:12:34:56",
        "F0:F5:BD:AB:CD:EF",
        "F0:F5:BD:99:88:77",
    ]
    for i, mac in enumerate(macs):
        obs = LinkabilityObservation(
            mac_address=mac,
            mac_type="RPA",
            ephemeral_key=f"fe9f{i:04x}11223344556677889900aabbccdd",
            timestamp=1000.0 + i * 300.0,
            rssi=-70,
            network_type="Google Find Hub",
        )
        res = detector.analyze(obs)
        if i >= 2:
            assert res.has_constant_oui is True
            assert res.oui_prefix == "F0:F5:BD"


def test_rotation_desync_analyzer_detects_timing_divergence():
    """Analyzer must calculate timing divergence when AdvA rotates before or after payload rotation."""
    analyzer = RotationDesyncAnalyzer()

    # Baseline observation at t=0
    analyzer.feed(
        LinkabilityObservation(
            mac_address="40:11:22:33:44:55",
            mac_type="RPA",
            ephemeral_key="key_alpha_1234567890",
            timestamp=1000.0,
            rssi=-60,
        )
    )

    # At t=100s: MAC rotates to new RPA, but ephemeral key remains 'key_alpha_1234567890' (Key outlived MAC)
    desync1 = analyzer.feed(
        LinkabilityObservation(
            mac_address="50:99:88:77:66:55",
            mac_type="RPA",
            ephemeral_key="key_alpha_1234567890",
            timestamp=1100.0,
            rssi=-62,
        )
    )
    assert desync1 is not None
    assert desync1.desync_type == "MAC_ROTATED_KEY_PERSISTED"
    assert desync1.delta_seconds >= 100.0
    assert desync1.is_linkable is True

    # At t=250s: Ephemeral key finally rotates to key_beta, while MAC remains unchanged (Key changed after MAC)
    desync2 = analyzer.feed(
        LinkabilityObservation(
            mac_address="50:99:88:77:66:55",
            mac_type="RPA",
            ephemeral_key="key_beta_9876543210",
            timestamp=1250.0,
            rssi=-61,
        )
    )
    assert desync2 is not None
    assert desync2.desync_type == "KEY_ROTATED_MAC_PERSISTED"
    assert desync2.delta_seconds == 150.0


def test_trajectory_reconstructor_links_rotated_beacons():
    """Trajectory reconstructor links sequential bursts across MAC rotation via RSSI and timing continuity."""
    reconstructor = TrajectoryReconstructor(max_time_gap=30.0, max_rssi_delta=15.0)

    # Observation from Tag A (MAC 1)
    obs1 = LinkabilityObservation(
        mac_address="44:11:22:33:44:11",
        mac_type="RPA",
        ephemeral_key="4c0012aaaa1111222233334444555566",
        timestamp=500.0,
        rssi=-58,
        network_type="Apple Find My",
    )
    # Observation from Tag A immediately after MAC rotation (MAC 2), similar RSSI and short time delta
    obs2 = LinkabilityObservation(
        mac_address="66:AA:BB:CC:DD:66",
        mac_type="RPA",
        ephemeral_key="4c0012bbbb1111222233334444555566",
        timestamp=505.0,
        rssi=-59,
        network_type="Apple Find My",
    )
    # Unrelated observation from different distant device with weak signal
    obs_unrelated = LinkabilityObservation(
        mac_address="77:00:11:22:33:77",
        mac_type="RPA",
        ephemeral_key="feed00112233",
        timestamp=506.0,
        rssi=-92,
        network_type="Tile",
    )

    reconstructor.add_observation(obs1)
    reconstructor.add_observation(obs2)
    reconstructor.add_observation(obs_unrelated)

    trajectories = reconstructor.reconstruct_trajectories()
    assert len(trajectories) >= 1

    # Find trajectory containing obs1
    traj_a = next(t for t in trajectories if obs1.mac_address in t.mac_addresses)
    assert obs2.mac_address in traj_a.mac_addresses
    assert obs_unrelated.mac_address not in traj_a.mac_addresses
    assert traj_a.confidence >= 0.70
