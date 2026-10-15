"""Unit and integration tests for two-ended BLE pairing relay testbed and SMP handshake analysis."""

from __future__ import annotations

from airtell.adversarial.relay import (
    PairingFailureCode,
    PairingRelayBridge,
    RelayedLinkLayerPacket,
    SMPPairingState,
)


def test_pairing_relay_bridge_packet_forwarding():
    """Verify that PairingRelayBridge forwards Link Layer frames with microsecond fidelity."""
    bridge = PairingRelayBridge()

    # Device 1 sniffs a CONNECT_IND frame
    connect_pdu = bytes.fromhex("0522112233445566aabbccddeeff0102030405060708090a0b0c0d0e0f10111213141516")
    packet = RelayedLinkLayerPacket(
        channel=37,
        rssi=-52,
        timestamp_usec=1700000000_123456,
        pdu_type="CONNECT_IND",
        initiator_mac="AA:BB:CC:DD:EE:FF",
        target_mac="11:22:33:44:55:66",
        raw_pdu=connect_pdu,
    )

    # Ingest from Device 1
    bridge.ingest_sniffed_packet(packet)
    assert bridge.pending_packets_count() == 1

    # Device 2 proxy retrieves packet
    forwarded = bridge.drain_next_packet()
    assert forwarded is not None
    assert forwarded.initiator_mac == "AA:BB:CC:DD:EE:FF"
    assert forwarded.target_mac == "11:22:33:44:55:66"
    assert forwarded.pdu_type == "CONNECT_IND"
    assert forwarded.timestamp_usec == 1700000000_123456
    assert bridge.pending_packets_count() == 0


def test_pairing_handshake_state_machine_tracking():
    """Verify SMP pairing handshake state transitions from REQ to CONFIRM or FAILED."""
    bridge = PairingRelayBridge()

    # 1. CONNECT_IND
    bridge.feed_pdu(
        pdu_type="CONNECT_IND",
        initiator_mac="40:11:22:33:44:55",
        target_mac="50:AA:BB:CC:DD:EE",
        payload_bytes=bytes.fromhex("052240112233445550aabbccddee"),
        timestamp_usec=1000_000,
    )
    assert bridge.current_pairing_state == SMPPairingState.CONNECTED

    # 2. SMP Pairing Request (Code 0x01)
    smp_req_payload = bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07])
    event1 = bridge.feed_pdu(
        pdu_type="SMP",
        initiator_mac="40:11:22:33:44:55",
        target_mac="50:AA:BB:CC:DD:EE",
        payload_bytes=smp_req_payload,
        timestamp_usec=1050_000,
    )
    assert event1 is not None
    assert bridge.current_pairing_state == SMPPairingState.PAIRING_REQUESTED
    assert event1.event_type == "SMP_PAIRING_REQUEST"

    # 3. SMP Pairing Response (Code 0x02)
    smp_rsp_payload = bytes([0x02, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07])
    event2 = bridge.feed_pdu(
        pdu_type="SMP",
        initiator_mac="50:AA:BB:CC:DD:EE",
        target_mac="40:11:22:33:44:55",
        payload_bytes=smp_rsp_payload,
        timestamp_usec=1090_000,
    )
    assert event2 is not None
    assert bridge.current_pairing_state == SMPPairingState.PAIRING_RESPONSE
    assert event2.event_type == "SMP_PAIRING_RESPONSE"


def test_pairing_failure_signal_extraction_and_mac_linkability():
    """Verify extraction of SMP Pairing Failed error codes and correlation across rotating MACs."""
    bridge = PairingRelayBridge()

    # Session 1: Initiator MAC 1 fails pairing with code 0x05 (PAIRING_NOT_SUPPORTED)
    smp_fail_05 = bytes([0x05, 0x05])  # SMP Code 0x05, Reason 0x05 (Pairing Not Supported)
    event_fail1 = bridge.feed_pdu(
        pdu_type="SMP",
        initiator_mac="40:11:22:33:44:11",
        target_mac="50:AA:BB:CC:DD:EE",
        payload_bytes=smp_fail_05,
        timestamp_usec=1000_000,
    )
    assert event_fail1 is not None
    assert event_fail1.event_type == "SMP_PAIRING_FAILED"
    assert event_fail1.failure_code == PairingFailureCode.PAIRING_NOT_SUPPORTED

    # Session 2: After MAC rotation to MAC 2, initiator exhibits the same unique failure code and timing
    event_fail2 = bridge.feed_pdu(
        pdu_type="SMP",
        initiator_mac="40:99:88:77:66:22",
        target_mac="50:AA:BB:CC:DD:EE",
        payload_bytes=smp_fail_05,
        timestamp_usec=1120_000,
    )
    assert event_fail2 is not None

    # Correlation query across rotating MACs
    linked_identities = bridge.get_linked_pairing_signatures()
    assert len(linked_identities) >= 1
    sig = linked_identities[0]
    assert "40:11:22:33:44:11" in sig.correlated_macs
    assert "40:99:88:77:66:22" in sig.correlated_macs
    assert sig.failure_code == PairingFailureCode.PAIRING_NOT_SUPPORTED
