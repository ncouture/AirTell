"""Empirical Adversarial Stress & Boundary Challenge Suite for Milestone 4.

Stress tests the Milestone 4 E2E side-channel analysis pipeline under extreme
conditions:
1. Malformed PCAP records & headers (corrupted magic, invalid DLT, truncated headers/payloads).
2. Truncated Link-Layer & L2CAP frames (truncated control PDUs, partial ATT signed writes, malformed ADVs).
3. Corrupted & pathological timestamps (negative timestamps, backwards drift, microsecond overflows, 32-bit roll).
4. High packet volume & burst floods (10,000+ packets throughput, sub-second latency, queue bounding).
5. Rapid connection tear-downs & state churn (abrupt terminations, connection AA reuse, collisions).
6. Mutation coverage validation (verifying test assertion sensitivity against inverted/mutated traces).
"""

from __future__ import annotations

import struct
import time

import pytest

from airtell.sidechannel import (
    BlePacketRecord,
    Verdict,
    analyze_pcap,
    analyze_stream,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_header,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_ll_terminate_ind,
    build_scan_req,
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
    generate_synthetic_pcap,
)
from airtell.sidechannel.ll_dissector import (
    dissect_advertising_pdu,
    dissect_data_channel_pdu,
)
from airtell.sidechannel.synthetic import (
    ERROR_PIN_OR_KEY_MISSING,
    OPCODE_LL_ENC_REQ,
    SyntheticEvent,
)
from airtell.sniff.pcap import (
    BLE_ADV_AA,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    GLOBAL_HEADER_FORMAT,
    PACKET_HEADER_FORMAT,
    PCAP_MAGIC_USEC,
)

CSRK_TEST_KEY: bytes = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"


# =============================================================================
# 1. Malformed PCAP Records & Headers
# =============================================================================
class TestAdversarialPcapExtremeConditions:
    """Stress tests PCAP parser with malformed headers, corrupt magic, and invalid payloads."""

    def test_pcap_corrupted_magic_raises_value_error(self) -> None:
        """PCAP with corrupt magic number (0xDEADBEEF) is rejected immediately."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, 0xDEADBEEF, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        with pytest.raises(ValueError, match="Invalid PCAP magic: 0xDEADBEEF"):
            analyze_pcap(hdr)

    def test_pcap_unsupported_dlt_raises_value_error(self) -> None:
        """PCAP with unsupported DLT (e.g. Ethernet DLT=1) is rejected immediately."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, 1)
        with pytest.raises(ValueError, match="Unsupported LinkType: 1"):
            analyze_pcap(hdr)

    def test_pcap_truncated_global_header_raises_value_error(self) -> None:
        """PCAP shorter than 24-byte global header raises ValueError."""
        with pytest.raises(ValueError, match="File too short for PCAP global header"):
            analyze_pcap(b"\xD4\xC3\xB2\xA1\x02\x00")

    def test_pcap_truncated_packet_header_handled_as_eof(self) -> None:
        """Valid 24-byte global header followed by truncated 7-byte packet header yields 0 packets."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        rep = analyze_pcap(hdr + b"\x01\x02\x03\x04\x05\x06\x07")
        assert rep.total_packets == 0
        assert rep.overall_verdict == Verdict.INCONCLUSIVE.value

    def test_pcap_truncated_packet_payload_raises_eof_error(self) -> None:
        """Packet header claiming 100 bytes payload when only 10 bytes remain raises EOFError."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        pkt_hdr = struct.pack(PACKET_HEADER_FORMAT, 1000, 0, 100, 100)
        with pytest.raises(EOFError, match="Truncated packet payload in PCAP"):
            analyze_pcap(hdr + pkt_hdr + b"\x00" * 10)

    def test_pcap_payload_too_short_for_phdr_raises_value_error(self) -> None:
        """Packet payload shorter than 17-byte pseudo-header minimum raises ValueError."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        pkt_hdr = struct.pack(PACKET_HEADER_FORMAT, 1000, 0, 12, 12)
        with pytest.raises(ValueError, match="Payload too short for BLE PHDR"):
            analyze_pcap(hdr + pkt_hdr + b"\x00" * 12)

    def test_pcap_massive_incl_len_exceeding_stream(self) -> None:
        """Packet header with massive incl_len (0x7FFFFFFF) raises EOFError without crashing memory."""
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        pkt_hdr = struct.pack(PACKET_HEADER_FORMAT, 1000, 0, 0x7FFFFFFF, 0x7FFFFFFF)
        with pytest.raises(EOFError):
            analyze_pcap(hdr + pkt_hdr + b"\x00" * 10)


# =============================================================================
# 2. Truncated Link-Layer & L2CAP Frames
# =============================================================================
class TestAdversarialFrameTruncationsAndMalformations:
    """Stress tests frame dissectors and analyzers against truncated and malformed PDUs."""

    def test_truncated_adv_ind_missing_adva(self) -> None:
        """ADV_IND truncated before 6-byte AdvA is handled safely."""
        pdu = dissect_advertising_pdu(b"\x00\x02\x01\x02")  # Header length 2, but needs 6B AdvA
        assert pdu is not None
        assert pdu.adv_a is None

    def test_truncated_adv_direct_ind_missing_targeta(self) -> None:
        """ADV_DIRECT_IND containing AdvA but truncated before TargetA is handled safely."""
        pdu = dissect_advertising_pdu(b"\x01\x06\x11\x22\x33\x44\x55\x66")
        assert pdu is not None
        assert pdu.target_a is None

    def test_truncated_connect_ind_missing_lldata(self) -> None:
        """CONNECT_IND with addresses but truncated LLData does not produce invalid connection profiles."""
        pdu = dissect_advertising_pdu(b"\x05\x0C" + b"\x11" * 6 + b"\x22" * 6)
        assert pdu is not None
        assert pdu.conn_aa is None
        assert pdu.interval is None

    def test_data_pdu_sub_header_truncation(self) -> None:
        """Data channel PDU with 0 or 1 byte total length returns None safely."""
        assert dissect_data_channel_pdu(b"") is None
        assert dissect_data_channel_pdu(b"\x03") is None

    def test_ll_control_pdu_declared_length_zero(self) -> None:
        """LLID=0b11 (Control) with declared length=0 has control_frame=None."""
        pdu = dissect_data_channel_pdu(b"\x03\x00")
        assert pdu is not None
        assert pdu.control_frame is None

    def test_ll_enc_req_truncated_payload_fallback(self) -> None:
        """LL_ENC_REQ opcode with truncated payload sets error flag and missing fields to None."""
        # 1-byte opcode only, missing rand, ediv, skdm, ivm
        pdu = dissect_data_channel_pdu(bytes([0x03, 0x01, OPCODE_LL_ENC_REQ]))
        assert pdu is not None
        assert pdu.control_frame is not None
        assert pdu.control_frame.opcode == OPCODE_LL_ENC_REQ
        assert pdu.control_frame.payload.get("error") == "truncated_enc_req"
        assert pdu.control_frame.payload.get("ediv") is None

    def test_l2cap_truncated_header_missing_cid(self) -> None:
        """L2CAP start PDU (LLID=0b10) with length < 4 bytes cannot parse CID and yields att_frame=None."""
        pdu = dissect_data_channel_pdu(bytes([0x02, 0x02, 0x05, 0x00]))
        assert pdu is not None
        assert pdu.att_frame is None

    def test_att_signed_write_truncated_missing_signature(self) -> None:
        """ATT Signed Write (Opcode 0xD2) with length < 15 bytes yields att_frame=None."""
        # LLID=0b10, L2CAP len=5, CID=0x0004, Opcode=0xD2, handle=0x0001 (only 1B value, missing 12B sig)
        raw = build_ll_header(0b10, 8) + struct.pack("<HH", 4, 0x0004) + b"\xD2\x01\x00\x00"
        pdu = dissect_data_channel_pdu(raw)
        assert pdu is not None
        assert pdu.att_frame is None


# =============================================================================
# 3. Corrupted & Pathological Timestamps
# =============================================================================
class TestAdversarialTimestampCorruptionsAndJitter:
    """Stress tests timestamp handling with negative values, backwards drift, and overflows."""

    def test_negative_timestamp_stream_processing(self) -> None:
        """BlePacketRecord with negative timestamp_usec does not crash analysis engine."""
        records = [
            BlePacketRecord(
                body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                channel=37,
                rssi=-60,
                timestamp_usec=-50_000_000,
                access_address=BLE_ADV_AA,
            ),
            BlePacketRecord(
                body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                channel=37,
                rssi=-60,
                timestamp_usec=-20_000_000,
                access_address=BLE_ADV_AA,
            ),
        ]
        rep = analyze_stream(records, analyzers=["bat"])
        assert rep.total_packets == 2
        assert rep.overall_verdict == Verdict.INCONCLUSIVE.value

    def test_reverse_out_of_order_timestamps(self) -> None:
        """Stream with strictly decreasing timestamps is processed without crash or division by zero."""
        records = [
            BlePacketRecord(
                body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                channel=37,
                rssi=-60,
                timestamp_usec=200_000_000,
                access_address=BLE_ADV_AA,
            ),
            BlePacketRecord(
                body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                channel=37,
                rssi=-60,
                timestamp_usec=100_000_000,
                access_address=BLE_ADV_AA,
            ),
            BlePacketRecord(
                body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                channel=37,
                rssi=-60,
                timestamp_usec=50_000_000,
                access_address=BLE_ADV_AA,
            ),
        ]
        rep = analyze_stream(records, analyzers=["bat"])
        assert rep.total_packets == 3
        # Intervals are strictly non-negative; negative delta skips interval appending
        assert len(rep.reports["bat_allowlist"].findings) == 0

    def test_extreme_temporal_gap_across_connections(self) -> None:
        """Temporal gap of 3600 seconds prevents false cross-RPA linking in CSRK tracker."""
        conn_aa1 = 0x11112222
        conn_aa2 = 0x33334444
        events = [
            # Session 1 at t=1,000s
            SyntheticEvent(ts_usec=1_000_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("44:55:66:77:88:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa1)),
            SyntheticEvent(ts_usec=1_000_010_000, chan=1, aa=conn_aa1, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY, handle=0x0012, value=b"\x01", counter=10)),
            # Session 2 at t=4,600s (+3600s, well beyond 300s temporal linking limit)
            SyntheticEvent(ts_usec=4_600_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("44:55:66:77:88:02", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa2)),
            SyntheticEvent(ts_usec=4_600_010_000, chan=1, aa=conn_aa2, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY, handle=0x0012, value=b"\x01", counter=11)),
        ]
        pcap_data = generate_synthetic_pcap(events)
        rep = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY)
        # Should NOT link RPAs due to expired temporal window
        assert rep.reports["csrk_counter"].verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert len(rep.reports["csrk_counter"].metrics["linked_rpa_groups"]) == 0


# =============================================================================
# 4. High Packet Volume & Burst Floods
# =============================================================================
class TestAdversarialHighVolumeAndBurstStress:
    """Stress tests performance and queue stability under high packet volumes."""

    def test_ten_thousand_packets_high_throughput(self) -> None:
        """10,000 synthetic packets processed across all analyzers in under 1.0 second."""
        conn_aa = 0x33445566
        records: list[BlePacketRecord] = [
            BlePacketRecord(
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
                channel=37,
                rssi=-50,
                timestamp_usec=1_000_000,
                access_address=BLE_ADV_AA,
            )
        ]

        # 10,000 signed write packets
        for i in range(10000):
            records.append(
                BlePacketRecord(
                    body=build_att_signed_write(csrk=CSRK_TEST_KEY, handle=0x0012, value=b"\x01", counter=i),
                    channel=i % 37,
                    rssi=-60,
                    timestamp_usec=1_000_000 + (i * 10),
                    access_address=conn_aa,
                )
            )

        t_start = time.perf_counter()
        rep = analyze_stream(records, analyzers=["all"], csrk=CSRK_TEST_KEY)
        elapsed = time.perf_counter() - t_start

        assert rep.total_packets == 10001
        assert rep.reports["csrk_counter"].metrics["total_signed_writes"] == 10000
        assert elapsed < 1.0, f"10k packet analysis took {elapsed:.2f}s, expected < 1.0s"

    def test_probe_flood_and_bulk_expiration(self) -> None:
        """3,000 active scan probes arriving in the same millisecond are expired cleanly without leak."""
        records: list[BlePacketRecord] = []
        base_ts = 1_000_000
        periph = "AA:BB:CC:DD:EE:02"

        for i in range(3000):
            records.append(
                BlePacketRecord(
                    body=build_scan_req(f"10:00:00:{(i//65536)%256:02X}:{(i//256)%256:02X}:{i%256:02X}", periph),
                    channel=37,
                    rssi=-55,
                    timestamp_usec=base_ts + (i % 500),
                    access_address=BLE_ADV_AA,
                )
            )

        # Trigger bulk expiration with packet 10ms later
        records.append(
            BlePacketRecord(
                body=build_adv_ind(periph),
                channel=37,
                rssi=-55,
                timestamp_usec=base_ts + 50_000,
                access_address=BLE_ADV_AA,
            )
        )

        t_start = time.perf_counter()
        rep = analyze_stream(records, analyzers=["bat"])
        elapsed = time.perf_counter() - t_start

        assert rep.total_packets == 3001
        assert elapsed < 1.0


# =============================================================================
# 5. Rapid Connection Tear-Downs & State Churn
# =============================================================================
class TestAdversarialRapidConnectionTearDowns:
    """Stress tests state machines under rapid connection creation, aborts, and terminations."""

    def test_hundred_rapid_connect_terminate_cycles(self) -> None:
        """100 rapid connection and immediate termination cycles produce clean INCONCLUSIVE verdict."""
        records: list[BlePacketRecord] = []
        ts = 1_000_000

        for i in range(100):
            conn_aa = 0x20000000 + i
            records.append(
                BlePacketRecord(
                    body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
                    channel=37,
                    rssi=-50,
                    timestamp_usec=ts,
                    access_address=BLE_ADV_AA,
                )
            )
            records.append(
                BlePacketRecord(
                    body=build_ll_terminate_ind(0x13),
                    channel=1,
                    rssi=-50,
                    timestamp_usec=ts + 10,
                    access_address=conn_aa,
                )
            )
            ts += 50

        rep = analyze_stream(records, analyzers=["encryption"])
        assert rep.total_packets == 200
        assert rep.reports["differential_encryption"].metrics["total_connections"] == 100
        assert rep.reports["differential_encryption"].metrics["shared_ltk_sessions"] == 0
        assert rep.reports["differential_encryption"].verdict == Verdict.INCONCLUSIVE.value

    def test_aborted_encryption_handshake_via_terminate_ind(self) -> None:
        """LL_ENC_REQ followed immediately by LL_TERMINATE_IND resets session without false findings."""
        conn_aa = 0x55443322
        events = [
            SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa)),
            SyntheticEvent(ts_usec=2000, chan=1, aa=conn_aa, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=3000, chan=1, aa=conn_aa, direction=0, body=build_ll_terminate_ind(0x13)),
        ]
        pcap_data = generate_synthetic_pcap(events)
        rep = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert rep.overall_verdict == Verdict.INCONCLUSIVE.value
        assert len(rep.reports["differential_encryption"].findings) == 0

    def test_sequential_connections_distinct_access_addresses(self) -> None:
        """Two sequential connections with distinct Access Addresses produce CONFIRMED_EXCLUSIVE."""
        conn_aa1 = 0x8899AABB
        conn_aa2 = 0x8899AACC
        events = [
            # Connection 1: Shared LTK
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa1)),
            SyntheticEvent(ts_usec=1_010_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=1_020_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=1_030_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=1_040_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=1_050_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
            SyntheticEvent(ts_usec=1_060_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_terminate_ind(0x13)),

            # Connection 2: Rejected
            SyntheticEvent(ts_usec=2_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", conn_aa=conn_aa2)),
            SyntheticEvent(ts_usec=2_010_000, chan=1, aa=conn_aa2, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=2_020_000, chan=1, aa=conn_aa2, direction=1, body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING)),
        ]
        pcap_data = generate_synthetic_pcap(events)
        rep = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert rep.overall_verdict == Verdict.CONFIRMED_EXCLUSIVE.value

    def test_identical_access_address_collision_behavior(self) -> None:
        """Sequential connections reusing identical AA coalesce under physical layer AA grouping."""
        conn_aa = 0x8899AABB
        events = [
            # Connection 1: Shared LTK
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa)),
            SyntheticEvent(ts_usec=1_010_000, chan=1, aa=conn_aa, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=1_020_000, chan=1, aa=conn_aa, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=1_030_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=1_040_000, chan=1, aa=conn_aa, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=1_050_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
            SyntheticEvent(ts_usec=1_060_000, chan=1, aa=conn_aa, direction=0, body=build_ll_terminate_ind(0x13)),

            # Connection 2: Reusing conn_aa, Rejected
            SyntheticEvent(ts_usec=2_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", conn_aa=conn_aa)),
            SyntheticEvent(ts_usec=2_010_000, chan=1, aa=conn_aa, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=2_020_000, chan=1, aa=conn_aa, direction=1, body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING)),
        ]
        pcap_data = generate_synthetic_pcap(events)
        rep = analyze_pcap(pcap_data, analyzers=["encryption"])
        # Because session state was established on conn_aa, in-session state isolation preserves PAIRED_SHARED_LTK
        assert rep.overall_verdict == Verdict.PAIRED_SHARED_LTK.value


# =============================================================================
# 6. Mutation Testing & Assertion Sensitivity
# =============================================================================
class TestAdversarialMutationSensitivity:
    """Verifies that test assertions fail when inputs or expectations are mutated."""

    def test_mutation_shared_ltk_assertion_fails_on_rejected_trace(self) -> None:
        """Asserting PAIRED_SHARED_LTK on a rejected trace fails."""
        pcap = generate_encryption_trace(shared_ltk=False, error_code=ERROR_PIN_OR_KEY_MISSING)
        rep = analyze_pcap(pcap, analyzers=["encryption"]).reports["differential_encryption"]
        with pytest.raises(AssertionError):
            assert rep.verdict == Verdict.PAIRED_SHARED_LTK.value

    def test_mutation_rejected_untrusted_assertion_fails_on_shared_trace(self) -> None:
        """Asserting REJECTED_UNTRUSTED on a shared LTK trace fails."""
        pcap = generate_encryption_trace(shared_ltk=True)
        rep = analyze_pcap(pcap, analyzers=["encryption"]).reports["differential_encryption"]
        with pytest.raises(AssertionError):
            assert rep.verdict == Verdict.REJECTED_UNTRUSTED.value

    def test_mutation_csrk_monotonic_assertion_fails_on_replay(self) -> None:
        """Asserting SEQUENTIAL_MONOTONIC on a replayed trace fails."""
        pcap = generate_csrk_trace(counter_sequence=[10, 11, 11, 12], csrk=CSRK_TEST_KEY)
        rep = analyze_pcap(pcap, analyzers=["csrk"]).reports["csrk_counter"]
        with pytest.raises(AssertionError):
            assert rep.verdict == Verdict.SEQUENTIAL_MONOTONIC.value

    def test_mutation_csrk_replay_assertion_fails_on_monotonic(self) -> None:
        """Asserting ANOMALY_REPLAY on a monotonic trace fails."""
        pcap = generate_csrk_trace(counter_sequence=[10, 11, 12, 13], csrk=CSRK_TEST_KEY)
        rep = analyze_pcap(pcap, analyzers=["csrk"]).reports["csrk_counter"]
        with pytest.raises(AssertionError):
            assert rep.verdict == Verdict.ANOMALY_REPLAY.value

    def test_mutation_bat_allowlist_assertion_fails_on_open_device(self) -> None:
        """Asserting ALLOWLIST_CONFIRMED on an open advertiser trace fails."""
        pcap = generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="11:22:33:44:55:66",
            periph_addr="AA:BB:CC:DD:EE:02",
            mode="selective_probe",
        )
        rep = analyze_pcap(pcap, analyzers=["bat"]).reports["bat_allowlist"]
        with pytest.raises(AssertionError):
            assert rep.verdict == Verdict.ALLOWLIST_CONFIRMED.value
