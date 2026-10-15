"""Adversarial stress testing & empirical challenge suite for Milestone 2.

Covers:
1. Malformed Opcodes & Frame Fuzzing (All 256 opcodes, random bit fuzzing, oversized payloads).
2. Truncated PDUs & Header Discrepancies (Length discrepancies, sub-header truncations).
3. Adversarial Handshake State Transitions (Out-of-order, packet drops, premature terminations, floods).
4. Empirical Verification of Discovered Vulnerabilities:
   - Truncated LL_REJECT_IND / LL_REJECT_EXT_IND unhandled TypeError in string formatting.
   - Cross-procedure false positive classification of non-encryption rejections (LL_REJECT_EXT_IND).
   - In-session state corruption causing false CONFIRMED_EXCLUSIVE verdict on single connection.
   - Redundant finding duplication across standard dual LL_START_ENC_RSP and RF retransmissions.
   - Filter leakage on unassociated data channel connections.
5. Large-Scale Interleaved & Concurrent Connection Stress Harness (100 concurrent connections).
"""

from __future__ import annotations

import io
import random
import struct

from airtell.sidechannel import (
    BlePacketRecord,
    DifferentialEncryptionAnalyzer,
    EncryptionInitiationFinding,
    SyntheticEvent,
    Verdict,
    build_connect_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_header,
    build_ll_reject_ext_ind,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_ll_terminate_ind,
    dissect_advertising_pdu,
    dissect_data_channel_pdu,
    dissect_ll_control_pdu,
    generate_encryption_trace,
)
from airtell.sniff.pcap import BLE_ADV_AA, CapturedBlePacket, PcapBleReader


# =============================================================================
# 1. Malformed Opcodes & Frame Fuzzing Stress Harness
# =============================================================================
class TestDissectorFuzzingAndMalformedOpcodes:
    """Stress tests dissectors with malformed opcodes, random noise, and fuzzing."""

    def test_fuzz_all_256_opcodes_empty_payload(self) -> None:
        """Every single byte opcode (0x00-0xFF) with 0-byte payload must not crash."""
        for op in range(256):
            pdu = bytes([op])
            frame = dissect_ll_control_pdu(pdu)
            assert frame is not None
            assert frame.opcode == op
            assert isinstance(frame.payload, dict)

    def test_fuzz_all_256_opcodes_short_payload(self) -> None:
        """Every single byte opcode (0x00-0xFF) with 1 to 5 random bytes must not crash."""
        rng = random.Random(42)
        for op in range(256):
            payload = rng.randbytes(rng.randint(1, 5))
            frame = dissect_ll_control_pdu(bytes([op]) + payload)
            assert frame is not None
            assert frame.opcode == op

    def test_fuzz_all_256_opcodes_oversized_payload(self) -> None:
        """Every opcode with 255 bytes of arbitrary data must not crash."""
        rng = random.Random(1337)
        for op in range(256):
            payload = rng.randbytes(255)
            frame = dissect_ll_control_pdu(bytes([op]) + payload)
            assert frame is not None
            assert frame.opcode == op

    def test_fuzz_random_data_channel_payloads_1000_trials(self) -> None:
        """1,000 completely random byte sequences must be parsed safely by data channel dissector."""
        rng = random.Random(2026)
        for _ in range(1000):
            length = rng.randint(0, 300)
            garbage = rng.randbytes(length)
            # Must return DissectedDataPdu or None, never crash
            res = dissect_data_channel_pdu(garbage)
            if length < 2:
                assert res is None
            else:
                assert res is not None

    def test_fuzz_random_advertising_payloads_1000_trials(self) -> None:
        """1,000 completely random byte sequences must be parsed safely by advertising dissector."""
        rng = random.Random(9999)
        for _ in range(1000):
            length = rng.randint(0, 300)
            garbage = rng.randbytes(length)
            res = dissect_advertising_pdu(garbage)
            if length < 2:
                assert res is None
            else:
                assert res is not None

    def test_fuzz_corrupted_ll_headers(self) -> None:
        """Exhaustive test across all 4 LLID combinations (0b00, 0b01, 0b10, 0b11)."""
        for llid in (0, 1, 2, 3):
            for sn in (0, 1):
                for nesn in (0, 1):
                    hdr0 = llid | (nesn << 2) | (sn << 3)
                    hdr1 = 16  # declared length
                    raw = bytes([hdr0, hdr1]) + b"\x55" * 16
                    dissected = dissect_data_channel_pdu(raw)
                    assert dissected is not None
                    assert dissected.llid == llid
                    assert dissected.sn == sn
                    assert dissected.nesn == nesn
                    assert dissected.length == 16


# =============================================================================
# 2. Truncated PDUs & Header Discrepancies
# =============================================================================
class TestTruncatedPdusAndBufferDiscrepancies:
    """Stress tests boundary truncations and buffer/header discrepancies."""

    def test_truncated_data_pdu_sub_two_bytes(self) -> None:
        """Buffers smaller than 2-byte LL header must safely return None."""
        assert dissect_data_channel_pdu(b"") is None
        assert dissect_data_channel_pdu(b"\x00") is None
        assert dissect_advertising_pdu(b"") is None
        assert dissect_advertising_pdu(b"\x05") is None

    def test_declared_length_exceeds_actual_buffer(self) -> None:
        """Declared length = 255 but buffer only has 10 bytes."""
        raw = bytes([0x03, 0xFF]) + b"\x03" + b"\x00" * 7
        dissected = dissect_data_channel_pdu(raw)
        assert dissected is not None
        assert dissected.length == 255
        assert len(dissected.raw_payload) == 8  # truncated payload preserved safely
        assert dissected.control_frame is not None

    def test_declared_length_smaller_than_actual_buffer(self) -> None:
        """Declared length = 2 but buffer has 100 bytes (trailing data)."""
        raw = bytes([0x03, 0x02, 0x0D, 0x06]) + b"\xAA" * 96
        dissected = dissect_data_channel_pdu(raw)
        assert dissected is not None
        assert dissected.length == 2
        assert len(dissected.raw_payload) == 2  # exactly length sliced

    def test_truncated_enc_req_payload_boundary_sweep(self) -> None:
        """LL_ENC_REQ requires 22 bytes. Slicing from 0 to 21 bytes must flag truncated."""
        full_payload = b"\x01" * 8 + b"\x12\x34" + b"\x02" * 8 + b"\x03" * 4
        assert len(full_payload) == 22

        for plen in range(22):
            ctr_data = bytes([0x03]) + full_payload[:plen]
            frame = dissect_ll_control_pdu(ctr_data)
            assert frame is not None
            assert frame.opcode == 0x03
            assert frame.payload.get("error") == "truncated_enc_req"
            assert "ediv" not in frame.payload

        # Exactly 22 bytes must parse successfully
        valid_frame = dissect_ll_control_pdu(bytes([0x03]) + full_payload)
        assert valid_frame is not None
        assert valid_frame.payload.get("ediv") == 0x3412

    def test_truncated_enc_rsp_payload_boundary_sweep(self) -> None:
        """LL_ENC_RSP requires 12 bytes. Slicing from 0 to 11 bytes must flag truncated."""
        full_payload = b"\xAA" * 8 + b"\xBB" * 4
        for plen in range(12):
            ctr_data = bytes([0x04]) + full_payload[:plen]
            frame = dissect_ll_control_pdu(ctr_data)
            assert frame is not None
            assert frame.opcode == 0x04
            assert frame.payload.get("error") == "truncated_enc_rsp"

        valid_frame = dissect_ll_control_pdu(bytes([0x04]) + full_payload)
        assert valid_frame is not None
        assert valid_frame.payload.get("skds") == b"\xAA" * 8

    def test_truncated_conn_update_ind_boundary_sweep(self) -> None:
        """LL_CONNECTION_UPDATE_IND requires 11 bytes. Slicing from 0 to 10 bytes must flag truncated."""
        full_payload = bytes([1]) + struct.pack("<HHHHH", 10, 24, 0, 100, 50)
        for plen in range(11):
            ctr_data = bytes([0x00]) + full_payload[:plen]
            frame = dissect_ll_control_pdu(ctr_data)
            assert frame is not None
            assert frame.opcode == 0x00
            assert frame.payload.get("error") == "truncated_conn_update_ind"

        valid_frame = dissect_ll_control_pdu(bytes([0x00]) + full_payload)
        assert valid_frame is not None
        assert valid_frame.payload.get("interval") == 24

    def test_truncated_conn_param_req_rsp_boundary_sweep(self) -> None:
        """LL_CONNECTION_PARAM_REQ (0x0F) and RSP (0x10) require 8 bytes."""
        full_payload = struct.pack("<HHHH", 24, 32, 0, 100)
        for op in (0x0F, 0x10):
            for plen in range(8):
                ctr_data = bytes([op]) + full_payload[:plen]
                frame = dissect_ll_control_pdu(ctr_data)
                assert frame is not None
                assert frame.payload.get("error") == "truncated_conn_param"

            valid_frame = dissect_ll_control_pdu(bytes([op]) + full_payload)
            assert valid_frame is not None
            assert valid_frame.payload.get("interval_min") == 24

    def test_truncated_l2cap_header_sub_four_bytes(self) -> None:
        """Data channel PDU with LLID=0b10 (L2CAP Start) but payload < 4 bytes."""
        for length in (0, 1, 2, 3):
            pdu = build_ll_header(llid=2, length=length) + b"\x01" * length
            dissected = dissect_data_channel_pdu(pdu)
            assert dissected is not None
            assert dissected.att_frame is None

    def test_truncated_att_signed_write_boundary_sweep(self) -> None:
        """ATT Signed write (0xD2) requires >= 15 bytes in L2CAP payload."""
        csrk = b"\x22" * 16
        for plen in range(1, 15):
            # L2CAP payload: 0xD2 + garbage up to plen
            l2cap_body = bytes([0xD2]) + b"\x00" * (plen - 1)
            pdu = (
                build_ll_header(llid=2, length=4 + plen)
                + struct.pack("<HH", plen, 0x0004)
                + l2cap_body
            )
            dissected = dissect_data_channel_pdu(pdu, csrk=csrk)
            assert dissected is not None
            assert dissected.att_frame is None

    def test_truncated_advertising_pdus_boundary_sweep(self) -> None:
        """Truncated CONNECT_IND (< 34B), SCAN_REQ (< 12B), ADV_DIRECT_IND (< 12B)."""
        # CONNECT_IND requires 34 bytes
        for length in (0, 6, 12, 33):
            pdu = bytes([0x05, length]) + b"\x11" * length
            adv = dissect_advertising_pdu(pdu)
            assert adv is not None
            assert adv.conn_aa is None

        # SCAN_REQ requires 12 bytes
        for length in (0, 5, 11):
            pdu = bytes([0x03, length]) + b"\x22" * length
            adv = dissect_advertising_pdu(pdu)
            assert adv is not None
            assert adv.scan_a is None

        # ADV_DIRECT_IND requires 12 bytes
        for length in (0, 5, 11):
            pdu = bytes([0x01, length]) + b"\x33" * length
            adv = dissect_advertising_pdu(pdu)
            assert adv is not None
            assert adv.target_a is None


# =============================================================================
# 3. Adversarial Handshake State Transitions
# =============================================================================
class TestAdversarialHandshakeStateTransitions:
    """Stress tests out-of-order handshakes, premature terminates, and retransmissions."""

    def test_out_of_order_start_enc_rsp_without_prior_req(self) -> None:
        """Adversarial scenario: LL_START_ENC_RSP injected into an IDLE connection."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x12345678
        rsp_pdu = build_ll_start_enc_rsp()
        findings = analyzer.process_packet(
            BlePacketRecord(body=rsp_pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.verdict == Verdict.PAIRED_SHARED_LTK.value
        # Parameters never established must be None, not crash
        assert finding.details["ediv"] is None
        assert finding.details["rand"] is None

    def test_out_of_order_start_enc_req_without_enc_req(self) -> None:
        """LL_START_ENC_REQ received without any prior LL_ENC_REQ."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x22334455
        req_pdu = build_ll_start_enc_req()
        findings = analyzer.process_packet(
            BlePacketRecord(body=req_pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)
        )
        # LL_START_ENC_REQ alone does not finalize handshake
        assert len(findings) == 0
        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value

    def test_out_of_order_enc_rsp_without_enc_req(self) -> None:
        """LL_ENC_RSP received without any prior LL_ENC_REQ."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x33445566
        rsp_pdu = build_ll_enc_rsp()
        findings = analyzer.process_packet(
            BlePacketRecord(body=rsp_pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)
        )
        assert len(findings) == 0
        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value

    def test_premature_termination_after_enc_req(self) -> None:
        """Connection terminates immediately after LL_ENC_REQ."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x44556677
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)
        )
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_terminate_ind(error_code=0x13), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa)
        )
        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value
        assert report.metrics["shared_ltk_sessions"] == 0
        assert report.metrics["rejected_sessions"] == 0

    def test_premature_termination_after_enc_rsp(self) -> None:
        """Connection terminates immediately after LL_ENC_RSP."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x55667788
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)
        )
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa)
        )
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_terminate_ind(error_code=0x13), channel=1, rssi=-60, timestamp_usec=3000, access_address=aa)
        )
        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value

    def test_retransmissions_enc_req_flood(self) -> None:
        """10 repeated LL_ENC_REQ retransmissions due to RF interference."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x66778899
        enc_req = build_ll_enc_req()
        for i in range(10):
            analyzer.process_packet(
                BlePacketRecord(body=enc_req, channel=1, rssi=-60, timestamp_usec=1000 + (i * 100), access_address=aa)
            )
        # Followed by normal rejection
        analyzer.process_packet(
            BlePacketRecord(body=build_ll_reject_ind(error_code=0x06), channel=1, rssi=-60, timestamp_usec=3000, access_address=aa)
        )
        report = analyzer.finalize()
        assert report.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert report.metrics["rejected_sessions"] == 1


# =============================================================================
# 4. Discovered Vulnerabilities Empirical Verification
# =============================================================================
class TestDiscoveredVulnerabilitiesEmpiricalVerification:
    """Verifies remediation of the 5 failure modes and bugs identified by Challenger 1."""

    def test_vulnerability_truncated_reject_ind_type_error(self) -> None:
        """REMEDIATED BUG 1: Truncated LL_REJECT_IND formats safely as UNKNOWN without TypeError."""
        analyzer = DifferentialEncryptionAnalyzer()
        pdu = build_ll_header(llid=3, length=1) + bytes([0x0D])
        pkt = BlePacketRecord(body=pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=0x12345678)

        # Must not crash with TypeError; must format error code safely
        findings = analyzer.process_packet(pkt)
        assert len(findings) == 1
        assert findings[0].details["error_code"] is None
        assert "ErrorCode=UNKNOWN" in findings[0].details["summary"]

    def test_vulnerability_truncated_reject_ext_ind_type_error(self) -> None:
        """REMEDIATED BUG 1b: Truncated LL_REJECT_EXT_IND (<2 bytes) formats safely without TypeError."""
        analyzer = DifferentialEncryptionAnalyzer()
        # Truncated LL_REJECT_EXT_IND with reject_opcode=0x03 (ENC_REQ) but missing error_code
        pdu = build_ll_header(llid=3, length=2) + bytes([0x11, 0x03])
        pkt = BlePacketRecord(body=pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=0x12345678)

        findings = analyzer.process_packet(pkt)
        assert len(findings) == 1
        assert findings[0].details["error_code"] is None
        assert "ErrorCode=UNKNOWN" in findings[0].details["summary"]

    def test_vulnerability_reject_ext_ind_cross_procedure_false_positive(self) -> None:
        """REMEDIATED BUG 2: LL_REJECT_EXT_IND for non-encryption opcodes is disregarded."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x88776655
        # Connection parameter request rejected (opcode 0x0F, not 0x03)
        pdu_rej_param = build_ll_reject_ext_ind(reject_opcode=0x0F, error_code=0x20)
        pkt = BlePacketRecord(body=pdu_rej_param, channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)

        findings = analyzer.process_packet(pkt)
        # Non-encryption control rejections must not emit encryption side-channel findings
        assert len(findings) == 0

        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value
        assert report.metrics["rejected_sessions"] == 0

    def test_vulnerability_post_encryption_param_reject_exclusive_collision(self) -> None:
        """REMEDIATED BUG 3: In-session state isolation preserves PAIRED_SHARED_LTK status."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x99887766

        # Step 1: Successful encryption handshake
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa))
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_req(), channel=1, rssi=-60, timestamp_usec=3000, access_address=aa))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=4000, access_address=aa))

        # Step 2: Later, peer rejects connection parameter request (0x0F)
        analyzer.process_packet(BlePacketRecord(body=build_ll_reject_ext_ind(reject_opcode=0x0F, error_code=0x20), channel=1, rssi=-60, timestamp_usec=5000, access_address=aa))

        report = analyzer.finalize()
        # Session retains PAIRED_SHARED_LTK verdict without collision or demotion
        assert report.metrics["total_connections"] == 1
        assert report.metrics["shared_ltk_sessions"] == 1
        assert report.metrics["rejected_sessions"] == 0
        assert report.verdict == Verdict.PAIRED_SHARED_LTK.value

    def test_vulnerability_duplicate_findings_on_dual_start_enc_rsp(self) -> None:
        """REMEDIATED BUG 4: Duplicate suppression emits exactly 1 finding per handshake."""
        pcap = generate_encryption_trace(shared_ltk=True)
        analyzer = DifferentialEncryptionAnalyzer()
        emitted: list[EncryptionInitiationFinding] = []
        for pkt in PcapBleReader(io.BytesIO(pcap)):
            emitted.extend(analyzer.process_packet(pkt))

        # Duplicate findings suppressed on 2-way LL_START_ENC_RSP
        assert len(emitted) == 1
        assert emitted[0].verdict == Verdict.PAIRED_SHARED_LTK.value

    def test_target_filter_leak_on_unknown_mac(self) -> None:
        """REMEDIATED BUG 5: Target MAC filter correctly filters unassociated data channel connections."""
        target = "AA:BB:CC:DD:EE:01"
        analyzer = DifferentialEncryptionAnalyzer(target_mac=target)
        aa = 0x11223344

        # Inject handshake without CONNECT_IND matching the target
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa))
        findings = analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa))

        # Filter strictly enforced: no leak of untargeted sessions
        assert len(findings) == 0


# =============================================================================
# 5. Interleaved & Multi-Connection Scalability Stress Harness
# =============================================================================
class TestAdversarialInterleavedConnections:
    """Stress tests high-volume, interleaved, multi-connection scenarios."""

    def test_100_concurrent_interleaved_connections_stress(self) -> None:
        """100 concurrent connections interleaved in a single packet stream.

        - 40 connections: shared LTK established (PAIRED_SHARED_LTK)
        - 40 connections: untrusted PIN/Key missing rejection (REJECTED_UNTRUSTED)
        - 20 connections: premature termination (TERMINATED)
        All 100 connections must be correctly demultiplexed by Access Address.
        """
        analyzer = DifferentialEncryptionAnalyzer()
        events: list[BlePacketRecord] = []

        base_aa = 0x20000000

        # Construct packet stages for each connection
        conn_packets: dict[int, list[bytes]] = {}
        for i in range(100):
            aa = base_aa + i
            pkts: list[bytes] = []
            # Step 1: CONNECT_IND
            init_mac = f"AA:BB:CC:DD:EE:{i:02X}"
            periph_mac = f"11:22:33:44:55:{i:02X}"
            conn_ind = build_connect_ind(init_a=init_mac, adv_a=periph_mac, conn_aa=aa)

            if i < 40:
                # Shared LTK sequence
                pkts = [
                    conn_ind,
                    build_ll_enc_req(),
                    build_ll_enc_rsp(),
                    build_ll_start_enc_req(),
                    build_ll_start_enc_rsp(),
                ]
            elif i < 80:
                # Rejected sequence
                pkts = [
                    conn_ind,
                    build_ll_enc_req(),
                    build_ll_reject_ind(error_code=0x06),
                    build_ll_terminate_ind(error_code=0x13),
                ]
            else:
                # Premature terminate sequence
                pkts = [
                    conn_ind,
                    build_ll_enc_req(),
                    build_ll_terminate_ind(error_code=0x13),
                ]
            conn_packets[aa] = pkts

        # Interleave packets across all 100 connections round-robin
        max_stages = max(len(p) for p in conn_packets.values())
        t = 1_000_000
        for stage in range(max_stages):
            for i in range(100):
                aa = base_aa + i
                stage_pkts = conn_packets[aa]
                if stage < len(stage_pkts):
                    body = stage_pkts[stage]
                    is_adv = stage == 0
                    rec = BlePacketRecord(
                        body=body,
                        channel=37 if is_adv else 1,
                        rssi=-60,
                        timestamp_usec=t,
                        access_address=BLE_ADV_AA if is_adv else aa,
                    )
                    events.append(rec)
                    t += 500

        # Process the interleaved stream
        for pkt in events:
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.CONFIRMED_EXCLUSIVE.value
        assert report.metrics["total_connections"] == 100
        assert report.metrics["shared_ltk_sessions"] == 40
        assert report.metrics["rejected_sessions"] == 40
        assert report.metrics["pin_missing_errors"] == 40

    def test_reused_peripheral_mac_different_access_addresses(self) -> None:
        """Peripheral connects to Central A (conn_aa=0x11111111) then Central B (conn_aa=0x22222222)."""
        analyzer = DifferentialEncryptionAnalyzer()
        periph = "AA:BB:CC:DD:EE:99"

        # Conn 1: accepted
        analyzer.process_packet(BlePacketRecord(body=build_connect_ind("11:11:11:11:11:11", periph, conn_aa=0x11111111), channel=37, rssi=-60, timestamp_usec=1000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=2000, access_address=0x11111111))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=3000, access_address=0x11111111))
        analyzer.process_packet(BlePacketRecord(body=build_ll_terminate_ind(), channel=1, rssi=-60, timestamp_usec=4000, access_address=0x11111111))

        # Conn 2: rejected
        analyzer.process_packet(BlePacketRecord(body=build_connect_ind("22:22:22:22:22:22", periph, conn_aa=0x22222222), channel=37, rssi=-60, timestamp_usec=5000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=6000, access_address=0x22222222))
        analyzer.process_packet(BlePacketRecord(body=build_ll_reject_ind(error_code=0x06), channel=1, rssi=-60, timestamp_usec=7000, access_address=0x22222222))

        report = analyzer.finalize()
        assert report.verdict == Verdict.CONFIRMED_EXCLUSIVE.value
        assert report.metrics["total_connections"] == 2
        assert report.metrics["shared_ltk_sessions"] == 1
        assert report.metrics["rejected_sessions"] == 1


# =============================================================================
# 6. Analyzer Streaming and Reset Integrity
# =============================================================================
class TestAnalyzerStreamingAndResetIntegrity:
    """Stress tests reset lifecycle and mixed packet type coercion."""

    def test_rapid_reset_cycle_stress(self) -> None:
        """50 rapid cycles of process_packet followed by reset()."""
        analyzer = DifferentialEncryptionAnalyzer()
        for cycle in range(50):
            aa = 0x30000000 + cycle
            analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa))
            analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa))
            rep = analyzer.finalize()
            assert rep.verdict == Verdict.PAIRED_SHARED_LTK.value
            analyzer.reset()
            empty_rep = analyzer.finalize()
            assert empty_rep.verdict == Verdict.INCONCLUSIVE.value
            assert empty_rep.metrics["packets_processed"] == 0

    def test_coerced_packet_types_interleaved_stream(self) -> None:
        """Feed stream mixing BlePacketRecord, CapturedBlePacket, and SyntheticEvent."""
        aa = 0x44332211
        p1 = BlePacketRecord(body=build_connect_ind("AA:BB:CC:00:11:22", "AA:BB:CC:33:44:55", conn_aa=aa), channel=37, rssi=-60, timestamp_usec=1000, access_address=BLE_ADV_AA)
        p2 = SyntheticEvent(ts_usec=2000, chan=1, aa=aa, body=build_ll_enc_req(), direction=0)
        p3 = CapturedBlePacket(
            ts_sec=0,
            ts_usec=3000,
            ts_epoch=0.003,
            rf_chan=1,
            ble_chan=1,
            rssi=-65,
            noise=-128,
            aa=aa,
            flags=0x0800,
            crc_err=False,
            phy=0,
            pdu_type=2,
            body=build_ll_start_enc_rsp(),
            crc=0x123456,
            raw_packet=b"",
        )

        analyzer = DifferentialEncryptionAnalyzer()
        analyzer.process_packet(p1)
        analyzer.process_packet(p2)
        analyzer.process_packet(p3)

        report = analyzer.finalize()
        assert report.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.metrics["shared_ltk_sessions"] == 1
