"""Comprehensive automated test suite for BLE Link-Layer dissector & side-channel analyzers.

Tests:
1. Low-level Link-Layer Control PDU and ATT Signed Write packet dissection.
2. Differential Encryption Initiation analyzer (positive shared LTK vs negative rejected).
3. CSRK 32-bit SignCounter monotonicity, anomaly detection, and cross-RPA linking.
4. BAT Allowlist auto-connection timing oracle, directed bursts, and connection profiling.
5. End-to-end PCAP ingestion via PcapBleReader and in-memory streams.
"""

from __future__ import annotations

import io
import json
import struct

import pytest

from airtell.protocol.wire import PacketMessage
from airtell.sidechannel import (
    AnalyzerReport,
    BatAllowlistAnalyzer,
    BlePacketRecord,
    CsrkCounterAnalyzer,
    DifferentialEncryptionAnalyzer,
    EncryptionInitiationFinding,
    SideChannelType,
    SyntheticEvent,
    Verdict,
    build_adv_direct_ind,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_connection_update_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_header,
    build_ll_reject_ext_ind,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_ll_terminate_ind,
    build_scan_req,
    build_scan_rsp,
    dissect_advertising_pdu,
    dissect_ble_pdu,
    dissect_data_channel_pdu,
    dissect_ll_control_pdu,
    events_to_captured_packets,
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
)
from airtell.sniff.pcap import (
    BLE_ADV_AA,
    CapturedBlePacket,
    PcapBleReader,
)


# =============================================================================
# 1. Models & Packet Records Tests
# =============================================================================
class TestModelsAndRecords:
    """Tests for BlePacketRecord, Finding objects, and AnalyzerReport."""

    def test_ble_packet_record_from_packet_message(self) -> None:
        raw_pdu = build_ll_enc_req()
        raw_msg = PacketMessage.pack(
            body=raw_pdu,
            ts=1_500_000,
            direction=1,
            crc_err=False,
            event=12,
            rssi=-55,
            chan=17,
            phy=0,
        )
        msg = PacketMessage(raw_msg)
        rec = BlePacketRecord.coerce(msg)
        assert rec.timestamp_usec == 1_500_000
        assert rec.timestamp == 1.5
        assert rec.direction == 1
        assert rec.channel == 17
        assert rec.rssi == -55
        assert rec.body == raw_pdu
        assert rec.crc_err is False

    def test_ble_packet_record_from_captured_ble_packet(self) -> None:
        raw_pdu = build_ll_start_enc_req()
        pkt = CapturedBlePacket(
            ts_sec=100,
            ts_usec=250_000,
            ts_epoch=100.25,
            rf_chan=1,
            ble_chan=0,
            rssi=-70,
            noise=-128,
            aa=0x12345678,
            flags=0x0800,
            crc_err=False,
            phy=0,
            pdu_type=3,  # Slave to Master (dir=1)
            body=raw_pdu,
            crc=0x112233,
            raw_packet=b"",
        )
        rec = BlePacketRecord.coerce(pkt)
        assert rec.timestamp_usec == 100_250_000
        assert rec.direction == 1
        assert rec.access_address == 0x12345678
        assert rec.channel == 0
        assert rec.body == raw_pdu

    def test_ble_packet_record_coerce_unsupported_raises(self) -> None:
        with pytest.raises(TypeError):
            BlePacketRecord.coerce("invalid_object")

    def test_finding_and_report_serialization(self) -> None:
        finding = EncryptionInitiationFinding(
            finding_type=SideChannelType.DIFFERENTIAL_ENCRYPTION.value,
            timestamp=123.456,
            device_addr="AA:BB:CC:DD:EE:02",
            target_addr="AA:BB:CC:DD:EE:01",
            verdict=Verdict.PAIRED_SHARED_LTK.value,
            confidence=1.0,
            details={"is_shared_ltk": True},
        )
        d = finding.to_dict()
        assert d["finding_type"] == "differential_encryption"
        assert d["verdict"] == "PAIRED_SHARED_LTK"
        assert d["confidence"] == 1.0

        report = AnalyzerReport(
            analyzer_name="DifferentialEncryptionAnalyzer",
            verdict=Verdict.PAIRED_SHARED_LTK.value,
            summary="Test summary",
            findings=[finding],
            metrics={"count": 1},
        )
        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["analyzer_name"] == "DifferentialEncryptionAnalyzer"
        assert data["verdict"] == "PAIRED_SHARED_LTK"
        assert len(data["findings"]) == 1


# =============================================================================
# 2. Link-Layer Control & ATT Dissector Tests
# =============================================================================
class TestLinkLayerDissector:
    """Tests for ll_dissector.py functions and frame models."""

    def test_dissect_ll_enc_req(self) -> None:
        pdu = build_ll_enc_req(
            rand=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            ediv=0x1234,
            skdm=b"\x11\x22\x33\x44\x55\x66\x77\x88",
            ivm=b"\xAA\xBB\xCC\xDD",
        )
        dissected = dissect_data_channel_pdu(pdu)
        assert dissected is not None
        assert dissected.llid == 3
        assert dissected.control_frame is not None
        ctrl = dissected.control_frame
        assert ctrl.opcode == 0x03
        assert ctrl.name == "LL_ENC_REQ"
        assert ctrl.payload["ediv"] == 0x1234
        assert ctrl.payload["rand"] == b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def test_dissect_ll_enc_rsp(self) -> None:
        pdu = build_ll_enc_rsp(
            skds=b"\x99" * 8,
            ivs=b"\x88" * 4,
        )
        dissected = dissect_data_channel_pdu(pdu)
        assert dissected is not None
        ctrl = dissected.control_frame
        assert ctrl is not None
        assert ctrl.opcode == 0x04
        assert ctrl.name == "LL_ENC_RSP"
        assert ctrl.payload["skds"] == b"\x99" * 8
        assert ctrl.payload["ivs"] == b"\x88" * 4

    def test_dissect_ll_start_enc_req_and_rsp(self) -> None:
        req_pdu = build_ll_start_enc_req()
        dissected_req = dissect_data_channel_pdu(req_pdu)
        assert dissected_req is not None
        assert dissected_req.control_frame is not None
        assert dissected_req.control_frame.opcode == 0x05

        rsp_pdu = build_ll_start_enc_rsp(mic=b"\x12\x34\x56\x78")
        dissected_rsp = dissect_data_channel_pdu(rsp_pdu)
        assert dissected_rsp is not None
        assert dissected_rsp.control_frame is not None
        assert dissected_rsp.control_frame.opcode == 0x06
        assert dissected_rsp.control_frame.payload.get("mic") == b"\x12\x34\x56\x78"

    def test_dissect_ll_reject_ind_and_ext_ind(self) -> None:
        rej_pdu = build_ll_reject_ind(error_code=0x06)
        dissected_rej = dissect_data_channel_pdu(rej_pdu)
        assert dissected_rej is not None
        ctrl = dissected_rej.control_frame
        assert ctrl is not None
        assert ctrl.opcode == 0x0D
        assert ctrl.payload["error_code"] == 0x06

        ext_pdu = build_ll_reject_ext_ind(reject_opcode=0x03, error_code=0x06)
        dissected_ext = dissect_data_channel_pdu(ext_pdu)
        assert dissected_ext is not None
        ctrl_ext = dissected_ext.control_frame
        assert ctrl_ext is not None
        assert ctrl_ext.opcode == 0x11
        assert ctrl_ext.payload["reject_opcode"] == 0x03
        assert ctrl_ext.payload["error_code"] == 0x06

    def test_dissect_ll_terminate_and_conn_update(self) -> None:
        term_pdu = build_ll_terminate_ind(error_code=0x13)
        dissected_term = dissect_data_channel_pdu(term_pdu)
        assert dissected_term is not None
        assert dissected_term.control_frame is not None
        assert dissected_term.control_frame.opcode == 0x02
        assert dissected_term.control_frame.payload["error_code"] == 0x13

        upd_pdu = build_ll_connection_update_ind(interval=32, latency=1, timeout=200)
        dissected_upd = dissect_data_channel_pdu(upd_pdu)
        assert dissected_upd is not None
        assert dissected_upd.control_frame is not None
        assert dissected_upd.control_frame.opcode == 0x00
        assert dissected_upd.control_frame.payload["interval"] == 32
        assert dissected_upd.control_frame.payload["interval_ms"] == 40.0

    def test_dissect_att_signed_write_cmd(self) -> None:
        csrk = b"\xAA" * 16
        write_pdu = build_att_signed_write(
            csrk=csrk,
            handle=0x0015,
            value=b"\xDE\xAD\xBE\xEF",
            counter=42,
        )
        # Verify valid signature
        dissected = dissect_data_channel_pdu(write_pdu, csrk=csrk)
        assert dissected is not None
        assert dissected.llid == 2  # L2CAP Start
        att = dissected.att_frame
        assert att is not None
        assert att.handle == 0x0015
        assert att.value == b"\xDE\xAD\xBE\xEF"
        assert att.sign_counter == 42
        assert att.mac_valid is True

        # Verify signature failure with wrong key
        wrong_csrk = b"\xBB" * 16
        dissected_wrong = dissect_data_channel_pdu(write_pdu, csrk=wrong_csrk)
        assert dissected_wrong is not None
        assert dissected_wrong.att_frame is not None
        assert dissected_wrong.att_frame.mac_valid is False

        # Verify without key
        dissected_no_key = dissect_data_channel_pdu(write_pdu, csrk=None)
        assert dissected_no_key is not None
        assert dissected_no_key.att_frame is not None
        assert dissected_no_key.att_frame.mac_valid is None

    def test_dissect_advertising_channel_pdus(self) -> None:
        adv_pdu = build_adv_ind(adv_a="11:22:33:44:55:66", ad_data=b"\x02\x01\x06")
        adv = dissect_advertising_pdu(adv_pdu)
        assert adv is not None
        assert adv.pdu_name == "ADV_IND"
        assert adv.adv_a == "11:22:33:44:55:66"

        direct_pdu = build_adv_direct_ind(adv_a="11:22:33:44:55:66", target_a="AA:BB:CC:DD:EE:01")
        direct = dissect_advertising_pdu(direct_pdu)
        assert direct is not None
        assert direct.pdu_name == "ADV_DIRECT_IND"
        assert direct.target_a == "AA:BB:CC:DD:EE:01"

        scan_req_pdu = build_scan_req(scan_a="AA:BB:CC:DD:EE:01", adv_a="11:22:33:44:55:66")
        scan = dissect_advertising_pdu(scan_req_pdu)
        assert scan is not None
        assert scan.scan_a == "AA:BB:CC:DD:EE:01"

        scan_rsp_pdu = build_scan_rsp(adv_a="11:22:33:44:55:66", scan_rsp_data=b"\x05\x08Test")
        rsp = dissect_advertising_pdu(scan_rsp_pdu)
        assert rsp is not None
        assert rsp.adv_a == "11:22:33:44:55:66"

        conn_pdu = build_connect_ind(
            init_a="AA:BB:CC:DD:EE:01",
            adv_a="11:22:33:44:55:66",
            conn_aa=0x87654321,
            interval=36,
            latency=2,
            timeout=150,
            hop=9,
        )
        conn = dissect_advertising_pdu(conn_pdu)
        assert conn is not None
        assert conn.init_a == "AA:BB:CC:DD:EE:01"
        assert conn.adv_a == "11:22:33:44:55:66"
        assert conn.conn_aa == 0x87654321
        assert conn.interval == 36
        assert conn.latency == 2
        assert conn.timeout == 150
        assert conn.hop == 9

    def test_dissect_ble_pdu_demuxer(self) -> None:
        adv_pdu = build_adv_ind(adv_a="11:22:33:44:55:66")
        res_adv = dissect_ble_pdu(adv_pdu, access_address=BLE_ADV_AA)
        assert res_adv is not None
        assert hasattr(res_adv, "adv_a")

        data_pdu = build_ll_terminate_ind(error_code=0x13)
        res_data = dissect_ble_pdu(data_pdu, access_address=0x12345678)
        assert res_data is not None
        assert hasattr(res_data, "control_frame")

    def test_dissector_malformed_and_truncated(self) -> None:
        assert dissect_data_channel_pdu(b"") is None
        assert dissect_data_channel_pdu(b"\x01") is None
        assert dissect_advertising_pdu(b"") is None

        # Truncated control frame
        bad_ctrl = dissect_ll_control_pdu(bytes([0x03, 0x01, 0x02]))  # LL_ENC_REQ with only 2 bytes payload
        assert bad_ctrl is not None
        assert "error" in bad_ctrl.payload


# =============================================================================
# 3. Differential Encryption Initiation Analyzer Tests
# =============================================================================
class TestDifferentialEncryptionAnalyzer:
    """Tests for DifferentialEncryptionAnalyzer against positive and negative fixtures."""

    def test_encryption_positive_shared_ltk_pcap(self) -> None:
        pcap_bytes = generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        reader = PcapBleReader(io.BytesIO(pcap_bytes))
        analyzer = DifferentialEncryptionAnalyzer()

        for pkt in reader:
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.metrics["shared_ltk_sessions"] == 1
        assert report.metrics["rejected_sessions"] == 0
        assert len(report.findings) >= 1

        finding = report.findings[0]
        assert finding.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert finding.confidence == 1.0
        assert finding.device_addr == "AA:BB:CC:DD:EE:02"
        assert finding.target_addr == "AA:BB:CC:DD:EE:01"
        assert finding.details["is_shared_ltk"] is True

    def test_encryption_negative_rejected_pcap(self) -> None:
        pcap_bytes = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        reader = PcapBleReader(io.BytesIO(pcap_bytes))
        analyzer = DifferentialEncryptionAnalyzer()

        for pkt in reader:
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert report.metrics["rejected_sessions"] == 1
        assert report.metrics["shared_ltk_sessions"] == 0
        assert report.metrics["pin_missing_errors"] == 1

        finding = report.findings[0]
        assert finding.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert finding.confidence == 1.0
        assert finding.details["error_code"] == 0x06
        assert finding.details["is_shared_ltk"] is False

    def test_encryption_negative_extended_reject(self) -> None:
        pcap_bytes = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        reader = PcapBleReader(io.BytesIO(pcap_bytes))
        analyzer = DifferentialEncryptionAnalyzer()

        for pkt in reader:
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert report.metrics["rejected_sessions"] == 1
        finding = report.findings[0]
        assert finding.details["reject_opcode"] == 0x03
        assert finding.details["error_code"] == 0x06

    def test_differential_encryption_multi_session(self) -> None:
        # Session 1: Positive shared LTK
        pcap1 = generate_encryption_trace(
            shared_ltk=True,
            conn_aa=0x11111111,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        # Session 2: Negative rejected
        pcap2 = generate_encryption_trace(
            shared_ltk=False,
            conn_aa=0x22222222,
            central_addr="99:88:77:66:55:44",
            periph_addr="AA:BB:CC:DD:EE:02",
        )

        analyzer = DifferentialEncryptionAnalyzer()
        for pkt in PcapBleReader(io.BytesIO(pcap1)):
            analyzer.process_packet(pkt)
        for pkt in PcapBleReader(io.BytesIO(pcap2)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.CONFIRMED_EXCLUSIVE.value
        assert report.metrics["shared_ltk_sessions"] == 1
        assert report.metrics["rejected_sessions"] == 1

    def test_differential_encryption_target_filter_and_reset(self) -> None:
        pcap_bytes = generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        # Filter for different MAC
        analyzer = DifferentialEncryptionAnalyzer(target_mac="FF:FF:FF:FF:FF:FF")
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)
        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value
        assert len(report.findings) == 0

        # Reset
        analyzer.reset()
        assert analyzer._packets_processed == 0


# =============================================================================
# 4. CSRK Counter Monotonicity & Integrity Analyzer Tests
# =============================================================================
class TestCsrkCounterAnalyzer:
    """Tests for CsrkCounterAnalyzer against sequential, replayed, jumped, and corrupted MAC traces."""

    def test_csrk_strictly_monotonic_sequential(self) -> None:
        csrk = b"\x33" * 16
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[10, 11, 12, 13, 14],
            csrk=csrk,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert report.metrics["total_signed_writes"] == 5
        assert report.metrics["total_anomalies"] == 0

    def test_csrk_replay_attack_anomaly(self) -> None:
        csrk = b"\x44" * 16
        # Replay: 100, 101, 101 (replay), 102
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[100, 101, 101, 102],
            csrk=csrk,
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.ANOMALY_REPLAY.value
        assert report.metrics["replay_anomalies"] == 1
        replay_finding = next(f for f in report.findings if f.verdict == Verdict.ANOMALY_REPLAY.value)
        assert replay_finding.details["counter"] == 101
        assert replay_finding.details["is_anomaly"] is True

    def test_csrk_rollback_anomaly(self) -> None:
        csrk = b"\x55" * 16
        # Rollback: 50, 51, 48 (rollback), 52
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[50, 51, 48, 52],
            csrk=csrk,
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.ANOMALY_ROLLBACK.value
        assert report.metrics["rollback_anomalies"] == 1
        rollback_finding = next(f for f in report.findings if f.verdict == Verdict.ANOMALY_ROLLBACK.value)
        assert rollback_finding.details["counter"] == 48

    def test_csrk_gap_jump_anomaly(self) -> None:
        csrk = b"\x66" * 16
        # Gap: 1, 2, 50 (jump), 51
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[1, 2, 50, 51],
            csrk=csrk,
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.ANOMALY_JUMP.value
        assert report.metrics["jump_anomalies"] == 1
        jump_finding = next(f for f in report.findings if f.verdict == Verdict.ANOMALY_JUMP.value)
        assert jump_finding.details["delta"] == 48

    def test_csrk_cryptographic_verification_rejection(self) -> None:
        csrk = b"\x77" * 16
        # Corrupt MAC at index 1
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[10, 11, 12],
            csrk=csrk,
            corrupt_mac_indices=[1],
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.VERIFICATION_FAILED.value
        assert report.metrics["mac_verification_failures"] == 1
        fail_finding = next(f for f in report.findings if f.verdict == Verdict.VERIFICATION_FAILED.value)
        assert fail_finding.details["mac_valid"] is False

    def test_csrk_cross_rpa_linking(self) -> None:
        csrk = b"\x88" * 16
        # Central rotates RPA from AA:BB:CC:DD:EE:01 to 66:77:88:99:AA:BB at index 2
        pcap_bytes = generate_csrk_trace(
            counter_sequence=[200, 201, 202, 203],
            csrk=csrk,
            central_addr="AA:BB:CC:DD:EE:01",
            rotate_rpa_indices=[2],
            rpa_sequence=["66:77:88:99:AA:BB"],
        )
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.CROSS_RPA_LINKED.value
        assert len(report.metrics["linked_rpa_groups"]) == 1
        linked_group = report.metrics["linked_rpa_groups"][0]
        assert "AA:BB:CC:DD:EE:01" in linked_group
        assert "66:77:88:99:AA:BB" in linked_group


# =============================================================================
# 5. BAT Allowlist Auto-Connection & Timing Analyzer Tests
# =============================================================================
class TestBatAllowlistAnalyzer:
    """Tests for BatAllowlistAnalyzer against selective probes, directed bursts, and profiles."""

    def test_bat_allowlist_selective_probe_confirmed(self) -> None:
        pcap_bytes = generate_bat_allowlist_trace(
            allowlist_enabled=True,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="99:88:77:66:55:44",
            periph_addr="11:22:33:44:55:66",
            mode="selective_probe",
        )
        analyzer = BatAllowlistAnalyzer()
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert report.metrics["allowlist_confirmed_peripherals"] == 1
        finding = next(f for f in report.findings if f.verdict == Verdict.ALLOWLIST_CONFIRMED.value)
        assert finding.device_addr == "11:22:33:44:55:66"

    def test_bat_open_advertiser_probe_response(self) -> None:
        pcap_bytes = generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="99:88:77:66:55:44",
            periph_addr="11:22:33:44:55:66",
            mode="selective_probe",
        )
        analyzer = BatAllowlistAnalyzer()
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.OPEN_ADVERTISER.value
        assert report.metrics["allowlist_confirmed_peripherals"] == 0

    def test_bat_directed_exclusive_advertising(self) -> None:
        pcap_bytes = generate_bat_allowlist_trace(
            target_rpa="AA:BB:CC:DD:EE:01",
            periph_addr="11:22:33:44:55:66",
            mode="directed",
        )
        analyzer = BatAllowlistAnalyzer()
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.DIRECTED_EXCLUSIVE.value
        assert report.metrics["directed_advertising_events"] >= 1
        finding = next(f for f in report.findings if f.verdict == Verdict.DIRECTED_EXCLUSIVE.value)
        assert finding.device_addr == "11:22:33:44:55:66"
        assert finding.target_addr == "AA:BB:CC:DD:EE:01"

    def test_bat_reconnection_timing_and_connection_profile(self) -> None:
        pcap_bytes = generate_bat_allowlist_trace(
            target_rpa="AA:BB:CC:DD:EE:01",
            periph_addr="11:22:33:44:55:66",
            mode="reconnection_timing",
            fast_interval_ms=30.0,
            slow_interval_ms=1200.0,
            conn_params=(24, 0, 100, 5),
        )
        analyzer = BatAllowlistAnalyzer()
        for pkt in PcapBleReader(io.BytesIO(pcap_bytes)):
            analyzer.process_packet(pkt)

        report = analyzer.finalize()
        assert report.verdict == Verdict.PROFILE_MATCH.value
        assert report.metrics["connection_profiles_extracted"] == 1
        assert report.metrics["fast_slow_transition_peripherals"] == 1
        profile_finding = next(f for f in report.findings if f.verdict == Verdict.PROFILE_MATCH.value)
        assert profile_finding.details["profile_tuple"] == (24, 0, 100, 5)


# =============================================================================
# 6. Stream and Reset Integration Tests
# =============================================================================
class TestAnalyzerStreamAndReset:
    """Tests verify analyzer behavior across reset() and in-memory streams."""

    def test_analyzer_reset_state_clean(self) -> None:
        enc_analyzer = DifferentialEncryptionAnalyzer()
        csrk_analyzer = CsrkCounterAnalyzer()
        bat_analyzer = BatAllowlistAnalyzer()

        pcap = generate_encryption_trace(shared_ltk=True)
        for pkt in PcapBleReader(io.BytesIO(pcap)):
            enc_analyzer.process_packet(pkt)
            csrk_analyzer.process_packet(pkt)
            bat_analyzer.process_packet(pkt)

        assert enc_analyzer._packets_processed > 0
        enc_analyzer.reset()
        csrk_analyzer.reset()
        bat_analyzer.reset()

        assert enc_analyzer.finalize().verdict == Verdict.INCONCLUSIVE.value
        assert csrk_analyzer.finalize().verdict == Verdict.INCONCLUSIVE.value
        assert bat_analyzer.finalize().verdict == Verdict.INCONCLUSIVE.value

    def test_in_memory_captured_packets_stream_processing(self) -> None:
        # Generate stream of encryption handshake events
        events = [
            SyntheticEvent(ts_usec=1_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=0x55555555)),
            SyntheticEvent(ts_usec=2_000, chan=1, aa=0x55555555, body=build_ll_enc_req(), direction=0),
            SyntheticEvent(ts_usec=3_000, chan=1, aa=0x55555555, body=build_ll_enc_rsp(), direction=1),
            SyntheticEvent(ts_usec=4_000, chan=1, aa=0x55555555, body=build_ll_start_enc_req(), direction=1),
            SyntheticEvent(ts_usec=5_000, chan=1, aa=0x55555555, body=build_ll_start_enc_rsp(), direction=0),
            SyntheticEvent(ts_usec=6_000, chan=1, aa=0x55555555, body=build_ll_start_enc_rsp(), direction=1),
        ]
        pkts = events_to_captured_packets(events)
        analyzer = DifferentialEncryptionAnalyzer()
        for pkt in pkts:
            analyzer.process_packet(pkt)
        report = analyzer.finalize()
        assert report.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.metrics["shared_ltk_sessions"] == 1


# =============================================================================
# 7. Additional Edge Cases & Boundary Tests
# =============================================================================
class TestEdgeCasesAndBoundaries:
    """Stress tests and boundary condition checks for dissectors and analyzers."""

    def test_dissect_connection_param_req_and_pause_enc(self) -> None:
        # LL_CONNECTION_PARAM_REQ (0x0F)
        pdu_req = build_ll_header(llid=3, length=9) + bytes([0x0F]) + struct.pack("<HHHH", 24, 32, 0, 100)
        dissected = dissect_data_channel_pdu(pdu_req)
        assert dissected is not None
        assert dissected.control_frame is not None
        assert dissected.control_frame.opcode == 0x0F
        assert dissected.control_frame.payload["interval_min"] == 24
        assert dissected.control_frame.payload["interval_min_ms"] == 30.0

        # LL_PAUSE_ENC_REQ (0x0A)
        pdu_pause = build_ll_header(llid=3, length=1) + bytes([0x0A])
        dissected_pause = dissect_data_channel_pdu(pdu_pause)
        assert dissected_pause is not None
        assert dissected_pause.control_frame is not None
        assert dissected_pause.control_frame.opcode == 0x0A

    def test_dissect_unknown_ll_control_opcode(self) -> None:
        pdu_unk = build_ll_header(llid=3, length=3) + bytes([0xFE, 0x11, 0x22])
        dissected = dissect_data_channel_pdu(pdu_unk)
        assert dissected is not None
        assert dissected.control_frame is not None
        assert dissected.control_frame.opcode == 0xFE
        assert "UNKNOWN_LL_CONTROL" in dissected.control_frame.name

    def test_dissect_non_att_l2cap_cid(self) -> None:
        # L2CAP CID 0x0006 (SMP)
        pdu_smp = build_ll_header(llid=2, length=6) + struct.pack("<HH", 2, 0x0006) + b"\x01\x00"
        dissected = dissect_data_channel_pdu(pdu_smp)
        assert dissected is not None
        assert dissected.llid == 2
        assert dissected.att_frame is None

    def test_dissect_att_error_response(self) -> None:
        # ATT Error Response (0x01): req_opcode=0xD2, handle=0x0015, error=0x05 (Insufficient Auth)
        pdu_err = build_ll_header(llid=2, length=9) + struct.pack("<HH", 5, 0x0004) + bytes([0x01, 0xD2]) + struct.pack("<H", 0x0015) + bytes([0x05])
        dissected = dissect_data_channel_pdu(pdu_err)
        assert dissected is not None
        assert dissected.att_error is not None
        assert dissected.att_error.req_opcode == 0xD2
        assert dissected.att_error.handle == 0x0015
        assert dissected.att_error.error_code == 0x05

    def test_dissect_att_signed_write_empty_value_and_truncated(self) -> None:
        csrk = b"\x12" * 16
        # Empty value payload
        pdu_empty = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=1)
        dissected = dissect_data_channel_pdu(pdu_empty, csrk=csrk)
        assert dissected is not None
        assert dissected.att_frame is not None
        assert dissected.att_frame.value == b""
        assert dissected.att_frame.sign_counter == 1
        assert dissected.att_frame.mac_valid is True

        # Truncated ATT signed write (< 15 bytes L2CAP payload)
        pdu_trunc = build_ll_header(llid=2, length=8) + struct.pack("<HH", 4, 0x0004) + bytes([0xD2, 0x01, 0x02, 0x03])
        dissected_trunc = dissect_data_channel_pdu(pdu_trunc)
        assert dissected_trunc is not None
        assert dissected_trunc.att_frame is None

    def test_differential_encryption_unsupported_feature_rejection(self) -> None:
        # Rejection with ErrorCode = 0x1A (UNSUPPORTED_REMOTE_FEATURE)
        pdu_enc_req = build_ll_enc_req()
        pdu_rej_feat = build_ll_reject_ind(error_code=0x1A)

        analyzer = DifferentialEncryptionAnalyzer()
        # Direct data channel packet without advertising CONNECT_IND
        analyzer.process_packet(BlePacketRecord(body=pdu_enc_req, channel=1, rssi=-60, timestamp_usec=1_000, access_address=0x99999999))
        analyzer.process_packet(BlePacketRecord(body=pdu_rej_feat, channel=1, rssi=-60, timestamp_usec=2_000, access_address=0x99999999))

        report = analyzer.finalize()
        assert report.verdict == Verdict.UNPAIRED_KEY_REJECTED.value
        assert report.metrics["rejected_sessions"] == 1
        finding = report.findings[0]
        assert finding.details["is_unsupported_feature"] is True

    def test_csrk_counter_att_error_response_handling(self) -> None:
        # ATT Signed write followed by ATT Error Response 0x01 (Insufficient Auth 0x05)
        csrk = b"\x44" * 16
        pdu_conn = build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=0x77777777)
        pdu_write = build_att_signed_write(csrk=csrk, handle=0x0005, value=b"\x01", counter=10)
        pdu_err = build_ll_header(llid=2, length=9) + struct.pack("<HH", 5, 0x0004) + bytes([0x01, 0xD2]) + struct.pack("<H", 0x0005) + bytes([0x05])

        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        analyzer.process_packet(BlePacketRecord(body=pdu_conn, channel=37, rssi=-60, timestamp_usec=1_000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=pdu_write, channel=1, rssi=-60, timestamp_usec=2_000, access_address=0x77777777, direction=0))
        analyzer.process_packet(BlePacketRecord(body=pdu_err, channel=1, rssi=-60, timestamp_usec=3_000, access_address=0x77777777, direction=1))

        report = analyzer.finalize()
        assert any(f.verdict == Verdict.VERIFICATION_FAILED.value for f in report.findings)

    def test_csrk_counter_boundary_uint32(self) -> None:
        csrk = b"\x55" * 16
        # Counter increment near 32-bit uint boundary
        pdu_write1 = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=0xFFFFFFFE)
        pdu_write2 = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=0xFFFFFFFF)

        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        analyzer.process_packet(BlePacketRecord(body=pdu_write1, channel=1, rssi=-60, timestamp_usec=1_000, access_address=0x88888888, direction=0))
        analyzer.process_packet(BlePacketRecord(body=pdu_write2, channel=1, rssi=-60, timestamp_usec=2_000, access_address=0x88888888, direction=0))

        report = analyzer.finalize()
        assert report.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert report.metrics["total_signed_writes"] == 2
        assert report.metrics["total_anomalies"] == 0

    def test_bat_allowlist_flush_on_finalize(self) -> None:
        # SCAN_REQ from foreign scanner without any subsequent packet
        # finalize() must flush pending probe and detect silence!
        pdu_adv = build_adv_ind("11:22:33:44:55:66")
        pdu_probe_allowed = build_scan_req("AA:BB:CC:DD:EE:01", "11:22:33:44:55:66")
        pdu_rsp_allowed = build_scan_rsp("11:22:33:44:55:66")
        pdu_probe_foreign = build_scan_req("99:88:77:66:55:44", "11:22:33:44:55:66")

        analyzer = BatAllowlistAnalyzer()
        # Peripheral advertises
        analyzer.process_packet(BlePacketRecord(body=pdu_adv, channel=37, rssi=-60, timestamp_usec=1_000))
        # Allowed scanner probes and receives response in 150us
        analyzer.process_packet(BlePacketRecord(body=pdu_probe_allowed, channel=37, rssi=-60, timestamp_usec=2_000))
        analyzer.process_packet(BlePacketRecord(body=pdu_rsp_allowed, channel=37, rssi=-60, timestamp_usec=2_150))
        # Foreign scanner probes, but sniffer capture ends (no response ever emitted)
        analyzer.process_packet(BlePacketRecord(body=pdu_probe_foreign, channel=37, rssi=-60, timestamp_usec=30_000))

        report = analyzer.finalize()
        assert report.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert report.metrics["allowlist_confirmed_peripherals"] == 1


# =============================================================================
# 6. Remediated Side-Channel Analyzers Verification Suite
# =============================================================================
class TestRemediatedSidechannelAnalyzers:
    """Explicit unit tests covering all remediation fixes from Challenger 1 and 2."""

    def test_differential_encryption_truncated_rejection_safe_formatting(self) -> None:
        """Truncated LL_REJECT_IND without error_code does not crash and formats as UNKNOWN."""
        analyzer = DifferentialEncryptionAnalyzer()
        pdu = build_ll_header(llid=3, length=1) + bytes([0x0D])
        pkt = BlePacketRecord(body=pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=0x12345678)

        findings = analyzer.process_packet(pkt)
        assert len(findings) == 1
        assert findings[0].details["error_code"] is None
        assert "ErrorCode=UNKNOWN" in findings[0].details["summary"]

    def test_differential_encryption_non_encryption_rejection_ignored(self) -> None:
        """LL_REJECT_EXT_IND for non-encryption opcodes (e.g. 0x0F, 0x00) must be disregarded."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x88776655
        pdu = build_ll_reject_ext_ind(reject_opcode=0x0F, error_code=0x20)
        pkt = BlePacketRecord(body=pdu, channel=1, rssi=-60, timestamp_usec=1000, access_address=aa)

        findings = analyzer.process_packet(pkt)
        assert len(findings) == 0

        report = analyzer.finalize()
        assert report.verdict == Verdict.INCONCLUSIVE.value
        assert report.metrics["rejected_sessions"] == 0

    def test_differential_encryption_duplicate_start_enc_rsp_suppression(self) -> None:
        """Retransmissions of LL_START_ENC_RSP must not produce duplicate findings."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x12345678

        # Central and Peripheral both send LL_START_ENC_RSP + retransmissions
        f1 = analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa))
        f2 = analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa))
        f3 = analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=3000, access_address=aa))

        assert len(f1) == 1
        assert len(f2) == 0
        assert len(f3) == 0
        assert len(analyzer._all_findings) == 1

    def test_differential_encryption_state_isolation_established_session(self) -> None:
        """Established encryption session must not be demoted by unrelated rejections."""
        analyzer = DifferentialEncryptionAnalyzer()
        aa = 0x55443322

        analyzer.process_packet(BlePacketRecord(body=build_ll_enc_req(), channel=1, rssi=-60, timestamp_usec=1000, access_address=aa))
        analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=2000, access_address=aa))
        # Unrelated rejection later in connection
        analyzer.process_packet(BlePacketRecord(body=build_ll_reject_ext_ind(reject_opcode=0x0F, error_code=0x20), channel=1, rssi=-60, timestamp_usec=3000, access_address=aa))

        report = analyzer.finalize()
        assert report.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.metrics["shared_ltk_sessions"] == 1
        assert report.metrics["rejected_sessions"] == 0

    def test_differential_encryption_target_filter_strict(self) -> None:
        """Target MAC filter must not leak unassociated PERIPH_ connections."""
        analyzer = DifferentialEncryptionAnalyzer(target_mac="AA:BB:CC:DD:EE:01")
        # Packet with different AA and no CONNECT_IND matching target
        findings = analyzer.process_packet(BlePacketRecord(body=build_ll_start_enc_rsp(), channel=1, rssi=-60, timestamp_usec=1000, access_address=0x99999999))
        assert len(findings) == 0

    def test_csrk_counter_invalid_mac_aborts_without_state_pollution(self) -> None:
        """Corrupt MAC signature emits VERIFICATION_FAILED and does not pollute counter state."""
        csrk = b"\x22" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev = "C0:01:02:03:04:05"
        periph = "D0:01:02:03:04:05"
        aa = 0x11223344

        analyzer.process_packet(BlePacketRecord(body=build_connect_ind(dev, periph, conn_aa=aa), channel=37, rssi=-60, timestamp_usec=1000, access_address=BLE_ADV_AA))

        # Injected packet with corrupted MAC and SC=999
        bad_write = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"x", counter=999, corrupt_mac=True)
        f_bad = analyzer.process_packet(BlePacketRecord(body=bad_write, channel=1, rssi=-60, timestamp_usec=2000, access_address=aa, direction=0))

        assert len(f_bad) == 1
        assert f_bad[0].verdict == Verdict.VERIFICATION_FAILED.value
        # State must not have been updated with counter 999
        assert analyzer._senders[dev].last_counter is None

        # Subsequent legitimate packet SC=1 must be accepted as initial counter
        good_write = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"x", counter=1, corrupt_mac=False)
        f_good = analyzer.process_packet(BlePacketRecord(body=good_write, channel=1, rssi=-60, timestamp_usec=3000, access_address=aa, direction=0))

        assert len(f_good) == 1
        assert f_good[0].verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert analyzer._senders[dev].last_counter == 1

    def test_csrk_counter_replay_vs_rollback_classification(self) -> None:
        """Seen counter flags ANOMALY_REPLAY; unseen smaller counter flags ANOMALY_ROLLBACK."""
        csrk = b"\x33" * 16
        analyzer = CsrkCounterAnalyzer(csrk=csrk)
        dev = "C0:11:22:33:44:55"
        periph = "D0:11:22:33:44:55"
        aa = 0x22334455

        analyzer.process_packet(BlePacketRecord(body=build_connect_ind(dev, periph, conn_aa=aa), channel=37, rssi=-60, timestamp_usec=1000, access_address=BLE_ADV_AA))

        # Legitimate sequence 10, 11, 12
        for sc in (10, 11, 12):
            w = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=sc)
            analyzer.process_packet(BlePacketRecord(body=w, channel=1, rssi=-60, timestamp_usec=1000 + sc * 100, access_address=aa, direction=0))

        # Replay SC=10 (already seen)
        w_replay = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=10)
        f_rep = analyzer.process_packet(BlePacketRecord(body=w_replay, channel=1, rssi=-60, timestamp_usec=5000, access_address=aa, direction=0))
        assert f_rep[0].verdict == Verdict.ANOMALY_REPLAY.value

        # High-water mark preserved at 12 -> SC=13 is delta=1 (SEQUENTIAL_MONOTONIC)
        w_next = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=13)
        f_next = analyzer.process_packet(BlePacketRecord(body=w_next, channel=1, rssi=-60, timestamp_usec=6000, access_address=aa, direction=0))
        assert f_next[0].verdict == Verdict.SEQUENTIAL_MONOTONIC.value

        # Rollback to SC=5 (never seen before)
        w_roll = build_att_signed_write(csrk=csrk, handle=0x0001, value=b"", counter=5)
        f_roll = analyzer.process_packet(BlePacketRecord(body=w_roll, channel=1, rssi=-60, timestamp_usec=7000, access_address=aa, direction=0))
        assert f_roll[0].verdict == Verdict.ANOMALY_ROLLBACK.value

    def test_csrk_counter_cross_rpa_scoped_by_target_peripheral(self) -> None:
        """Cross-RPA linking does not link across different target peripherals."""
        analyzer = CsrkCounterAnalyzer()
        rpa_a = "C0:00:00:00:00:01"
        rpa_b = "C0:00:00:00:00:02"

        # Sender A connects to Peripheral 1
        analyzer.process_packet(BlePacketRecord(body=build_connect_ind(rpa_a, "D0:01:00:00:00:00", conn_aa=0x11111111), channel=37, rssi=-60, timestamp_usec=1000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_att_signed_write(csrk=b"\x11" * 16, handle=0x0001, value=b"", counter=10), channel=1, rssi=-60, timestamp_usec=2000, access_address=0x11111111, direction=0))

        # Sender B connects to Peripheral 2 with SC=11 (delta=1)
        analyzer.process_packet(BlePacketRecord(body=build_connect_ind(rpa_b, "D0:02:00:00:00:00", conn_aa=0x22222222), channel=37, rssi=-60, timestamp_usec=3000, access_address=BLE_ADV_AA))
        analyzer.process_packet(BlePacketRecord(body=build_att_signed_write(csrk=b"\x22" * 16, handle=0x0001, value=b"", counter=11), channel=1, rssi=-60, timestamp_usec=4000, access_address=0x22222222, direction=0))

        report = analyzer.finalize()
        # Must NOT link rpa_a and rpa_b because target peripherals differ
        assert not any(rpa_a in g and rpa_b in g for g in report.metrics["linked_rpa_groups"])

    def test_bat_allowlist_nearest_t_ifs_probe_matching(self) -> None:
        """Nearest-T_IFS probe matching correctly resolves concurrent scanner probes."""
        analyzer = BatAllowlistAnalyzer()
        foreign_scanner = "F0:00:00:00:00:01"
        allowed_scanner = "A0:00:00:00:00:01"
        periph = "11:22:33:44:55:66"

        analyzer.process_packet(BlePacketRecord(body=build_adv_ind(periph), channel=37, rssi=-60, timestamp_usec=500))
        # Foreign probes at 1000us, Allowed probes at 1100us
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(foreign_scanner, periph), channel=37, rssi=-60, timestamp_usec=1000))
        analyzer.process_packet(BlePacketRecord(body=build_scan_req(allowed_scanner, periph), channel=37, rssi=-60, timestamp_usec=1100))
        # Response at 1250us (150us after allowed, 250us after foreign)
        analyzer.process_packet(BlePacketRecord(body=build_scan_rsp(periph), channel=37, rssi=-60, timestamp_usec=1250))

        report = analyzer.finalize()
        assert report.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        periph_state = analyzer._peripherals[periph]
        assert allowed_scanner in periph_state.probes_responded
        assert foreign_scanner in periph_state.probes_silenced

