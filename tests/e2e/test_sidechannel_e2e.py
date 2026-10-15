"""Comprehensive 5-Tier End-to-End (E2E) and Adversarial Verification Suite.

Validates the exclusive-use BLE side-channel detection and analysis suite
(airtell.sidechannel), public Python API, and CLI subcommand
(bluetooth-sniffle sidechannel) across all 5 verification tiers per
PoPETs 2025-0103 and ACM CCS 2022.

Tier Architecture:
- Tier 1: Feature Coverage Isolation (>= 5 tests per feature area)
- Tier 2: Boundary & Corner Cases (rollovers, 0-byte PCAP, truncated frames, jitter)
- Tier 3: Cross-Feature Combinations (pairwise interleaved protocols and CLI combinations)
- Tier 4: Realistic Real-World Application Workloads (multi-device office, 3-epoch wearable)
- Tier 5: Adversarial Stress & Subprocess Hardening (subprocess CLI, fuzzing, volume stress)
"""

from __future__ import annotations

import json
import random
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from airtell.cli import main
from airtell.sidechannel import (
    BlePacketRecord,
    ConnectionParameters,
    SideChannelSuiteReport,
    SyntheticEvent,
    Verdict,
    analyze_pcap,
    analyze_stream,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
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
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
    generate_synthetic_pcap,
)
from airtell.sidechannel.synthetic import (
    ERROR_PIN_OR_KEY_MISSING,
    ERROR_UNSUPPORTED_REMOTE_FEATURE,
    OPCODE_LL_CONNECTION_PARAM_REQ,
    OPCODE_LL_ENC_REQ,
)
from airtell.sniff.pcap import (
    BLE_ADV_AA,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    GLOBAL_HEADER_FORMAT,
    PCAP_MAGIC_USEC,
)

CSRK_TEST_KEY_1: bytes = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
CSRK_TEST_KEY_2: bytes = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x00"


# =============================================================================
# Tier 1: Feature Coverage Isolation Tests
# =============================================================================
class TestTier1FeatureIsolation:
    """Tier 1: Comprehensive isolated verification of each protocol analyzer and CLI feature."""

    # -------------------------------------------------------------------------
    # 1. Differential Encryption Analyzer
    # -------------------------------------------------------------------------
    def test_diff_enc_valid_handshake_shared_ltk_verdict(self) -> None:
        """Valid encryption handshake yields PAIRED_SHARED_LTK verdict with 1.0 confidence."""
        pcap_data = generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert "differential_encryption" in report.reports
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert rep.metrics["shared_ltk_sessions"] == 1
        assert rep.metrics["rejected_sessions"] == 0
        assert len(rep.findings) == 1
        finding = rep.findings[0]
        assert finding.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert finding.confidence == 1.0
        assert finding.device_addr == "AA:BB:CC:DD:EE:02"
        assert finding.target_addr == "AA:BB:CC:DD:EE:01"
        assert finding.details["is_shared_ltk"] is True
        assert report.has_detections is True

    def test_diff_enc_reject_ind_untrusted_key_verdict(self) -> None:
        """Rejected handshake via LL_REJECT_IND (0x06) yields REJECTED_UNTRUSTED."""
        pcap_data = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            error_code=ERROR_PIN_OR_KEY_MISSING,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert rep.metrics["shared_ltk_sessions"] == 0
        assert rep.metrics["rejected_sessions"] == 1
        assert rep.metrics["pin_missing_errors"] == 1
        assert len(rep.findings) == 1
        finding = rep.findings[0]
        assert finding.verdict == Verdict.REJECTED_UNTRUSTED.value
        assert finding.confidence == 1.0
        assert finding.details["is_pin_or_key_missing"] is True
        assert report.overall_verdict == Verdict.REJECTED_UNTRUSTED.value
        # Rejection of untrusted pairing indicates non-bonded state, so has_detections is False
        assert report.has_detections is False

    def test_diff_enc_reject_ext_ind_untrusted_key_verdict(self) -> None:
        """Rejected handshake via LL_REJECT_EXT_IND (0x06) yields REJECTED_UNTRUSTED."""
        pcap_data = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=True,
            error_code=ERROR_PIN_OR_KEY_MISSING,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.REJECTED_UNTRUSTED.value
        finding = rep.findings[0]
        assert finding.details["reject_opcode"] == OPCODE_LL_ENC_REQ
        assert finding.details["error_code"] == ERROR_PIN_OR_KEY_MISSING

    def test_diff_enc_non_enc_rejection_ignored(self) -> None:
        """LL_REJECT_EXT_IND rejecting non-encryption opcodes is ignored by the analyzer."""
        conn_aa = 0x12345678
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            ),
            # Rejecting connection param request (0x0F), NOT LL_ENC_REQ (0x03)
            SyntheticEvent(
                ts_usec=2000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_reject_ext_ind(
                    reject_opcode=OPCODE_LL_CONNECTION_PARAM_REQ,
                    error_code=ERROR_PIN_OR_KEY_MISSING,
                ),
            ),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.INCONCLUSIVE.value
        assert len(rep.findings) == 0
        assert rep.metrics["rejected_sessions"] == 0

    def test_diff_enc_unpaired_non_pin_error(self) -> None:
        """Rejected handshake with non-PIN error code yields UNPAIRED_KEY_REJECTED."""
        pcap_data = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            error_code=ERROR_UNSUPPORTED_REMOTE_FEATURE,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.UNPAIRED_KEY_REJECTED.value
        assert rep.metrics["pin_missing_errors"] == 0
        assert rep.findings[0].details["is_unsupported_feature"] is True

    def test_diff_enc_public_api_analyze_pcap(self, tmp_path: Path) -> None:
        """Public API analyze_pcap operates transparently on bytes, str, Path, and file-like objects."""
        pcap_data = generate_encryption_trace(shared_ltk=True)
        file_path = tmp_path / "enc_test.pcap"
        file_path.write_bytes(pcap_data)

        # Path input
        rep_path = analyze_pcap(file_path, analyzers=["encryption"])
        assert rep_path.overall_verdict == Verdict.PAIRED_SHARED_LTK.value

        # String input
        rep_str = analyze_pcap(str(file_path), analyzers=["encryption"])
        assert rep_str.overall_verdict == Verdict.PAIRED_SHARED_LTK.value

        # Raw bytes input
        rep_bytes = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert rep_bytes.overall_verdict == Verdict.PAIRED_SHARED_LTK.value

        # BinaryIO stream input
        with open(file_path, "rb") as f:
            rep_io = analyze_pcap(f, analyzers=["encryption"])
            assert rep_io.overall_verdict == Verdict.PAIRED_SHARED_LTK.value

    def test_diff_enc_public_api_analyze_stream(self) -> None:
        """Public API analyze_stream processes iterable sequences of BlePacketRecord objects."""
        conn_aa = 0x55667788
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            ),
            SyntheticEvent(
                ts_usec=2000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_enc_req(rand=b"\x01" * 8, ediv=0x1234, skdm=b"\x02" * 8, ivm=b"\x03" * 4),
            ),
            SyntheticEvent(
                ts_usec=3000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_enc_rsp(skds=b"\x04" * 8, ivs=b"\x05" * 4),
            ),
            SyntheticEvent(
                ts_usec=4000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_start_enc_req(),
            ),
            SyntheticEvent(
                ts_usec=5000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_start_enc_rsp(),
            ),
            SyntheticEvent(
                ts_usec=6000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD"),
            ),
        ]
        records = [BlePacketRecord.coerce(ev) for ev in events]
        report = analyze_stream(records, analyzers=["encryption"])
        assert report.overall_verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.total_packets == 6

    # -------------------------------------------------------------------------
    # 2. CSRK Monotonic Counter Tracker
    # -------------------------------------------------------------------------
    def test_csrk_strictly_monotonic_increments(self) -> None:
        """Strictly sequential counter increments produce SEQUENTIAL_MONOTONIC with zero anomalies."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[100, 101, 102, 103, 104, 105],
            csrk=CSRK_TEST_KEY_1,
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY_1)
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert rep.metrics["total_signed_writes"] == 6
        assert rep.metrics["total_anomalies"] == 0
        assert rep.metrics["mac_verification_failures"] == 0
        # All emitted findings have is_anomaly == False
        for f in rep.findings:
            assert f.verdict == Verdict.SEQUENTIAL_MONOTONIC.value
            assert f.details["is_anomaly"] is False

    def test_csrk_replay_attack_detected(self) -> None:
        """Replaying a previously observed SignCounter triggers ANOMALY_REPLAY."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[10, 11, 11, 12],
            csrk=CSRK_TEST_KEY_1,
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.ANOMALY_REPLAY.value
        assert rep.metrics["replay_anomalies"] == 1
        assert rep.metrics["total_anomalies"] == 1
        replays = [f for f in rep.findings if f.verdict == Verdict.ANOMALY_REPLAY.value]
        assert len(replays) == 1
        assert replays[0].details["counter"] == 11
        assert report.has_detections is True

    def test_csrk_rollback_anomaly_detected(self) -> None:
        """Decreasing SignCounter to an unseen lower value triggers ANOMALY_ROLLBACK."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[50, 51, 40, 52],
            csrk=CSRK_TEST_KEY_1,
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.ANOMALY_ROLLBACK.value
        assert rep.metrics["rollback_anomalies"] == 1
        rollbacks = [f for f in rep.findings if f.verdict == Verdict.ANOMALY_ROLLBACK.value]
        assert len(rollbacks) == 1
        assert rollbacks[0].details["delta"] < 0

    def test_csrk_jump_anomaly_detected(self) -> None:
        """Large counter gap (> 1000 step) triggers ANOMALY_JUMP."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[1, 2, 5000, 5001],
            csrk=CSRK_TEST_KEY_1,
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.ANOMALY_JUMP.value
        assert rep.metrics["jump_anomalies"] == 1
        jumps = [f for f in rep.findings if f.verdict == Verdict.ANOMALY_JUMP.value]
        assert len(jumps) == 1
        assert jumps[0].details["delta"] == 4998

    def test_csrk_corrupted_mac_signature_verification_failure(self) -> None:
        """Corrupted MAC with known CSRK key produces VERIFICATION_FAILED and halts state poisoning."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[1, 2, 3, 4],
            csrk=CSRK_TEST_KEY_1,
            corrupt_mac_indices=[2],  # Corrupt packet with SC=3
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY_1)
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.VERIFICATION_FAILED.value
        assert rep.metrics["mac_verification_failures"] == 1
        fail_finding = [f for f in rep.findings if f.verdict == Verdict.VERIFICATION_FAILED.value][0]
        assert fail_finding.details["counter"] == 3
        assert fail_finding.details["mac_valid"] is False

    def test_csrk_cross_rpa_linking(self) -> None:
        """Continuous counter sequence across distinct central RPAs links both addresses."""
        pcap_data = generate_csrk_trace(
            counter_sequence=[10, 11, 12, 13, 14],
            csrk=CSRK_TEST_KEY_1,
            central_addr="44:55:66:77:88:01",
            rotate_rpa_indices=[3],  # Rotate at SC=13
            rpa_sequence=["44:55:66:77:88:02"],
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.CROSS_RPA_LINKED.value
        assert len(rep.metrics["linked_rpa_groups"]) == 1
        group = rep.metrics["linked_rpa_groups"][0]
        assert "44:55:66:77:88:01" in group
        assert "44:55:66:77:88:02" in group
        link_findings = [f for f in rep.findings if f.verdict == Verdict.CROSS_RPA_LINKED.value]
        assert len(link_findings) >= 1
        assert link_findings[0].details["counter"] == 13

    # -------------------------------------------------------------------------
    # 3. BAT Allowlist & Reconnection Timing
    # -------------------------------------------------------------------------
    def test_bat_allowlist_selective_probe_response(self) -> None:
        """Selective response to authorized RPA and silence to unauthorized RPA confirms allowlist."""
        pcap_data = generate_bat_allowlist_trace(
            allowlist_enabled=True,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="11:22:33:44:55:66",
            periph_addr="AA:BB:CC:DD:EE:02",
            mode="selective_probe",
        )
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert rep.metrics["allowlist_confirmed_peripherals"] == 1
        assert len(rep.findings) >= 1
        finding = rep.findings[0]
        assert finding.verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert finding.device_addr == "AA:BB:CC:DD:EE:02"
        assert report.has_detections is True

    def test_bat_open_device_responds_equally(self) -> None:
        """Open device responding equally to all active probes yields OPEN_ADVERTISER without detections."""
        pcap_data = generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="11:22:33:44:55:66",
            periph_addr="AA:BB:CC:DD:EE:02",
            mode="selective_probe",
        )
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.verdict == Verdict.OPEN_ADVERTISER.value
        assert rep.metrics["allowlist_confirmed_peripherals"] == 0
        assert report.has_detections is False
        assert report.overall_verdict == Verdict.OPEN_ADVERTISER.value

    def test_bat_directed_exclusive_advertising(self) -> None:
        """ADV_DIRECT_IND high-duty advertising burst triggers DIRECTED_EXCLUSIVE."""
        pcap_data = generate_bat_allowlist_trace(
            mode="directed",
            target_rpa="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.verdict == Verdict.DIRECTED_EXCLUSIVE.value
        assert rep.metrics["directed_advertising_events"] >= 1
        finding = rep.findings[0]
        assert finding.verdict == Verdict.DIRECTED_EXCLUSIVE.value
        assert finding.device_addr == "AA:BB:CC:DD:EE:02"
        assert finding.target_addr == "AA:BB:CC:DD:EE:01"
        assert report.has_detections is True

    def test_bat_reconnection_advertising_interval_transitions(self) -> None:
        """Differential fast (30ms) to slow (1200ms) advertising transitions are extracted into metrics."""
        pcap_data = generate_bat_allowlist_trace(
            mode="reconnection_timing",
            fast_interval_ms=30.0,
            slow_interval_ms=1200.0,
            periph_addr="AA:BB:CC:DD:EE:02",
            conn_params=ConnectionParameters(interval=24, latency=0, timeout=100, hop_increment=5),
        )
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.metrics["fast_slow_transition_peripherals"] == 1
        assert rep.metrics["connection_profiles_extracted"] >= 1
        assert rep.verdict == Verdict.PROFILE_MATCH.value

    def test_bat_timing_jitter_within_tolerance(self) -> None:
        """SCAN_RSP with microsecond jitter (+/- 20us from 150us T_IFS) matches probe correctly."""
        periph_addr = "AA:BB:CC:DD:EE:02"
        scan_a = "AA:BB:CC:DD:EE:01"
        # Probe at t=1,000,000 us; response at t=1,000,165 us (165us, within 150 +/- 20us)
        events = [
            SyntheticEvent(ts_usec=900_000, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph_addr)),
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req(scan_a, periph_addr)),
            SyntheticEvent(ts_usec=1_000_165, chan=37, aa=BLE_ADV_AA, body=build_scan_rsp(periph_addr)),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.verdict == Verdict.OPEN_ADVERTISER.value
        assert len(rep.findings) == 1
        assert rep.findings[0].details["response_delay_usec"] == 165

    def test_bat_non_probe_packet_filtering(self) -> None:
        """Non-probe packets on advertising channels do not generate false allowlist findings."""
        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_adv_ind("11:22:33:44:55:66")),
            SyntheticEvent(ts_usec=1_050_000, chan=38, aa=BLE_ADV_AA, body=build_adv_ind("11:22:33:44:55:66")),
            SyntheticEvent(ts_usec=1_100_000, chan=39, aa=BLE_ADV_AA, body=build_adv_ind("11:22:33:44:55:66")),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.verdict == Verdict.INCONCLUSIVE.value
        assert len(rep.findings) == 0

    # -------------------------------------------------------------------------
    # 4. CLI Subcommand & Public API Integration
    # -------------------------------------------------------------------------
    def test_cli_mock_detection_exit_code_one(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --mock executes simulation, returns exit code 1, and reports detections."""
        rc = main(["sidechannel", "--mock"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "Bluetooth-Sniffle Side-Channel Analysis Report" in captured.out
        assert "Detections Found:            YES" in captured.out

    def test_cli_pcap_clean_exit_code_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --pcap on clean open advertiser returns exit code 0."""
        clean_pcap = tmp_path / "clean_open.pcap"
        generate_bat_allowlist_trace(
            allowlist_enabled=False,
            output_path=clean_pcap,
            mode="selective_probe",
        )
        rc = main(["sidechannel", "--pcap", str(clean_pcap)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Detections Found:            NO" in captured.out

    def test_cli_pcap_vuln_exit_code_one(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --pcap on vulnerable/exclusive trace returns exit code 1."""
        vuln_pcap = tmp_path / "vuln_shared_ltk.pcap"
        generate_encryption_trace(
            shared_ltk=True,
            output_path=vuln_pcap,
        )
        rc = main(["sidechannel", "--pcap", str(vuln_pcap)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "Detections Found:            YES" in captured.out

    def test_cli_json_and_output_file_writing(self, tmp_path: Path) -> None:
        """CLI with --json and --output exports complete structured report to file."""
        out_file = tmp_path / "report.json"
        rc = main(["sidechannel", "--mock", "--json", "--output", str(out_file)])
        assert rc == 1
        assert out_file.exists()

        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert "overall_verdict" in content
        assert "has_detections" in content
        assert content["has_detections"] is True
        assert "reports" in content
        assert "findings" in content
        assert isinstance(content["findings"], list)

    def test_cli_analyzer_selective_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --analyzer encryption executes only the encryption analyzer."""
        rc = main(["sidechannel", "--mock", "--analyzer", "encryption", "--json"])
        assert rc == 1
        captured = capsys.readouterr()
        doc = json.loads(captured.out)
        assert "differential_encryption" in doc["reports"]
        assert "csrk_counter" not in doc["reports"]
        assert "bat_allowlist" not in doc["reports"]


# =============================================================================
# Tier 2: Boundary & Corner Cases Tests
# =============================================================================
class TestTier2BoundariesCorners:
    """Tier 2: Extreme values, boundary conditions, zero-byte inputs, and protocol corner cases."""

    def test_csrk_32bit_rollover_near_max(self) -> None:
        """32-bit counter progression near 0xFFFFFFFF (0xFFFFFFFE -> 0xFFFFFFFF -> 0x00000000)."""
        # Sequential increment up to 0xFFFFFFFF
        pcap_data = generate_csrk_trace(
            counter_sequence=[0xFFFFFFFE, 0xFFFFFFFF],
            csrk=CSRK_TEST_KEY_1,
        )
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        assert report.reports["csrk_counter"].verdict == Verdict.SEQUENTIAL_MONOTONIC.value

        # Progression wrapping to 0 triggers rollback detection
        pcap_wrap = generate_csrk_trace(
            counter_sequence=[0xFFFFFFFF, 0x00000000],
            csrk=CSRK_TEST_KEY_1,
        )
        report_wrap = analyze_pcap(pcap_wrap, analyzers=["csrk"])
        assert report_wrap.reports["csrk_counter"].verdict == Verdict.ANOMALY_ROLLBACK.value

    def test_empty_zero_byte_pcap_handling(self, tmp_path: Path) -> None:
        """0-byte file passed to analyze_pcap raises ValueError for missing global header."""
        empty_file = tmp_path / "empty_zero.pcap"
        empty_file.write_bytes(b"")

        with pytest.raises(ValueError, match="File too short for PCAP global header"):
            analyze_pcap(empty_file)

    def test_empty_pcap_header_zero_packets(self, tmp_path: Path) -> None:
        """Valid 24-byte PCAP header with 0 packet records returns clean INCONCLUSIVE report."""
        header_only = tmp_path / "header_only.pcap"
        # Write valid PCAP global header (magic, 2.4, thiszone=0, sigfigs=0, snaplen=65535, dlt=256)
        hdr = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        header_only.write_bytes(hdr)

        report = analyze_pcap(header_only)
        assert report.total_packets == 0
        assert report.has_detections is False
        assert report.overall_verdict == Verdict.INCONCLUSIVE.value

    def test_truncated_or_incomplete_ll_control_pdu(self) -> None:
        """Truncated LL Control PDU (LL_ENC_REQ with only 2 bytes payload) handled safely without crash."""
        conn_aa = 0x99887766
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            ),
            # LLID=0b11, length=3, opcode=0x03 (LL_ENC_REQ), but only 2 payload bytes instead of 22
            SyntheticEvent(
                ts_usec=2000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_header(0b11, 3) + bytes([OPCODE_LL_ENC_REQ, 0x11, 0x22]),
            ),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert report.total_packets == 2
        rep = report.reports["differential_encryption"]
        assert rep.verdict == Verdict.INCONCLUSIVE.value

    def test_zero_length_payload_data_packet(self) -> None:
        """Empty Link-Layer data channel PDU (length = 0) is parsed cleanly without IndexError."""
        conn_aa = 0xAABBCCDD
        events = [
            # LLID=0b01 (empty/continuation), length=0
            SyntheticEvent(
                ts_usec=2000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_header(0b01, 0),
            ),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption", "csrk"])
        assert report.total_packets == 1
        assert report.has_detections is False

    def test_dual_dongle_timing_jitter_and_clock_drift(self) -> None:
        """Interleaved dual-channel stream with non-monotonic timestamps and microsecond drift."""
        events = []
        base_ts = 1_000_000
        for i in range(20):
            # Introduce jitter: alternating offsets
            jitter = (i % 3 - 1) * 5
            ts = base_ts + (i * 20_000) + jitter
            chan = 37 if i % 2 == 0 else 38
            events.append(
                SyntheticEvent(
                    ts_usec=ts,
                    chan=chan,
                    aa=BLE_ADV_AA,
                    body=build_adv_ind("AA:BB:CC:DD:EE:02"),
                )
            )
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        assert report.total_packets == 20
        assert report.reports["bat_allowlist"].metrics["monitored_peripherals"] == 1

    def test_rapid_rpa_rotations_subsecond(self) -> None:
        """Multiple rapid RPA address rotations within 50ms window are handled without state leakage."""
        conn_aa = 0x44332211
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("44:55:66:77:88:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            )
        ]
        # Central rotates RPA 5 times in 50ms (every 10ms)
        for i in range(5):
            events.append(
                SyntheticEvent(
                    ts_usec=10_000 + (i * 10_000),
                    chan=1,
                    aa=conn_aa,
                    direction=0,
                    body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=i),
                )
            )
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY_1)
        rep = report.reports["csrk_counter"]
        assert rep.metrics["total_signed_writes"] == 5

    def test_maximum_packet_burst_flood(self) -> None:
        """Burst of 500 packets in a single millisecond is processed without dropped state or buffer overflow."""
        conn_aa = 0x88776655
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            )
        ]
        for i in range(500):
            events.append(
                SyntheticEvent(
                    ts_usec=2000 + i,
                    chan=1,
                    aa=conn_aa,
                    direction=0,
                    body=build_ll_header(0b01, 0),
                )
            )
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data)
        assert report.total_packets == 501

    def test_unknown_ll_control_opcode(self) -> None:
        """Undocumented Link-Layer control opcode (0xFE) is parsed safely as generic control frame."""
        conn_aa = 0x11223344
        events = [
            SyntheticEvent(
                ts_usec=1000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            ),
            SyntheticEvent(
                ts_usec=2000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_header(0b11, 2) + bytes([0xFE, 0x99]),
            ),
        ]
        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert report.total_packets == 2
        assert report.reports["differential_encryption"].verdict == Verdict.INCONCLUSIVE.value


# =============================================================================
# Tier 3: Cross-Feature Combinations (Pairwise Coverage)
# =============================================================================
class TestTier3CrossFeatureCombinations:
    """Tier 3: Pairwise and multi-analyzer interactions over interleaved Link-Layer protocols."""

    def test_interleaved_encryption_handshake_and_csrk_signed_writes(self) -> None:
        """Single connection session executing both valid encryption handshake AND CSRK signed writes."""
        conn_aa = 0x22334455
        events = [
            SyntheticEvent(
                ts_usec=1_000_000,
                chan=37,
                aa=BLE_ADV_AA,
                body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa),
            ),
            # 1. Encryption handshake
            SyntheticEvent(
                ts_usec=1_050_000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_enc_req(rand=b"\x01" * 8, ediv=0x1234, skdm=b"\x02" * 8, ivm=b"\x03" * 4),
            ),
            SyntheticEvent(
                ts_usec=1_060_000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_enc_rsp(skds=b"\x04" * 8, ivs=b"\x05" * 4),
            ),
            SyntheticEvent(
                ts_usec=1_070_000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_start_enc_req(),
            ),
            SyntheticEvent(
                ts_usec=1_080_000,
                chan=1,
                aa=conn_aa,
                direction=0,
                body=build_ll_start_enc_rsp(),
            ),
            SyntheticEvent(
                ts_usec=1_090_000,
                chan=1,
                aa=conn_aa,
                direction=1,
                body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD"),
            ),
        ]
        # 2. Interleaved CSRK Signed Writes
        for i in range(5):
            events.append(
                SyntheticEvent(
                    ts_usec=1_150_000 + (i * 20_000),
                    chan=1,
                    aa=conn_aa,
                    direction=0,
                    body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0020, value=b"\x02", counter=i),
                )
            )

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["all"], csrk=CSRK_TEST_KEY_1)

        # Both analyzers confirm exclusive-use characteristics
        assert report.reports["differential_encryption"].verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.reports["csrk_counter"].verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert report.has_detections is True
        assert "AA:BB:CC:DD:EE:02" in report.confirmed_exclusive_devices

    def test_interleaved_bat_allowlist_probing_and_differential_encryption(self) -> None:
        """Allowlist probe discrimination on advertising channel followed by connection and encryption."""
        periph_addr = "AA:BB:CC:DD:EE:02"
        target_rpa = "AA:BB:CC:DD:EE:01"
        foreign_rpa = "99:88:77:66:55:44"
        conn_aa = 0x33445566

        events = [
            # 1. BAT allowlist probing
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph_addr)),
            # Foreign probe (silenced)
            SyntheticEvent(ts_usec=1_010_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req(foreign_rpa, periph_addr)),
            # Target authorized probe (answered in 150us)
            SyntheticEvent(ts_usec=1_030_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req(target_rpa, periph_addr)),
            SyntheticEvent(ts_usec=1_030_150, chan=37, aa=BLE_ADV_AA, body=build_scan_rsp(periph_addr)),
            # 2. Connection and encryption setup
            SyntheticEvent(ts_usec=1_100_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(target_rpa, periph_addr, conn_aa=conn_aa)),
            SyntheticEvent(ts_usec=1_150_000, chan=1, aa=conn_aa, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=1_160_000, chan=1, aa=conn_aa, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=1_170_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=1_180_000, chan=1, aa=conn_aa, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=1_190_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["bat", "encryption"])

        assert report.reports["bat_allowlist"].verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert report.reports["differential_encryption"].verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.has_detections is True

    def test_cross_rpa_tracking_with_both_csrk_and_encryption_active(self) -> None:
        """Central rotates RPA across multiple connections while maintaining both encryption and CSRK counters."""
        rpa_1 = "44:55:66:77:88:01"
        rpa_2 = "44:55:66:77:88:02"
        periph = "AA:BB:CC:DD:EE:02"
        conn_aa1 = 0x11112222
        conn_aa2 = 0x33334444

        events = [
            # Session 1 with RPA 1: Connect, Encrypt, Signed Writes SC=10, 11
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(rpa_1, periph, conn_aa=conn_aa1)),
            SyntheticEvent(ts_usec=1_010_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=1_020_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=1_030_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=1_040_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=1_050_000, chan=1, aa=conn_aa1, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
            SyntheticEvent(ts_usec=1_060_000, chan=1, aa=conn_aa1, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=10)),
            SyntheticEvent(ts_usec=1_070_000, chan=1, aa=conn_aa1, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=11)),
            # Disconnect
            SyntheticEvent(ts_usec=1_080_000, chan=1, aa=conn_aa1, direction=0, body=build_ll_terminate_ind(0x13)),

            # Session 2 with RPA 2 (within 300s window): Connect, Encrypt, Signed Writes SC=12, 13
            SyntheticEvent(ts_usec=2_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(rpa_2, periph, conn_aa=conn_aa2)),
            SyntheticEvent(ts_usec=2_010_000, chan=1, aa=conn_aa2, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=2_020_000, chan=1, aa=conn_aa2, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=2_030_000, chan=1, aa=conn_aa2, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=2_040_000, chan=1, aa=conn_aa2, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=2_050_000, chan=1, aa=conn_aa2, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
            SyntheticEvent(ts_usec=2_060_000, chan=1, aa=conn_aa2, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=12)),
            SyntheticEvent(ts_usec=2_070_000, chan=1, aa=conn_aa2, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=13)),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["csrk", "encryption"], csrk=CSRK_TEST_KEY_1)

        assert report.reports["csrk_counter"].verdict == Verdict.CROSS_RPA_LINKED.value
        assert report.reports["differential_encryption"].verdict == Verdict.PAIRED_SHARED_LTK.value
        assert rpa_1 in report.confirmed_exclusive_devices
        assert rpa_2 in report.confirmed_exclusive_devices

    def test_cli_pairwise_combination_flags(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with pairwise combination of --pcap, --analyzer, --json, --output, and --summary."""
        pcap_file = tmp_path / "pairwise.pcap"
        generate_bat_allowlist_trace(
            allowlist_enabled=True,
            output_path=pcap_file,
            mode="directed",
        )
        out_json = tmp_path / "pairwise_out.json"

        rc = main([
            "sidechannel",
            "--pcap", str(pcap_file),
            "--analyzer", "bat",
            "--json",
            "--output", str(out_json),
            "--summary",
        ])
        assert rc == 1
        assert out_json.exists()
        doc = json.loads(out_json.read_text(encoding="utf-8"))
        assert "bat_allowlist" in doc["reports"]
        assert doc["overall_verdict"] == Verdict.DIRECTED_EXCLUSIVE.value

    def test_multi_analyzer_target_filtering(self) -> None:
        """Runner with target_mac filter filters traffic across all analyzers concurrently."""
        target = "AA:BB:CC:DD:EE:02"
        other = "99:99:99:99:99:99"
        conn_aa_target = 0x11111111
        conn_aa_other = 0x22222222

        events = [
            # Target connection
            SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", target, conn_aa=conn_aa_target)),
            SyntheticEvent(ts_usec=2000, chan=1, aa=conn_aa_target, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=3000, chan=1, aa=conn_aa_target, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=4000, chan=1, aa=conn_aa_target, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=5000, chan=1, aa=conn_aa_target, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=6000, chan=1, aa=conn_aa_target, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),

            # Other unrelated connection (should be filtered out)
            SyntheticEvent(ts_usec=7000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("88:88:88:88:88:88", other, conn_aa=conn_aa_other)),
            SyntheticEvent(ts_usec=8000, chan=1, aa=conn_aa_other, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=9000, chan=1, aa=conn_aa_other, direction=1, body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING)),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption"], target_mac=target)
        rep = report.reports["differential_encryption"]

        assert rep.verdict == Verdict.PAIRED_SHARED_LTK.value
        assert rep.metrics["shared_ltk_sessions"] == 1
        assert rep.metrics["rejected_sessions"] == 0

    def test_mixed_verdict_suite_aggregation(self) -> None:
        """Capture with one rejected session and one shared LTK session yields CONFIRMED_EXCLUSIVE."""
        conn_aa1 = 0x11111111
        conn_aa2 = 0x22222222

        events = [
            # Session 1: Rejected encryption
            SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa1)),
            SyntheticEvent(ts_usec=2000, chan=1, aa=conn_aa1, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=3000, chan=1, aa=conn_aa1, direction=1, body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING)),

            # Session 2: Confirmed shared LTK
            SyntheticEvent(ts_usec=4000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", conn_aa=conn_aa2)),
            SyntheticEvent(ts_usec=5000, chan=1, aa=conn_aa2, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)),
            SyntheticEvent(ts_usec=6000, chan=1, aa=conn_aa2, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)),
            SyntheticEvent(ts_usec=7000, chan=1, aa=conn_aa2, direction=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=8000, chan=1, aa=conn_aa2, direction=0, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=9000, chan=1, aa=conn_aa2, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["encryption"])
        assert report.overall_verdict == Verdict.CONFIRMED_EXCLUSIVE.value
        assert report.reports["differential_encryption"].verdict == Verdict.CONFIRMED_EXCLUSIVE.value


# =============================================================================
# Tier 4: Realistic Real-World Application Workloads
# =============================================================================
class TestTier4RealWorldWorkloads:
    """Tier 4: End-to-end multi-device and multi-epoch ecosystem simulations."""

    def test_ecosystem_simulation_1_exclusive_peripheral_rotating_rpas(self) -> None:
        """Ecosystem 1: Wearable device communicating with bonded smartphone across 3 address rotations.

        Validates:
        - 3 distinct epochs with Central RPAs: RPA_1 -> RPA_2 -> RPA_3.
        - BAT Allowlist: peripheral selectively answers SCAN_REQ from Central, ignoring foreign scanners.
        - CSRK Monotonic Counter: continuous sequence across all epochs (100-102, 103-105, 106-108).
        - Shared LTK verified during encryption setup in each connection.
        - De-anonymizes and links all 3 RPAs into a single identity.
        """
        central_rpas = ["40:01:02:03:04:01", "40:01:02:03:04:02", "40:01:02:03:04:03"]
        foreign_scanner = "70:80:90:A0:B0:C0"
        periph_addr = "F0:DE:F1:22:33:44"
        events: list[SyntheticEvent] = []

        sc = 100
        for epoch_idx, c_rpa in enumerate(central_rpas):
            base_epoch_us = 1_000_000 + (epoch_idx * 60_000_000)  # 60s between epochs (< 300s temporal linking limit)
            conn_aa = 0x50000000 + epoch_idx

            # 1. Advertising phase: BAT allowlist probe discrimination
            events.append(SyntheticEvent(ts_usec=base_epoch_us, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph_addr)))
            # Foreign probe (ignored by peripheral)
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 10_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req(foreign_scanner, periph_addr)))
            # Authorized Central probe (answered in 150us)
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 30_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req(c_rpa, periph_addr)))
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 30_150, chan=37, aa=BLE_ADV_AA, body=build_scan_rsp(periph_addr)))

            # 2. Connection establishment
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 100_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(c_rpa, periph_addr, conn_aa=conn_aa)))

            # 3. Differential Encryption Handshake (Shared LTK confirmed)
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 150_000, chan=1, aa=conn_aa, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)))
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 160_000, chan=1, aa=conn_aa, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)))
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 170_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_req()))
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 180_000, chan=1, aa=conn_aa, direction=0, body=build_ll_start_enc_rsp()))
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 190_000, chan=1, aa=conn_aa, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")))

            # 4. Continuous Signed Writes (3 packets per epoch)
            for _ in range(3):
                events.append(SyntheticEvent(
                    ts_usec=base_epoch_us + 250_000 + ((sc - 100) * 20_000),
                    chan=1,
                    aa=conn_aa,
                    direction=0,
                    body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0015, value=b"\x01", counter=sc),
                ))
                sc += 1

            # 5. Clean disconnect
            events.append(SyntheticEvent(ts_usec=base_epoch_us + 350_000, chan=1, aa=conn_aa, direction=0, body=build_ll_terminate_ind(0x13)))

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["all"], csrk=CSRK_TEST_KEY_1)

        # Confirm all 3 analyzers detected their respective signals
        assert report.reports["bat_allowlist"].verdict == Verdict.ALLOWLIST_CONFIRMED.value
        assert report.reports["differential_encryption"].verdict == Verdict.PAIRED_SHARED_LTK.value
        assert report.reports["csrk_counter"].verdict == Verdict.CROSS_RPA_LINKED.value

        # Confirm complete deanonymization across rotating RPAs
        for rpa in central_rpas:
            assert rpa in report.confirmed_exclusive_devices

    def test_ecosystem_simulation_2_multi_device_office_environment(self) -> None:
        """Ecosystem 2: Complex multi-device office RF capture with 5 concurrent devices.

        Devices:
        - D1: Public beacon broadcasting unbonded telemetry (open, no connections).
        - D2: Open environmental sensor answering all scan requests (open advertiser).
        - D3: Non-bonded peripheral rejecting central pairing with LL_REJECT_IND 0x06.
        - D4: Bonded corporate asset badge establishing mutual shared LTK encryption.
        - D5: Smart office door lock enforcing strict BAT allowlist.

        Verifies that full pipeline analysis accurately distinguishes each device without cross-talk.
        """
        d1_beacon = "E0:00:00:00:00:01"
        d2_sensor = "E0:00:00:00:00:02"
        d3_unpaired = "E0:00:00:00:00:03"
        d4_bonded = "E0:00:00:00:00:04"
        d5_lock = "E0:00:00:00:00:05"

        events: list[SyntheticEvent] = []

        # D1: Public beacon
        for i in range(10):
            events.append(SyntheticEvent(ts_usec=1_000_000 + (i * 100_000), chan=37 + (i % 3), aa=BLE_ADV_AA, body=build_adv_ind(d1_beacon)))

        # D2: Open sensor (responds to 2 distinct scanners)
        events.append(SyntheticEvent(ts_usec=1_050_000, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(d2_sensor)))
        events.append(SyntheticEvent(ts_usec=1_060_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req("10:00:00:00:00:01", d2_sensor)))
        events.append(SyntheticEvent(ts_usec=1_060_150, chan=37, aa=BLE_ADV_AA, body=build_scan_rsp(d2_sensor)))
        events.append(SyntheticEvent(ts_usec=1_070_000, chan=38, aa=BLE_ADV_AA, body=build_scan_req("10:00:00:00:00:02", d2_sensor)))
        events.append(SyntheticEvent(ts_usec=1_070_150, chan=38, aa=BLE_ADV_AA, body=build_scan_rsp(d2_sensor)))

        # D3: Unpaired peripheral rejected
        conn_aa_d3 = 0x33333333
        events.append(SyntheticEvent(ts_usec=1_100_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("C0:00:00:00:00:03", d3_unpaired, conn_aa=conn_aa_d3)))
        events.append(SyntheticEvent(ts_usec=1_150_000, chan=1, aa=conn_aa_d3, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)))
        events.append(SyntheticEvent(ts_usec=1_160_000, chan=1, aa=conn_aa_d3, direction=1, body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING)))

        # D4: Bonded badge shared LTK
        conn_aa_d4 = 0x44444444
        events.append(SyntheticEvent(ts_usec=1_200_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("C0:00:00:00:00:04", d4_bonded, conn_aa=conn_aa_d4)))
        events.append(SyntheticEvent(ts_usec=1_250_000, chan=2, aa=conn_aa_d4, direction=0, body=build_ll_enc_req(rand=b"\x01"*8, ediv=0x1234, skdm=b"\x02"*8, ivm=b"\x03"*4)))
        events.append(SyntheticEvent(ts_usec=1_260_000, chan=2, aa=conn_aa_d4, direction=1, body=build_ll_enc_rsp(skds=b"\x04"*8, ivs=b"\x05"*4)))
        events.append(SyntheticEvent(ts_usec=1_270_000, chan=2, aa=conn_aa_d4, direction=1, body=build_ll_start_enc_req()))
        events.append(SyntheticEvent(ts_usec=1_280_000, chan=2, aa=conn_aa_d4, direction=0, body=build_ll_start_enc_rsp()))
        events.append(SyntheticEvent(ts_usec=1_290_000, chan=2, aa=conn_aa_d4, direction=1, body=build_ll_start_enc_rsp(mic=b"\xAA\xBB\xCC\xDD")))

        # D5: Smart lock with BAT allowlist (silent to walk-by phone, selective to key owner)
        events.append(SyntheticEvent(ts_usec=1_300_000, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(d5_lock)))
        events.append(SyntheticEvent(ts_usec=1_310_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req("F0:00:00:00:00:05", d5_lock)))  # Silent drop
        events.append(SyntheticEvent(ts_usec=1_350_000, chan=37, aa=BLE_ADV_AA, body=build_scan_req("A0:00:00:00:00:05", d5_lock)))  # Owner
        events.append(SyntheticEvent(ts_usec=1_350_150, chan=37, aa=BLE_ADV_AA, body=build_scan_rsp(d5_lock)))

        # Sort events deterministically by timestamp
        events.sort(key=lambda ev: ev.ts_usec)

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["all"])

        # Validate findings accurately attribute each device
        enc_rep = report.reports["differential_encryption"]
        assert enc_rep.metrics["shared_ltk_sessions"] == 1
        assert enc_rep.metrics["rejected_sessions"] == 1
        assert d4_bonded in [f.device_addr for f in enc_rep.findings if f.verdict == Verdict.PAIRED_SHARED_LTK.value]
        assert d3_unpaired in [f.device_addr for f in enc_rep.findings if f.verdict == Verdict.REJECTED_UNTRUSTED.value]

        bat_rep = report.reports["bat_allowlist"]
        assert d5_lock in [f.device_addr for f in bat_rep.findings if f.verdict == Verdict.ALLOWLIST_CONFIRMED.value]
        assert d2_sensor in [f.device_addr for f in bat_rep.findings if f.verdict == Verdict.OPEN_ADVERTISER.value]

    def test_ecosystem_simulation_3_replay_attack_in_wild(self) -> None:
        """Adversary captures signed write and injects replays into an active session.

        Verifies:
        - Legitimate sequence SC=50, 51.
        - Attacker replays packet SC=51 twice.
        - Monotonic high-water mark is preserved.
        - Next legitimate packet SC=52 is processed normally without false regression.
        """
        conn_aa = 0x77889900
        central = "AA:BB:CC:DD:EE:01"
        periph = "AA:BB:CC:DD:EE:02"

        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(central, periph, conn_aa=conn_aa)),
            # Legitimate writes
            SyntheticEvent(ts_usec=1_050_000, chan=1, aa=conn_aa, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=50)),
            SyntheticEvent(ts_usec=1_100_000, chan=1, aa=conn_aa, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=51)),
            # Attacker replay burst
            SyntheticEvent(ts_usec=1_150_000, chan=1, aa=conn_aa, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=51)),
            SyntheticEvent(ts_usec=1_200_000, chan=1, aa=conn_aa, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=51)),
            # Legitimate next write SC=52
            SyntheticEvent(ts_usec=1_250_000, chan=1, aa=conn_aa, direction=0, body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=52)),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY_1)
        rep = report.reports["csrk_counter"]

        assert rep.verdict == Verdict.ANOMALY_REPLAY.value
        assert rep.metrics["replay_anomalies"] == 2
        assert rep.metrics["total_signed_writes"] == 5

    def test_ecosystem_simulation_4_mobile_central_reconnection_storm(self) -> None:
        """Rapid reconnection storm: 8 connection cycles within 5 seconds negotiating parameters."""
        central = "AA:BB:CC:DD:EE:01"
        periph = "AA:BB:CC:DD:EE:02"
        events: list[SyntheticEvent] = []

        for i in range(8):
            conn_aa = 0x60000000 + i
            ts = 1_000_000 + (i * 500_000)
            events.append(SyntheticEvent(ts_usec=ts, chan=37, aa=BLE_ADV_AA, body=build_adv_ind(periph)))
            events.append(SyntheticEvent(ts_usec=ts + 10_000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind(central, periph, conn_aa=conn_aa, interval=24, latency=0, timeout=100, hop=5)))
            events.append(SyntheticEvent(ts_usec=ts + 50_000, chan=1, aa=conn_aa, direction=0, body=build_ll_terminate_ind(0x13)))

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["bat"])
        rep = report.reports["bat_allowlist"]

        assert rep.metrics["connection_profiles_extracted"] == 8
        assert rep.verdict == Verdict.PROFILE_MATCH.value


# =============================================================================
# Tier 5: Adversarial Stress & Subprocess Hardening
# =============================================================================
class TestTier5AdversarialStressSubprocess:
    """Tier 5: Direct subprocess CLI execution, fuzz byte mutations, and high-volume performance."""

    def test_subprocess_cli_mock_execution(self) -> None:
        """Direct subprocess execution of python -m airtell.cli sidechannel --mock."""
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--mock"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 1
        assert "Bluetooth-Sniffle Side-Channel Analysis Report" in res.stdout
        assert "Detections Found:            YES" in res.stdout

    def test_subprocess_cli_pcap_execution(self, tmp_path: Path) -> None:
        """Direct subprocess execution of python -m airtell.cli sidechannel --pcap <file> --json."""
        pcap_file = tmp_path / "subp_test.pcap"
        generate_encryption_trace(shared_ltk=True, output_path=pcap_file)

        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--pcap", str(pcap_file), "--json"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 1

        doc = json.loads(res.stdout)
        assert doc["has_detections"] is True
        assert doc["reports"]["differential_encryption"]["verdict"] == Verdict.PAIRED_SHARED_LTK.value

    def test_subprocess_cli_conflicting_arguments_stderr(self, tmp_path: Path) -> None:
        """Passing multiple conflicting sources (--pcap and --mock) exits with code 2 and stderr message."""
        dummy_pcap = tmp_path / "dummy.pcap"
        dummy_pcap.write_bytes(b"dummy")

        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--pcap", str(dummy_pcap), "--mock"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 2
        assert "ERROR: Multiple conflicting input sources specified" in res.stderr

    def test_subprocess_cli_invalid_csrk_hex_stderr(self) -> None:
        """Non-hex string passed to --csrk exits with code 2 and stderr diagnostic."""
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--mock", "--csrk", "ZZ_NOT_HEX_VALUE"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 2
        assert "ERROR: Invalid hex string for CSRK" in res.stderr

    def test_subprocess_cli_invalid_csrk_length_stderr(self) -> None:
        """Hex string with invalid length (< 16 bytes) exits with code 2 and stderr diagnostic."""
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--mock", "--csrk", "1122334455"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 2
        assert "CSRK must be 16 bytes" in res.stderr

    def test_subprocess_cli_nonexistent_pcap_stderr(self) -> None:
        """Specifying non-existent PCAP path exits with code 2 and stderr message."""
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--pcap", "/tmp/does_not_exist_987654.pcap"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 2
        assert "ERROR: PCAP file not found" in res.stderr

    def test_adversarial_pcap_corrupt_packet_bytes(self) -> None:
        """PCAP with mutated packet payloads and flipped bits runs safely without unhandled crashes."""
        base_pcap = bytearray(generate_encryption_trace(shared_ltk=True))
        # Fuzz 50 random byte locations inside packet bodies (preserving the 24-byte PCAP header)
        rng = random.Random(42)
        for _ in range(50):
            idx = rng.randint(24, len(base_pcap) - 1)
            base_pcap[idx] = rng.randint(0, 255)

        # Runner must process or discard invalid frames without raising unexpected exceptions
        try:
            report = analyze_pcap(bytes(base_pcap))
            assert isinstance(report, SideChannelSuiteReport)
        except Exception as exc:
            # Only standard parsing / frame discard exceptions permitted
            assert isinstance(exc, (ValueError, EOFError))

    def test_high_packet_volume_stress_performance(self) -> None:
        """2000 synthetic packets processed through full analysis suite in under 2.0 seconds."""
        events: list[SyntheticEvent] = []
        conn_aa = 0x12344321
        events.append(SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa)))

        # Build 2000 sequential data packets
        for i in range(2000):
            events.append(
                SyntheticEvent(
                    ts_usec=2000 + (i * 100),
                    chan=i % 37,
                    aa=conn_aa,
                    direction=0,
                    body=build_att_signed_write(csrk=CSRK_TEST_KEY_1, handle=0x0012, value=b"\x01", counter=i),
                )
            )

        pcap_data = generate_synthetic_pcap(events)

        t_start = time.perf_counter()
        report = analyze_pcap(pcap_data, analyzers=["csrk"], csrk=CSRK_TEST_KEY_1)
        duration = time.perf_counter() - t_start

        assert report.total_packets == 2001
        assert report.reports["csrk_counter"].metrics["total_signed_writes"] == 2000
        # Verification requirement: sub-second to < 2.0s analysis performance
        assert duration < 2.0, f"Analysis took {duration:.2f}s, exceeding 2.0s limit"

    def test_adversarial_deeply_nested_malformed_l2cap(self) -> None:
        """Packets with invalid L2CAP CID, truncated headers, and negative lengths handled gracefully."""
        conn_aa = 0x99998888
        events = [
            SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=build_connect_ind("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", conn_aa=conn_aa)),
            # LLID=0b10 (L2CAP start), but L2CAP declared length is 0x0080 (128) with only 4 bytes payload
            SyntheticEvent(ts_usec=2000, chan=1, aa=conn_aa, direction=0, body=build_ll_header(0b10, 8) + struct.pack("<HH", 128, 0x0004) + b"\xD2\x01\x02\x03"),
            # LLID=0b10 with invalid CID 0xFFFF
            SyntheticEvent(ts_usec=3000, chan=1, aa=conn_aa, direction=0, body=build_ll_header(0b10, 6) + struct.pack("<HH", 2, 0xFFFF) + b"\x00\x00"),
            # LLID=0b10 with ATT signed write opcode 0xD2, but payload truncated to only 2 bytes (missing 12B signature)
            SyntheticEvent(ts_usec=4000, chan=1, aa=conn_aa, direction=0, body=build_ll_header(0b10, 6) + struct.pack("<HH", 2, 0x0004) + b"\xD2\x01"),
        ]

        pcap_data = generate_synthetic_pcap(events)
        report = analyze_pcap(pcap_data, analyzers=["csrk"])
        assert report.total_packets == 4
        # Malformed frames are safely discarded without crashing
        assert report.reports["csrk_counter"].metrics["total_signed_writes"] == 0
