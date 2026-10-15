"""Comprehensive automated test suite for Side-Channel CLI and Python API (Milestone 3).

Verifies:
1. CLI argument parsing, subcommands, help banners, and aliases.
2. Offline PCAP analysis on Differential Encryption fixtures (positive shared LTK vs negative rejected).
3. Offline PCAP analysis on CSRK fixtures (sequential monotonic vs replayed/jumped/corrupted).
4. Offline PCAP analysis on BAT Allowlist fixtures (selective probe, open advertiser, directed advertising).
5. Error handling for missing files, invalid analyzer options, and malformed CSRKs (exit code 2).
6. High-level Python API calls (analyze_pcap, analyze_stream, SideChannelAnalysisRunner).
7. Mock simulation mode and output reporting (JSON format, text summary, file export).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from airtell.cli import create_parser, main
from airtell.protocol.wire import PacketMessage
from airtell.sidechannel import (
    SideChannelAnalysisRunner,
    SideChannelSuiteReport,
    SyntheticEvent,
    Verdict,
    analyze_pcap,
    analyze_stream,
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
    generate_mock_stream,
)
from airtell.sniff.pcap import CapturedBlePacket, PcapBleReader


# =============================================================================
# 1. CLI Argument Parsing and Option Validation Tests
# =============================================================================
class TestCliArgumentParsing:
    """Tests verifying CLI argument parsing, flags, and parameter validation."""

    def test_parser_has_sidechannel_subcommand(self) -> None:
        parser = create_parser()
        # Ensure subcommand is recognized
        args = parser.parse_args(["sidechannel", "--mock"])
        assert args.command == "sidechannel"
        assert args.mock is True
        assert args.analyzer == "all"

    def test_sidechannel_help_banner(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["sidechannel", "--help"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "--pcap" in captured.out
        assert "--mock" in captured.out
        assert "--analyzer" in captured.out
        assert "--target" in captured.out
        assert "--csrk" in captured.out
        assert "--json" in captured.out
        assert "--output" in captured.out
        assert "--summary" in captured.out

    @pytest.mark.parametrize("subcmd_alias", ["side-channel", "analyze-sidechannel"])
    def test_sidechannel_subcommand_aliases(
        self, subcmd_alias: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main([subcmd_alias, "--help"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "--pcap" in captured.out

    def test_missing_input_source_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Must specify an input source" in captured.err

    def test_nonexistent_pcap_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--pcap", "/tmp/definitely_nonexistent_pcap_12345.pcap"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: PCAP file not found" in captured.err

    def test_invalid_analyzer_choice_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--analyzer", "unsupported_analyzer"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "invalid choice" in captured.err or "usage:" in captured.err

    def test_invalid_csrk_non_hex_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--csrk", "not_a_valid_hex_string_xyz"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Invalid hex string for CSRK" in captured.err

    def test_invalid_csrk_length_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # 4 bytes hex instead of 16
        rc = main(["sidechannel", "--mock", "--csrk", "11223344"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: CSRK must be 16 bytes" in captured.err

    def test_csrk_empty_string_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--csrk", ""])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: CSRK must be 16 bytes (32 hex characters), got 0 bytes" in captured.err

    def test_multiple_input_sources_mock_and_pcap_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dummy_pcap = tmp_path / "dummy.pcap"
        dummy_pcap.write_bytes(b"dummy")
        rc = main(["sidechannel", "--mock", "--pcap", str(dummy_pcap)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Multiple conflicting input sources specified" in captured.err

    def test_multiple_input_sources_mock_and_live_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--live", "/dev/ttyUSB0"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Multiple conflicting input sources specified" in captured.err

    def test_multiple_input_sources_pcap_and_live_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dummy_pcap = tmp_path / "dummy.pcap"
        dummy_pcap.write_bytes(b"dummy")
        rc = main(["sidechannel", "--pcap", str(dummy_pcap), "--live", "/dev/ttyUSB0"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Multiple conflicting input sources specified" in captured.err

    def test_live_interface_failure_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--live", "/dev/nonexistent_serial_port_999"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Live sniffing interface not available" in captured.err

    def test_output_file_generation_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_file = tmp_path / "nested" / "report.json"
        rc = main(["sidechannel", "--mock", "--json", "--output", str(out_file)])
        assert rc in (0, 1)
        assert out_file.exists()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert "overall_verdict" in parsed
        assert "reports" in parsed

    def test_output_file_generation_text_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_file = tmp_path / "report.txt"
        rc = main(["sidechannel", "--mock", "--summary", "--output", str(out_file)])
        assert rc in (0, 1)
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "Bluetooth-Sniffle Side-Channel Analysis Report" in content
        assert "Active Analyzer Results:" in content


# =============================================================================
# 2. Differential Encryption Initiation PCAP & CLI Tests
# =============================================================================
class TestDifferentialEncryptionCliAndPcap:
    """Tests differential encryption analyzer integration via CLI and PCAP."""

    def test_positive_shared_ltk_pcap_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "shared_ltk.pcap"
        generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
            "--json",
        ])
        assert rc == 1  # Exclusive-use side-channel detected

        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.PAIRED_SHARED_LTK.value
        assert "AA:BB:CC:DD:EE:02" in report["confirmed_exclusive_devices"]
        assert len(report["findings"]) >= 1

        finding = report["findings"][0]
        assert finding["verdict"] == Verdict.PAIRED_SHARED_LTK.value
        assert finding["details"]["is_shared_ltk"] is True

    def test_negative_rejected_pcap_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "rejected_ltk.pcap"
        generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
            "--json",
        ])
        assert rc == 0  # Clean analysis, no shared LTK / exclusive device detected

        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is False
        assert report["overall_verdict"] == Verdict.REJECTED_UNTRUSTED.value
        assert report["confirmed_exclusive_devices"] == []

    def test_negative_extended_reject_pcap_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "ext_rejected_ltk.pcap"
        generate_encryption_trace(
            shared_ltk=False,
            extended_reject=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
            "--json",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is False
        assert report["overall_verdict"] == Verdict.REJECTED_UNTRUSTED.value

    def test_differential_encryption_target_filter(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "filtered_ltk.pcap"
        generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        # Match target filter
        rc_match = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
            "--target",
            "AA:BB:CC:DD:EE:02",
            "--json",
        ])
        assert rc_match == 1

        # Mismatch target filter
        rc_mismatch = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
            "--target",
            "FF:FF:FF:FF:FF:FF",
            "--json",
        ])
        assert rc_mismatch == 0


# =============================================================================
# 3. CSRK Counter Monotonicity & Anomaly PCAP & CLI Tests
# =============================================================================
class TestCsrkCounterCliAndPcap:
    """Tests CSRK counter analyzer integration via CLI and PCAP."""

    def test_csrk_sequential_monotonic_clean_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = b"\x11" * 16
        pcap_path = tmp_path / "csrk_sequential.pcap"
        generate_csrk_trace(
            counter_sequence=[10, 11, 12, 13, 14],
            csrk=csrk,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
            "--json",
        ])
        assert rc == 0  # Sequential normal monotonic, no anomaly
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is False
        assert report["overall_verdict"] == Verdict.SEQUENTIAL_MONOTONIC.value

    def test_csrk_replay_anomaly_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = b"\x22" * 16
        pcap_path = tmp_path / "csrk_replay.pcap"
        generate_csrk_trace(
            counter_sequence=[100, 101, 101, 102],
            csrk=csrk,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
            "--json",
        ])
        assert rc == 1  # Anomaly detected
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.ANOMALY_REPLAY.value
        replay_finding = next(
            f for f in report["findings"] if f["verdict"] == Verdict.ANOMALY_REPLAY.value
        )
        assert replay_finding["details"]["counter"] == 101

    def test_csrk_jump_anomaly_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = b"\x33" * 16
        pcap_path = tmp_path / "csrk_jump.pcap"
        generate_csrk_trace(
            counter_sequence=[1, 2, 50, 51],
            csrk=csrk,
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.ANOMALY_JUMP.value

    def test_csrk_cryptographic_verification_failure_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = b"\x44" * 16
        pcap_path = tmp_path / "csrk_bad_mac.pcap"
        generate_csrk_trace(
            counter_sequence=[5, 6, 7],
            csrk=csrk,
            corrupt_mac_indices=[1],
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.VERIFICATION_FAILED.value

    def test_csrk_cross_rpa_linking_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = b"\x55" * 16
        pcap_path = tmp_path / "csrk_cross_rpa.pcap"
        generate_csrk_trace(
            counter_sequence=[200, 201, 202, 203],
            csrk=csrk,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
            rotate_rpa_indices=[2],
            rpa_sequence=["66:77:88:99:AA:BB"],
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.CROSS_RPA_LINKED.value
        assert "AA:BB:CC:DD:EE:01" in report["confirmed_exclusive_devices"]
        assert "66:77:88:99:AA:BB" in report["confirmed_exclusive_devices"]


# =============================================================================
# 4. BAT Allowlist Auto-Connection PCAP & CLI Tests
# =============================================================================
class TestBatAllowlistCliAndPcap:
    """Tests BAT allowlist analyzer integration via CLI and PCAP."""

    def test_bat_allowlist_confirmed_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "bat_allowlist.pcap"
        generate_bat_allowlist_trace(
            allowlist_enabled=True,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="99:88:77:66:55:44",
            periph_addr="11:22:33:44:55:66",
            mode="selective_probe",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.ALLOWLIST_CONFIRMED.value
        assert "11:22:33:44:55:66" in report["confirmed_exclusive_devices"]

    def test_bat_open_advertiser_clean_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "bat_open.pcap"
        generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="AA:BB:CC:DD:EE:01",
            foreign_rpa="99:88:77:66:55:44",
            periph_addr="11:22:33:44:55:66",
            mode="selective_probe",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
            "--json",
        ])
        assert rc == 0  # Clean open advertiser, no allowlist
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is False
        assert report["overall_verdict"] == Verdict.OPEN_ADVERTISER.value

    def test_bat_directed_exclusive_advertising_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "bat_directed.pcap"
        generate_bat_allowlist_trace(
            target_rpa="AA:BB:CC:DD:EE:01",
            periph_addr="11:22:33:44:55:66",
            mode="directed",
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.DIRECTED_EXCLUSIVE.value

    def test_bat_reconnection_profile_match_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_path = tmp_path / "bat_profile.pcap"
        generate_bat_allowlist_trace(
            target_rpa="AA:BB:CC:DD:EE:01",
            periph_addr="11:22:33:44:55:66",
            mode="reconnection_timing",
            fast_interval_ms=30.0,
            slow_interval_ms=1200.0,
            conn_params=(24, 0, 100, 5),
            output_path=pcap_path,
        )

        rc = main([
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
            "--json",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["has_detections"] is True
        assert report["overall_verdict"] == Verdict.PROFILE_MATCH.value


# =============================================================================
# 5. Mock Simulation Mode Tests
# =============================================================================
class TestMockSimulationModeCli:
    """Tests executing side-channel analysis in mock mode."""

    def test_mock_all_analyzers_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["sidechannel", "--mock", "--json"])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert "reports" in report
        assert "differential_encryption" in report["reports"]
        assert "csrk_counter" in report["reports"]
        assert "bat_allowlist" in report["reports"]

    def test_mock_selective_encryption_analyzer(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--analyzer", "encryption", "--json"])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert "differential_encryption" in report["reports"]
        assert "csrk_counter" not in report["reports"]
        assert "bat_allowlist" not in report["reports"]

    def test_mock_selective_csrk_analyzer(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        csrk = (b"\x77" * 16).hex()
        rc = main(["sidechannel", "--mock", "--analyzer", "csrk", "--csrk", csrk, "--json"])
        assert rc in (0, 1)
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert "csrk_counter" in report["reports"]
        assert "differential_encryption" not in report["reports"]

    def test_mock_selective_bat_analyzer(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--analyzer", "bat", "--json"])
        assert rc == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert "bat_allowlist" in report["reports"]


# =============================================================================
# 6. Python API & SideChannelAnalysisRunner Tests
# =============================================================================
class TestSideChannelPythonApi:
    """Tests for public top-level Python API functions and classes."""

    def test_analyze_pcap_with_bytes(self) -> None:
        pcap_bytes = generate_encryption_trace(shared_ltk=True)
        report = analyze_pcap(pcap_bytes)
        assert isinstance(report, SideChannelSuiteReport)
        assert report.has_detections is True
        assert report.total_packets > 0
        assert report.to_dict()["has_detections"] is True
        assert "PAIRED_SHARED_LTK" in report.to_json()

    def test_analyze_pcap_with_bytesio(self) -> None:
        pcap_bytes = generate_encryption_trace(shared_ltk=False)
        stream = io.BytesIO(pcap_bytes)
        report = analyze_pcap(stream, analyzers=["encryption"])
        assert report.has_detections is False
        assert report.overall_verdict == Verdict.REJECTED_UNTRUSTED.value

    def test_analyze_pcap_with_filepath(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "trace.pcap"
        generate_encryption_trace(shared_ltk=True, output_path=pcap_path)
        report = analyze_pcap(str(pcap_path))
        assert report.has_detections is True
        assert len(report.confirmed_exclusive_devices) >= 1

    def test_analyze_stream_with_captured_packets(self) -> None:
        pcap_bytes = generate_bat_allowlist_trace(allowlist_enabled=True, mode="selective_probe")
        packets = list(PcapBleReader(io.BytesIO(pcap_bytes)))
        report = analyze_stream(packets, analyzers=["bat"])
        assert report.has_detections is True
        assert report.overall_verdict == Verdict.ALLOWLIST_CONFIRMED.value

    def test_analyze_stream_with_packet_messages(self) -> None:
        csrk = b"\x88" * 16
        pcap_bytes = generate_csrk_trace(counter_sequence=[1, 2, 3], csrk=csrk)
        captured_pkts = list(PcapBleReader(io.BytesIO(pcap_bytes)))
        # Convert to PacketMessage instances
        packet_messages = [
            PacketMessage(
                PacketMessage.pack(
                    body=pkt.body,
                    ts=pkt.ts_usec,
                    chan=pkt.ble_chan,
                    rssi=pkt.rssi,
                    direction=1 if pkt.pdu_type == 3 else 0,
                    crc_err=pkt.crc_err,
                )
            )
            for pkt in captured_pkts
        ]
        report = analyze_stream(packet_messages, analyzers=["csrk"], csrk=csrk)
        assert report.has_detections is False
        assert report.overall_verdict == Verdict.SEQUENTIAL_MONOTONIC.value
        assert report.total_packets == len(packet_messages)

    def test_analyze_stream_with_synthetic_events(self) -> None:
        events = [
            SyntheticEvent(ts_usec=1_000_000, body=b"\x00\x02\x01\x02"),
            SyntheticEvent(ts_usec=1_050_000, body=b"\x00\x02\x03\x04"),
        ]
        report = analyze_stream(events, analyzers=["all"])
        assert report.total_packets == 2
        assert report.has_detections is False

    def test_runner_class_instance(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "runner_test.pcap"
        generate_encryption_trace(shared_ltk=True, output_path=pcap_path)
        runner = SideChannelAnalysisRunner(analyzers=["encryption"], target_mac="AA:BB:CC:DD:EE:02")
        report = runner.run_pcap(pcap_path)
        assert report.target_mac == "AA:BB:CC:DD:EE:02"
        assert report.has_detections is True

    def test_runner_file_not_found(self) -> None:
        runner = SideChannelAnalysisRunner()
        with pytest.raises(FileNotFoundError):
            runner.run_pcap("/path/does/not/exist.pcap")

    def test_runner_invalid_analyzer_name(self) -> None:
        runner = SideChannelAnalysisRunner()
        with pytest.raises(ValueError, match="Unknown analyzer name"):
            runner.run_stream([], analyzers=["nonexistent"])

    def test_runner_invalid_csrk_length(self) -> None:
        runner = SideChannelAnalysisRunner()
        with pytest.raises(ValueError, match="CSRK must be 16 bytes"):
            runner.run_stream([], csrk=b"too_short")

    def test_generate_mock_stream_helper(self) -> None:
        stream = generate_mock_stream("all")
        pkts = list(stream)
        assert len(pkts) > 0
        assert all(isinstance(p, CapturedBlePacket) for p in pkts)

    def test_report_methods_and_properties(self) -> None:
        report = SideChannelSuiteReport(
            target_mac="AA:BB:CC:DD:EE:01",
            total_packets=10,
        )
        assert report.has_detections is False
        assert report.confirmed_exclusive_devices == []
        assert report.overall_verdict == Verdict.INCONCLUSIVE.value
        assert report.total_findings == 0
        assert report.all_findings == []

        d = report.to_dict()
        assert d["target_mac"] == "AA:BB:CC:DD:EE:01"
        assert d["total_packets"] == 10
        assert "summary" in d
        assert isinstance(report.to_json(), str)
        assert "Bluetooth-Sniffle Side-Channel Analysis Report" in report.to_text_summary()
