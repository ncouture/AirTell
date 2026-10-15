"""Adversarial stress testing suite for Side-Channel CLI subcommand (Milestone 3).

Stress-tests:
1. Argument validation, truncated options, unknown flags, and invalid analyzer choices.
2. CSRK hex string validation, length anomalies, non-hex chars, and empty-string edge case.
3. Non-existent files, directory targets, unreadable PCAPs, and unwritable output paths.
4. Corrupted PCAP headers, 0-byte files, invalid link types, and truncated packet records.
5. JSON output purity, pipe compatibility, and stdout isolation from log messages.
6. Strict exit code contract conformance (0 = clean, 1 = detections, 2 = errors) and
   auditing live interface error exit codes.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from airtell.cli import main
from airtell.sidechannel import (
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
)
from airtell.sniff.pcap import PcapBleWriter


# =============================================================================
# 1. Argument Parsing, Truncation & Invalid Choices
# =============================================================================
class TestAdversarialCliArgumentValidation:
    """Stress-tests for CLI argument handling, truncated options, and choice bounds."""

    def test_missing_input_source_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Must specify an input source" in captured.err
        assert captured.out == ""

    @pytest.mark.parametrize(
        "truncated_args",
        [
            ["sidechannel", "--pcap"],
            ["sidechannel", "--mock", "--csrk"],
            ["sidechannel", "--mock", "--analyzer"],
            ["sidechannel", "--mock", "--target"],
            ["sidechannel", "--mock", "--output"],
        ],
    )
    def test_truncated_argument_options_return_code_two(
        self, truncated_args: list[str]
    ) -> None:
        cmd = [sys.executable, "-m", "airtell.cli"] + truncated_args
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 2
        assert "expected one argument" in res.stderr.lower() or "usage:" in res.stderr.lower()

    @pytest.mark.parametrize(
        "unknown_flag",
        [
            "--nonexistent-flag",
            "-z",
            "--pcap-bad",
            "--simulate",
        ],
    )
    def test_unknown_flags_return_code_two(self, unknown_flag: str) -> None:
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", unknown_flag]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 2
        assert "unrecognized arguments" in res.stderr.lower()

    @pytest.mark.parametrize(
        "invalid_choice",
        [
            "invalid_choice",
            "ALL",
            "Encryption",
            "CSRK",
            "BAT",
            "",
            "all,encryption",
        ],
    )
    def test_invalid_analyzer_choices_return_code_two(
        self, invalid_choice: str
    ) -> None:
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--mock",
            "--analyzer",
            invalid_choice,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 2
        assert "invalid choice" in res.stderr.lower() or "usage:" in res.stderr.lower()

    def test_invalid_target_mac_format_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--target", "INVALID_MAC_ADDR"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "Invalid MAC address string" in captured.err


# =============================================================================
# 2. CSRK Hex String Validation & Edge Cases
# =============================================================================
class TestAdversarialCsrkValidation:
    """Stress-tests for CSRK input validation and parsing edge cases."""

    @pytest.mark.parametrize(
        "odd_hex",
        [
            "1",
            "123",
            "0123456789abcdef0123456789abcde",  # 31 chars
            "0123456789abcdef0123456789abcdef0",  # 33 chars
        ],
    )
    def test_odd_length_csrk_returns_code_two(
        self, odd_hex: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--csrk", odd_hex])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Invalid hex string for CSRK" in captured.err

    @pytest.mark.parametrize(
        "invalid_len_hex",
        [
            "00" * 15,  # 15 bytes (30 hex chars)
            "00" * 17,  # 17 bytes (34 hex chars)
            "00" * 8,   # 8 bytes
            "00" * 32,  # 32 bytes
        ],
    )
    def test_invalid_length_csrk_returns_code_two(
        self, invalid_len_hex: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--csrk", invalid_len_hex])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: CSRK must be 16 bytes" in captured.err

    @pytest.mark.parametrize(
        "non_hex_str",
        [
            "0123456789abcdef0123456789abcdeg",  # contains 'g'
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "0x" + ("00" * 16),                   # 0x prefix is invalid for bytes.fromhex
            "00" * 15 + "??",
        ],
    )
    def test_non_hex_csrk_returns_code_two(
        self, non_hex_str: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--csrk", non_hex_str])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Invalid hex string for CSRK" in captured.err

    def test_csrk_empty_string_behavior(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Adversarial check: passing --csrk '' should be caught as validation error.

        In Python, bool('') is False, so `if args.csrk:` skips validation if not carefully checked.
        """
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--mock",
            "--csrk",
            "",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        # Empty CSRK must be rejected with exit code 2 and a validation error
        assert res.returncode == 2
        assert "ERROR: CSRK must be 16 bytes" in res.stderr


# =============================================================================
# 3. File & Path Edge Cases
# =============================================================================
class TestAdversarialFileAndPathHandling:
    """Stress-tests for non-existent, unreadable, directory, or unwritable paths."""

    def test_nonexistent_pcap_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--pcap", "/nonexistent/path/trace_9999.pcap"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: PCAP file not found" in captured.err

    def test_directory_as_pcap_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        test_dir = tmp_path / "a_directory.pcap"
        test_dir.mkdir()
        rc = main(["sidechannel", "--pcap", str(test_dir)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: PCAP file not found" in captured.err

    def test_unreadable_pcap_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "unreadable.pcap"
        pcap_file.write_bytes(b"\x00" * 32)
        pcap_file.chmod(0o000)
        try:
            rc = main(["sidechannel", "--pcap", str(pcap_file)])
            assert rc == 2
            captured = capsys.readouterr()
            assert "Permission denied" in captured.err
        finally:
            pcap_file.chmod(0o644)

    def test_unwritable_output_path_returns_code_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["sidechannel", "--mock", "--output", "/proc/bad_output.json"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Failed to write output file" in captured.err

    def test_directory_as_output_path_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "out_directory"
        out_dir.mkdir()
        rc = main(["sidechannel", "--mock", "--output", str(out_dir)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "ERROR: Failed to write output file" in captured.err


# =============================================================================
# 4. PCAP Formatting, Truncation & Corrupted Header Tests
# =============================================================================
class TestAdversarialPcapCorruptions:
    """Stress-tests for corrupted PCAP headers, 0-byte files, and corrupted Link-Layer PDUs."""

    def test_zero_byte_pcap_file_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "zero.pcap"
        pcap_file.write_bytes(b"")
        rc = main(["sidechannel", "--pcap", str(pcap_file)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "File too short for PCAP global header" in captured.err

    @pytest.mark.parametrize("header_len", [1, 5, 12, 23])
    def test_truncated_global_header_returns_code_two(
        self, tmp_path: Path, header_len: int, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / f"trunc_{header_len}.pcap"
        pcap_file.write_bytes(b"\x00" * header_len)
        rc = main(["sidechannel", "--pcap", str(pcap_file)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "File too short for PCAP global header" in captured.err

    def test_invalid_pcap_magic_number_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "bad_magic.pcap"
        # 24 bytes with non-matching magic
        pcap_file.write_bytes(b"BADM" + (b"\x00" * 20))
        rc = main(["sidechannel", "--pcap", str(pcap_file)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "Invalid PCAP magic" in captured.err

    def test_unsupported_linktype_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "bad_dlt.pcap"
        # DLT 1 (Ethernet) instead of 256 (Bluetooth LE PHDR)
        hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pcap_file.write_bytes(hdr)
        rc = main(["sidechannel", "--pcap", str(pcap_file)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "Unsupported LinkType: 1" in captured.err

    def test_valid_pcap_header_with_zero_packets_returns_code_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "empty_valid.pcap"
        hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256)
        pcap_file.write_bytes(hdr)
        rc = main(["sidechannel", "--pcap", str(pcap_file), "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["total_packets"] == 0
        assert report["has_detections"] is False

    def test_truncated_packet_payload_returns_code_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "trunc_payload.pcap"
        hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256)
        # Packet header with incl_len = 50, but only 10 bytes written
        pkt_hdr = struct.pack("<IIII", 100, 0, 50, 50)
        pcap_file.write_bytes(hdr + pkt_hdr + (b"\x00" * 10))
        rc = main(["sidechannel", "--pcap", str(pcap_file)])
        assert rc == 2
        captured = capsys.readouterr()
        assert "Truncated packet payload in PCAP" in captured.err

    def test_corrupted_link_layer_pdus_handled_gracefully(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pcap_file = tmp_path / "corrupted_pdus.pcap"
        writer = PcapBleWriter(str(pcap_file))
        # Zero-byte payload
        writer.write_packet(ts_usec=1000, aa=0x12345678, chan=1, rssi=-50, packet=b"", pdu_type=2)
        # 1-byte payload (invalid PDU header)
        writer.write_packet(ts_usec=2000, aa=0x12345678, chan=1, rssi=-50, packet=b"\x03", pdu_type=2)
        # Control opcode 0xFF (unknown)
        writer.write_packet(ts_usec=3000, aa=0x12345678, chan=1, rssi=-50, packet=b"\x03\x01\xFF", pdu_type=2)
        # Truncated LL_ENC_REQ
        writer.write_packet(ts_usec=4000, aa=0x12345678, chan=1, rssi=-50, packet=b"\x03\x05\x03\x01\x02\x03\x04", pdu_type=2)
        # Truncated ATT Signed Write
        writer.write_packet(ts_usec=5000, aa=0x12345678, chan=1, rssi=-50, packet=b"\x02\x08\x04\x00\x04\x00\xD2\x01\x00", pdu_type=2)
        writer.close()

        rc = main(["sidechannel", "--pcap", str(pcap_file), "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["total_packets"] == 5
        assert parsed["has_detections"] is False


# =============================================================================
# 5. JSON Output Purity & Pipe Compatibility
# =============================================================================
class TestAdversarialJsonPiping:
    """Stress-tests for JSON pipe compatibility, log isolation, and stdout cleanliness."""

    def test_json_stdout_pipe_validity(self) -> None:
        cmd = [sys.executable, "-m", "airtell.cli", "sidechannel", "--mock", "--json"]
        p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p1.communicate()
        assert p1.returncode in (0, 1)
        # Ensure stdout is bit-for-bit valid JSON
        data = json.loads(out.decode("utf-8"))
        assert "overall_verdict" in data
        assert "reports" in data
        assert "findings" in data

    def test_verbose_logging_does_not_pollute_json_stdout(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "-v",
            "sidechannel",
            "--mock",
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode in (0, 1)
        # JSON parsing of stdout must succeed without stripping or trimming logs
        data = json.loads(res.stdout)
        assert data["overall_verdict"] == "PAIRED_SHARED_LTK"
        # Stderr may contain logs, stdout must not contain logger prefixes
        assert "[DEBUG]" not in res.stdout
        assert "[INFO]" not in res.stdout

    def test_error_conditions_emit_empty_stdout(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            "/nonexistent_pcap_trace.pcap",
            "--json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 2
        assert res.stdout == ""
        assert "ERROR:" in res.stderr


# =============================================================================
# 6. Exit Code Contract Conformance & Error Auditing
# =============================================================================
class TestAdversarialExitCodeConformance:
    """Rigorous verification that exit codes conform to 0=clean, 1=detections, 2=error."""

    def test_differential_encryption_positive_exits_code_one(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "enc_pos.pcap"
        pcap_path.write_bytes(generate_encryption_trace(shared_ltk=True))
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 1

    def test_differential_encryption_negative_exits_code_zero(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "enc_neg.pcap"
        pcap_path.write_bytes(generate_encryption_trace(shared_ltk=False))
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "encryption",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0

    def test_csrk_monotonic_clean_exits_code_zero(self, tmp_path: Path) -> None:
        csrk = b"\x44" * 16
        pcap_path = tmp_path / "csrk_mono.pcap"
        pcap_path.write_bytes(generate_csrk_trace([1, 2, 3, 4, 5], csrk=csrk))
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0

    @pytest.mark.parametrize(
        ("counter_seq", "corrupt_indices"),
        [
            ([1, 2, 2, 3], None),       # Replay anomaly
            ([10, 5], None),            # Rollback anomaly
            ([1, 1000], None),          # Jump anomaly
            ([1, 2, 3], [1]),           # Corrupted MAC signature
        ],
    )
    def test_csrk_anomalies_exit_code_one(
        self, tmp_path: Path, counter_seq: list[int], corrupt_indices: list[int] | None
    ) -> None:
        csrk = b"\x44" * 16
        pcap_path = tmp_path / "csrk_anomaly.pcap"
        pcap_path.write_bytes(
            generate_csrk_trace(counter_seq, csrk=csrk, corrupt_mac_indices=corrupt_indices)
        )
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "csrk",
            "--csrk",
            csrk.hex(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 1

    def test_bat_allowlist_positive_exits_code_one(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "bat_pos.pcap"
        pcap_path.write_bytes(generate_bat_allowlist_trace(allowlist_enabled=True, mode="selective_probe"))
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 1

    def test_bat_allowlist_negative_exits_code_zero(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "bat_neg.pcap"
        pcap_path.write_bytes(generate_bat_allowlist_trace(allowlist_enabled=False, mode="open_advertiser"))
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--pcap",
            str(pcap_path),
            "--analyzer",
            "bat",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0

    def test_live_interface_unavailable_audited_exit_code(self) -> None:
        """Audits the exit code behavior when --live specifies an unavailable serial port.

        Contract Requirement:
        - Exit code 0: Clean / No side-channels detected
        - Exit code 1: Side-channel detected
        - Exit code 2: Error (validation, execution, missing file, hardware error)

        FINDING: cli.py line 732 returns exit code 1 when the live sniffing interface
        is not available, which violates the contract by conflating an interface error
        with a confirmed side-channel detection.
        """
        cmd = [
            sys.executable,
            "-m",
            "airtell.cli",
            "sidechannel",
            "--live",
            "/dev/ttyUSB99_nonexistent",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        # We assert that an error message was logged to stderr
        assert "ERROR: Live sniffing interface not available" in res.stderr
        # Live interface failure must return exit code 2 per CLI contract
        assert res.returncode == 2
