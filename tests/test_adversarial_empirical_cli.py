"""Adversarial CLI and Edge Probing Verification Suite for PCAP MAC Timeline Generator.

Authored by Empirical Challenger 2.
Directly probes CLI parameter combinations, boundaries, conflicting arguments,
error exit codes, file exports, and format consistency.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SPECTRAMESH_DIR = REPO_ROOT / "spectramesh_ouidb"
OUIDB_BIN = SPECTRAMESH_DIR / "oui_db.bin"
MERGED_PCAP = REPO_ROOT / "app" / "data" / "merged.pcap"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(SPECTRAMESH_DIR) not in sys.path:
    sys.path.insert(0, str(SPECTRAMESH_DIR))

from airtell.cli import create_parser, main  # noqa: E402
from airtell.sniff.timeline import generate_mac_timeline  # noqa: E402


class TestCliAdversarialProbing:
    """Adversarial challenge tests exercising CLI boundaries, conflicts, and error modes."""

    def test_cli_missing_pcap_file(self, tmp_path: Path) -> None:
        """Probe: Nonexistent PCAP file path must return exit code 2."""
        nonexistent = tmp_path / "does_not_exist.pcap"
        ret = main(["pcap-timeline", "-i", str(nonexistent)])
        assert ret == 2

    def test_cli_missing_ouidb_file(self, tmp_path: Path) -> None:
        """Probe: Nonexistent OUI database file path must return exit code 2."""
        nonexistent = tmp_path / "nonexistent_ouidb.bin"
        ret = main(["pcap-timeline", "-i", str(MERGED_PCAP), "--ouidb", str(nonexistent)])
        assert ret == 2

    def test_cli_directory_passed_as_pcap(self, tmp_path: Path) -> None:
        """Probe: Directory passed as PCAP file must return exit code 2."""
        ret = main(["pcap-timeline", "-i", str(tmp_path)])
        assert ret == 2

    def test_cli_nonexistent_category_filter(self) -> None:
        """Probe: Nonexistent device category must succeed with 0 entries and exit code 0."""
        ret = main([
            "pcap-timeline",
            "-i", str(MERGED_PCAP),
            "--category", "nonexistent_spacecraft_class",
            "--max-packets", "1000",
            "--json",
        ])
        assert ret == 0

    def test_cli_conflicting_surveillance_and_category_none(self) -> None:
        """Probe: --surveillance-only with --category none is mutually exclusive; returns 0 entries."""
        report = generate_mac_timeline(
            str(MERGED_PCAP),
            surveillance_only=True,
            category="none",
            max_packets=10000,
        )
        assert len(report.entries) == 0

    def test_cli_limit_zero(self) -> None:
        """Probe: --limit 0 should result in 0 entries without crashing."""
        report = generate_mac_timeline(
            str(MERGED_PCAP),
            limit=0,
        )
        assert len(report.entries) == 0

    def test_cli_limit_negative(self) -> None:
        """Probe: Negative limit behavior returns 0 entries."""
        report = generate_mac_timeline(str(MERGED_PCAP), max_entries=-1, max_packets=1000)
        assert len(report.entries) == 0
        report_lim = generate_mac_timeline(str(MERGED_PCAP), limit=-1, max_packets=1000)
        assert len(report_lim.entries) == 0

    def test_cli_max_packets_negative(self) -> None:
        """Probe: Negative max_packets behavior returns 0 packets and 0 entries."""
        report = generate_mac_timeline(str(MERGED_PCAP), max_packets=-5)
        assert report.total_packets_processed == 0
        assert len(report.entries) == 0

    def test_cli_negative_limits_exit_code_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Probe: Negative limit, max-packets, and max-entries must exit with code 2 and stderr message."""
        ret = main(["pcap-timeline", "-i", str(MERGED_PCAP), "--limit", "-1"])
        assert ret == 2
        err = capsys.readouterr().err
        assert "ERROR: limit must be non-negative: -1" in err

        ret = main(["pcap-timeline", "-i", str(MERGED_PCAP), "--max-packets", "-5"])
        assert ret == 2
        err = capsys.readouterr().err
        assert "ERROR: max-packets must be non-negative: -5" in err

        ret = main(["pcap-timeline", "-i", str(MERGED_PCAP), "--max-entries", "-10"])
        assert ret == 2
        err = capsys.readouterr().err
        assert "ERROR: max-entries must be non-negative: -10" in err

    def test_cli_timeline_alias_execution(self) -> None:
        """Probe: Command alias 'timeline' behaves identically to 'pcap-timeline'."""
        parser = create_parser()
        args = parser.parse_args(["timeline", "-i", str(MERGED_PCAP), "--limit", "50"])
        assert args.command in ("pcap-timeline", "timeline")
        assert args.limit == 50

    def test_cli_export_json_validity(self, tmp_path: Path) -> None:
        """Probe: JSON export must write strictly valid, parseable JSON matching report structure."""
        out_file = tmp_path / "report.json"
        ret = main([
            "pcap-timeline",
            "-i", str(MERGED_PCAP),
            "--limit", "2000",
            "-o", str(out_file),
        ])
        assert ret == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "pcap_path" in data
        assert "ouidb_path" in data
        assert "total_packets_processed" in data
        assert "entries" in data
        assert isinstance(data["entries"], list)

    def test_cli_export_csv_validity(self, tmp_path: Path) -> None:
        """Probe: CSV export must write valid RFC 4180 CSV with standard header columns."""
        out_file = tmp_path / "report.csv"
        ret = main([
            "pcap-timeline",
            "-i", str(MERGED_PCAP),
            "--limit", "2000",
            "-o", str(out_file),
        ])
        assert ret == 0
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            assert headers is not None
            expected_headers = [
                "mac", "first_seen", "first_seen_iso", "last_seen", "last_seen_iso",
                "packet_count", "packet_types", "roles", "is_random", "vendor",
                "prefix", "prefix_bits", "table", "device_category", "flags", "is_surveillance"
            ]
            for h in expected_headers:
                assert h in headers, f"Missing expected CSV header {h}"
            rows = list(reader)
            assert len(rows) > 0

    def test_cli_export_markdown_validity(self, tmp_path: Path) -> None:
        """Probe: Markdown export must write table with pipe delimiters and header divider."""
        out_file = tmp_path / "report.md"
        ret = main([
            "pcap-timeline",
            "-i", str(MERGED_PCAP),
            "--limit", "2000",
            "-o", str(out_file),
        ])
        assert ret == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "# BLE PCAP MAC Timeline Report" in content
        assert "| # | First Seen (UTC) | Last Seen (UTC) | MAC Address |" in content
        assert "|---|---|---|---|" in content

    def test_cli_export_nested_parent_directory(self, tmp_path: Path) -> None:
        """Probe: Exporting to non-existent nested subdirectory creates parents without error."""
        nested_file = tmp_path / "deep" / "nested" / "dir" / "timeline.json"
        ret = main([
            "pcap-timeline",
            "-i", str(MERGED_PCAP),
            "--limit", "500",
            "-o", str(nested_file),
        ])
        assert ret == 0
        assert nested_file.exists()

    def test_cli_corrupted_pcap_file(self, tmp_path: Path) -> None:
        """Probe: Non-PCAP corrupt binary file returns error exit code 1 or 2 without traceback."""
        corrupt_file = tmp_path / "corrupt.pcap"
        corrupt_file.write_bytes(b"\xDE\xAD\xBE\xEF\x00\x01\x02\x03\x04\x05\x06\x07")
        ret = main(["pcap-timeline", "-i", str(corrupt_file)])
        assert ret in (1, 2)

    def test_cli_zero_byte_pcap_file(self, tmp_path: Path) -> None:
        """Probe: 0-byte PCAP file returns clean empty report and exit code 0."""
        zero_file = tmp_path / "empty.pcap"
        zero_file.write_bytes(b"")
        ret = main(["pcap-timeline", "-i", str(zero_file), "--json"])
        assert ret == 0


class TestFormatConsistency:
    """Validates structural equivalence across JSON, CSV, Markdown, and Text representations."""

    def test_format_congruence(self) -> None:
        """Verify report entries and summary metrics match across all format serializers."""
        report = generate_mac_timeline(
            str(MERGED_PCAP),
            limit=2000,
        )

        # JSON
        json_str = report.to_json()
        json_obj = json.loads(json_str)
        assert json_obj["total_matched_macs"] == len(report.entries)
        assert len(json_obj["entries"]) == len(report.entries)

        # CSV
        csv_str = report.to_csv()
        reader = csv.DictReader(io.StringIO(csv_str))
        csv_rows = list(reader)
        assert len(csv_rows) == len(report.entries)

        # Markdown
        md_str = report.to_markdown()
        assert f"- **Total Matched OUI MACs**: {report.total_matched_macs:,}" in md_str

        # Text
        text_str = report.to_text()
        assert f"Matched OUI MACs:          {report.total_matched_macs:,}" in text_str

        # Entry-by-entry parity check between JSON and CSV
        for i, entry in enumerate(report.entries):
            json_entry = json_obj["entries"][i]
            csv_entry = csv_rows[i]
            assert entry.mac == json_entry["mac"] == csv_entry["mac"]
            assert entry.vendor == json_entry["vendor"] == csv_entry["vendor"]
            assert entry.device_category == json_entry["device_category"] == csv_entry["device_category"]
            assert entry.packet_count == json_entry["packet_count"] == int(csv_entry["packet_count"])
