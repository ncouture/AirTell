"""Unit test suite for Spectra Mesh OUI classification and PCAP MAC timeline generator.

Validates:
1. Spectra Mesh OUI database device classification (vendor, category, prefix, endianness).
2. DeviceTelemetrySummary and TelemetrySession enrichment (JSON, CSV, multi-device).
3. PcapTimelineEntry and PcapTimelineReport data models and multi-format serialization.
4. Multi-role address extraction (AdvA, ScanA, InitA, TargetA) across PDU types.
5. Chronological ordering, category filtering, and limit constraints.
6. Integration verification against sample PCAP data.
7. AirTell CLI subcommand `pcap-timeline` and `timeline` alias.
"""

import csv
import json
from pathlib import Path

import pytest

from airtell.cli import create_parser, main
from airtell.sniff.pcap import PcapBleWriter
from airtell.sniff.telemetry import (
    DeviceTelemetrySummary,
    TelemetrySession,
    canonical_mac,
    get_default_ouidb_path,
    resolve_device_oui,
)
from airtell.sniff.timeline import (
    PcapTimelineEntry,
    PcapTimelineReport,
    generate_mac_timeline,
)

# ==============================================================================
# Helper fixtures & synthetic packet builders
# ==============================================================================


def _build_adv_ind_pdu(adv_a_wire: bytes, ad_data: bytes = b"\x02\x01\x06") -> bytes:
    """Build raw PDU bytes for ADV_IND (PDU type 0x00)."""
    payload = adv_a_wire + ad_data
    hdr0 = 0x00  # PDU type 0, TxAdd 0, RxAdd 0
    hdr1 = len(payload) & 0x3F
    return bytes([hdr0, hdr1]) + payload


def _build_scan_req_pdu(scan_a_wire: bytes, adv_a_wire: bytes) -> bytes:
    """Build raw PDU bytes for SCAN_REQ (PDU type 0x03)."""
    payload = scan_a_wire + adv_a_wire
    hdr0 = 0x03  # PDU type 3, TxAdd 0, RxAdd 0
    hdr1 = len(payload) & 0x3F
    return bytes([hdr0, hdr1]) + payload


def _build_connect_ind_pdu(init_a_wire: bytes, adv_a_wire: bytes) -> bytes:
    """Build raw PDU bytes for CONNECT_IND (PDU type 0x05)."""
    # 6 bytes InitA + 6 bytes AdvA + 22 bytes LLData = 34 bytes
    payload = init_a_wire + adv_a_wire + (b"\x00" * 22)
    hdr0 = 0x05  # PDU type 5, TxAdd 0, RxAdd 0
    hdr1 = len(payload) & 0x3F
    return bytes([hdr0, hdr1]) + payload


def _build_adv_direct_ind_pdu(adv_a_wire: bytes, target_a_wire: bytes) -> bytes:
    """Build raw PDU bytes for ADV_DIRECT_IND (PDU type 0x01)."""
    payload = adv_a_wire + target_a_wire
    hdr0 = 0x01  # PDU type 1, TxAdd 0, RxAdd 0
    hdr1 = len(payload) & 0x3F
    return bytes([hdr0, hdr1]) + payload


def _create_synthetic_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    """Create a DLT 256 PCAP containing given (epoch_ts, raw_pdu) pairs."""
    with PcapBleWriter(path) as writer:
        for epoch_ts, raw_pdu in packets:
            writer.write_packet(
                ts_usec=int(epoch_ts * 1_000_000),
                chan=37,
                rssi=-60,
                packet=raw_pdu,
            )


# ==============================================================================
# 1. Spectra Mesh OUI Database Lookup & Device Classification Tests
# ==============================================================================


class TestResolveDeviceOui:
    """Tests device classification and longest-prefix OUI resolution."""

    def test_default_ouidb_path_exists(self):
        db_path = get_default_ouidb_path()
        assert db_path.exists(), f"Default OUI database not found at {db_path}"
        assert db_path.name == "oui_db.bin"

    def test_canonical_mac_reversal(self):
        wire = "B3:A5:D7:83:38:E4"
        canon = canonical_mac(wire)
        assert canon == "E4:38:83:D7:A5:B3"
        # Idempotence check on reversal
        assert canonical_mac(canon) == "B3:A5:D7:83:38:E4"

    @pytest.mark.parametrize(
        ("mac", "expected_category", "expected_vendor_substr", "is_surv"),
        [
            ("B0:10:41:12:34:56", "alpr", "Flock Safety", True),
            ("E4:38:83:D7:A5:B3", "alpr", "Flock Safety", True),
            ("0C:9A:E6:37:F6:2D", "drone", "Dji", True),
            ("68:9A:87:20:6B:FF", "drone", "Skydio", True),
            ("D0:3F:27:B0:07:6E", "camera", "Wyze", True),
            ("74:EC:B2:97:05:FD", "camera", "Ring", True),
            ("44:A6:42:A5:DE:34", "camera", "Hikvision", True),
            ("00:25:DF:11:22:33", "bodycam", "Axon", True),
            ("00:00:0C:44:55:66", "none", "Cisco", False),
            ("48:D6:D5:E5:30:52", "none", "Google", False),
        ],
    )
    def test_surveillance_device_classes(
        self, mac: str, expected_category: str, expected_vendor_substr: str, is_surv: bool
    ):
        res = resolve_device_oui(mac)
        assert res is not None, f"Failed to resolve MAC {mac}"
        assert res.device_type == expected_category
        assert res.category == expected_category
        assert expected_vendor_substr.lower() in res.vendor.lower()
        assert res.is_surveillance is is_surv

    def test_wire_little_endian_resolution_fallback(self):
        # Wire address transmitted LSB first: reversed matches Flock Safety E4:38:83
        wire_mac = "B3:A5:D7:83:38:E4"
        res = resolve_device_oui(wire_mac)
        assert res is not None
        assert "Flock Safety" in res.vendor
        assert res.device_type == "alpr"

    def test_unmatched_random_mac_returns_none(self):
        # Random non-resolvable private address
        unmatched = "1A:2B:3C:4D:5E:6F"
        res = resolve_device_oui(unmatched)
        assert res is None

    def test_empty_and_none_mac_handling(self):
        assert resolve_device_oui("") is None
        assert resolve_device_oui("   ") is None


# ==============================================================================
# 2. Telemetry Summary & Session Enrichment Tests
# ==============================================================================


class TestTelemetryEnrichment:
    """Tests enrichment of DeviceTelemetrySummary and TelemetrySession."""

    def test_device_telemetry_summary_defaults(self):
        dev = DeviceTelemetrySummary(mac_address="B0:10:41:12:34:56")
        assert dev.vendor is None
        assert dev.device_class is None
        assert dev.oui_prefix is None
        assert dev.is_surveillance is False

    def test_device_telemetry_summary_enrichment_surveillance(self):
        dev = DeviceTelemetrySummary(mac_address="B0:10:41:12:34:56")
        dev.enrich_from_ouidb()
        assert dev.vendor == "Flock Safety"
        assert dev.device_class == "alpr"
        assert dev.oui_prefix == "B0:10:41"
        assert dev.is_surveillance is True

    def test_device_telemetry_summary_enrichment_non_surveillance(self):
        dev = DeviceTelemetrySummary(mac_address="48:D6:D5:E5:30:52")
        dev.enrich_from_ouidb()
        assert dev.vendor == "Google, Inc."
        assert dev.device_class == "none"
        assert dev.oui_prefix == "48:D6:D5"
        assert dev.is_surveillance is False

    def test_to_dict_includes_enriched_fields(self):
        dev = DeviceTelemetrySummary(mac_address="0C:9A:E6:37:F6:2D")
        dev.enrich_from_ouidb()
        d = dev.to_dict()
        assert d["vendor"] == "Sz Dji Technology Co.,Ltd"
        assert d["device_class"] == "drone"
        assert d["oui_prefix"] == "0C:9A:E6"
        assert d["is_surveillance"] is True

    def test_to_csv_row_includes_enriched_fields(self):
        dev = DeviceTelemetrySummary(mac_address="D0:3F:27:B0:07:6E")
        dev.enrich_from_ouidb()
        row = dev.to_csv_row()
        assert row["vendor"] == "Wyze Labs Inc"
        assert row["device_class"] == "camera"
        assert row["oui_prefix"] == "D0:3F:27"
        assert row["is_surveillance"] is True

    def test_telemetry_session_enrich_devices_method(self):
        session = TelemetrySession()
        session.devices["B0:10:41:11:22:33"] = DeviceTelemetrySummary(mac_address="B0:10:41:11:22:33")
        session.devices["0C:9A:E6:44:55:66"] = DeviceTelemetrySummary(mac_address="0C:9A:E6:44:55:66")
        session.devices["48:D6:D5:77:88:99"] = DeviceTelemetrySummary(mac_address="48:D6:D5:77:88:99")

        session.enrich_devices()

        assert session.devices["B0:10:41:11:22:33"].device_class == "alpr"
        assert session.devices["0C:9A:E6:44:55:66"].device_class == "drone"
        assert session.devices["48:D6:D5:77:88:99"].device_class == "none"

    def test_telemetry_session_export_devices_csv(self, tmp_path: Path):
        session = TelemetrySession()
        session.devices["B0:10:41:11:22:33"] = DeviceTelemetrySummary(
            mac_address="B0:10:41:11:22:33",
            packet_count=5,
        )
        session.enrich_devices()

        csv_file = tmp_path / "devices.csv"
        session.export_devices_csv(csv_file)

        assert csv_file.exists()
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
        assert len(reader) == 1
        row = reader[0]
        assert row["mac_address"] == "B0:10:41:11:22:33"
        assert row["vendor"] == "Flock Safety"
        assert row["device_class"] == "alpr"
        assert row["oui_prefix"] == "B0:10:41"
        assert row["is_surveillance"] == "True"


# ==============================================================================
# 3. PcapTimelineEntry & PcapTimelineReport Data Models & Serialization
# ==============================================================================


class TestTimelineModels:
    """Tests dataclass serialization across dict, JSON, CSV, Markdown, and text."""

    def test_entry_to_dict(self):
        entry = PcapTimelineEntry(
            mac="E4:38:83:D7:A5:B3",
            first_seen=1793800000.0,
            first_seen_iso="2026-11-04T13:46:40+00:00",
            last_seen=1793800010.0,
            last_seen_iso="2026-11-04T13:46:50+00:00",
            packet_count=12,
            packet_types=["ADV_IND", "SCAN_RSP"],
            roles=["AdvA"],
            is_random=False,
            vendor="Flock Safety",
            prefix="E4:38:83",
            prefix_bits=24,
            table="MA-L",
            device_category="alpr",
            flags=2,
            is_surveillance=True,
        )
        d = entry.to_dict()
        assert d["mac"] == "E4:38:83:D7:A5:B3"
        assert d["vendor"] == "Flock Safety"
        assert d["device_category"] == "alpr"
        assert d["is_surveillance"] is True
        assert d["packet_count"] == 12

    def test_report_serialization_formats(self, tmp_path: Path):
        entry = PcapTimelineEntry(
            mac="0C:9A:E6:37:F6:2D",
            first_seen=1793800000.0,
            first_seen_iso="2026-11-04T13:46:40+00:00",
            last_seen=1793800005.0,
            last_seen_iso="2026-11-04T13:46:45+00:00",
            packet_count=8,
            packet_types=["ADV_IND"],
            roles=["AdvA"],
            is_random=False,
            vendor="Sz Dji Technology Co.,Ltd",
            prefix="0C:9A:E6",
            prefix_bits=24,
            table="MA-L",
            device_category="drone",
            flags=3,
            is_surveillance=True,
        )
        report = PcapTimelineReport(
            pcap_path="test.pcap",
            ouidb_path="oui_db.bin",
            total_packets_processed=100,
            total_unique_macs=10,
            total_matched_macs=1,
            total_surveillance_macs=1,
            duration_sec=5.0,
            entries=[entry],
        )

        # 1. JSON
        j_str = report.to_json()
        j_data = json.loads(j_str)
        assert j_data["total_packets_processed"] == 100
        assert len(j_data["entries"]) == 1
        assert j_data["entries"][0]["vendor"] == "Sz Dji Technology Co.,Ltd"

        # 2. CSV
        c_str = report.to_csv()
        reader = list(csv.DictReader(c_str.splitlines()))
        assert len(reader) == 1
        assert reader[0]["mac"] == "0C:9A:E6:37:F6:2D"
        assert reader[0]["device_category"] == "drone"

        # 3. Markdown
        m_str = report.to_markdown()
        assert "# BLE PCAP MAC Timeline Report" in m_str
        assert "| `0C:9A:E6:37:F6:2D` |" in m_str
        assert "Sz Dji Technology Co.,Ltd" in m_str

        # 4. Text
        t_str = report.to_text()
        assert "BLE PCAP MAC TIMELINE REPORT" in t_str
        assert "0C:9A:E6:37:F6:2D" in t_str

        # 5. File exports
        out_json = tmp_path / "out.json"
        report.export(out_json)
        assert out_json.exists()

        out_csv = tmp_path / "out.csv"
        report.export(out_csv)
        assert out_csv.exists()

        out_md = tmp_path / "out.md"
        report.export(out_md)
        assert out_md.exists()

        out_txt = tmp_path / "out.txt"
        report.export(out_txt)
        assert out_txt.exists()


# ==============================================================================
# 4. Multi-Role Address Demuxing & Synthetic PCAP Tests
# ==============================================================================


class TestTimelineMultiRoleExtraction:
    """Tests demuxing AdvA, ScanA, InitA, and TargetA across advertising PDU types."""

    def test_multi_role_pdu_demuxing(self, tmp_path: Path):
        pcap_path = tmp_path / "synthetic_roles.pcap"

        # Wire bytes for MACs (LSB first over the air):
        # Flock Safety ALPR: canonical E4:38:83:D7:A5:B3 -> wire B3:A5:D7:83:38:E4
        flock_wire = bytes.fromhex("B3A5D78338E4")
        # Skydio Drone: canonical 68:9A:87:20:6B:FF -> wire FF:6B:20:87:9A:68
        skydio_wire = bytes.fromhex("FF6B20879A68")
        # Wyze Camera: canonical D0:3F:27:B0:07:6E -> wire 6E:07:B0:27:3F:D0
        wyze_wire = bytes.fromhex("6E07B0273FD0")
        # Axon Bodycam: canonical 00:25:DF:11:22:33 -> wire 33:22:11:DF:25:00
        axon_wire = bytes.fromhex("332211DF2500")

        packets = [
            # Packet 1 at t=10.0: ADV_IND with Flock as AdvA
            (10.0, _build_adv_ind_pdu(flock_wire)),
            # Packet 2 at t=11.0: SCAN_REQ with Skydio as ScanA, Flock as AdvA
            (11.0, _build_scan_req_pdu(scan_a_wire=skydio_wire, adv_a_wire=flock_wire)),
            # Packet 3 at t=12.0: CONNECT_IND with Axon as InitA, Wyze as AdvA
            (12.0, _build_connect_ind_pdu(init_a_wire=axon_wire, adv_a_wire=wyze_wire)),
            # Packet 4 at t=13.0: ADV_DIRECT_IND with Wyze as AdvA, Skydio as TargetA
            (13.0, _build_adv_direct_ind_pdu(adv_a_wire=wyze_wire, target_a_wire=skydio_wire)),
        ]

        _create_synthetic_pcap(pcap_path, packets)

        report = generate_mac_timeline(pcap_path)

        assert report.total_packets_processed == 4
        # All 4 unique MACs belong to Spectra Mesh OUI database
        assert len(report.entries) == 4

        entries_by_mac = {e.mac: e for e in report.entries}

        # 1. Flock Safety: roles AdvA
        assert "E4:38:83:D7:A5:B3" in entries_by_mac
        flock_entry = entries_by_mac["E4:38:83:D7:A5:B3"]
        assert flock_entry.device_category == "alpr"
        assert "AdvA" in flock_entry.roles
        assert flock_entry.packet_count == 2  # Pkt 1 and Pkt 2

        # 2. Skydio Drone: roles ScanA and TargetA
        assert "68:9A:87:20:6B:FF" in entries_by_mac
        skydio_entry = entries_by_mac["68:9A:87:20:6B:FF"]
        assert skydio_entry.device_category == "drone"
        assert "ScanA" in skydio_entry.roles
        assert "TargetA" in skydio_entry.roles
        assert skydio_entry.packet_count == 2  # Pkt 2 and Pkt 4

        # 3. Wyze Camera: roles AdvA
        assert "D0:3F:27:B0:07:6E" in entries_by_mac
        wyze_entry = entries_by_mac["D0:3F:27:B0:07:6E"]
        assert wyze_entry.device_category == "camera"
        assert "AdvA" in wyze_entry.roles
        assert wyze_entry.packet_count == 2  # Pkt 3 and Pkt 4

        # 4. Axon Bodycam: roles InitA
        assert "00:25:DF:11:22:33" in entries_by_mac
        axon_entry = entries_by_mac["00:25:DF:11:22:33"]
        assert axon_entry.device_category == "bodycam"
        assert "InitA" in axon_entry.roles
        assert axon_entry.packet_count == 1  # Pkt 3


# ==============================================================================
# 5. Chronological Ordering, Filtering, and Limit Tests
# ==============================================================================


class TestTimelineOrderingAndFiltering:
    """Tests strict chronological sorting, category filtering, and limit enforcement."""

    @pytest.fixture
    def synthetic_timeline_pcap(self, tmp_path: Path) -> Path:
        pcap_path = tmp_path / "order_and_filter.pcap"
        # Canonical MACs:
        # t=100: Google (none) -> wire 52:30:E5:D5:D6:48 (canon 48:D6:D5:E5:30:52)
        google_wire = bytes.fromhex("5230E5D5D648")
        # t=200: Flock Safety (alpr) -> wire B3:A5:D7:83:38:E4 (canon E4:38:83:D7:A5:B3)
        flock_wire = bytes.fromhex("B3A5D78338E4")
        # t=300: DJI (drone) -> wire 2D:F6:37:E6:9A:0C (canon 0C:9A:E6:37:F6:2D)
        dji_wire = bytes.fromhex("2DF637E69A0C")
        # t=400: Wyze (camera) -> wire 6E:07:B0:27:3F:D0 (canon D0:3F:27:B0:07:6E)
        wyze_wire = bytes.fromhex("6E07B0273FD0")

        packets = [
            (100.0, _build_adv_ind_pdu(google_wire)),
            (200.0, _build_adv_ind_pdu(flock_wire)),
            (300.0, _build_adv_ind_pdu(dji_wire)),
            (400.0, _build_adv_ind_pdu(wyze_wire)),
        ]
        _create_synthetic_pcap(pcap_path, packets)
        return pcap_path

    def test_strict_chronological_ordering(self, synthetic_timeline_pcap: Path):
        report = generate_mac_timeline(synthetic_timeline_pcap)
        assert len(report.entries) == 4

        for i in range(len(report.entries) - 1):
            assert report.entries[i].first_seen <= report.entries[i + 1].first_seen

        assert report.entries[0].mac == "48:D6:D5:E5:30:52"
        assert report.entries[1].mac == "E4:38:83:D7:A5:B3"
        assert report.entries[2].mac == "0C:9A:E6:37:F6:2D"
        assert report.entries[3].mac == "D0:3F:27:B0:07:6E"

    def test_surveillance_only_filter(self, synthetic_timeline_pcap: Path):
        report = generate_mac_timeline(synthetic_timeline_pcap, surveillance_only=True)
        # Google (none) must be excluded
        assert len(report.entries) == 3
        cats = [e.device_category for e in report.entries]
        assert cats == ["alpr", "drone", "camera"]
        assert all(e.is_surveillance for e in report.entries)

    def test_specific_category_filter(self, synthetic_timeline_pcap: Path):
        report = generate_mac_timeline(synthetic_timeline_pcap, category="drone")
        assert len(report.entries) == 1
        assert report.entries[0].mac == "0C:9A:E6:37:F6:2D"
        assert report.entries[0].device_category == "drone"

    def test_limit_parameter_capping_entries(self, synthetic_timeline_pcap: Path):
        report = generate_mac_timeline(synthetic_timeline_pcap, limit=2)
        assert len(report.entries) <= 2


# ==============================================================================
# 6. Integration Verification with `app/data/merged.pcap`
# ==============================================================================


class TestMergedPcapIntegration:
    """Verifies fast streaming extraction and ground truth against merged.pcap."""

    PCAP_PATH = Path("app/data/merged.pcap")

    @pytest.mark.skipif(not PCAP_PATH.exists(), reason="merged.pcap not present")
    def test_merged_pcap_fast_slice_extraction(self):
        # Rapid slice test (5,000 packets) executes in < 0.2s
        report = generate_mac_timeline(self.PCAP_PATH, max_packets=5000)

        assert report.total_packets_processed == 5000
        assert report.total_unique_macs > 0
        assert report.total_matched_macs > 0
        assert len(report.entries) > 0

        # Verify strict chronological ordering
        for i in range(len(report.entries) - 1):
            assert report.entries[i].first_seen <= report.entries[i + 1].first_seen

        # Verify all entries have valid OUI metadata
        for e in report.entries:
            assert len(e.mac) == 17
            assert e.vendor != ""
            assert e.prefix != ""
            assert e.table in ("MA-L", "MA-M", "MA-S")

    @pytest.mark.parametrize(
        ("mac", "category", "vendor"),
        [
            ("E4:38:83:D7:A5:B3", "alpr", "Flock Safety"),
            ("0C:9A:E6:37:F6:2D", "drone", "Sz Dji Technology Co.,Ltd"),
            ("68:9A:87:20:6B:FF", "drone", "Skydio, Inc."),
            ("D0:3F:27:B0:07:6E", "camera", "Wyze Labs Inc"),
            ("74:EC:B2:97:05:FD", "camera", "Ring LLC"),
            ("44:A6:42:A5:DE:34", "camera", "Hangzhou Hikvision Digital Technology Co.,Ltd."),
        ],
    )
    def test_ground_truth_surveillance_devices_in_ouidb(self, mac: str, category: str, vendor: str):
        """Confirm ground truth surveillance devices resolve accurately in oui_db."""
        res = resolve_device_oui(mac)
        assert res is not None
        assert res.device_type == category
        assert res.vendor == vendor
        assert res.is_surveillance is True


# ==============================================================================
# 7. CLI Subcommand & Argument Parser Tests
# ==============================================================================


class TestTimelineCliSubcommand:
    """Verifies `airtell pcap-timeline` and `airtell timeline` command execution."""

    def test_parser_has_timeline_commands(self):
        parser = create_parser()
        subparsers_action = next(a for a in parser._actions if a.dest == "command")
        assert "pcap-timeline" in subparsers_action.choices
        assert "timeline" in subparsers_action.choices

    def test_cli_execution_with_limit_and_json(self, capsys):
        exit_code = main(["timeline", "--limit", "100", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total_packets_processed" in data
        assert "entries" in data
        assert data["total_packets_processed"] == 100

    def test_cli_execution_with_markdown_flag(self, capsys):
        exit_code = main(["pcap-timeline", "--limit", "10", "--markdown"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "# BLE PCAP MAC Timeline Report" in captured.out
        assert "| # | First Seen (UTC) |" in captured.out

    def test_cli_execution_output_to_file(self, tmp_path: Path):
        out_csv = tmp_path / "cli_report.csv"
        exit_code = main(["timeline", "--limit", "20", "-o", str(out_csv)])
        assert exit_code == 0
        assert out_csv.exists()
        with open(out_csv, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) > 1
        assert "mac,first_seen" in lines[0]

    def test_cli_missing_pcap_error_exit_code(self):
        exit_code = main(["pcap-timeline", "--pcap", "/nonexistent/path/capture.pcap"])
        assert exit_code == 2

    def test_cli_missing_ouidb_error_exit_code(self):
        exit_code = main(["timeline", "--ouidb", "/nonexistent/path/oui_db.bin"])
        assert exit_code == 2
