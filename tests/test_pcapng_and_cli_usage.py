"""Tests verifying PCAPNG reading support, -i/--input CLI flags, and scripts module packaging."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from airtell.adversarial.rogue_beacon import RogueBeaconGenerator, SyntheticBeaconSpec
from airtell.cli import create_parser, main
from airtell.sniff.pcap import CapturedBlePacket, PcapBleReader


class TestCliUsageAndFlags:
    """Verify CLI argument parser fixes for -i / --input and -o / --output."""

    def test_sidechannel_short_flag_i_parsed(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["sidechannel", "-i", "data/scan1-37.pcap", "--summary"])
        assert args.command == "sidechannel"
        assert args.pcap == "data/scan1-37.pcap"
        assert args.summary is True

    def test_sidechannel_long_flag_input_parsed(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["sidechannel", "--input", "test.pcap"])
        assert args.pcap == "test.pcap"

    def test_sidechannel_short_flag_o_parsed(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["sidechannel", "-i", "test.pcap", "-o", "report.json"])
        assert args.output == "report.json"

    def test_sidechannel_limit_parsed(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["sidechannel", "--mock", "--limit", "50"])
        assert args.limit == 50


class TestScriptsPackagingAndImports:
    """Verify scripts module packaging and import compatibility."""

    def test_import_airtell_scripts(self) -> None:
        from airtell.scripts.ble_antistalking_tracker import (
            BLETrackerDB,
            classify_payload,
        )

        assert BLETrackerDB is not None
        assert callable(classify_payload)

    def test_import_bluetooth_sniffle_compat(self) -> None:
        from bluetooth_sniffle.scripts.ble_antistalking_tracker import (
            BLETrackerDB,
            classify_payload,
        )

        assert BLETrackerDB is not None
        assert callable(classify_payload)

    def test_import_scripts_alias(self) -> None:
        import scripts.ble_antistalking_tracker as tracker_mod

        assert hasattr(tracker_mod, "BLETrackerDB")
        assert hasattr(tracker_mod, "classify_payload")

    def test_rogue_beacon_generator_construction(self) -> None:
        generator = RogueBeaconGenerator()
        spec = SyntheticBeaconSpec(network_type="Apple Find My", ephemeral_key="010203040506")
        payload = generator.build_payload(spec)
        assert len(payload) <= 31
        assert b"\x4c\x00\x12" in payload


class TestPcapngReader:
    """Verify PcapBleReader handles PCAPNG byte streams and files correctly."""

    def test_read_synthetic_pcapng_stream(self) -> None:
        # Construct synthetic PCAPNG in memory:
        # 1. SHB (Section Header Block, type 0x0A0D0D0A)
        # Total len = 4 (type) + 4 (len) + 4 (BOM) + 4 (major/minor) + 8 (sec_len) + 4 (len) = 28 bytes
        shb = (
            struct.pack("<II", 0x0A0D0D0A, 28)
            + struct.pack("<I", 0x1A2B3C4D)  # Byte-order magic (little-endian)
            + struct.pack("<HH", 1, 0)        # Version 1.0
            + struct.pack("<q", -1)           # Section length unspecified
            + struct.pack("<I", 28)
        )

        # 2. IDB (Interface Description Block, type 0x00000001)
        # Body: 2B link_type (256), 2B reserved, 4B snaplen (65535) = 8 bytes
        # Total len = 4 + 4 + 8 + 4 = 20 bytes
        idb = (
            struct.pack("<II", 0x00000001, 20)
            + struct.pack("<HHI", 256, 0, 65535)
            + struct.pack("<I", 20)
        )

        # 3. EPB (Enhanced Packet Block, type 0x00000006)
        # BLE packet payload:
        # 10B pseudo-header: rf_chan=0 (ble 37), rssi=-80, noise=-128, rsvd=0, aa=0x8e89bed6, flags=0x0c13
        # 4B wire_aa = 0x8e89bed6
        # 4B body = b"\x01\x02\x03\x04"
        # 3B CRC = b"\xaa\xbb\xcc"
        # Total payload len = 10 + 4 + 4 + 3 = 21 bytes -> padded to 24 bytes
        pseudo_hdr = struct.pack("<BbbBIH", 0, -80, -128, 0, 0x8E89BED6, 0x0C13)
        wire_aa = struct.pack("<I", 0x8E89BED6)
        body = b"\x01\x02\x03\x04"
        crc = b"\xaa\xbb\xcc"
        ble_payload = pseudo_hdr + wire_aa + body + crc
        cap_len = len(ble_payload)  # 21
        padded_payload = ble_payload.ljust((cap_len + 3) & ~3, b"\x00")  # 24

        # EPB header: 4B iface_id=0, 4B ts_hi, 4B ts_lo, 4B cap_len, 4B orig_len = 20 bytes
        # Total EPB len = 8 (block hdr) + 20 + 24 (padded data) + 4 (block trailer) = 56 bytes
        ts_usec = 1700000000123456
        ts_hi = ts_usec >> 32
        ts_lo = ts_usec & 0xFFFFFFFF
        epb = (
            struct.pack("<II", 0x00000006, 56)
            + struct.pack("<IIIII", 0, ts_hi, ts_lo, cap_len, cap_len)
            + padded_payload
            + struct.pack("<I", 56)
        )

        stream = io.BytesIO(shb + idb + epb)
        reader = PcapBleReader(stream)
        assert reader._is_pcapng is True

        pkt = reader.read_packet()
        assert pkt is not None
        assert isinstance(pkt, CapturedBlePacket)
        assert pkt.ble_chan == 37
        assert pkt.rssi == -80
        assert pkt.aa == 0x8E89BED6
        assert pkt.body == body

        # EOF
        assert reader.read_packet() is None

    def test_read_real_pcapng_scan_file(self) -> None:
        pcap_path = Path("data/scan1-37.pcap")
        if not pcap_path.exists():
            pytest.skip("data/scan1-37.pcap not present")

        with PcapBleReader(pcap_path) as reader:
            assert reader._is_pcapng is True
            packets = []
            for pkt in reader:
                packets.append(pkt)
                if len(packets) >= 50:
                    break

            assert len(packets) == 50
            for p in packets:
                assert p.ble_chan in (37, 38, 39)
                assert isinstance(p.rssi, int)
                assert len(p.body) >= 2


class TestSidechannelCliExecution:
    """Verify sidechannel CLI execution with -i on real PCAP capture."""

    def test_sidechannel_cli_with_dash_i_and_limit(self, capsys: pytest.CaptureFixture[str]) -> None:
        pcap_path = Path("data/scan1-37.pcap")
        if not pcap_path.exists():
            pytest.skip("data/scan1-37.pcap not present")

        # Run with -i and --limit 200 --summary
        rc = main(["sidechannel", "-i", str(pcap_path), "--limit", "200", "--summary"])
        # Detections found in capture -> rc = 1, clean execution -> rc in (0, 1)
        assert rc in (0, 1)

        captured = capsys.readouterr()
        assert "Side-Channel Analysis Report" in captured.out
        assert "Total Packets Processed:     200" in captured.out

    def test_text_summary_truncates_large_findings_and_devices(self) -> None:
        from airtell.sidechannel.models import (
            AnalyzerReport,
            BatAllowlistFinding,
            Verdict,
        )
        from airtell.sidechannel.runner import SideChannelSuiteReport

        dummy_findings = [
            BatAllowlistFinding(
                finding_type="BAT_ALLOWLIST",
                timestamp=1000.0 + i,
                device_addr=f"AA:BB:CC:DD:EE:{i % 256:02X}",
                target_addr="11:22:33:44:55:66",
                verdict=Verdict.ALLOWLIST_CONFIRMED.value,
                confidence=1.0,
                details={},
            )
            for i in range(100)
        ]

        rep = AnalyzerReport(
            analyzer_name="BatAllowlistAnalyzer",
            verdict=Verdict.ALLOWLIST_CONFIRMED.value,
            summary="Confirmed allowlist",
            findings=dummy_findings,
        )
        suite = SideChannelSuiteReport(
            target_mac=None,
            reports={"bat_allowlist": rep},
            total_packets=100000,
        )
        summary = suite.to_text_summary()
        assert "Findings (100):" in summary
        assert "... and 75 more findings" in summary
        assert "(... and" in summary  # exclusive devices truncated

    def test_bat_allowlist_memory_bounded_history(self) -> None:
        from airtell.sidechannel.bat_allowlist import BatAllowlistAnalyzer
        from airtell.sidechannel.models import BlePacketRecord
        from airtell.sidechannel.synthetic import build_adv_ind

        analyzer = BatAllowlistAnalyzer()
        pdu = build_adv_ind("AA:BB:CC:DD:EE:01")
        for i in range(500):
            pkt = BlePacketRecord(
                body=pdu,
                channel=37,
                rssi=-65,
                timestamp_usec=1_000_000 + (i * 20_000),
            )
            analyzer.process_packet(pkt)

        p_state = analyzer._peripherals["AA:BB:CC:DD:EE:01"]
        assert len(p_state.adv_timestamps) <= 10
        assert len(p_state.measured_intervals_ms) <= 100
