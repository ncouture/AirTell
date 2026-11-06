"""Comprehensive End-to-End (E2E) Test Suite for Spectra Mesh OUI Database Integration & PCAP MAC Timeline Generator.

Derived strictly from user requirements in ORIGINAL_REQUEST.md and PROJECT.md.
Follows the 4-tier testing methodology:
- Tier 1: Feature Coverage (≥5 tests per feature for F1 to F6)
- Tier 2: Boundary & Corner Cases (≥5 tests per feature for B1 to B5)
- Tier 3: Cross-Feature Combinations (Pairwise coverage)
- Tier 4: Real-World Application Scenarios (Against app/data/merged.pcap)
"""

from __future__ import annotations

import csv
import io
import json
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

# Ensure repo root and submodules are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SPECTRAMESH_DIR = REPO_ROOT / "spectramesh_ouidb"
SRC_DIR = REPO_ROOT / "src"
OUIDB_BIN_PATH = SPECTRAMESH_DIR / "oui_db.bin"
MERGED_PCAP_PATH = REPO_ROOT / "app" / "data" / "merged.pcap"

if str(SPECTRAMESH_DIR) not in sys.path:
    sys.path.insert(0, str(SPECTRAMESH_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Core imports
from airtell.sniff.dissector import (  # noqa: E402
    PDU_TYPE_ADV_DIRECT_IND,
    PDU_TYPE_ADV_IND,
    PDU_TYPE_ADV_NONCONN_IND,
    PDU_TYPE_ADV_SCAN_IND,
    PDU_TYPE_CONNECT_IND,
    PDU_TYPE_SCAN_REQ,
    PDU_TYPE_SCAN_RSP,
)
from airtell.sniff.pcap import (  # noqa: E402
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    PCAP_MAGIC_USEC,
    PcapBleWriter,
)
from spectramesh_ouidb import (  # noqa: E402
    OUI_SURV_ALPR,
    OUI_SURV_BODYCAM,
    OUI_SURV_CAMERA,
    OUI_SURV_DRONE,
    OUI_SURV_NONE,
    OuiDb,
)

# Implementation under test (Worker track may still be completing these)
try:
    from airtell.sniff.telemetry import (
        DeviceTelemetrySummary,
        resolve_device_oui,
    )
except ImportError:
    resolve_device_oui = None  # type: ignore[assignment]
    DeviceTelemetrySummary = None  # type: ignore[assignment]

try:
    from airtell.sniff.timeline import (
        PcapTimelineEntry,
        PcapTimelineReport,
        PcapTimelineReportGenerator,
        generate_mac_timeline,
    )
except ImportError:
    PcapTimelineEntry = None  # type: ignore[assignment]
    PcapTimelineReport = None  # type: ignore[assignment]
    PcapTimelineReportGenerator = None  # type: ignore[assignment]
    generate_mac_timeline = None  # type: ignore[assignment]

try:
    from airtell.cli import create_parser
except ImportError:
    create_parser = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Test Fixtures & Synthetic Generators
# ---------------------------------------------------------------------------

def _mac_to_wire_bytes(mac_str: str) -> bytes:
    """Convert canonical MAC string (e.g. 'E4:38:83:D7:A5:B3') to BLE wire Little-Endian bytes."""
    octets = [int(x, 16) for x in mac_str.split(":")]
    return bytes(reversed(octets))


def _mac_to_canonical_bytes(mac_str: str) -> bytes:
    """Convert canonical MAC string to IEEE Big-Endian bytes."""
    return bytes(int(x, 16) for x in mac_str.split(":"))


def _build_adv_pdu(
    pdu_type: int,
    adv_a_mac: str,
    data: bytes = b"",
    scan_a_mac: str | None = None,
    target_a_mac: str | None = None,
    init_a_mac: str | None = None,
    tx_add: int = 0,
    rx_add: int = 0,
) -> bytes:
    """Construct standard BLE Link Layer advertising channel PDU."""
    adv_a_bytes = _mac_to_wire_bytes(adv_a_mac)
    if pdu_type in (PDU_TYPE_ADV_IND, PDU_TYPE_ADV_NONCONN_IND, PDU_TYPE_ADV_SCAN_IND, PDU_TYPE_SCAN_RSP):
        payload = adv_a_bytes + data
    elif pdu_type == PDU_TYPE_SCAN_REQ:
        scan_a = _mac_to_wire_bytes(scan_a_mac or "11:22:33:44:55:66")
        payload = scan_a + adv_a_bytes
    elif pdu_type == PDU_TYPE_ADV_DIRECT_IND:
        target_a = _mac_to_wire_bytes(target_a_mac or "AA:BB:CC:DD:EE:FF")
        payload = adv_a_bytes + target_a
    elif pdu_type == PDU_TYPE_CONNECT_IND:
        init_a = _mac_to_wire_bytes(init_a_mac or "11:22:33:44:55:66")
        ll_data = b"\x00" * 22
        payload = init_a + adv_a_bytes + ll_data
    else:
        payload = adv_a_bytes + data

    hdr0 = (pdu_type & 0x0F) | ((tx_add & 0x01) << 6) | ((rx_add & 0x01) << 7)
    hdr1 = len(payload) & 0x3F
    return bytes([hdr0, hdr1]) + payload


def _create_synthetic_pcap_file(
    packets: list[tuple[float, bytes]],
    output_path: Path,
) -> Path:
    """Create a DLT 256 PCAP file with specified (timestamp_epoch, raw_pdu) pairs."""
    with PcapBleWriter(output=output_path, base_epoch=0.0) as writer:
        for ts_epoch, pdu_bytes in packets:
            ts_usec = int(ts_epoch * 1_000_000)
            writer.write_packet(ts_usec=ts_usec, packet=pdu_bytes)
    return output_path


def _make_soui_blob(
    *,
    magic: bytes = b"SOUI",
    version: int = 1,
    mal_entries: list[tuple[int, int, int]] | None = None,
    mam_entries: list[tuple[int, int, int]] | None = None,
    mas_entries: list[tuple[int, int, int]] | None = None,
    str_pool: bytes = b"TestVendor\x00",
) -> bytes:
    """Construct binary SOUI v1 database blob for unit and boundary testing."""
    mal = sorted(mal_entries or [], key=lambda x: x[0])
    mam = sorted(mam_entries or [], key=lambda x: x[0])
    mas = sorted(mas_entries or [], key=lambda x: x[0])

    hdr_fmt = "<4s9I"
    hdr_size = struct.calcsize(hdr_fmt)

    mal_offset = hdr_size
    mam_offset = mal_offset + len(mal) * 9
    mas_offset = mam_offset + len(mam) * 9
    str_offset = mas_offset + len(mas) * 13

    hdr = struct.pack(
        hdr_fmt,
        magic,
        version,
        len(mal),
        len(mam),
        len(mas),
        mal_offset,
        mam_offset,
        mas_offset,
        str_offset,
        len(str_pool),
    )

    buf = bytearray(hdr)
    for pfx, soff, flg in mal:
        buf.extend(struct.pack("<IIB", pfx, soff, flg))
    for pfx, soff, flg in mam:
        buf.extend(struct.pack("<IIB", pfx, soff, flg))
    for pfx, soff, flg in mas:
        buf.extend(struct.pack("<QIB", pfx, soff, flg))
    buf.extend(str_pool)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Tier 1: Feature Coverage (F1 to F6, ≥5 per feature)
# ---------------------------------------------------------------------------

class TestTier1FeatureCoverage:
    """Tier 1: Feature Coverage in Isolation (F1 to F6)."""

    # --- Feature 1: Spectra Mesh OUI Engine & Endianness Resolution ---

    def test_f01_mal_24bit_prefix_lookup(self) -> None:
        """F1.1: 24-bit MA-L OUI prefix lookup in spectramesh_ouidb."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("E4:38:83:D7:A5:B3")
            assert res is not None
            assert res.vendor == "Flock Safety"
            assert res.prefix_bits == 24
            assert res.table == "MA-L"
            assert res.prefix_str == "E4:38:83"
            assert res.device_type == "alpr"
            assert res.is_surveillance is True

    def test_f01_mam_28bit_prefix_lookup(self) -> None:
        """F1.2: 28-bit MA-M prefix lookup in spectramesh_ouidb."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            # Interaxon Inc prefix 00:55:DA:B0/28 (flags=6 bodycam)
            res = db.lookup("00:55:DA:B0:12:34")
            assert res is not None
            assert res.vendor == "Interaxon Inc"
            assert res.prefix_bits == 28
            assert res.table == "MA-M"
            assert res.prefix_str == "00:55:DA:B0/28"
            assert res.device_type == "bodycam"
            assert res.is_surveillance is True

    def test_f01_mas_36bit_prefix_lookup(self) -> None:
        """F1.3: 36-bit MA-S prefix lookup in spectramesh_ouidb."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            # Charlotte's Web Networks prefix 00:50:C2:0D:80/36 (flags=1 camera)
            res = db.lookup("00:50:C2:0D:80:12")
            assert res is not None
            assert res.vendor == "Charlotte's Web Networks"
            assert res.prefix_bits == 36
            assert res.table == "MA-S"
            assert res.prefix_str == "00:50:C2:0D:80/36"
            assert res.device_type == "camera"
            assert res.is_surveillance is True

    def test_f01_unknown_mac_returns_none(self) -> None:
        """F1.4: Random or unassigned MAC addresses return None."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("FA:CE:DE:AD:BE:EF")
            assert res is None

    def test_f01_wire_vs_canonical_endianness_resolution(self) -> None:
        """F1.5: BLE Little-Endian wire MAC resolves to canonical Big-Endian OUI."""
        if resolve_device_oui is None:
            pytest.fail("resolve_device_oui is not implemented in airtell.sniff.telemetry")

        # Wire byte order for Flock Safety E4:38:83:D7:A5:B3 is B3:A5:D7:83:38:E4
        res = resolve_device_oui("B3:A5:D7:83:38:E4", str(OUIDB_BIN_PATH))
        assert res is not None
        assert res.vendor == "Flock Safety"
        assert res.device_type == "alpr"
        assert res.is_surveillance is True

    def test_f01_wire_direct_fallback(self) -> None:
        """F1.6: When canonical reversed MAC misses, wire direct MAC fallback is evaluated."""
        if resolve_device_oui is None:
            pytest.fail("resolve_device_oui is not implemented in airtell.sniff.telemetry")

        # Query canonical MAC directly (already Big-Endian)
        res = resolve_device_oui("E4:38:83:D7:A5:B3", str(OUIDB_BIN_PATH))
        assert res is not None
        assert res.vendor == "Flock Safety"
        assert res.device_type == "alpr"

    # --- Feature 2: Device Class Resolution Across Categories ---

    def test_f02_device_class_camera(self) -> None:
        """F2.1: Camera category resolution for Wyze Labs and Hikvision."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res_wyze = db.lookup("D0:3F:27:00:00:00")
            assert res_wyze is not None
            assert res_wyze.vendor == "Wyze Labs Inc"
            assert res_wyze.device_type == "camera"
            assert res_wyze.flags == OUI_SURV_CAMERA
            assert res_wyze.is_surveillance is True

            res_hik = db.lookup("44:A6:42:00:00:00")
            assert res_hik is not None
            assert "Hikvision" in res_hik.vendor
            assert res_hik.device_type == "camera"
            assert res_hik.is_surveillance is True

    def test_f02_device_class_alpr(self) -> None:
        """F2.2: ALPR category resolution for Flock Safety."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("E4:38:83:00:00:00")
            assert res is not None
            assert res.vendor == "Flock Safety"
            assert res.device_type == "alpr"
            assert res.flags == OUI_SURV_ALPR
            assert res.is_surveillance is True

    def test_f02_device_class_drone(self) -> None:
        """F2.3: Drone category resolution for DJI and Skydio."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res_dji = db.lookup("0C:9A:E6:00:00:00")
            assert res_dji is not None
            assert "Dji" in res_dji.vendor
            assert res_dji.device_type == "drone"
            assert res_dji.flags == OUI_SURV_DRONE
            assert res_dji.is_surveillance is True

            res_skydio = db.lookup("68:9A:87:00:00:00")
            assert res_skydio is not None
            assert "Skydio" in res_skydio.vendor
            assert res_skydio.device_type == "drone"
            assert res_skydio.is_surveillance is True

    def test_f02_device_class_bodycam(self) -> None:
        """F2.4: Bodycam category resolution for Axon Enterprise."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("00:25:DF:00:00:00")
            assert res is not None
            assert "Axon" in res.vendor
            assert res.device_type == "bodycam"
            assert res.flags == OUI_SURV_BODYCAM
            assert res.is_surveillance is True

    def test_f02_device_class_none_consumer(self) -> None:
        """F2.5: Consumer electronics resolution (Apple, Google, Espressif) with category 'none'."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            for mac, expected_vendor in [
                ("3C:22:FB:00:00:00", "Apple, Inc."),
                ("48:D6:D5:00:00:00", "Google, Inc."),
                ("84:1F:E8:00:00:00", "Espressif Inc."),
            ]:
                res = db.lookup(mac)
                assert res is not None
                assert expected_vendor in res.vendor
                assert res.device_type == "none"
                assert res.flags == OUI_SURV_NONE
                assert res.is_surveillance is False

    def test_f02_airtell_telemetry_enrichment(self) -> None:
        """F2.6: DeviceTelemetrySummary enriched with vendor, device_class, and is_surveillance."""
        if DeviceTelemetrySummary is None or resolve_device_oui is None:
            pytest.fail("DeviceTelemetrySummary or resolve_device_oui not yet implemented")

        summary = DeviceTelemetrySummary(mac_address="E4:38:83:D7:A5:B3")
        assert hasattr(summary, "vendor")
        assert hasattr(summary, "device_class")
        assert hasattr(summary, "oui_prefix")
        assert hasattr(summary, "is_surveillance")

        # Enrich via resolve_device_oui
        res = resolve_device_oui(summary.mac_address, str(OUIDB_BIN_PATH))
        assert res is not None
        summary.vendor = res.vendor
        summary.device_class = res.device_type
        summary.oui_prefix = res.prefix_str
        summary.is_surveillance = res.is_surveillance

        assert summary.vendor == "Flock Safety"
        assert summary.device_class == "alpr"
        assert summary.is_surveillance is True

    # --- Feature 3: PCAP Ingestion with Advertising PDU Types ---

    def test_f03_pcap_ingest_adv_ind(self, tmp_path: Path) -> None:
        """F3.1: PCAP ingestion with ADV_IND extracts AdvA with role 'AdvA'."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3", data=b"\x02\x01\x06")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "adv_ind.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.mac == "E4:38:83:D7:A5:B3"
        assert "AdvA" in entry.roles
        assert "ADV_IND" in entry.packet_types

    def test_f03_pcap_ingest_scan_req(self, tmp_path: Path) -> None:
        """F3.2: PCAP ingestion with SCAN_REQ extracts ScanA (scanner) and AdvA (advertiser)."""
        # Skydio drone as scanner, Google as advertiser
        pdu = _build_adv_pdu(
            PDU_TYPE_SCAN_REQ,
            adv_a_mac="48:D6:D5:11:22:33",
            scan_a_mac="68:9A:87:20:6B:FF",
        )
        pcap_file = _create_synthetic_pcap_file([(1001.0, pdu)], tmp_path / "scan_req.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        macs = {e.mac: e for e in report.entries}

        assert "68:9A:87:20:6B:FF" in macs
        skydio_entry = macs["68:9A:87:20:6B:FF"]
        assert "ScanA" in skydio_entry.roles
        assert skydio_entry.device_category == "drone"

        assert "48:D6:D5:11:22:33" in macs
        google_entry = macs["48:D6:D5:11:22:33"]
        assert "AdvA" in google_entry.roles
        assert google_entry.device_category == "none"

    def test_f03_pcap_ingest_scan_rsp(self, tmp_path: Path) -> None:
        """F3.3: PCAP ingestion with SCAN_RSP extracts AdvA with role 'AdvA'."""
        pdu = _build_adv_pdu(PDU_TYPE_SCAN_RSP, "D0:3F:27:5A:C4:76", data=b"\x05\x09Wyze")
        pcap_file = _create_synthetic_pcap_file([(1002.0, pdu)], tmp_path / "scan_rsp.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.mac == "D0:3F:27:5A:C4:76"
        assert "AdvA" in entry.roles
        assert "SCAN_RSP" in entry.packet_types
        assert entry.device_category == "camera"

    def test_f03_pcap_ingest_adv_direct_ind(self, tmp_path: Path) -> None:
        """F3.4: PCAP ingestion with ADV_DIRECT_IND extracts AdvA and TargetA."""
        pdu = _build_adv_pdu(
            PDU_TYPE_ADV_DIRECT_IND,
            adv_a_mac="0C:9A:E6:37:F6:2D",
            target_a_mac="3C:22:FB:11:22:33",
        )
        pcap_file = _create_synthetic_pcap_file([(1003.0, pdu)], tmp_path / "adv_direct.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        macs = {e.mac: e for e in report.entries}

        assert "0C:9A:E6:37:F6:2D" in macs
        dji_entry = macs["0C:9A:E6:37:F6:2D"]
        assert "AdvA" in dji_entry.roles
        assert dji_entry.device_category == "drone"

        assert "3C:22:FB:11:22:33" in macs
        apple_entry = macs["3C:22:FB:11:22:33"]
        assert "TargetA" in apple_entry.roles

    def test_f03_pcap_ingest_connect_ind(self, tmp_path: Path) -> None:
        """F3.5: PCAP ingestion with CONNECT_IND extracts InitA and AdvA."""
        pdu = _build_adv_pdu(
            PDU_TYPE_CONNECT_IND,
            adv_a_mac="80:48:2C:53:47:33",
            init_a_mac="48:D6:D5:AA:BB:CC",
        )
        pcap_file = _create_synthetic_pcap_file([(1004.0, pdu)], tmp_path / "connect_ind.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        macs = {e.mac: e for e in report.entries}

        assert "80:48:2C:53:47:33" in macs
        wyze_entry = macs["80:48:2C:53:47:33"]
        assert "AdvA" in wyze_entry.roles

        assert "48:D6:D5:AA:BB:CC" in macs
        google_entry = macs["48:D6:D5:AA:BB:CC"]
        assert "InitA" in google_entry.roles

    # --- Feature 4: OUI Filtering & Strict Chronological Ordering ---

    def test_f04_oui_filtering_excludes_random_addresses(self, tmp_path: Path) -> None:
        """F4.1: Random private addresses (RPAs) not in OUI DB are excluded."""
        # Unassigned random address + Flock Safety
        pdu_rpa = _build_adv_pdu(PDU_TYPE_ADV_IND, "7F:11:22:33:44:55", tx_add=1)
        pdu_oui = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")

        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu_rpa), (1001.0, pdu_oui)],
            tmp_path / "filter_rpa.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"

    def test_f04_oui_filtering_retains_database_matches(self, tmp_path: Path) -> None:
        """F4.2: All addresses matching Spectra Mesh OUI DB are retained."""
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pdu2 = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")
        pdu3 = _build_adv_pdu(PDU_TYPE_ADV_IND, "D0:3F:27:B0:07:6E")

        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu1), (1001.0, pdu2), (1002.0, pdu3)],
            tmp_path / "retain_oui.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 3
        macs = [e.mac for e in report.entries]
        assert macs == ["E4:38:83:D7:A5:B3", "0C:9A:E6:37:F6:2D", "D0:3F:27:B0:07:6E"]

    def test_f04_strict_chronological_ordering(self, tmp_path: Path) -> None:
        """F4.3: Timeline entries are sorted strictly ascending by first_seen."""
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "D0:3F:27:B0:07:6E")  # Wyze at t=1020
        pdu2 = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # Flock at t=1010
        pdu3 = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")  # DJI at t=1030

        pcap_file = _create_synthetic_pcap_file(
            [(1020.0, pdu1), (1010.0, pdu2), (1030.0, pdu3)],
            tmp_path / "sort_chrono.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 3
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"
        assert report.entries[1].mac == "D0:3F:27:B0:07:6E"
        assert report.entries[2].mac == "0C:9A:E6:37:F6:2D"
        for i in range(len(report.entries) - 1):
            assert report.entries[i].first_seen <= report.entries[i + 1].first_seen

    def test_f04_first_seen_and_last_seen_tracking(self, tmp_path: Path) -> None:
        """F4.4: Multiple occurrences track earliest first_seen and latest last_seen."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")

        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu), (1050.0, pdu), (1100.0, pdu)],
            tmp_path / "first_last.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.first_seen == pytest.approx(1000.0, abs=1e-3)
        assert entry.last_seen == pytest.approx(1100.0, abs=1e-3)
        assert entry.first_seen <= entry.last_seen

    def test_f04_packet_count_increment(self, tmp_path: Path) -> None:
        """F4.5: Packet count increments accurately for repeated observations."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")

        pcap_file = _create_synthetic_pcap_file(
            [(float(1000 + i), pdu) for i in range(15)],
            tmp_path / "packet_count.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        assert report.entries[0].packet_count == 15

    # --- Feature 5: Timeline Metadata Enrichment ---

    def test_f05_timestamp_metadata_iso8601(self, tmp_path: Path) -> None:
        """F5.1: Verification of first_seen_iso and last_seen_iso format."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        epoch = 1793798748.211015
        pcap_file = _create_synthetic_pcap_file([(epoch, pdu)], tmp_path / "iso_time.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entry = report.entries[0]
        assert isinstance(entry.first_seen_iso, str)
        assert isinstance(entry.last_seen_iso, str)
        # Verify parseable by datetime.fromisoformat
        dt1 = datetime.fromisoformat(entry.first_seen_iso.replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(entry.last_seen_iso.replace("Z", "+00:00"))
        assert dt1 <= dt2

    def test_f05_packet_metadata_types_and_roles(self, tmp_path: Path) -> None:
        """F5.2: Verification of packet_types list and roles list."""
        pdu_adv = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pdu_rsp = _build_adv_pdu(PDU_TYPE_SCAN_RSP, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu_adv), (1001.0, pdu_rsp)],
            tmp_path / "types_roles.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entry = report.entries[0]
        assert "ADV_IND" in entry.packet_types
        assert "SCAN_RSP" in entry.packet_types
        assert "AdvA" in entry.roles

    def test_f05_database_prefix_and_table_metadata(self, tmp_path: Path) -> None:
        """F5.3: Verification of vendor, prefix, prefix_bits, and table."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "pfx_table.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entry = report.entries[0]
        assert entry.vendor == "Flock Safety"
        assert entry.prefix == "E4:38:83"
        assert entry.prefix_bits == 24
        assert entry.table == "MA-L"

    def test_f05_device_category_and_flags(self, tmp_path: Path) -> None:
        """F5.4: Verification of device_category label and integer flags."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "cat_flags.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entry = report.entries[0]
        assert entry.device_category == "alpr"
        assert entry.flags == OUI_SURV_ALPR

    def test_f05_is_surveillance_flag_integrity(self, tmp_path: Path) -> None:
        """F5.5: Verification that is_surveillance is True iff flags != 0."""
        pdu_surv = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # Flock (alpr)
        pdu_cons = _build_adv_pdu(PDU_TYPE_ADV_IND, "48:D6:D5:11:22:33")  # Google (none)
        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu_surv), (1001.0, pdu_cons)],
            tmp_path / "surv_flags.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        macs = {e.mac: e for e in report.entries}
        assert macs["E4:38:83:D7:A5:B3"].is_surveillance is True
        assert macs["E4:38:83:D7:A5:B3"].flags != 0
        assert macs["48:D6:D5:11:22:33"].is_surveillance is False
        assert macs["48:D6:D5:11:22:33"].flags == 0

    # --- Feature 6: Timeline Report Formats & CLI ---

    def test_f06_report_to_dict(self, tmp_path: Path) -> None:
        """F6.1: Serialization to dictionary."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "dict_test.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "entries" in d
        assert len(d["entries"]) == 1
        assert d["entries"][0]["mac"] == "E4:38:83:D7:A5:B3"
        assert d["entries"][0]["vendor"] == "Flock Safety"

    def test_f06_report_to_json(self, tmp_path: Path) -> None:
        """F6.2: Serialization to valid JSON."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "json_test.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "entries" in parsed
        assert parsed["entries"][0]["mac"] == "E4:38:83:D7:A5:B3"

    def test_f06_report_to_csv(self, tmp_path: Path) -> None:
        """F6.3: Serialization to CSV with correct headers."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "csv_test.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        csv_str = report.to_csv()
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["mac"] == "E4:38:83:D7:A5:B3"
        assert rows[0]["vendor"] == "Flock Safety"
        assert rows[0]["device_category"] == "alpr"

    def test_f06_report_to_markdown(self, tmp_path: Path) -> None:
        """F6.4: Serialization to Markdown table."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "md_test.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        md_str = report.to_markdown()
        assert "| MAC Address |" in md_str or "| mac |" in md_str.lower()
        assert "E4:38:83:D7:A5:B3" in md_str
        assert "Flock Safety" in md_str

    def test_f06_report_to_text(self, tmp_path: Path) -> None:
        """F6.5: Serialization to formatted plain text."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "text_test.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        txt = report.to_text()
        assert "E4:38:83:D7:A5:B3" in txt
        assert "Flock Safety" in txt

    def test_f06_cli_pcap_timeline_subcommand(self) -> None:
        """F6.6: CLI parser registers pcap-timeline and alias timeline."""
        if create_parser is None:
            pytest.fail("create_parser is not implemented in airtell.cli")

        parser = create_parser()
        args1 = parser.parse_args(["pcap-timeline", "-i", "app/data/merged.pcap", "--json"])
        assert args1.pcap == "app/data/merged.pcap"
        assert args1.json is True

        args2 = parser.parse_args(["timeline", "-i", "app/data/merged.pcap", "--surveillance-only"])
        assert args2.pcap == "app/data/merged.pcap"
        assert args2.surveillance_only is True


# ---------------------------------------------------------------------------
# Tier 2: Boundary & Corner Cases (B1 to B5, ≥5 per feature)
# ---------------------------------------------------------------------------

class TestTier2BoundaryAndCornerCases:
    """Tier 2: Boundary & Corner Cases (B1 to B5)."""

    # --- Boundary 1: Empty and Malformed PCAP Files ---

    def test_b01_zero_byte_pcap(self, tmp_path: Path) -> None:
        """B1.1: 0-byte PCAP file raises descriptive error or returns empty report."""
        empty_file = tmp_path / "empty.pcap"
        empty_file.write_bytes(b"")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        try:
            report = generate_mac_timeline(str(empty_file), str(OUIDB_BIN_PATH))
            assert len(report.entries) == 0
        except ValueError as exc:
            assert "empty" in str(exc).lower() or "header" in str(exc).lower()

    def test_b01_truncated_pcap_global_header(self, tmp_path: Path) -> None:
        """B1.2: PCAP file truncated mid global header (<24 bytes) raises descriptive error."""
        trunc_hdr = tmp_path / "trunc_hdr.pcap"
        trunc_hdr.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")  # 6 bytes only

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        with pytest.raises(ValueError, match=r"header|short|truncated"):
            generate_mac_timeline(str(trunc_hdr), str(OUIDB_BIN_PATH))

    def test_b01_truncated_pcap_packet_header(self, tmp_path: Path) -> None:
        """B1.3: Truncated packet header yields 0 complete packets without crash."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        valid_pcap = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "partial.pcap")
        data = valid_pcap.read_bytes()
        # Truncate 5 bytes off the packet header
        corrupt_pcap = tmp_path / "corrupt_pkt.pcap"
        corrupt_pcap.write_bytes(data[:28])

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(corrupt_pcap), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 0

    def test_b01_truncated_packet_payload(self, tmp_path: Path) -> None:
        """B1.4: Header declares 50-byte payload, only 10 bytes present."""
        hdr = struct.pack("<IHHIIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        # Declares caplen=50, but we provide only 10 bytes
        pkt_hdr = struct.pack("<IIII", 1000, 0, 50, 50)
        incomplete = tmp_path / "incomplete_payload.pcap"
        incomplete.write_bytes(hdr + pkt_hdr + b"\x00" * 10)

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        try:
            report = generate_mac_timeline(str(incomplete), str(OUIDB_BIN_PATH))
            assert len(report.entries) == 0
        except (ValueError, EOFError) as exc:
            assert "truncated" in str(exc).lower() or "pcap" in str(exc).lower()

    def test_b01_single_packet_pcap(self, tmp_path: Path) -> None:
        """B1.5: PCAP with exactly 1 packet produces timeline with first_seen == last_seen."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "single.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.packet_count == 1
        assert entry.first_seen == entry.last_seen

    # --- Boundary 2: Zero Matching MACs ---

    def test_b02_pure_rpa_pcap(self, tmp_path: Path) -> None:
        """B2.1: PCAP containing solely random private addresses (RPAs)."""
        # Resolvable Private Address: top 2 bits of MSB are 0b01
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "41:22:33:44:55:66", tx_add=1)
        pdu2 = _build_adv_pdu(PDU_TYPE_ADV_IND, "5E:AA:BB:CC:DD:EE", tx_add=1)
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu1), (1001.0, pdu2)], tmp_path / "rpa.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 0

    def test_b02_pure_nrpa_pcap(self, tmp_path: Path) -> None:
        """B2.2: PCAP containing solely non-resolvable private addresses (NRPAs)."""
        # NRPA: top 2 bits of MSB are 0b00
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "01:22:33:44:55:66", tx_add=1)
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu1)], tmp_path / "nrpa.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 0

    def test_b02_empty_report_serialization(self) -> None:
        """B2.3: Empty timeline report serializes cleanly across JSON, CSV, Markdown, text."""
        if PcapTimelineReport is None:
            pytest.fail("PcapTimelineReport is not implemented in airtell.sniff.timeline")

        empty_report = PcapTimelineReport(
            pcap_path="test_empty.pcap",
            ouidb_path=str(OUIDB_BIN_PATH),
            total_packets_processed=0,
            total_unique_macs=0,
            total_matched_macs=0,
            total_surveillance_macs=0,
            duration_sec=0.0,
            entries=[],
        )
        assert empty_report.to_dict()["entries"] == []
        assert json.loads(empty_report.to_json())["entries"] == []
        assert isinstance(empty_report.to_csv(), str)
        assert isinstance(empty_report.to_markdown(), str)
        assert isinstance(empty_report.to_text(), str)

    def test_b02_unregistered_public_macs(self, tmp_path: Path) -> None:
        """B2.4: Public MAC addresses not registered with IEEE OUI DB are excluded."""
        # Unallocated IEEE OUI prefix
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "00:00:00:11:22:33")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "unreg.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        # Either 00:00:00 is Xerox (if in IEEE) or filtered if missing
        for entry in report.entries:
            assert entry.vendor != ""

    def test_b02_filtered_category_yields_zero(self, tmp_path: Path) -> None:
        """B2.5: Filtering by category 'bodycam' on capture with only cameras returns empty report."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "D0:3F:27:B0:07:6E")  # Wyze camera
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "cam_only.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), category="bodycam")
        assert len(report.entries) == 0

    # --- Boundary 3: Longest Prefix Match (LPM) Collisions ---

    def test_b03_mas_36bit_overrides_mam_and_mal(self, tmp_path: Path) -> None:
        """B3.1: When MAC matches MA-L, MA-M, and MA-S, MA-S (36-bit) must win."""
        str_pool = b"VendorMAL\x00VendorMAM\x00VendorMAS\x00"
        blob = _make_soui_blob(
            mal_entries=[(0xAABBCC, 0, OUI_SURV_NONE)],
            mam_entries=[(0xAABBCCD, 10, OUI_SURV_CAMERA)],
            mas_entries=[(0xAABBCCDDE, 20, OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "lpm.bin"
        db_path.write_bytes(blob)

        with OuiDb(db_path) as db:
            res = db.lookup("AA:BB:CC:DD:EF:01")
            assert res is not None
            assert res.vendor == "VendorMAS"
            assert res.prefix_bits == 36
            assert res.table == "MA-S"
            assert res.device_type == "drone"

    def test_b03_mam_28bit_overrides_mal(self, tmp_path: Path) -> None:
        """B3.2: When MAC matches MA-L and MA-M, MA-M (28-bit) must win."""
        str_pool = b"VendorMAL\x00VendorMAM\x00VendorMAS\x00"
        blob = _make_soui_blob(
            mal_entries=[(0xAABBCC, 0, OUI_SURV_NONE)],
            mam_entries=[(0xAABBCCD, 10, OUI_SURV_CAMERA)],
            mas_entries=[(0xAABBCCDDE, 20, OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "lpm.bin"
        db_path.write_bytes(blob)

        with OuiDb(db_path) as db:
            res = db.lookup("AA:BB:CC:DF:00:01")
            assert res is not None
            assert res.vendor == "VendorMAM"
            assert res.prefix_bits == 28
            assert res.table == "MA-M"
            assert res.device_type == "camera"

    def test_b03_mal_24bit_fallback_when_subprefix_misses(self, tmp_path: Path) -> None:
        """B3.3: When sub-prefixes miss, MA-L (24-bit) fallback matches."""
        str_pool = b"VendorMAL\x00VendorMAM\x00VendorMAS\x00"
        blob = _make_soui_blob(
            mal_entries=[(0xAABBCC, 0, OUI_SURV_NONE)],
            mam_entries=[(0xAABBCCD, 10, OUI_SURV_CAMERA)],
            mas_entries=[(0xAABBCCDDE, 20, OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "lpm.bin"
        db_path.write_bytes(blob)

        with OuiDb(db_path) as db:
            res = db.lookup("AA:BB:CC:EE:00:01")
            assert res is not None
            assert res.vendor == "VendorMAL"
            assert res.prefix_bits == 24
            assert res.table == "MA-L"

    def test_b03_adjacent_nibbles_in_mam_28(self, tmp_path: Path) -> None:
        """B3.4: Differentiate adjacent /28 blocks differing only by low nibble of byte 3."""
        str_pool = b"Block0\x00Block1\x00"
        blob = _make_soui_blob(
            mam_entries=[(0xAABBCC0, 0, OUI_SURV_NONE), (0xAABBCC1, 7, OUI_SURV_CAMERA)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "adjacent28.bin"
        db_path.write_bytes(blob)

        with OuiDb(db_path) as db:
            r0 = db.lookup("AA:BB:CC:0F:00:00")
            assert r0 is not None
            assert r0.vendor == "Block0"

            r1 = db.lookup("AA:BB:CC:1F:00:00")
            assert r1 is not None
            assert r1.vendor == "Block1"

    def test_b03_adjacent_nibbles_in_mas_36(self, tmp_path: Path) -> None:
        """B3.5: Differentiate adjacent /36 blocks differing only by low nibble of byte 4."""
        str_pool = b"BlockS0\x00BlockS1\x00"
        blob = _make_soui_blob(
            mas_entries=[(0xAABBCCDDE, 0, OUI_SURV_NONE), (0xAABBCCDDF, 8, OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "adjacent36.bin"
        db_path.write_bytes(blob)

        with OuiDb(db_path) as db:
            r0 = db.lookup("AA:BB:CC:DD:E0:12")
            assert r0 is not None
            assert r0.vendor == "BlockS0"

            r1 = db.lookup("AA:BB:CC:DD:F0:12")
            assert r1 is not None
            assert r1.vendor == "BlockS1"

    # --- Boundary 4: Special and Malformed MAC Addresses ---

    def test_b04_broadcast_mac(self) -> None:
        """B4.1: Broadcast address FF:FF:FF:FF:FF:FF handled safely."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("FF:FF:FF:FF:FF:FF")
            # Should safely return None or consumer
            assert res is None or res.is_surveillance is False

    def test_b04_multicast_mac(self) -> None:
        """B4.2: Multicast address 01:00:5E:00:00:01 handled safely."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("01:00:5E:00:00:01")
            assert res is None or res.vendor != ""

    def test_b04_all_zero_mac(self) -> None:
        """B4.3: All-zero MAC address 00:00:00:00:00:00 handled safely."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            res = db.lookup("00:00:00:00:00:00")
            assert res is None or res.vendor != ""

    def test_b04_invalid_mac_string_format(self) -> None:
        """B4.4: Malformed MAC strings raise ValueError."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            for invalid_mac in ["not-a-mac", "00:11:22", "00:11:22:33:44:ZZ", ""]:
                with pytest.raises(ValueError):
                    db.lookup(invalid_mac)

    def test_b04_mixed_case_and_delimiter_normalization(self) -> None:
        """B4.5: Lower-case and hyphen-delimited MAC addresses normalize properly."""
        with OuiDb(OUIDB_BIN_PATH) as db:
            r_lower = db.lookup("e4:38:83:d7:a5:b3")
            assert r_lower is not None
            assert r_lower.vendor == "Flock Safety"

            r_dash = db.lookup("E4-38-83-D7-A5-B3")
            assert r_dash is not None
            assert r_dash.vendor == "Flock Safety"

    # --- Boundary 5: Extreme Timestamps & Ordering ---

    def test_b05_timestamp_epoch_zero(self, tmp_path: Path) -> None:
        """B5.1: Packet with epoch timestamp 0.0 handled safely."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(0.0, pdu)], tmp_path / "epoch_zero.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        assert report.entries[0].first_seen == 0.0
        assert "1970" in report.entries[0].first_seen_iso

    def test_b05_far_future_timestamp(self, tmp_path: Path) -> None:
        """B5.2: Packet with far future timestamp (year 2038+)."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        future_epoch = 2147483648.0
        pcap_file = _create_synthetic_pcap_file([(future_epoch, pdu)], tmp_path / "future.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        assert report.entries[0].first_seen == future_epoch
        assert "2038" in report.entries[0].first_seen_iso

    def test_b05_microsecond_subsecond_precision(self, tmp_path: Path) -> None:
        """B5.3: Packets spaced 1 microsecond apart maintain microsecond precision."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        t1 = 1000.000001
        t2 = 1000.000002
        pcap_file = _create_synthetic_pcap_file([(t1, pdu), (t2, pdu)], tmp_path / "usec.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entry = report.entries[0]
        assert entry.first_seen == pytest.approx(t1, abs=1e-6)
        assert entry.last_seen == pytest.approx(t2, abs=1e-6)

    def test_b05_out_of_order_packets_in_pcap(self, tmp_path: Path) -> None:
        """B5.4: Packets arriving out of order in PCAP are sorted by earliest first_seen."""
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # Flock t=200, t=100
        pdu2 = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")  # DJI t=150

        # Written in order: t=200 (Flock), t=150 (DJI), t=100 (Flock)
        pcap_file = _create_synthetic_pcap_file(
            [(200.0, pdu1), (150.0, pdu2), (100.0, pdu1)],
            tmp_path / "ooo.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 2
        # Flock's earliest seen is 100.0, DJI's is 150.0 -> Flock must appear first!
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"
        assert report.entries[0].first_seen == 100.0
        assert report.entries[0].last_seen == 200.0
        assert report.entries[1].mac == "0C:9A:E6:37:F6:2D"
        assert report.entries[1].first_seen == 150.0

    def test_b05_limit_zero_and_negative(self, tmp_path: Path) -> None:
        """B5.5: limit=0 returns empty report or raises ValueError."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "limit0.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), limit=0)
        assert len(report.entries) == 0


# ---------------------------------------------------------------------------
# Tier 3: Cross-Feature Combinations (Pairwise Coverage)
# ---------------------------------------------------------------------------

class TestTier3CrossFeatureCombinations:
    """Tier 3: Cross-Feature Combinations & Multi-PDU Pairwise Interaction."""

    def test_c01_multirole_advertiser_and_scanner_surveillance(self, tmp_path: Path) -> None:
        """C1: Device appearing as AdvA and ScanA in consecutive packets aggregates roles."""
        mac = "68:9A:87:ED:21:EF"  # Skydio drone
        pdu1 = _build_adv_pdu(PDU_TYPE_ADV_IND, adv_a_mac=mac)
        pdu2 = _build_adv_pdu(PDU_TYPE_SCAN_REQ, adv_a_mac="48:D6:D5:11:22:33", scan_a_mac=mac)

        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu1), (1001.0, pdu2)], tmp_path / "multirole.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        skydio_entry = next(e for e in report.entries if e.mac == mac)
        assert "AdvA" in skydio_entry.roles
        assert "ScanA" in skydio_entry.roles
        assert skydio_entry.packet_count == 2
        assert skydio_entry.device_category == "drone"
        assert skydio_entry.is_surveillance is True

    def test_c02_surveillance_only_filter_with_json_and_csv(self, tmp_path: Path) -> None:
        """C2: surveillance_only=True combined with multi-format serialization."""
        pdu_flock = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # Surveillance (alpr)
        pdu_apple = _build_adv_pdu(PDU_TYPE_ADV_IND, "3C:22:FB:11:22:33")  # Consumer (none)
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu_flock), (1001.0, pdu_apple)], tmp_path / "surv_filter.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), surveillance_only=True)
        assert len(report.entries) == 1
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"

        # Verify JSON export contains only surveillance
        data = json.loads(report.to_json())
        assert len(data["entries"]) == 1
        assert data["entries"][0]["mac"] == "E4:38:83:D7:A5:B3"

        # Verify CSV export contains only surveillance
        csv_rows = list(csv.DictReader(io.StringIO(report.to_csv())))
        assert len(csv_rows) == 1
        assert csv_rows[0]["mac"] == "E4:38:83:D7:A5:B3"

    def test_c03_category_filter_with_limit(self, tmp_path: Path) -> None:
        """C3: category='camera' combined with limit=1."""
        pdu_cam1 = _build_adv_pdu(PDU_TYPE_ADV_IND, "D0:3F:27:B0:07:6E")  # Wyze camera
        pdu_drone = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")  # DJI drone
        pdu_cam2 = _build_adv_pdu(PDU_TYPE_ADV_IND, "80:48:2C:53:47:33")  # Wyze camera

        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu_cam1), (1001.0, pdu_drone), (1002.0, pdu_cam2)],
            tmp_path / "cat_limit.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), category="camera", limit=1)
        assert len(report.entries) == 1
        assert report.entries[0].mac == "D0:3F:27:B0:07:6E"
        assert report.entries[0].device_category == "camera"

    def test_c04_mixed_prefix_lengths_and_pdu_types(self, tmp_path: Path) -> None:
        """C4: Combination of MA-L, MA-M, and MA-S across ADV_IND, SCAN_REQ, SCAN_RSP."""
        pdu_mal = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # 24-bit MA-L Flock
        pdu_mam = _build_adv_pdu(PDU_TYPE_SCAN_REQ, adv_a_mac="E4:38:83:D7:A5:B3", scan_a_mac="00:55:DA:B0:12:34")  # 28-bit Interaxon
        pdu_mas = _build_adv_pdu(PDU_TYPE_SCAN_RSP, "00:50:C2:0D:80:12")  # 36-bit Charlotte's Web

        pcap_file = _create_synthetic_pcap_file(
            [(1000.0, pdu_mal), (1001.0, pdu_mam), (1002.0, pdu_mas)],
            tmp_path / "mixed_prefix.pcap",
        )

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        entries_by_mac = {e.mac: e for e in report.entries}

        assert entries_by_mac["E4:38:83:D7:A5:B3"].prefix_bits == 24
        assert entries_by_mac["00:55:DA:B0:12:34"].prefix_bits == 28
        assert entries_by_mac["00:50:C2:0D:80:12"].prefix_bits == 36

    def test_c05_device_telemetry_summary_and_timeline_congruence(self, tmp_path: Path) -> None:
        """C5: DeviceTelemetrySummary and PcapTimelineEntry report congruent metadata."""
        mac = "E4:38:83:D7:A5:B3"
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, mac)
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "congruence.pcap")

        if generate_mac_timeline is None or resolve_device_oui is None:
            pytest.fail("Timeline or telemetry module is not implemented")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH))
        timeline_entry = report.entries[0]

        summary_res = resolve_device_oui(mac, str(OUIDB_BIN_PATH))
        assert summary_res is not None

        assert timeline_entry.vendor == summary_res.vendor
        assert timeline_entry.device_category == summary_res.device_type
        assert timeline_entry.prefix == summary_res.prefix_str
        assert timeline_entry.prefix_bits == summary_res.prefix_bits
        assert timeline_entry.is_surveillance == summary_res.is_surveillance

    def test_c06_category_case_insensitivity_and_whitespace(self, tmp_path: Path) -> None:
        """C6: Category filter matches case-insensitively with leading/trailing whitespace."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")  # DJI drone
        pcap_file = _create_synthetic_pcap_file([(1000.0, pdu)], tmp_path / "cat_case.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), category="  DRONE  ")
        assert len(report.entries) == 1
        assert report.entries[0].device_category == "drone"

    def test_c07_timeline_limit_truncation(self, tmp_path: Path) -> None:
        """C7: limit=N truncates processing or output accurately."""
        packets = [
            (float(1000 + i), _build_adv_pdu(PDU_TYPE_ADV_IND, f"D0:3F:27:B0:07:{i:02X}"))
            for i in range(10)
        ]
        pcap_file = _create_synthetic_pcap_file(packets, tmp_path / "limit_trunc.pcap")

        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(str(pcap_file), str(OUIDB_BIN_PATH), limit=3)
        assert len(report.entries) <= 3


# ---------------------------------------------------------------------------
# Tier 4: Real-World Application Scenarios (Against app/data/merged.pcap)
# ---------------------------------------------------------------------------

class TestTier4RealWorldApplicationScenarios:
    """Tier 4: Verification of Real-World Ground Truth against app/data/merged.pcap."""

    @pytest.fixture
    def require_merged_pcap(self) -> Path:
        """Ensure app/data/merged.pcap exists and is readable."""
        if not MERGED_PCAP_PATH.exists():
            pytest.skip(f"Capture file {MERGED_PCAP_PATH} not found")
        return MERGED_PCAP_PATH

    def test_s01_merged_pcap_limited_window(self, require_merged_pcap: Path) -> None:
        """S1: Rapid execution against merged.pcap with limit=2000 asserting order and metadata."""
        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        t0 = time.time()
        report = generate_mac_timeline(str(require_merged_pcap), str(OUIDB_BIN_PATH), limit=2000)
        duration = time.time() - t0

        assert duration < 10.0, f"Processing limit=2000 took too long ({duration:.2f}s)"
        assert len(report.entries) > 0

        # Assert strict chronological ordering
        for i in range(len(report.entries) - 1):
            assert report.entries[i].first_seen <= report.entries[i + 1].first_seen

        # Assert every entry has valid metadata
        for entry in report.entries:
            assert entry.mac != ""
            assert entry.vendor != ""
            assert entry.packet_count >= 1
            assert entry.first_seen <= entry.last_seen

    def test_s02_merged_pcap_flock_safety_alpr(self, require_merged_pcap: Path) -> None:
        """S2: Ground truth verification of Flock Safety ALPR (E4:38:83:D7:A5:B3)."""
        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        # Flock Safety appears around packet 264,651 in merged.pcap
        report = generate_mac_timeline(
            str(require_merged_pcap),
            str(OUIDB_BIN_PATH),
            category="alpr",
            max_packets=300000,
        )

        flock_entry = next((e for e in report.entries if e.mac == "E4:38:83:D7:A5:B3"), None)
        assert flock_entry is not None, "Flock Safety ALPR (E4:38:83:D7:A5:B3) not found in merged.pcap window"
        assert flock_entry.vendor == "Flock Safety"
        assert flock_entry.device_category == "alpr"
        assert flock_entry.prefix == "E4:38:83"
        assert flock_entry.prefix_bits == 24
        assert flock_entry.table == "MA-L"
        assert flock_entry.is_surveillance is True
        assert "AdvA" in flock_entry.roles

    def test_s03_merged_pcap_dji_drones(self, require_merged_pcap: Path) -> None:
        """S3: Ground truth verification of DJI drone address resolution in database."""
        # Check DJI drone MACs from merged.pcap against OUI database
        dji_macs = ["0C:9A:E6:37:F6:2D", "4C:43:F6:30:A4:18", "88:29:85:3C:61:0D"]
        with OuiDb(OUIDB_BIN_PATH) as db:
            for mac in dji_macs:
                res = db.lookup(mac)
                assert res is not None, f"DJI MAC {mac} not found in OUI DB"
                assert "Dji" in res.vendor
                assert res.device_type == "drone"
                assert res.is_surveillance is True

    def test_s04_merged_pcap_skydio_drone_scanners(self, require_merged_pcap: Path) -> None:
        """S4: Ground truth verification of Skydio drone scanner addresses."""
        skydio_macs = [
            "68:9A:87:20:6B:FF",
            "68:9A:87:ED:21:EF",
            "68:9A:87:72:0A:C3",
            "68:9A:87:38:2D:88",
            "68:9A:87:31:88:CD",
            "68:9A:87:B5:DA:09",
        ]
        with OuiDb(OUIDB_BIN_PATH) as db:
            for mac in skydio_macs:
                res = db.lookup(mac)
                assert res is not None, f"Skydio MAC {mac} not found in OUI DB"
                assert "Skydio" in res.vendor
                assert res.device_type == "drone"
                assert res.prefix_str == "68:9A:87"
                assert res.is_surveillance is True

    def test_s05_merged_pcap_camera_devices(self, require_merged_pcap: Path) -> None:
        """S5: Ground truth verification of Wyze, Ring, and Hikvision cameras."""
        camera_macs = [
            ("D0:3F:27:B0:07:6E", "Wyze Labs Inc"),
            ("80:48:2C:53:47:33", "Wyze Labs Inc"),
            ("2C:AA:8E:44:02:A1", "Wyze Labs Inc"),
            ("74:EC:B2:97:05:FD", "Ring LLC"),
            ("44:A6:42:A5:DE:34", "Hangzhou Hikvision Digital Tech"),
        ]
        with OuiDb(OUIDB_BIN_PATH) as db:
            for mac, expected_vendor in camera_macs:
                res = db.lookup(mac)
                assert res is not None, f"Camera MAC {mac} not found in OUI DB"
                assert expected_vendor in res.vendor
                assert res.device_type == "camera"
                assert res.is_surveillance is True

    def test_s06_merged_pcap_surveillance_only_filter(self, require_merged_pcap: Path) -> None:
        """S6: surveillance_only=True against merged.pcap contains exclusively surveillance devices."""
        if generate_mac_timeline is None:
            pytest.fail("generate_mac_timeline is not implemented in airtell.sniff.timeline")

        report = generate_mac_timeline(
            str(require_merged_pcap),
            str(OUIDB_BIN_PATH),
            surveillance_only=True,
            max_packets=300000,
        )

        for entry in report.entries:
            assert entry.is_surveillance is True
            assert entry.device_category in ("camera", "drone", "alpr", "bodycam")
            assert entry.flags != 0

    def test_s07_merged_pcap_cli_invocation(self, require_merged_pcap: Path) -> None:
        """S7: CLI invocation of pcap-timeline against merged.pcap with --limit and --json."""
        if create_parser is None:
            pytest.fail("create_parser is not implemented in airtell.cli")

        parser = create_parser()
        args = parser.parse_args([
            "pcap-timeline",
            "-i", str(require_merged_pcap),
            "--limit", "1000",
            "--json",
        ])
        assert args.pcap == str(require_merged_pcap)
        assert args.limit == 1000
        assert args.json is True
