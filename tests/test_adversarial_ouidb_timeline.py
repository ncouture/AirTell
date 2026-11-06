"""Adversarial stress testing and empirical challenge harness for
PcapTimelineReportGenerator and resolve_device_oui.

Covers:
1. Malformed and corrupt PCAP headers, packet records, and Link Layer PDUs.
2. Longest Prefix Match (LPM) synthetic collision hierarchies (/36 > /28 > /24).
3. Endianness edge cases: palindromic MACs, mixed-case, whitespace, multicast/broadcast.
4. Resource scaling and O(1) memory verification across packet stream magnitudes.
5. Extreme timestamps, out-of-order packets, microsecond boundaries, and zero-match filters.
"""

from __future__ import annotations

import gc
import struct
import time
import tracemalloc
from pathlib import Path

import pytest

from airtell.sniff.dissector import (
    PDU_TYPE_ADV_DIRECT_IND,
    PDU_TYPE_ADV_IND,
    PDU_TYPE_CONNECT_IND,
    PDU_TYPE_SCAN_REQ,
    PDU_TYPE_SCAN_RSP,
)
from airtell.sniff.pcap import (
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    PCAP_MAGIC_USEC,
    PcapBleWriter,
)
from airtell.sniff.telemetry import (
    resolve_device_oui,
)
from airtell.sniff.timeline import (
    generate_mac_timeline,
)
from spectramesh_ouidb import (
    OUI_SURV_CAMERA,
    OUI_SURV_DRONE,
    OUI_SURV_NONE,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OUIDB_BIN_PATH = REPO_ROOT / "spectramesh_ouidb" / "oui_db.bin"


def _make_soui_blob(
    mal_entries: list[tuple[int, int, int]] | None = None,
    mam_entries: list[tuple[int, int, int]] | None = None,
    mas_entries: list[tuple[int, int, int]] | None = None,
    str_pool: bytes = b"\x00",
) -> bytes:
    """Build a valid binary SOUI blob for synthetic OUI database testing."""
    mal = sorted(mal_entries or [], key=lambda e: e[0])
    mam = sorted(mam_entries or [], key=lambda e: e[0])
    mas = sorted(mas_entries or [], key=lambda e: e[0])

    hdr_size = 40
    mal_offset = hdr_size
    mal_size = len(mal) * 9
    mam_offset = mal_offset + mal_size
    mam_size = len(mam) * 9
    mas_offset = mam_offset + mam_size
    mas_size = len(mas) * 13
    str_offset = mas_offset + mas_size
    str_size = len(str_pool)

    hdr = struct.pack(
        "<IIIIIIIIII",
        0x49554F53,  # SOUI magic
        1,           # version 1
        len(mal),
        len(mam),
        len(mas),
        mal_offset,
        mam_offset,
        mas_offset,
        str_offset,
        str_size,
    )

    mal_bytes = b"".join(struct.pack("<IIB", pfx, soff, flags) for pfx, soff, flags in mal)
    mam_bytes = b"".join(struct.pack("<IIB", pfx, soff, flags) for pfx, soff, flags in mam)
    mas_bytes = b"".join(struct.pack("<QIB", pfx, soff, flags) for pfx, soff, flags in mas)

    return hdr + mal_bytes + mam_bytes + mas_bytes + str_pool


def _build_adv_pdu(pdu_type: int, mac_str: str, payload_data: bytes = b"\x02\x01\x06") -> bytes:
    """Build raw PDU bytes for advertising channel PDUs."""
    mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
    wire_mac = bytes(reversed(mac_bytes))
    if pdu_type in (PDU_TYPE_ADV_IND, PDU_TYPE_SCAN_RSP):
        payload = wire_mac + payload_data
        hdr0 = pdu_type & 0x0F
        hdr1 = len(payload) & 0x3F
        return bytes([hdr0, hdr1]) + payload
    elif pdu_type == PDU_TYPE_SCAN_REQ:
        # 6B ScanA + 6B AdvA
        payload = wire_mac + wire_mac
        hdr0 = 0x03
        hdr1 = len(payload) & 0x3F
        return bytes([hdr0, hdr1]) + payload
    elif pdu_type == PDU_TYPE_CONNECT_IND:
        # 6B InitA + 6B AdvA + 22B LLData
        payload = wire_mac + wire_mac + (b"\x00" * 22)
        hdr0 = 0x05
        hdr1 = len(payload) & 0x3F
        return bytes([hdr0, hdr1]) + payload
    elif pdu_type == PDU_TYPE_ADV_DIRECT_IND:
        # 6B AdvA + 6B TargetA
        payload = wire_mac + wire_mac
        hdr0 = 0x01
        hdr1 = len(payload) & 0x3F
        return bytes([hdr0, hdr1]) + payload
    else:
        payload = wire_mac + payload_data
        hdr0 = pdu_type & 0x0F
        hdr1 = len(payload) & 0x3F
        return bytes([hdr0, hdr1]) + payload


def _create_synthetic_pcap(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    """Create a valid DLT 256 PCAP containing given (epoch_ts, raw_pdu) pairs with base_epoch=0.0."""
    with PcapBleWriter(output=path, base_epoch=0.0) as writer:
        for epoch_ts, raw_pdu in packets:
            writer.write_packet(
                ts_usec=int(epoch_ts * 1_000_000),
                chan=37,
                rssi=-60,
                packet=raw_pdu,
            )
    return path


# ==============================================================================
# Challenge Dimension 1: Corrupt Packets & Malformed PCAP Headers
# ==============================================================================


class TestCorruptPacketsAndMalformedInputs:
    """Stress tests malformed PCAP containers and truncated Link Layer payloads."""

    def test_zero_byte_pcap_returns_empty_report(self, tmp_path: Path) -> None:
        pcap = tmp_path / "zero_byte.pcap"
        pcap.touch()
        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert report.total_packets_processed == 0
        assert len(report.entries) == 0
        assert report.duration_sec == 0.0

    def test_truncated_global_headers_handled_safely(self, tmp_path: Path) -> None:
        """Truncated global headers (1, 4, 12, 23 bytes) must raise descriptive error or empty."""
        full_hdr = struct.pack("<IHHIIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        for cut in [1, 4, 12, 23]:
            bad_pcap = tmp_path / f"trunc_ghdr_{cut}.pcap"
            bad_pcap.write_bytes(full_hdr[:cut])
            with pytest.raises((ValueError, EOFError)):
                generate_mac_timeline(str(bad_pcap), str(OUIDB_BIN_PATH))

    def test_corrupt_magic_number_rejected(self, tmp_path: Path) -> None:
        """Unsupported/corrupted magic numbers must be rejected."""
        hdr = struct.pack("<IHHIIII", 0xDEADBEEF, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
        bad_pcap = tmp_path / "bad_magic.pcap"
        bad_pcap.write_bytes(hdr)
        with pytest.raises(ValueError, match="Invalid PCAP magic"):
            generate_mac_timeline(str(bad_pcap), str(OUIDB_BIN_PATH))

    def test_unsupported_linktype_rejected(self, tmp_path: Path) -> None:
        """LinkType other than DLT 256 (e.g. Ethernet 1) must raise descriptive ValueError."""
        hdr = struct.pack("<IHHIIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, 1)  # 1 = EN10MB Ethernet
        bad_pcap = tmp_path / "ethernet.pcap"
        bad_pcap.write_bytes(hdr)
        with pytest.raises(ValueError, match="Unsupported LinkType"):
            generate_mac_timeline(str(bad_pcap), str(OUIDB_BIN_PATH))

    def test_corrupt_packet_header_in_stream(self, tmp_path: Path) -> None:
        """Valid packet followed by truncated packet header must terminate cleanly."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        good_pcap = _create_synthetic_pcap(tmp_path / "valid.pcap", [(100.0, pdu)])
        content = good_pcap.read_bytes()

        # Append partial 6 bytes of a next packet header
        corrupt_pcap = tmp_path / "corrupt_next_hdr.pcap"
        corrupt_pcap.write_bytes(content + b"\x01\x02\x03\x04\x05\x06")

        report = generate_mac_timeline(str(corrupt_pcap), str(OUIDB_BIN_PATH))
        # First valid packet should have been processed
        assert report.total_packets_processed == 1
        assert len(report.entries) == 1
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"

    def test_zero_length_and_underlength_pdu_body(self, tmp_path: Path) -> None:
        """PDU with 0, 1, or 2 bytes must be skipped without aborting stream."""
        valid_pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        packets = [
            (10.0, b""),                     # 0 bytes (empty PDU)
            (11.0, b"\x00"),                 # 1 byte
            (12.0, b"\x00\x00"),             # 2 bytes (header with length 0)
            (13.0, b"\x00\x10" + b"\x00"*3), # Declared length 16, but only 3 bytes present
            (14.0, valid_pdu),               # Valid Flock Safety packet
        ]
        pcap = _create_synthetic_pcap(tmp_path / "malformed_pdus.pcap", packets)
        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert report.total_packets_processed == 5
        assert len(report.entries) == 1
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"

    def test_truncated_role_addresses_in_pdus(self, tmp_path: Path) -> None:
        """PDUs whose payloads are too short for their expected role addresses."""
        valid_flock = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        # Use random unassigned bytes 0x5E.. so it does not accidentally hit Xerox OUI (00:00:00)
        unassigned_bytes = b"\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E"
        packets = [
            # ADV_IND requires 6B AdvA, provide only 4B
            (20.0, bytes([PDU_TYPE_ADV_IND, 4]) + unassigned_bytes[:4]),
            # SCAN_REQ requires 12B (6B ScanA + 6B AdvA), provide only 8B
            (21.0, bytes([PDU_TYPE_SCAN_REQ, 8]) + unassigned_bytes[:8]),
            # CONNECT_IND requires 34B, provide only 14B
            (22.0, bytes([PDU_TYPE_CONNECT_IND, 14]) + unassigned_bytes[:14]),
            # ADV_DIRECT_IND requires 12B, provide only 6B
            (23.0, bytes([PDU_TYPE_ADV_DIRECT_IND, 6]) + unassigned_bytes[:6]),
            # Followed by valid packet
            (24.0, valid_flock),
        ]
        pcap = _create_synthetic_pcap(tmp_path / "truncated_roles.pcap", packets)
        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert report.total_packets_processed == 5
        assert len(report.entries) == 1
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"


# ==============================================================================
# Challenge Dimension 2: LPM Synthetic Collisions (/36 > /28 > /24)
# ==============================================================================


class TestLongestPrefixMatchCollisions:
    """Verifies longest prefix matching and disambiguation across colliding prefix tiers."""

    @pytest.fixture
    def colliding_ouidb(self, tmp_path: Path) -> Path:
        """Construct synthetic database with strict hierarchy:
        - MA-L (/24): 0x112233 -> VendorMAL (flags=0, none)
        - MA-M (/28): 0x1122334 -> VendorMAM (flags=1, camera)
        - MA-S (/36): 0x112233456 -> VendorMAS (flags=3, drone)
        """
        str_pool = b"VendorMAL\x00VendorMAM\x00VendorMAS\x00"
        blob = _make_soui_blob(
            mal_entries=[(0x112233, 0, OUI_SURV_NONE)],
            mam_entries=[(0x1122334, 10, OUI_SURV_CAMERA)],
            mas_entries=[(0x112233456, 20, OUI_SURV_DRONE)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "colliding_lpm.bin"
        db_path.write_bytes(blob)
        return db_path

    def test_mas_36_wins_over_mam_and_mal(self, colliding_ouidb: Path) -> None:
        """MAC 11:22:33:45:67:89 matches MA-L, MA-M, and MA-S; MA-S must win."""
        res = resolve_device_oui("11:22:33:45:67:89", ouidb_path=colliding_ouidb)
        assert res is not None
        assert res.vendor == "VendorMAS"
        assert res.table == "MA-S"
        assert res.prefix_bits == 36
        assert res.device_type == "drone"
        assert res.is_surveillance is True

    def test_mam_28_wins_over_mal_when_mas_misses(self, colliding_ouidb: Path) -> None:
        """MAC 11:22:33:40:00:01 matches MA-L and MA-M (/28 nibble 4); MA-M must win."""
        res = resolve_device_oui("11:22:33:40:00:01", ouidb_path=colliding_ouidb)
        assert res is not None
        assert res.vendor == "VendorMAM"
        assert res.table == "MA-M"
        assert res.prefix_bits == 28
        assert res.device_type == "camera"
        assert res.is_surveillance is True

    def test_mal_24_fallback_when_mam_and_mas_miss(self, colliding_ouidb: Path) -> None:
        """MAC 11:22:33:50:00:01 has nibble 5 != 4; falls back to MA-L."""
        res = resolve_device_oui("11:22:33:50:00:01", ouidb_path=colliding_ouidb)
        assert res is not None
        assert res.vendor == "VendorMAL"
        assert res.table == "MA-L"
        assert res.prefix_bits == 24
        assert res.device_type == "none"
        assert res.is_surveillance is False

    def test_unmatched_prefix_returns_none(self, colliding_ouidb: Path) -> None:
        """MAC 11:22:34:00:00:01 misses all tables."""
        res = resolve_device_oui("11:22:34:00:00:01", ouidb_path=colliding_ouidb)
        assert res is None

    def test_timeline_generator_honors_lpm_hierarchy(self, tmp_path: Path, colliding_ouidb: Path) -> None:
        """PcapTimelineReportGenerator with colliding database produces distinct entries."""
        # 3 packets: one hitting MA-S, one hitting MA-M, one hitting MA-L
        # Little-endian wire format:
        pdu_mas = _build_adv_pdu(PDU_TYPE_ADV_IND, "11:22:33:45:67:89")
        pdu_mam = _build_adv_pdu(PDU_TYPE_ADV_IND, "11:22:33:40:00:01")
        pdu_mal = _build_adv_pdu(PDU_TYPE_ADV_IND, "11:22:33:50:00:01")

        pcap = _create_synthetic_pcap(
            tmp_path / "lpm_stream.pcap",
            [(100.0, pdu_mas), (101.0, pdu_mam), (102.0, pdu_mal)],
        )

        report = generate_mac_timeline(str(pcap), str(colliding_ouidb))
        assert report.total_matched_macs == 3
        entries = {e.mac: e for e in report.entries}

        assert entries["11:22:33:45:67:89"].vendor == "VendorMAS"
        assert entries["11:22:33:45:67:89"].table == "MA-S"
        assert entries["11:22:33:45:67:89"].device_category == "drone"

        assert entries["11:22:33:40:00:01"].vendor == "VendorMAM"
        assert entries["11:22:33:40:00:01"].table == "MA-M"
        assert entries["11:22:33:40:00:01"].device_category == "camera"

        assert entries["11:22:33:50:00:01"].vendor == "VendorMAL"
        assert entries["11:22:33:50:00:01"].table == "MA-L"
        assert entries["11:22:33:50:00:01"].device_category == "none"


# ==============================================================================
# Challenge Dimension 3: Endianness, Case Sensitivity & Special MACs
# ==============================================================================


class TestAddressFormattingAndEndianness:
    """Tests address resolution edge cases including palindromic MACs and normalization."""

    def test_palindromic_mac_address(self, tmp_path: Path) -> None:
        """Palindromic MAC reversed byte-order is identical to forward byte-order."""
        # AA:BB:CC:CC:BB:AA -> reversed is AA:BB:CC:CC:BB:AA
        str_pool = b"PalindromicVendor\x00"
        blob = _make_soui_blob(
            mal_entries=[(0xAABBCC, 0, OUI_SURV_CAMERA)],
            str_pool=str_pool,
        )
        db_path = tmp_path / "palindromic.bin"
        db_path.write_bytes(blob)

        res = resolve_device_oui("AA:BB:CC:CC:BB:AA", ouidb_path=db_path)
        assert res is not None
        assert res.vendor == "PalindromicVendor"
        assert res.device_type == "camera"
        assert res.is_surveillance is True

    def test_mixed_case_normalization(self) -> None:
        """Mixed-case input addresses resolve identically to uppercase."""
        mixed_cases = [
            "e4:38:83:d7:a5:b3",
            "E4:38:83:D7:A5:B3",
            "e4:38:83:D7:a5:B3",
            "E4:38:83:d7:A5:b3",
        ]
        for mac in mixed_cases:
            res = resolve_device_oui(mac, ouidb_path=OUIDB_BIN_PATH)
            assert res is not None, f"Failed for {mac}"
            assert res.vendor == "Flock Safety"
            assert res.device_type == "alpr"

    def test_whitespace_and_padding_tolerance(self) -> None:
        """Leading/trailing whitespace or tab characters must be tolerated."""
        padded_macs = [
            "  E4:38:83:D7:A5:B3  ",
            "\tE4:38:83:D7:A5:B3\n",
            "\r\n  E4:38:83:D7:A5:B3  \r\n",
        ]
        for mac in padded_macs:
            res = resolve_device_oui(mac, ouidb_path=OUIDB_BIN_PATH)
            assert res is not None, f"Failed for {mac!r}"
            assert res.vendor == "Flock Safety"

    def test_broadcast_multicast_and_null_macs(self) -> None:
        """Broadcast, multicast, and all-zero addresses must be handled safely without surveillance misclassification."""
        special_macs = [
            "FF:FF:FF:FF:FF:FF",
            "00:00:00:00:00:00",
            "01:00:5E:00:00:01",
            "33:33:00:00:00:01",
            "01:80:C2:00:00:00",
        ]
        for mac in special_macs:
            res = resolve_device_oui(mac, ouidb_path=OUIDB_BIN_PATH)
            if res is not None:
                # If matched (e.g. 00:00:00 Xerox in IEEE DB), must NOT be classified as surveillance
                assert res.is_surveillance is False
                assert res.device_type == "none"

    def test_empty_and_invalid_inputs_return_none(self) -> None:
        """Invalid types and empty strings must return None without exceptions."""
        bad_inputs = ["", "   ", None, "invalid_mac", "00:11", "00:11:22:33:44:55:66"]
        for inp in bad_inputs:
            assert resolve_device_oui(inp, ouidb_path=OUIDB_BIN_PATH) is None


# ==============================================================================
# Challenge Dimension 4: Resource & Memory Scaling Harness (O(1) Streaming)
# ==============================================================================


class TestResourceAndMemoryScaling:
    """Empirical verification that memory remains O(1) during streaming PCAP processing."""

    def test_streaming_memory_scaling_is_constant(self, tmp_path: Path) -> None:
        """Verify that processing 1,000 vs 10,000 vs 50,000 packets does not grow heap memory."""
        macs = [
            "E4:38:83:D7:A5:B3",  # Flock Safety (alpr)
            "0C:9A:E6:37:F6:2D",  # DJI (drone)
            "D0:3F:27:B0:07:6E",  # Wyze (camera)
            "68:9A:87:20:6B:FF",  # Skydio (drone)
        ]
        pdus = [_build_adv_pdu(PDU_TYPE_ADV_IND, m) for m in macs]

        counts = [1_000, 10_000, 50_000]
        peak_memories: dict[int, int] = {}

        for count in counts:
            pcap_path = tmp_path / f"stream_{count}.pcap"
            packets = [(1000.0 + i * 0.01, pdus[i % len(pdus)]) for i in range(count)]
            _create_synthetic_pcap(pcap_path, packets)

            gc.collect()
            tracemalloc.start()

            report = generate_mac_timeline(str(pcap_path), str(OUIDB_BIN_PATH))
            assert report.total_packets_processed == count
            assert len(report.entries) == 4

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peak_memories[count] = peak

        # Print empirical memory results
        print("\nEmpirical Stream Memory Scaling:")
        for count in counts:
            print(f"  {count:,} packets -> peak heap: {peak_memories[count] / 1024:.2f} KB")

        # Memory delta between 10,000 and 50,000 packets should be essentially zero (within 50 KB variance)
        growth_kb = (peak_memories[50_000] - peak_memories[10_000]) / 1024.0
        print(f"Memory growth from 10k to 50k packets: {growth_kb:+.2f} KB")
        assert abs(growth_kb) < 100.0, f"Memory grew unexpectedly with stream size: {growth_kb} KB"

    def test_high_throughput_streaming_benchmark(self, tmp_path: Path) -> None:
        """Benchmark iteration speed (packets/sec) on PCAP timeline extraction."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        count = 25_000
        pcap_path = tmp_path / "benchmark.pcap"
        packets = [(1000.0 + i * 0.001, pdu) for i in range(count)]
        _create_synthetic_pcap(pcap_path, packets)

        t0 = time.perf_counter()
        report = generate_mac_timeline(str(pcap_path), str(OUIDB_BIN_PATH))
        t1 = time.perf_counter()

        elapsed = t1 - t0
        pkt_per_sec = count / elapsed
        print(f"\nThroughput benchmark: {count:,} packets in {elapsed:.3f}s ({pkt_per_sec:,.0f} pkts/sec)")

        assert report.total_packets_processed == count
        assert report.entries[0].packet_count == count
        assert pkt_per_sec > 5_000, f"Throughput too low: {pkt_per_sec:.0f} pkts/sec"


# ==============================================================================
# Challenge Dimension 5: Extreme Timestamps, Sorting & Boundaries
# ==============================================================================


class TestExtremeTimestampsAndOrdering:
    """Validates chronological ordering across timestamp boundaries and arrival orders."""

    def test_out_of_order_packets_sorted_chronologically(self, tmp_path: Path) -> None:
        """Packets written in reverse chronological order must be sorted by first_seen ascending."""
        pdu_flock = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        pdu_dji = _build_adv_pdu(PDU_TYPE_ADV_IND, "0C:9A:E6:37:F6:2D")
        pdu_wyze = _build_adv_pdu(PDU_TYPE_ADV_IND, "D0:3F:27:B0:07:6E")

        # Arrival order in file: t=300 (Wyze), t=200 (DJI), t=100 (Flock)
        packets = [
            (300.0, pdu_wyze),
            (200.0, pdu_dji),
            (100.0, pdu_flock),
        ]
        pcap = _create_synthetic_pcap(tmp_path / "out_of_order.pcap", packets)

        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 3

        # Must be strictly ordered: Flock (100.0), DJI (200.0), Wyze (300.0)
        assert report.entries[0].mac == "E4:38:83:D7:A5:B3"
        assert report.entries[0].first_seen == 100.0

        assert report.entries[1].mac == "0C:9A:E6:37:F6:2D"
        assert report.entries[1].first_seen == 200.0

        assert report.entries[2].mac == "D0:3F:27:B0:07:6E"
        assert report.entries[2].first_seen == 300.0

    def test_multiple_occurrences_update_first_and_last_seen(self, tmp_path: Path) -> None:
        """First packet seen at t=50, second at t=200, third at t=10:
        first_seen must be 10, last_seen must be 200."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        packets = [
            (50.0, pdu),
            (200.0, pdu),
            (10.0, pdu),
        ]
        pcap = _create_synthetic_pcap(tmp_path / "timestamp_updates.pcap", packets)

        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.packet_count == 3
        assert entry.first_seen == 10.0
        assert entry.last_seen == 200.0

    def test_epoch_zero_and_y2038_boundary(self, tmp_path: Path) -> None:
        """Epoch zero (1970-01-01) and year 2038+ timestamps format cleanly to ISO 8601."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")
        # 0.0 -> 1970-01-01T00:00:00+00:00
        # 2147483648.0 -> 2038-01-19T03:14:08+00:00 (past 32-bit signed overflow)
        packets = [
            (0.0, pdu),
            (2147483648.0, pdu),
        ]
        pcap = _create_synthetic_pcap(tmp_path / "extreme_ts.pcap", packets)

        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH))
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.first_seen == 0.0
        assert "1970-01-01" in entry.first_seen_iso
        assert entry.last_seen == 2147483648.0
        assert "2038" in entry.last_seen_iso

    def test_empty_filter_results_yield_valid_reports(self, tmp_path: Path) -> None:
        """Filters with 0 matches still produce well-formed reports across all export formats."""
        pdu = _build_adv_pdu(PDU_TYPE_ADV_IND, "E4:38:83:D7:A5:B3")  # Flock Safety (alpr)
        pcap = _create_synthetic_pcap(tmp_path / "single_flock.pcap", [(100.0, pdu)])

        # Filter for drone (none present)
        report = generate_mac_timeline(str(pcap), str(OUIDB_BIN_PATH), category="drone")
        assert len(report.entries) == 0
        assert report.total_matched_macs == 1
        assert report.total_surveillance_macs == 1

        # Check export formats
        d = report.to_dict()
        assert d["entries"] == []

        j = report.to_json()
        assert '"entries": []' in j

        c = report.to_csv()
        assert "mac,first_seen" in c
        # Only header row
        lines = [line for line in c.splitlines() if line.strip()]
        assert len(lines) == 1

        m = report.to_markdown()
        assert "| # | First Seen" in m

        txt = report.to_text()
        assert "No matching MAC addresses found." in txt
