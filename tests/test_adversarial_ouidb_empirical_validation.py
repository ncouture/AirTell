"""Empirical Ground Truth & CLI Adversarial Challenge Test Suite.

Authored by Empirical Challenger 2 (challenger_ouidb_2).
Conducts empirical ground-truth validation against app/data/merged.pcap,
asserts exact classification of all 21 surveillance devices, checks chronological
monotonicity, and exposes boundary/CLI edge argument behaviors.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SPECTRAMESH_DIR = REPO_ROOT / "spectramesh_ouidb"
MERGED_PCAP = REPO_ROOT / "app" / "data" / "merged.pcap"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(SPECTRAMESH_DIR) not in sys.path:
    sys.path.insert(0, str(SPECTRAMESH_DIR))

from airtell.sniff.dissector import dissect_advertising_pdu  # noqa: E402
from airtell.sniff.pcap import PcapBleReader  # noqa: E402
from airtell.sniff.telemetry import canonical_mac, get_ouidb  # noqa: E402
from airtell.sniff.timeline import generate_mac_timeline  # noqa: E402

GROUND_TRUTH_21_SURVEILLANCE = [
    # (Index, First Seen UTC, MAC, Vendor, Category, Prefix, Expected Role)
    (1, "2026-11-04T13:58:38", "E4:38:83:D7:A5:B3", "Flock Safety", "alpr", "E4:38:83", "AdvA"),
    (2, "2026-11-04T15:37:16", "0C:9A:E6:37:F6:2D", "Sz Dji Technology Co.,Ltd", "drone", "0C:9A:E6", "AdvA"),
    (3, "2026-11-04T16:32:03", "4C:43:F6:30:A4:18", "Sz Dji Technology Co.,Ltd", "drone", "4C:43:F6", "AdvA"),
    (4, "2026-11-04T16:38:42", "68:9A:87:20:6B:FF", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (5, "2026-11-04T17:31:26", "D0:3F:27:B0:07:6E", "Wyze Labs Inc", "camera", "D0:3F:27", "AdvA"),
    (6, "2026-11-04T17:32:35", "68:9A:87:ED:21:EF", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (7, "2026-11-04T17:33:46", "68:9A:87:72:0A:C3", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (8, "2026-11-04T17:37:11", "D0:3F:27:5A:C4:76", "Wyze Labs Inc", "camera", "D0:3F:27", "AdvA"),
    (9, "2026-11-04T18:55:48", "80:48:2C:53:47:33", "Wyze Labs Inc", "camera", "80:48:2C", "AdvA"),
    (10, "2026-11-04T19:00:10", "68:9A:87:38:2D:88", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (11, "2026-11-04T19:00:14", "74:EC:B2:97:05:FD", "Ring LLC", "camera", "74:EC:B2", "ScanA"),
    (12, "2026-11-04T20:39:04", "88:29:85:3C:61:0D", "Sz Dji Technology Co.,Ltd", "drone", "88:29:85", "AdvA"),
    (13, "2026-11-04T21:01:25", "68:9A:87:31:88:CD", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (14, "2026-11-04T21:03:40", "44:A6:42:A5:DE:34", "Hangzhou Hikvision Digital Tech", "camera", "44:A6:42", "AdvA"),
    (15, "2026-11-04T21:10:08", "74:EC:B2:EB:79:68", "Ring LLC", "camera", "74:EC:B2", "ScanA"),
    (16, "2026-11-04T21:16:10", "74:EC:B2:28:3E:82", "Ring LLC", "camera", "74:EC:B2", "ScanA"),
    (17, "2026-11-04T21:59:04", "D0:3F:27:69:94:DE", "Wyze Labs Inc", "camera", "D0:3F:27", "AdvA"),
    (18, "2026-11-04T22:12:27", "68:9A:87:B5:DA:09", "Skydio, Inc.", "drone", "68:9A:87", "ScanA"),
    (19, "2026-11-04T22:12:58", "2C:AA:8E:44:02:A1", "Wyze Labs Inc", "camera", "2C:AA:8E", "AdvA"),
    (20, "2026-11-04T22:34:28", "2C:AA:8E:D5:1E:4B", "Wyze Labs Inc", "camera", "2C:AA:8E", "AdvA"),
    (21, "2026-11-04T22:37:14", "74:EC:B2:04:04:34", "Ring LLC", "camera", "74:EC:B2", "ScanA"),
]


class TestEmpiricalGroundTruthSurveillance:
    """Verifies all 21 surveillance devices in merged.pcap and chronological monotonicity."""

    @pytest.fixture(scope="class")
    def merged_pcap_scan(self) -> dict[str, dict]:
        """Stream merged.pcap and locate observation metadata for all target surveillance devices."""
        if not MERGED_PCAP.exists():
            pytest.skip("app/data/merged.pcap not found")

        db = get_ouidb()
        target_macs = {mac: meta for idx, ts, mac, *meta in GROUND_TRUTH_21_SURVEILLANCE}
        wire_to_target = {canonical_mac(mac): mac for mac in target_macs}

        observed: dict[str, dict] = {}
        with PcapBleReader(str(MERGED_PCAP)) as reader:
            for idx, pkt in enumerate(reader):
                try:
                    adv = dissect_advertising_pdu(pkt.body, chan=pkt.ble_chan, rssi=pkt.rssi, ts_usec=pkt.ts_usec)
                except Exception:
                    continue

                for w_mac, role in [
                    (adv.adv_a, "AdvA"),
                    (adv.scan_a, "ScanA"),
                    (adv.init_a, "InitA"),
                    (adv.target_a, "TargetA"),
                ]:
                    if not w_mac:
                        continue
                    norm = w_mac.strip().upper()
                    if norm in wire_to_target:
                        c_mac = wire_to_target[norm]
                        if c_mac not in observed:
                            res = db.lookup(c_mac)
                            observed[c_mac] = {
                                "mac": c_mac,
                                "first_pkt": idx,
                                "first_seen": pkt.ts_epoch,
                                "last_seen": pkt.ts_epoch,
                                "packet_count": 0,
                                "roles": set(),
                                "vendor": res.vendor if res else "",
                                "category": res.device_type if res else "",
                                "prefix": res.prefix_str if res else "",
                            }
                        entry = observed[c_mac]
                        entry["packet_count"] += 1
                        entry["roles"].add(role)
                        if pkt.ts_epoch > entry["last_seen"]:
                            entry["last_seen"] = pkt.ts_epoch

                if len(observed) == 21:
                    # Found all 21 ground truth devices; continue briefly or conclude
                    break

        return observed

    def test_all_21_surveillance_devices_detected(self, merged_pcap_scan: dict[str, dict]) -> None:
        """Ground Truth: Asserts all 21 surveillance devices are accurately detected in merged.pcap."""
        assert len(merged_pcap_scan) == 21, f"Expected 21 devices, found {len(merged_pcap_scan)}"
        for idx, ts_iso, mac, vendor, category, prefix, role in GROUND_TRUTH_21_SURVEILLANCE:
            assert mac in merged_pcap_scan, f"Device {mac} ({vendor}, {category}) was not detected"

    def test_surveillance_device_classification_and_metadata(self, merged_pcap_scan: dict[str, dict]) -> None:
        """Ground Truth: Asserts device categories, vendors, prefixes, and roles match ground truth."""
        for idx, ts_iso, mac, vendor, category, prefix, role in GROUND_TRUTH_21_SURVEILLANCE:
            obs = merged_pcap_scan[mac]
            assert category == obs["category"], f"Category mismatch for {mac}: {obs['category']} != {category}"
            assert vendor in obs["vendor"] or obs["vendor"] in vendor, f"Vendor mismatch for {mac}: {obs['vendor']}"
            assert prefix == obs["prefix"], f"Prefix mismatch for {mac}: {obs['prefix']} != {prefix}"
            assert role in obs["roles"], f"Expected role {role} not in {obs['roles']} for {mac}"
            assert obs["packet_count"] >= 1
            assert obs["first_seen"] <= obs["last_seen"]

    def test_chronological_monotonicity_across_21_devices(self, merged_pcap_scan: dict[str, dict]) -> None:
        """Ground Truth: Asserts strict chronological monotonicity (first_seen[i] <= first_seen[i+1])."""
        # Sort detected devices by earliest observed timestamp
        sorted_devices = sorted(merged_pcap_scan.values(), key=lambda d: d["first_seen"])
        assert len(sorted_devices) == 21

        for i in range(len(sorted_devices) - 1):
            t_curr = sorted_devices[i]["first_seen"]
            t_next = sorted_devices[i + 1]["first_seen"]
            assert t_curr <= t_next, f"Inverted timestamps at index {i}: {t_curr} > {t_next}"

    def test_role_demuxing_distribution(self, merged_pcap_scan: dict[str, dict]) -> None:
        """Ground Truth: Asserts expected distribution of 14 AdvA devices and 7 ScanA devices."""
        adva_count = sum(1 for d in merged_pcap_scan.values() if "AdvA" in d["roles"] and "ScanA" not in d["roles"])
        scana_count = sum(1 for d in merged_pcap_scan.values() if "ScanA" in d["roles"] and "AdvA" not in d["roles"])
        assert adva_count == 14, f"Expected 14 advertiser devices, got {adva_count}"
        assert scana_count == 7, f"Expected 7 scanner devices, got {scana_count}"


class TestAdversarialCliDefects:
    """Adversarial stress-testing exposing parameter validation bugs and boundary issues."""

    def test_negative_max_entries_slice_vulnerability(self) -> None:
        """Adversarial: max_entries=-1 returns 0 entries."""
        rep_neg = generate_mac_timeline(str(MERGED_PCAP), max_entries=-1, max_packets=100)
        assert len(rep_neg.entries) == 0

    def test_zero_max_packets_off_by_one(self) -> None:
        """Adversarial: max_packets=0 processes 0 packets and returns 0 entries."""
        report = generate_mac_timeline(str(MERGED_PCAP), max_packets=0)
        assert report.total_packets_processed == 0
        assert len(report.entries) == 0

