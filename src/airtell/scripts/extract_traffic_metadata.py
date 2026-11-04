#!/usr/bin/env python3
"""extract_traffic_metadata.py

Forensic metadata extraction and device analysis tool for Bluetooth Low Energy
captures and side-channel reports (AirTell / Bluetooth-Sniffle).

Specifically targets:
  - Findings occurring in the 10:00:00 to 10:05:59 window.
  - Identification and clustering of similar MAC addresses (e.g. :FF:FF suffix,
    repeated OUI prefixes, palindromic addresses).
  - MAC address metadata enrichment: canonical byte ordering, IEEE OUI vendor
    lookups, Bluetooth Core Specification address classification (Public,
    Random Static, RPA, NRPA), U/L and I/G bit states.
  - Correlation with merged.pcap for packet-level EIR/AD metadata (Device Names,
    Bluetooth SIG Company IDs, Service UUIDs, Manufacturer Data).
  - Identification of emergency vehicle preemption (EVP) devices, police mobile
    routers/gateways, traffic cameras, and intersection monitoring sensors.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Ensure local AirTell package is importable
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

try:
    from airtell.protocol.mac import classify_mac_address
    from airtell.sniff.dissector import dissect_packet
    from airtell.sniff.pcap import PcapBleReader
except ImportError as err:
    print(f"Warning: Failed to import native AirTell modules: {err}", file=sys.stderr)


# Database of well-known traffic preemption and public safety manufacturers
TRAFFIC_SECURITY_EQUIPMENT_DATABASE = {
    # Emergency Vehicle Preemption (EVP) & Traffic Control
    "CC:69:B0": {"name": "Global Traffic Technologies (GTT Opticom)", "type": "EVP / Optical & GPS Preemption"},
    "44:C4:A9": {"name": "Opticom Communication, LLC", "type": "Traffic Preemption / Communications"},
    "00:17:D0": {"name": "Opticom Communications, LLC", "type": "Traffic Preemption / Communications"},
    "00:04:81": {"name": "Econolite Control Products, Inc.", "type": "Traffic Controllers & Cabinet Systems"},
    "00:04:CC": {"name": "Peek Traffic B.V.", "type": "Traffic Controllers & Sensors"},
    "44:6D:05": {"name": "NoTraffic", "type": "Autonomous Traffic Management & Intersection AI"},
    "50:0E:6D": {"name": "TrafficCast International", "type": "Bluetooth/Wi-Fi Travel Time & Traffic Sensors"},
    "00:05:97": {"name": "Eagle Traffic Control Systems", "type": "Traffic Signal Controllers"},
    # Intersection Cameras & Video Detection
    "84:F6:FA": {"name": "Miovision Technologies", "type": "Intersection Traffic Cameras & Travel Time AI"},
    "00:14:7B": {"name": "Iteris, Inc.", "type": "Vantage Intersection Video Detection Cameras"},
    "00:1B:D8": {"name": "FLIR Systems Inc.", "type": "TrafiCam / Thermal Intersection Cameras"},
    "00:40:7F": {"name": "FLIR Systems Inc.", "type": "Thermal Traffic Detection Sensors"},
    "00:13:56": {"name": "FLIR Radiation Inc.", "type": "Thermal & Optical Detection"},
    "00:22:9F": {"name": "Sensys Traffic AB", "type": "In-Pavement Wireless Traffic Magnetometers"},
    # Law Enforcement In-Vehicle Gateways & Electronics
    "00:A0:D5": {"name": "Sierra Wireless, ULC", "type": "AirLink Police In-Vehicle Mobile Gateway (MP70/XR90)"},
    "84:DB:2F": {"name": "Sierra Wireless, ULC", "type": "AirLink In-Vehicle LTE/5G Cellular Gateway"},
    "64:CE:6E": {"name": "Sierra Wireless, ULC", "type": "AirLink In-Vehicle Gateway"},
    "CC:93:4A": {"name": "Sierra Wireless, ULC", "type": "AirLink Rugged Gateway"},
    "28:A3:31": {"name": "Sierra Wireless, ULC", "type": "AirLink Gateway"},
    "00:30:44": {"name": "Cradlepoint, Inc.", "type": "IBR900 / R1900 Police Interceptor Router"},
    "00:E0:1C": {"name": "Cradlepoint, Inc.", "type": "Public Safety In-Vehicle Router"},
    "00:25:DF": {"name": "Taser International / Axon", "type": "Axon Fleet In-Car Video & Bodycam Trigger"},
    "00:58:28": {"name": "Axon Networks Inc.", "type": "Public Safety Wireless Infrastructure"},
}

# Known Bluetooth SIG Company Identifiers for relevant platforms
BLUETOOTH_SIG_COMPANIES = {
    76: "Apple, Inc.",
    87: "Garmin International, Inc.",
    117: "Samsung Electronics Co., Ltd.",
    529: "Telink Semiconductor Co. Ltd.",
    1744: "Espressif Systems (Shanghai) Co., Ltd.",
    2168: "The Chamberlain Group, Inc. (MyQ Access)",
    2128: "Yealink (Xiamen) Network Technology Co., Ltd.",
    9474: "Murata Manufacturing Co., Ltd.",
    19527: "Espressif Systems",
}


def load_ieee_oui_database() -> dict[str, str]:
    """Loads IEEE OUI (MA-L, MA-M, MA-S) database from system ieee-data directory."""
    oui_db: dict[str, str] = {}
    paths = [
        "/usr/share/ieee-data/oui.csv",
        "/usr/share/ieee-data/mam.csv",
        "/usr/share/ieee-data/oui36.csv",
    ]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p, mode="r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3 and row[1]:
                            assignment = row[1].strip().upper()
                            org = row[2].strip()
                            oui_db[assignment] = org
            except Exception as e:
                print(f"Warning loading {p}: {e}", file=sys.stderr)
    return oui_db


def canonical_mac(mac: str) -> str:
    """Converts BLE wire little-endian MAC into canonical IEEE 802 big-endian MAC."""
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(reversed(parts))
    return mac


def get_mac_metadata(mac: str, oui_db: dict[str, str]) -> dict[str, Any]:
    """Extracts all possible mathematical, protocol, and vendor metadata from a MAC."""
    parts = mac.split(":")
    if len(parts) != 6:
        return {"error": "Invalid MAC length"}

    raw_wire = bytes.fromhex(mac.replace(":", ""))
    canon_str = canonical_mac(mac)
    raw_canon = bytes.fromhex(canon_str.replace(":", ""))

    # Wire classification
    wire_type = "Unknown"
    canon_type = "Unknown"
    try:
        wire_type = classify_mac_address(mac)
        canon_type = classify_mac_address(canon_str)
    except Exception:
        pass

    # IEEE OUI resolution
    # In BLE little-endian wire transmission, canonical MAC (reversed) has the standard OUI at bytes 0..2.
    oui_canon_hex = canon_str.replace(":", "")[:6].upper()
    oui_wire_hex = mac.replace(":", "")[:6].upper()

    vendor_canon = oui_db.get(oui_canon_hex)
    vendor_wire = oui_db.get(oui_wire_hex)

    # Check 28-bit and 36-bit OUIs
    oui_canon_7 = canon_str.replace(":", "")[:7].upper()
    oui_canon_9 = canon_str.replace(":", "")[:9].upper()
    if not vendor_canon:
        vendor_canon = oui_db.get(oui_canon_7) or oui_db.get(oui_canon_9)

    vendor = vendor_canon or vendor_wire
    vendor_orientation = "Canonical (Reversed wire)" if vendor_canon else ("Wire direct" if vendor_wire else "None")

    # IEEE 802 Bitfield analysis on canonical MSB (raw_canon[0]):
    # Bit 0: Individual (0) / Group (1) [Unicast vs Multicast]
    # Bit 1: Universally Administered (0) / Locally Administered (1) [U/L bit]
    ig_bit = raw_canon[0] & 0x01
    ul_bit = (raw_canon[0] >> 1) & 0x01
    ig_str = "Group (Multicast)" if ig_bit else "Individual (Unicast)"
    ul_str = "Locally Administered (Private/Random)" if ul_bit else "Universally Administered (OUI Enforced)"

    # Check if MAC matches traffic/security device database
    traffic_match = None
    canon_prefix_3 = ":".join(canon_str.split(":")[:3]).upper()
    if canon_prefix_3 in TRAFFIC_SECURITY_EQUIPMENT_DATABASE:
        traffic_match = TRAFFIC_SECURITY_EQUIPMENT_DATABASE[canon_prefix_3]

    # Palindromic check (endianness-invariant)
    is_palindromic = (
        raw_wire[0] == raw_wire[5]
        and raw_wire[1] == raw_wire[4]
        and raw_wire[2] == raw_wire[3]
    )

    return {
        "mac_wire": mac.upper(),
        "mac_canonical": canon_str.upper(),
        "is_palindromic": is_palindromic,
        "classification": {
            "wire_order_type": wire_type,
            "canonical_order_type": canon_type,
            "address_space": ul_str,
            "cast_type": ig_str,
            "ul_bit": ul_bit,
            "ig_bit": ig_bit,
        },
        "vendor": {
            "organization": vendor,
            "resolved_via": vendor_orientation,
            "oui_canonical": f"{canon_prefix_3} ({oui_canon_hex})",
            "traffic_preemption_match": traffic_match,
        },
    }


def extract_pcap_correlations(
    pcap_path: str, t_start: float, t_end: float, target_macs: set[str]
) -> dict[str, dict[str, Any]]:
    """Extracts packet-level advertising payload data from pcap for target MACs."""
    correlations: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "names": set(),
            "company_ids": set(),
            "service_uuids": set(),
            "pdu_types": Counter(),
            "packet_count": 0,
            "min_rssi": 999,
            "max_rssi": -999,
        }
    )

    if not os.path.exists(pcap_path):
        return correlations

    try:
        with PcapBleReader(pcap_path) as reader:
            for pkt in reader:
                if pkt.ts_epoch < t_start:
                    continue
                if pkt.ts_epoch > t_end:
                    break
                frame = dissect_packet(pkt)
                for addr in [frame.adv_a, frame.scan_a]:
                    if addr and addr.upper() in target_macs:
                        c = correlations[addr.upper()]
                        c["packet_count"] += 1
                        c["pdu_types"][frame.pdu_type] += 1
                        if pkt.rssi is not None:
                            c["min_rssi"] = min(c["min_rssi"], pkt.rssi)
                            c["max_rssi"] = max(c["max_rssi"], pkt.rssi)
                        name = frame.complete_local_name or frame.shortened_local_name
                        if name:
                            c["names"].add(name)
                        for m in frame.manufacturer_data:
                            c["company_ids"].add(m.company_id)
                        for u in frame.service_uuids_16:
                            c["service_uuids"].add(f"0x{u:04X}")
    except Exception as e:
        print(f"Warning during pcap correlation: {e}", file=sys.stderr)

    return correlations


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and forensic-analyze findings and MAC metadata from merged.json."
    )
    parser.add_argument(
        "-i", "--input", default=str(REPO_ROOT / "merged.json"), help="Path to merged.json"
    )
    parser.add_argument(
        "-p", "--pcap", default=str(REPO_ROOT / "app/data/merged.pcap"), help="Path to merged.pcap"
    )
    parser.add_argument(
        "-o", "--output", default=None, help="Path to output JSON result file"
    )
    parser.add_argument(
        "--start-time", default="2026-05-21 10:00:00", help="Window start (YYYY-MM-DD HH:MM:SS)"
    )
    parser.add_argument(
        "--end-time", default="2026-05-21 10:05:59.999999", help="Window end (YYYY-MM-DD HH:MM:SS)"
    )
    parser.add_argument(
        "--pattern",
        default=None,
        help="Optional regex or substring to filter MACs (e.g. ':FF:FF')",
    )
    args = parser.parse_args()

    # Time conversion
    t_start = datetime.datetime.fromisoformat(args.start_time).timestamp()
    t_end = datetime.datetime.fromisoformat(args.end_time).timestamp()

    print(f"[*] Loading merged.json from: {args.input}")
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_findings = data.get("findings", [])
    print(f"[*] Total findings in dataset: {len(all_findings)}")

    # Filter window
    window_findings = [
        f for f in all_findings if t_start <= f.get("timestamp", 0) <= t_end
    ]
    if args.pattern is not None:
        pat_re = re.compile(args.pattern, re.IGNORECASE)
        window_findings = [
            f
            for f in window_findings
            if pat_re.search(str(f.get("device_addr") or ""))
            or pat_re.search(str(f.get("target_addr") or ""))
        ]
    print(f"[*] Findings in window [{args.start_time} - {args.end_time}]: {len(window_findings)}")

    # Collect unique MAC addresses
    unique_macs: set[str] = set()
    for f in window_findings:
        if f.get("device_addr"):
            mac_val = f["device_addr"].upper()
            if args.pattern is None or re.search(args.pattern, mac_val, re.IGNORECASE):
                unique_macs.add(mac_val)
        if f.get("target_addr"):
            mac_val = f["target_addr"].upper()
            if args.pattern is None or re.search(args.pattern, mac_val, re.IGNORECASE):
                unique_macs.add(mac_val)

    print(f"[*] Unique MAC addresses in window: {len(unique_macs)}")

    # Load IEEE OUI database
    oui_db = load_ieee_oui_database()
    print(f"[*] Loaded {len(oui_db)} IEEE OUI records.")

    # Correlate with PCAP
    print(f"[*] Correlating with PCAP payload telemetry: {args.pcap}...")
    pcap_corr = extract_pcap_correlations(args.pcap, t_start, t_end, unique_macs)

    # Process every entry and acquire metadata for each MAC
    mac_metadata_table: dict[str, Any] = {}
    for mac in unique_macs:
        meta = get_mac_metadata(mac, oui_db)
        # Enrich with pcap telemetry
        if mac in pcap_corr:
            pc = pcap_corr[mac]
            meta["pcap_telemetry"] = {
                "packet_count": pc["packet_count"],
                "observed_names": sorted(list(pc["names"])),
                "company_ids": [
                    {"id": cid, "name": BLUETOOTH_SIG_COMPANIES.get(cid, "Unknown")}
                    for cid in sorted(list(pc["company_ids"]))
                ],
                "service_uuids": sorted(list(pc["service_uuids"])),
                "pdu_types": dict(pc["pdu_types"]),
                "rssi_range": [pc["min_rssi"], pc["max_rssi"]] if pc["min_rssi"] <= pc["max_rssi"] else None,
            }
        else:
            meta["pcap_telemetry"] = None

        mac_metadata_table[mac] = meta

    # Identify "looks similar" clusters
    # 1. :FF:FF suffix cluster (Telink BLE Mesh / sequential hardware nodes)
    # 2. :3B:7D:00 suffix cluster
    # 3. :16:68:3C suffix cluster (VXi)
    # 4. :5A:D1:58 suffix cluster (TI)
    # 5. :69:34:94 suffix cluster (Silicon Labs)
    # 6. Repetitive scanner clusters
    suffix_groups: dict[str, list[str]] = defaultdict(list)
    for mac in unique_macs:
        suf = ":".join(mac.split(":")[-2:])
        suffix_groups[suf].append(mac)

    similar_clusters = {
        suf: macs for suf, macs in suffix_groups.items() if len(macs) > 1
    }

    # Identify potential security / traffic preemption / municipal devices
    traffic_and_security_devices = []
    for mac, meta in mac_metadata_table.items():
        vendor_org = meta["vendor"]["organization"] or ""
        pcap_data = meta["pcap_telemetry"] or {}
        names = pcap_data.get("observed_names", [])
        cids = [c["id"] for c in pcap_data.get("company_ids", [])]

        is_suspicious_or_security = False
        reasons = []

        # Check vendor
        for kw in ["Traffic", "Signal", "Opticom", "Iteris", "Miovision", "FLIR", "Sensys", "Sierra", "Cradlepoint", "Axon", "Taser", "Econolite"]:
            if kw.lower() in vendor_org.lower():
                is_suspicious_or_security = True
                reasons.append(f"OUI matched traffic/public-safety keyword '{kw}': {vendor_org}")

        # Check known traffic devices
        if meta["vendor"]["traffic_preemption_match"]:
            is_suspicious_or_security = True
            reasons.append(f"Preemption DB Match: {meta['vendor']['traffic_preemption_match']}")

        # Check in-car public safety / vehicle diagnostics / communications names
        for name in names:
            if any(term in name.upper() for term in ["FIXD", "TELEMATIC", "JCI", "SENA", "LEGEND", "RADAR", "COP", "POLICE", "TRANSIT", "BUS", "PREEMPT", "OPTICOM"]):
                is_suspicious_or_security = True
                reasons.append(f"Observed device name indicates vehicle/security/telematics: '{name}'")

        # Check Telink Mesh cluster (:FF:FF)
        if mac.endswith(":FF:FF") or 529 in cids:
            is_suspicious_or_security = True
            reasons.append("Telink Semiconductor BLE Mesh node with static :FF:FF broadcast pattern and sequential numeric identifier")

        if is_suspicious_or_security:
            traffic_and_security_devices.append({
                "mac": mac,
                "canonical_mac": meta["mac_canonical"],
                "vendor": vendor_org,
                "reasons": reasons,
                "telemetry": pcap_data,
                "classification": meta["classification"],
            })

    # Prepare enriched findings list
    enriched_findings = []
    for f in window_findings:
        f_copy = dict(f)
        dt = datetime.datetime.fromtimestamp(f["timestamp"])
        f_copy["datetime_local"] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        f_copy["device_metadata"] = mac_metadata_table.get((f.get("device_addr") or "").upper())
        f_copy["target_metadata"] = mac_metadata_table.get((f.get("target_addr") or "").upper())
        enriched_findings.append(f_copy)

    # Output structure
    report = {
        "analysis_metadata": {
            "window_start": args.start_time,
            "window_end": args.end_time,
            "total_findings_processed": len(enriched_findings),
            "total_unique_macs": len(unique_macs),
            "total_vendor_identified_macs": len([m for m in mac_metadata_table.values() if m["vendor"]["organization"]]),
            "similar_mac_clusters_count": len(similar_clusters),
        },
        "similar_mac_clusters": similar_clusters,
        "traffic_security_and_law_enforcement_evaluation": {
            "identified_candidates_count": len(traffic_and_security_devices),
            "candidates": traffic_and_security_devices,
        },
        "mac_metadata_table": mac_metadata_table,
        "findings": enriched_findings,
    }

    # Summary output
    print("\n" + "=" * 78)
    print("ANALYSIS SUMMARY & DEVICE FORENSIC AUDIT (10:00 - 10:05)")
    print("=" * 78)
    print(f"Processed Findings:              {len(enriched_findings)}")
    print(f"Unique MAC Addresses Evaluated:  {len(unique_macs)}")
    print(f"Vendor-Identified MAC Addresses: {report['analysis_metadata']['total_vendor_identified_macs']}")
    print(f"Clusters Looking Similar:        {len(similar_clusters)} suffix groups")
    print(f"Potential Security/Traffic Units:{len(traffic_and_security_devices)}")
    print("-" * 78)

    print("\n[+] SIMILAR MAC CLUSTERS (MACs sharing patterns/suffixes):")
    for suf, macs in sorted(similar_clusters.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  * Suffix '..:{suf}' ({len(macs)} devices): {macs}")

    print("\n[+] SECURITY / LAW ENFORCEMENT / TRAFFIC PREEMPTION CANDIDATES:")
    for cand in traffic_and_security_devices:
        print(f"  * MAC: {cand['mac']} (Canon: {cand['canonical_mac']})")
        print(f"    Vendor: {cand['vendor'] or 'Unknown (Random Address)'}")
        print(f"    Reasons: {'; '.join(cand['reasons'])}")
        if cand['telemetry'].get('observed_names'):
            print(f"    Broadcast Names: {cand['telemetry']['observed_names']}")
        print()

    # Save to file if writable
    out_file = (
        Path(args.output).resolve()
        if args.output
        else (REPO_ROOT / "extracted_traffic_metadata_1000_1005.json").resolve()
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Complete JSON export written to: {out_file}")


if __name__ == "__main__":
    main()
