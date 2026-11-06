"""Chronological BLE PCAP MAC Timeline Report Generator with Spectra Mesh OUI classification.

Processes Bluetooth Low Energy packet captures (DLT 256 / PCAPNG), demuxes Link
Layer advertising channel PDUs across AdvA, ScanA, InitA, and TargetA roles,
resolves addresses against the Spectra Mesh OUI database using longest prefix
matching (/36 -> /28 -> /24), and produces chronologically ordered timeline
reports with capture and database metadata in JSON, CSV, Markdown, and formatted text.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airtell.sniff.dissector import dissect_advertising_pdu
from airtell.sniff.pcap import PcapBleReader
from airtell.sniff.telemetry import (
    canonical_mac,
    get_default_ouidb_path,
    get_ouidb,
)


@dataclass
class PcapTimelineEntry:
    """Chronological observation record of an IEEE OUI-matched MAC in a BLE capture."""

    mac: str
    first_seen: float
    first_seen_iso: str
    last_seen: float
    last_seen_iso: str
    packet_count: int
    packet_types: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    is_random: bool = False
    vendor: str = ""
    prefix: str = ""
    prefix_bits: int = 24
    table: str = ""
    device_category: str = "none"
    flags: int = 0
    is_surveillance: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert timeline entry to structured dictionary."""
        return {
            "mac": self.mac,
            "first_seen": self.first_seen,
            "first_seen_iso": self.first_seen_iso,
            "last_seen": self.last_seen,
            "last_seen_iso": self.last_seen_iso,
            "packet_count": self.packet_count,
            "packet_types": list(self.packet_types),
            "roles": list(self.roles),
            "is_random": self.is_random,
            "vendor": self.vendor,
            "prefix": self.prefix,
            "prefix_bits": self.prefix_bits,
            "table": self.table,
            "device_category": self.device_category,
            "flags": self.flags,
            "is_surveillance": self.is_surveillance,
        }


@dataclass
class PcapTimelineReport:
    """Aggregated timeline report of OUI-matched devices observed in a PCAP capture."""

    pcap_path: str = ""
    ouidb_path: str = ""
    total_packets_processed: int = 0
    total_unique_macs: int = 0
    total_matched_macs: int = 0
    total_surveillance_macs: int = 0
    duration_sec: float = 0.0
    entries: list[PcapTimelineEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to structured dictionary."""
        return {
            "pcap_path": str(self.pcap_path),
            "ouidb_path": str(self.ouidb_path),
            "total_packets_processed": self.total_packets_processed,
            "total_unique_macs": self.total_unique_macs,
            "total_matched_macs": self.total_matched_macs,
            "total_surveillance_macs": self.total_surveillance_macs,
            "duration_sec": self.duration_sec,
            "entries": [e.to_dict() for e in self.entries],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_csv(self) -> str:
        """Serialize report entries to CSV format."""
        output = io.StringIO()
        fieldnames = [
            "mac",
            "first_seen",
            "first_seen_iso",
            "last_seen",
            "last_seen_iso",
            "packet_count",
            "packet_types",
            "roles",
            "is_random",
            "vendor",
            "prefix",
            "prefix_bits",
            "table",
            "device_category",
            "flags",
            "is_surveillance",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for e in self.entries:
            row = e.to_dict()
            row["packet_types"] = ";".join(e.packet_types)
            row["roles"] = ";".join(e.roles)
            writer.writerow(row)
        return output.getvalue()

    def to_markdown(self) -> str:
        """Format report as Markdown summary and table."""
        lines = [
            "# BLE PCAP MAC Timeline Report",
            "",
            f"- **PCAP File**: `{self.pcap_path}`",
            f"- **Spectra Mesh OUI Database**: `{self.ouidb_path}`",
            f"- **Total Packets Processed**: {self.total_packets_processed:,}",
            f"- **Total Unique MACs Observed**: {self.total_unique_macs:,}",
            f"- **Total Matched OUI MACs**: {self.total_matched_macs:,}",
            f"- **Total Surveillance Devices**: {self.total_surveillance_macs:,}",
            f"- **Capture Duration**: {self.duration_sec:.3f}s",
            "",
            "| # | First Seen (UTC) | Last Seen (UTC) | MAC Address | Vendor / Manufacturer | Category | Prefix | Packets | Roles | Surveillance |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for idx, e in enumerate(self.entries, start=1):
            roles_str = ", ".join(e.roles)
            surv_str = "Yes" if e.is_surveillance else "No"
            lines.append(
                f"| {idx} | {e.first_seen_iso} | {e.last_seen_iso} | `{e.mac}` | {e.vendor} | {e.device_category} | {e.prefix} | {e.packet_count:,} | {roles_str} | {surv_str} |"
            )
        lines.append("")
        return "\n".join(lines)

    def to_text(self) -> str:
        """Format report as clean human-readable console text."""
        lines = [
            "=" * 90,
            "BLE PCAP MAC TIMELINE REPORT (SPECTRA MESH OUI INTEGRATION)",
            "=" * 90,
            f"PCAP File:                 {self.pcap_path}",
            f"OUI Database:              {self.ouidb_path}",
            f"Total Packets Processed:   {self.total_packets_processed:,}",
            f"Total Unique MACs:         {self.total_unique_macs:,}",
            f"Matched OUI MACs:          {self.total_matched_macs:,}",
            f"Surveillance MACs:         {self.total_surveillance_macs:,}",
            f"Capture Duration:          {self.duration_sec:.3f}s",
            f"Timeline Entries Output:   {len(self.entries):,}",
            "-" * 90,
        ]
        if not self.entries:
            lines.append("No matching MAC addresses found.")
        else:
            lines.append(
                f"{'#':<4} {'First Seen (UTC)':<24} {'MAC Address':<18} {'Category':<10} {'Packets':<8} {'Roles':<12} {'Vendor (Prefix)'}"
            )
            lines.append("-" * 90)
            for idx, e in enumerate(self.entries, start=1):
                roles_str = ",".join(e.roles)
                lines.append(
                    f"{idx:<4} {e.first_seen_iso[:23]:<24} {e.mac:<18} {e.device_category:<10} {e.packet_count:<8} {roles_str:<12} {e.vendor} ({e.prefix})"
                )
        lines.append("=" * 90)
        return "\n".join(lines)

    def export_json(self, path: str | Path, indent: int = 2) -> None:
        """Export report to a JSON file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json(indent=indent))

    def export_csv(self, path: str | Path) -> None:
        """Export report to a CSV file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(self.to_csv())

    def export_markdown(self, path: str | Path) -> None:
        """Export report to a Markdown file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())

    def export_text(self, path: str | Path) -> None:
        """Export report to a text file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_text())

    def export(self, path: str | Path, format: str = "auto") -> None:
        """Export report to a file, auto-detecting or using explicit format."""
        p = Path(path)
        fmt = format.lower()
        if fmt == "auto":
            ext = p.suffix.lower()
            if ext == ".json":
                fmt = "json"
            elif ext == ".csv":
                fmt = "csv"
            elif ext in (".md", ".markdown"):
                fmt = "markdown"
            else:
                fmt = "text"
        if fmt == "json":
            self.export_json(p)
        elif fmt == "csv":
            self.export_csv(p)
        elif fmt in ("md", "markdown"):
            self.export_markdown(p)
        else:
            self.export_text(p)


class PcapTimelineReportGenerator:
    """Generates chronological MAC timeline reports from BLE PCAP captures."""

    def __init__(
        self,
        pcap_path: str | Path,
        ouidb_path: str | Path | None = None,
    ) -> None:
        self.pcap_path: Path = Path(pcap_path)
        self.ouidb_path: Path = Path(ouidb_path) if ouidb_path else get_default_ouidb_path()
        self._ouidb = get_ouidb(self.ouidb_path)

    def generate(
        self,
        surveillance_only: bool = False,
        category: str | None = None,
        limit: int | None = None,
        max_packets: int | None = None,
        max_entries: int | None = None,
    ) -> PcapTimelineReport:
        """Stream PCAP and extract chronological MAC timeline."""
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        # Resolve limit semantics
        effective_max_packets = max_packets
        effective_max_entries = max_entries
        if limit is not None:
            if effective_max_entries is None:
                effective_max_entries = limit
            if effective_max_packets is None and not (surveillance_only or category):
                effective_max_packets = limit

        total_packets = 0
        min_ts: float | None = None
        max_ts: float | None = None
        unique_macs: set[str] = set()
        matched_records: dict[str, dict[str, Any]] = {}
        lookup_cache: dict[str, tuple[str | None, Any]] = {}

        if (
            (effective_max_packets is not None and effective_max_packets <= 0)
            or (effective_max_entries is not None and effective_max_entries <= 0 and limit is not None and limit <= 0)
            or self.pcap_path.stat().st_size == 0
        ):
            return PcapTimelineReport(
                pcap_path=str(self.pcap_path),
                ouidb_path=str(self.ouidb_path),
                total_packets_processed=0,
                total_unique_macs=0,
                total_matched_macs=0,
                total_surveillance_macs=0,
                duration_sec=0.0,
                entries=[],
            )

        with PcapBleReader(str(self.pcap_path)) as reader:
            try:
                for pkt in reader:
                    total_packets += 1
                    ts = pkt.ts_epoch
                    if min_ts is None or ts < min_ts:
                        min_ts = ts
                    if max_ts is None or ts > max_ts:
                        max_ts = ts

                    try:
                        adv = dissect_advertising_pdu(
                            pkt.body,
                            chan=pkt.ble_chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts_usec,
                        )
                    except Exception:
                        continue

                    # Demux address roles across all advertising channel PDUs
                    candidates: list[tuple[str | None, str, bool]] = [
                        (
                            adv.adv_a,
                            "AdvA",
                            bool(adv.rx_add) if adv.pdu_type in ("SCAN_REQ", "CONNECT_IND") else bool(adv.tx_add),
                        ),
                        (adv.scan_a, "ScanA", bool(adv.tx_add)),
                        (adv.init_a, "InitA", bool(adv.tx_add)),
                        (adv.target_a, "TargetA", bool(adv.rx_add)),
                    ]

                    for wire_mac, role, is_rnd in candidates:
                        if not wire_mac:
                            continue
                        norm_wire = wire_mac.strip().upper()
                        unique_macs.add(norm_wire)

                        if norm_wire not in lookup_cache:
                            # Evaluate canonical reversed MAC first, then wire direct
                            canon = canonical_mac(norm_wire)
                            res_canon = self._ouidb.lookup(canon)
                            res_wire = self._ouidb.lookup(norm_wire)

                            if (
                                res_wire
                                and getattr(res_wire, "is_surveillance", False)
                                and not (res_canon and getattr(res_canon, "is_surveillance", False))
                            ):
                                lookup_cache[norm_wire] = (norm_wire, res_wire)
                            elif res_canon is not None:
                                lookup_cache[norm_wire] = (canon, res_canon)
                            elif res_wire is not None:
                                lookup_cache[norm_wire] = (norm_wire, res_wire)
                            else:
                                lookup_cache[norm_wire] = (None, None)

                        c_mac, res = lookup_cache[norm_wire]
                        if res is not None and c_mac is not None:
                            if c_mac not in matched_records:
                                matched_records[c_mac] = {
                                    "mac": c_mac,
                                    "first_seen": ts,
                                    "last_seen": ts,
                                    "packet_count": 0,
                                    "packet_types": [],
                                    "roles": [],
                                    "is_random": is_rnd,
                                    "vendor": res.vendor,
                                    "prefix": res.prefix_str,
                                    "prefix_bits": res.prefix_bits,
                                    "table": res.table,
                                    "device_category": res.device_type,
                                    "flags": res.flags,
                                    "is_surveillance": bool(res.is_surveillance),
                                }
                            rec = matched_records[c_mac]
                            rec["packet_count"] += 1
                            if ts < rec["first_seen"]:
                                rec["first_seen"] = ts
                            if ts > rec["last_seen"]:
                                rec["last_seen"] = ts
                            pdu_name = adv.pdu_type
                            if pdu_name not in rec["packet_types"]:
                                rec["packet_types"].append(pdu_name)
                            if role not in rec["roles"]:
                                rec["roles"].append(role)

                    if effective_max_packets is not None and total_packets >= effective_max_packets:
                        break
            except (EOFError, ValueError):
                pass

        duration_sec = round(max_ts - min_ts, 3) if (min_ts is not None and max_ts is not None) else 0.0
        total_matched = len(matched_records)
        total_surv = sum(1 for r in matched_records.values() if r["is_surveillance"])

        entries: list[PcapTimelineEntry] = []
        for data in matched_records.values():
            if surveillance_only and not data["is_surveillance"]:
                continue
            if category is not None and data["device_category"].lower() != category.strip().lower():
                continue

            first_iso = datetime.datetime.fromtimestamp(data["first_seen"], tz=datetime.timezone.utc).isoformat()
            last_iso = datetime.datetime.fromtimestamp(data["last_seen"], tz=datetime.timezone.utc).isoformat()

            entries.append(
                PcapTimelineEntry(
                    mac=data["mac"],
                    first_seen=data["first_seen"],
                    first_seen_iso=first_iso,
                    last_seen=data["last_seen"],
                    last_seen_iso=last_iso,
                    packet_count=data["packet_count"],
                    packet_types=data["packet_types"],
                    roles=data["roles"],
                    is_random=data["is_random"],
                    vendor=data["vendor"],
                    prefix=data["prefix"],
                    prefix_bits=data["prefix_bits"],
                    table=data["table"],
                    device_category=data["device_category"],
                    flags=data["flags"],
                    is_surveillance=data["is_surveillance"],
                )
            )

        # Strictly ordered ascending by first_seen (deterministic secondary sort by mac)
        entries.sort(key=lambda e: (e.first_seen, e.mac))

        if effective_max_entries is not None:
            if effective_max_entries <= 0:
                entries = []
            elif len(entries) > effective_max_entries:
                entries = entries[:effective_max_entries]

        return PcapTimelineReport(
            pcap_path=str(self.pcap_path),
            ouidb_path=str(self.ouidb_path),
            total_packets_processed=total_packets,
            total_unique_macs=len(unique_macs),
            total_matched_macs=total_matched,
            total_surveillance_macs=total_surv,
            duration_sec=duration_sec,
            entries=entries,
        )


def generate_mac_timeline(
    pcap_path: str | Path,
    ouidb_path: str | Path | None = None,
    surveillance_only: bool = False,
    category: str | None = None,
    limit: int | None = None,
    max_packets: int | None = None,
    max_entries: int | None = None,
) -> PcapTimelineReport:
    """Convenience function generating chronological PCAP MAC timeline."""
    generator = PcapTimelineReportGenerator(pcap_path=pcap_path, ouidb_path=ouidb_path)
    return generator.generate(
        surveillance_only=surveillance_only,
        category=category,
        limit=limit,
        max_packets=max_packets,
        max_entries=max_entries,
    )
