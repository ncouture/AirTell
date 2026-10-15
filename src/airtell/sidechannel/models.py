"""Data structures, enumerations, and base analyzer contracts for BLE side-channel detection.

Defines standardized packet records, finding objects, verdict classifications, and
the abstract analyzer interface across live streaming, offline PCAP, and synthetic modes.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from airtell.protocol.wire import PHY_1M, PacketMessage
from airtell.sniff.pcap import BLE_ADV_AA, CapturedBlePacket


class SideChannelType(str, Enum):
    """Enumeration of recognized exclusive-use side-channel mechanisms."""

    DIFFERENTIAL_ENCRYPTION = "differential_encryption"
    CSRK_COUNTER = "csrk_counter"
    BAT_ALLOWLIST = "bat_allowlist"


class Verdict(str, Enum):
    """Classification verdicts emitted by side-channel analyzers."""

    # General verdicts
    CONFIRMED_EXCLUSIVE = "CONFIRMED_EXCLUSIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NORMAL_BEHAVIOR = "NORMAL_BEHAVIOR"

    # Differential Encryption verdicts
    PAIRED_SHARED_LTK = "PAIRED_SHARED_LTK"
    REJECTED_UNTRUSTED = "REJECTED_UNTRUSTED"
    UNPAIRED_KEY_REJECTED = "UNPAIRED_KEY_REJECTED"

    # CSRK Counter verdicts
    SEQUENTIAL_MONOTONIC = "SEQUENTIAL_MONOTONIC"
    ANOMALY_REPLAY = "ANOMALY_REPLAY"
    ANOMALY_ROLLBACK = "ANOMALY_ROLLBACK"
    ANOMALY_JUMP = "ANOMALY_JUMP"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CROSS_RPA_LINKED = "CROSS_RPA_LINKED"

    # BAT Allowlist verdicts
    ALLOWLIST_CONFIRMED = "ALLOWLIST_CONFIRMED"
    OPEN_ADVERTISER = "OPEN_ADVERTISER"
    DIRECTED_EXCLUSIVE = "DIRECTED_EXCLUSIVE"
    PROFILE_MATCH = "PROFILE_MATCH"


@dataclass
class BlePacketRecord:
    """Unified representation of a BLE packet across PCAP, live UART, and synthetic sources.

    Attributes:
        body: Raw Link-Layer PDU bytes (2-byte header + payload).
        channel: BLE logical channel index (0-39).
        rssi: Received signal strength in dBm.
        timestamp_usec: Microsecond timestamp.
        access_address: 32-bit Access Address.
        direction: Packet direction (0: Central->Peripheral, 1: Peripheral->Central).
        crc_err: Whether the CRC failed.
        phy: PHY mode (0 = 1M, 1 = 2M, 2/3 = Coded).
        pdu_type: Pseudo-header PDU type override (0: adv, 2: slave->master, 3: master->slave).
    """

    body: bytes
    channel: int
    rssi: int
    timestamp_usec: int
    access_address: int = BLE_ADV_AA
    direction: int = 0
    crc_err: bool = False
    phy: int = PHY_1M
    pdu_type: int | None = None

    @property
    def timestamp(self) -> float:
        """Timestamp in fractional seconds."""
        return self.timestamp_usec / 1_000_000.0

    @classmethod
    def from_packet_message(cls, pkt: PacketMessage) -> BlePacketRecord:
        """Construct record from a Sniffle live wire PacketMessage."""
        return cls(
            body=pkt.body,
            channel=pkt.chan,
            rssi=pkt.rssi,
            timestamp_usec=pkt.ts,
            direction=pkt.pkt_dir,
            crc_err=pkt.crc_err,
            phy=pkt.phy,
        )

    @classmethod
    def from_captured_ble_packet(cls, pkt: CapturedBlePacket) -> BlePacketRecord:
        """Construct record from a DLT 256 CapturedBlePacket read from PCAP."""
        # In DLT 256 flags / pdu_type:
        # 2 = Data Channel PDU from Master/Central to Slave/Peripheral (dir=0)
        # 3 = Data Channel PDU from Slave/Peripheral to Master/Central (dir=1)
        direction = 1 if pkt.pdu_type == 3 else 0
        usec = (pkt.ts_sec * 1_000_000) + pkt.ts_usec
        return cls(
            body=pkt.body,
            channel=pkt.ble_chan,
            rssi=pkt.rssi,
            timestamp_usec=usec,
            access_address=pkt.aa,
            direction=direction,
            crc_err=pkt.crc_err,
            phy=pkt.phy,
            pdu_type=pkt.pdu_type,
        )

    @classmethod
    def coerce(cls, pkt: Any) -> BlePacketRecord:
        """Coerce an arbitrary packet object into BlePacketRecord."""
        if isinstance(pkt, cls):
            return pkt
        if isinstance(pkt, PacketMessage):
            return cls.from_packet_message(pkt)
        if isinstance(pkt, CapturedBlePacket):
            return cls.from_captured_ble_packet(pkt)
        if hasattr(pkt, "body") and hasattr(pkt, "ts_usec"):
            # SyntheticEvent duck-type
            return cls(
                body=pkt.body,
                channel=getattr(pkt, "chan", 37),
                rssi=getattr(pkt, "rssi", -60),
                timestamp_usec=pkt.ts_usec,
                access_address=getattr(pkt, "aa", BLE_ADV_AA),
                direction=getattr(pkt, "direction", 0),
                crc_err=getattr(pkt, "crc_err", False),
                phy=getattr(pkt, "phy", PHY_1M),
                pdu_type=getattr(pkt, "pdu_type", None),
            )
        raise TypeError(f"Cannot coerce object of type {type(pkt).__name__} to BlePacketRecord")


@dataclass
class SideChannelFinding:
    """Represents a specific observation or anomaly detected by a side-channel analyzer.

    Attributes:
        finding_type: Identifier of the side-channel mechanism (e.g. 'differential_encryption').
        timestamp: Microsecond-precision epoch timestamp of the finding.
        device_addr: Subject device address (MAC or RPA) associated with the finding.
        target_addr: Optional peer address (e.g. initiator or companion).
        verdict: Specific classification verdict string or Verdict enum.
        confidence: Confidence score between 0.0 and 1.0.
        details: Arbitrary analyzer-specific telemetry and contextual key-values.
    """

    finding_type: str
    timestamp: float
    device_addr: str
    target_addr: str | None = None
    verdict: str = Verdict.INCONCLUSIVE.value
    confidence: float = 0.5
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard dictionary representation."""
        res = asdict(self)
        if isinstance(self.verdict, Enum):
            res["verdict"] = self.verdict.value
        if isinstance(self.finding_type, Enum):
            res["finding_type"] = self.finding_type.value
        return res

    def to_json(self, indent: int | None = None) -> str:
        """Serialize finding to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class EncryptionInitiationFinding(SideChannelFinding):
    """Specialized finding for Link-Layer Differential Encryption Initiation analysis."""

    def __post_init__(self) -> None:
        if not self.finding_type:
            self.finding_type = SideChannelType.DIFFERENTIAL_ENCRYPTION.value


@dataclass
class CsrkCounterFinding(SideChannelFinding):
    """Specialized finding for CSRK 32-bit SignCounter monotonicity and integrity analysis."""

    def __post_init__(self) -> None:
        if not self.finding_type:
            self.finding_type = SideChannelType.CSRK_COUNTER.value


@dataclass
class BatAllowlistFinding(SideChannelFinding):
    """Specialized finding for Bluetooth Address Tracking (BAT) allowlist analysis."""

    def __post_init__(self) -> None:
        if not self.finding_type:
            self.finding_type = SideChannelType.BAT_ALLOWLIST.value


@dataclass
class AnalyzerReport:
    """Aggregated final report emitted by a side-channel analyzer.

    Attributes:
        analyzer_name: Name of the analyzer that produced the report.
        verdict: Overall verdict across all evaluated packets.
        summary: Human-readable narrative explaining the verdict.
        findings: List of individual discrete findings generated during analysis.
        metrics: Numeric telemetry and counters (e.g. packet counts, anomalies).
    """

    analyzer_name: str
    verdict: str
    summary: str
    findings: list[SideChannelFinding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to serializable dictionary."""
        return {
            "analyzer_name": self.analyzer_name,
            "verdict": self.verdict.value if isinstance(self.verdict, Enum) else self.verdict,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": dict(self.metrics),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class SideChannelAnalyzer(ABC):
    """Abstract base class for Link-Layer side-channel protocol analyzers."""

    @abstractmethod
    def process_packet(self, packet: BlePacketRecord | Any) -> list[SideChannelFinding]:
        """Process a single packet and return any newly triggered findings.

        Args:
            packet: BlePacketRecord or compatible packet object.

        Returns:
            List of findings generated from this packet (may be empty).
        """
        raise NotImplementedError

    @abstractmethod
    def finalize(self) -> AnalyzerReport:
        """Finalize the session analysis and produce a comprehensive report.

        Returns:
            AnalyzerReport summarizing observations, metrics, and overall verdict.
        """
        raise NotImplementedError

    def reset(self) -> None:
        """Reset internal tracking state for a new session."""
        pass
