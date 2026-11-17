"""IDBLEED Bluetooth Link-Layer Side-Channel Verification Specification.

Provides offline protocol state evaluators, bounds-checked Link-Layer and Attribute Protocol
(ATT) PDU serializers/deserializers, cryptographic CSRK signature verification, and
multi-window Resolvable Private Address (RPA) correlation auditing for BLE privacy
leakage detection and defensive stack verification.
"""

from __future__ import annotations

import enum
import hmac
import struct
import time
import unittest
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

from airtell.sidechannel.ll_dissector import dissect_advertising_pdu
from airtell.sidechannel.models import (
    AnalyzerReport,
    BlePacketRecord,
    SideChannelAnalyzer,
    SideChannelFinding,
    Verdict,
)
from airtell.sniff.pcap import BLE_ADV_AA

L2CAP_CID_ATT: int = 0x0004
FINDING_TYPE_IDBLEED: str = "idbleed_verification"


class OracleResult(enum.Enum):
    """Classification outcome emitted by Link-Layer and GATT privacy leak evaluators."""

    UNPAIRED = 0
    PAIRED = 1
    INDETERMINATE = 2


class LLOpcode(enum.IntEnum):
    """Bluetooth Low Energy Link-Layer Control PDU opcodes (Core Spec Vol 6, Part B, §2.4.2)."""

    LL_CONNECTION_UPDATE_IND = 0x00
    LL_CHANNEL_MAP_IND = 0x01
    LL_TERMINATE_IND = 0x02
    LL_ENC_REQ = 0x03
    LL_ENC_RSP = 0x04
    LL_START_ENC_REQ = 0x05
    LL_START_ENC_RSP = 0x06
    LL_REJECT_IND = 0x0D
    LL_SLAVE_FEATURE_REQ = 0x0E
    LL_CONNECTION_PARAM_REQ = 0x0F
    LL_CONNECTION_PARAM_RSP = 0x10
    LL_REJECT_EXT_IND = 0x11
    LL_PING_REQ = 0x12
    LL_PING_RSP = 0x13
    LL_LENGTH_REQ = 0x14
    LL_LENGTH_RSP = 0x15
    LL_PHY_REQ = 0x16
    LL_PHY_RSP = 0x17
    LL_PHY_UPDATE_IND = 0x18
    LL_MIN_USED_CHANNELS_IND = 0x19


class ATTOpcode(enum.IntEnum):
    """Bluetooth Low Energy Attribute Protocol (ATT) opcodes (Core Spec Vol 3, Part F, §3.4)."""

    ATT_ERROR_RSP = 0x01
    ATT_EXCHANGE_MTU_REQ = 0x02
    ATT_EXCHANGE_MTU_RSP = 0x03
    ATT_FIND_INFO_REQ = 0x04
    ATT_FIND_INFO_RSP = 0x05
    ATT_READ_BY_TYPE_REQ = 0x08
    ATT_READ_BY_TYPE_RSP = 0x09
    ATT_READ_REQ = 0x0A
    ATT_READ_RSP = 0x0B
    ATT_WRITE_REQ = 0x12
    ATT_WRITE_RSP = 0x13
    ATT_WRITE_CMD = 0x52
    ATT_SIGNED_WRITE_CMD = 0xD2
    ATT_HANDLE_VALUE_NOTI = 0x1B


@dataclass
class BLEFrame:
    """Normalized BLE protocol frame representation for offline side-channel verification.

    Attributes:
        timestamp: Capture or simulation timestamp in fractional seconds.
        channel: BLE logical channel index (0-39).
        rssi: Received signal strength indicator in dBm.
        source_mac: Transmitter MAC or Resolvable Private Address string.
        dest_mac: Receiver MAC or Resolvable Private Address string.
        pdu_type: Logical protocol layer label (e.g. 'LL_CONTROL', 'ATT', 'LL_DATA').
        payload: Inner protocol PDU bytes starting with opcode (or empty bytes).
        crc_valid: Whether Link-Layer CRC check succeeded.
    """

    timestamp: float
    channel: int
    rssi: int
    source_mac: str
    dest_mac: str
    pdu_type: str
    payload: bytes
    crc_valid: bool = True


@dataclass
class LLEncryptionReqPayload:
    """Structured representation of a Link-Layer LL_ENC_REQ (0x03) control PDU.

    Attributes:
        rand: 8-byte random vector (Rand).
        ediv: 16-bit unsigned little-endian Encrypted Diversifier (EDIV).
        skd_c: 8-byte Central Session Key Diversifier (SKD_m / SKD_c).
        iv_c: 4-byte Central Initialization Vector (IV_m / IV_c).
    """

    rand: bytes
    ediv: int
    skd_c: bytes
    iv_c: bytes

    def serialize(self) -> bytes:
        """Serialize LL_ENC_REQ fields into a 23-byte wire payload.

        Returns:
            23-byte LL_ENC_REQ PDU starting with opcode 0x03.

        Raises:
            ValueError: If any field violates Bluetooth Core Spec byte length or integer bounds.
        """
        if len(self.rand) != 8:
            raise ValueError(f"LL_ENC_REQ rand must be 8 bytes, got {len(self.rand)}")
        if not (0 <= self.ediv <= 0xFFFF):
            raise ValueError(f"LL_ENC_REQ ediv must be uint16 (0..0xFFFF), got {self.ediv}")
        if len(self.skd_c) != 8:
            raise ValueError(f"LL_ENC_REQ skd_c must be 8 bytes, got {len(self.skd_c)}")
        if len(self.iv_c) != 4:
            raise ValueError(f"LL_ENC_REQ iv_c must be 4 bytes, got {len(self.iv_c)}")

        return struct.pack(
            "<B8sH8s4s",
            int(LLOpcode.LL_ENC_REQ),
            self.rand,
            self.ediv,
            self.skd_c,
            self.iv_c,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> LLEncryptionReqPayload:
        """Bounds-checked deserialization of a 23-byte LL_ENC_REQ PDU.

        Args:
            data: Raw LL Control PDU bytes starting with opcode 0x03.

        Returns:
            Parsed LLEncryptionReqPayload instance.

        Raises:
            ValueError: If data is shorter than 23 bytes or opcode is not LL_ENC_REQ.
        """
        if len(data) < 23:
            raise ValueError(f"LL_ENC_REQ requires at least 23 bytes, got {len(data)}")
        if data[0] != LLOpcode.LL_ENC_REQ:
            raise ValueError(f"Expected LL_ENC_REQ opcode 0x03, got 0x{data[0]:02X}")

        _, rand, ediv, skd_c, iv_c = struct.unpack("<B8sH8s4s", data[:23])
        return cls(rand=rand, ediv=ediv, skd_c=skd_c, iv_c=iv_c)


def compute_csrk_cmac(
    csrk: bytes,
    handle: int,
    value: bytes,
    signature_counter: int,
) -> bytes:
    """Compute 8-byte truncated AES-CMAC authentication signature per Core Spec Vol 3 Part H §2.4.5.

    Args:
        csrk: 16-byte (128-bit) Connection Signature Resolving Key.
        handle: 16-bit unsigned little-endian ATT attribute handle.
        value: Variable-length ATT attribute value payload.
        signature_counter: 32-bit unsigned little-endian monotonic SignCounter.

    Returns:
        8-byte (64-bit) truncated AES-CMAC tag.

    Raises:
        ValueError: If CSRK length is not 16 bytes or integer fields are out of bounds.
    """
    if len(csrk) != 16:
        raise ValueError(f"CSRK must be 16 bytes (128 bits), got {len(csrk)}")
    if not (0 <= handle <= 0xFFFF):
        raise ValueError(f"Attribute handle must be uint16 (0..0xFFFF), got {handle}")
    if not (0 <= signature_counter <= 0xFFFFFFFF):
        raise ValueError(f"Signature counter must be uint32 (0..0xFFFFFFFF), got {signature_counter}")

    message = (
        struct.pack("<BH", int(ATTOpcode.ATT_SIGNED_WRITE_CMD), handle) + value + struct.pack("<I", signature_counter)
    )
    signer = CMAC(algorithms.AES(csrk))
    signer.update(message)
    return signer.finalize()[:8]


@dataclass
class ATTSignedWritePayload:
    """Structured representation of an ATT_SIGNED_WRITE_CMD (0xD2) PDU for signature auditing.

    Attributes:
        handle: 16-bit unsigned little-endian attribute handle.
        value: Characteristic value payload bytes.
        signature_counter: 32-bit unsigned little-endian monotonic SignCounter.
        cmac: 8-byte truncated AES-CMAC authentication tag.
    """

    handle: int
    value: bytes
    signature_counter: int
    cmac: bytes

    compute_csrk_cmac = staticmethod(compute_csrk_cmac)

    def serialize(self) -> bytes:
        """Serialize ATT_SIGNED_WRITE_CMD into wire format (15 + len(value) bytes).

        Returns:
            Serialized ATT PDU bytes starting with opcode 0xD2.

        Raises:
            ValueError: If handle, signature_counter, or cmac violates bounds.
        """
        if not (0 <= self.handle <= 0xFFFF):
            raise ValueError(f"Attribute handle must be uint16 (0..0xFFFF), got {self.handle}")
        if not (0 <= self.signature_counter <= 0xFFFFFFFF):
            raise ValueError(f"Signature counter must be uint32 (0..0xFFFFFFFF), got {self.signature_counter}")
        if len(self.cmac) != 8:
            raise ValueError(f"Truncated AES-CMAC must be 8 bytes, got {len(self.cmac)}")

        return (
            struct.pack("<BH", int(ATTOpcode.ATT_SIGNED_WRITE_CMD), self.handle)
            + self.value
            + struct.pack("<I", self.signature_counter)
            + self.cmac
        )

    @classmethod
    def deserialize(cls, data: bytes) -> ATTSignedWritePayload:
        """Bounds-checked deserialization of an ATT_SIGNED_WRITE_CMD (0xD2) PDU.

        Args:
            data: Raw ATT PDU bytes (minimum 15 bytes: 1B opcode + 2B handle + 4B counter + 8B CMAC).

        Returns:
            Parsed ATTSignedWritePayload instance.

        Raises:
            ValueError: If data is shorter than 15 bytes or opcode is not 0xD2.
        """
        if len(data) < 15:
            raise ValueError(f"ATT_SIGNED_WRITE_CMD requires at least 15 bytes, got {len(data)}")
        if data[0] != ATTOpcode.ATT_SIGNED_WRITE_CMD:
            raise ValueError(f"Expected ATT_SIGNED_WRITE_CMD opcode 0xD2, got 0x{data[0]:02X}")

        handle = struct.unpack("<H", data[1:3])[0]
        value = data[3:-12]
        signature_counter = struct.unpack("<I", data[-12:-8])[0]
        cmac_tag = data[-8:]
        return cls(
            handle=handle,
            value=value,
            signature_counter=signature_counter,
            cmac=cmac_tag,
        )

    def verify_cmac(self, csrk: bytes) -> bool:
        """Cryptographically verify the 8-byte truncated AES-CMAC against a 16-byte CSRK.

        Args:
            csrk: 16-byte Connection Signature Resolving Key.

        Returns:
            True if the constant-time CMAC comparison matches, False otherwise.

        Raises:
            ValueError: If csrk is not 16 bytes.
        """
        if len(self.cmac) != 8:
            return False
        expected = compute_csrk_cmac(
            csrk=csrk,
            handle=self.handle,
            value=self.value,
            signature_counter=self.signature_counter,
        )
        return hmac.compare_digest(self.cmac, expected)


class LLEncryptionOracleEvaluator:
    """Audits BLE Link-Layer encryption handshakes for differential LTK state leakage."""

    def __init__(self, target_mac: str, timeout_seconds: float = 2.0) -> None:
        """Initialize evaluator for a specific peripheral or peer MAC address.

        Args:
            target_mac: Target device MAC or RPA address to audit.
            timeout_seconds: Maximum allowed handshake duration before timeout.
        """
        self.target_mac: str = target_mac.upper()
        self.timeout_seconds: float = timeout_seconds
        self.start_time: float = 0.0
        self.state: str = "IDLE"
        self.last_enc_req: LLEncryptionReqPayload | None = None
        self._handshake_active: bool = False

    def reset(self) -> None:
        """Reset handshake tracking state for a new audit session."""
        self.start_time = 0.0
        self.state = "IDLE"
        self.last_enc_req = None
        self._handshake_active = False

    def process_frame(self, frame: BLEFrame) -> tuple[OracleResult, str]:
        """Evaluate a single Link-Layer frame for differential encryption side-channel leakage.

        Args:
            frame: Captured or synthesized BLEFrame.

        Returns:
            Tuple of (OracleResult classification, diagnostic explanation string).
        """
        if not frame.crc_valid:
            return (OracleResult.INDETERMINATE, "Invalid CRC: frame ignored")

        if self.target_mac not in (frame.source_mac.upper(), frame.dest_mac.upper()):
            return (OracleResult.INDETERMINATE, "MAC address mismatch")

        pdu = frame.payload
        if not pdu:
            return (OracleResult.INDETERMINATE, "Empty PDU")

        if (self.start_time > 0.0 or self._handshake_active) and (
            frame.timestamp - self.start_time
        ) > self.timeout_seconds:
            self.reset()
            return (OracleResult.INDETERMINATE, "Encryption handshake timeout exceeded")

        opcode = pdu[0]

        if opcode == LLOpcode.LL_ENC_REQ:
            if len(pdu) < 23:
                return (OracleResult.INDETERMINATE, "Truncated LL_ENC_REQ payload")
            self.last_enc_req = LLEncryptionReqPayload.deserialize(pdu)
            self.start_time = frame.timestamp
            self._handshake_active = True
            self.state = "ENC_REQ_SENT"
            return (OracleResult.INDETERMINATE, "Observed LL_ENC_REQ: Handshake initiated")

        if opcode == LLOpcode.LL_ENC_RSP:
            if not self._handshake_active and self.start_time == 0.0:
                self.start_time = frame.timestamp
                self._handshake_active = True
            self.state = "ENC_RSP_RECEIVED"
            return (OracleResult.INDETERMINATE, "Observed LL_ENC_RSP: Session diversifier exchanged")

        if opcode == LLOpcode.LL_START_ENC_REQ:
            self.state = "START_ENC_REQ_SENT"
            return (OracleResult.INDETERMINATE, "Observed LL_START_ENC_REQ: Awaiting confirmation")

        if opcode == LLOpcode.LL_START_ENC_RSP:
            self.state = "ENCRYPTED"
            self._handshake_active = False
            return (OracleResult.PAIRED, "Observed LL_START_ENC_RSP: Matching LTK verified")

        if opcode in (LLOpcode.LL_REJECT_IND, LLOpcode.LL_REJECT_EXT_IND):
            self.state = "REJECTED"
            self._handshake_active = False
            return (OracleResult.UNPAIRED, f"Observed rejection opcode 0x{opcode:02X}: Missing LTK")

        if opcode == LLOpcode.LL_TERMINATE_IND:
            self.state = "TERMINATED"
            self._handshake_active = False
            return (OracleResult.UNPAIRED, "Connection terminated during encryption handshake")

        return (OracleResult.INDETERMINATE, f"Unrelated Link-Layer opcode 0x{opcode:02X}")


class CSRKSigningOracleEvaluator:
    """Audits ATT Signed Write (0xD2) acknowledgement behavior and SignCounter monotonicity."""

    def __init__(self, target_mac: str, csrk: bytes | None = None) -> None:
        """Initialize CSRK signing oracle evaluator.

        Args:
            target_mac: Target peripheral MAC or RPA address to audit.
            csrk: Optional 16-byte CSRK for local AES-CMAC signature verification.
        """
        if csrk is not None and len(csrk) != 16:
            raise ValueError(f"CSRK must be 16 bytes, got {len(csrk)}")
        self.target_mac: str = target_mac.upper()
        self.csrk: bytes | None = csrk
        self.last_counter: int | None = None

    def reset(self) -> None:
        """Reset monotonic counter tracking state."""
        self.last_counter = None

    def evaluate_signature_response(
        self,
        request_frame: BLEFrame,
        response_frame: BLEFrame,
    ) -> tuple[OracleResult, str]:
        """Evaluate a signed write request/response pair for CSRK verification leakage.

        Args:
            request_frame: Outbound ATT_SIGNED_WRITE_CMD frame directed to target.
            response_frame: Subsequent response or Link-Layer event frame from target.

        Returns:
            Tuple of (OracleResult classification, diagnostic explanation string).
        """
        if not request_frame.crc_valid or not response_frame.crc_valid:
            return (OracleResult.INDETERMINATE, "Invalid CRC in request or response frame")

        req_involves_target = self.target_mac in (
            request_frame.source_mac.upper(),
            request_frame.dest_mac.upper(),
        )
        rsp_involves_target = self.target_mac in (
            response_frame.source_mac.upper(),
            response_frame.dest_mac.upper(),
        )
        if not req_involves_target or not rsp_involves_target:
            return (OracleResult.INDETERMINATE, "MAC address mismatch")

        req_pdu = request_frame.payload
        if not req_pdu or req_pdu[0] != ATTOpcode.ATT_SIGNED_WRITE_CMD:
            return (OracleResult.INDETERMINATE, "Request PDU is not ATT_SIGNED_WRITE_CMD")

        if len(req_pdu) < 15:
            return (OracleResult.INDETERMINATE, "Truncated ATT_SIGNED_WRITE_CMD payload")

        parsed_req = ATTSignedWritePayload.deserialize(req_pdu)
        counter = parsed_req.signature_counter

        if self.csrk is not None and not parsed_req.verify_cmac(self.csrk):
            return (OracleResult.UNPAIRED, "Invalid CSRK AES-CMAC signature")

        if self.last_counter is not None and counter <= self.last_counter:
            return (
                OracleResult.UNPAIRED,
                f"SignCounter replay or rollback rejected ({counter} <= {self.last_counter})",
            )

        rsp_pdu = response_frame.payload
        if not rsp_pdu:
            return (OracleResult.UNPAIRED, "Empty response PDU: silent signature drop")

        rsp_opcode = rsp_pdu[0]
        if rsp_opcode == LLOpcode.LL_TERMINATE_IND:
            return (OracleResult.UNPAIRED, "Connection terminated on CSRK verification failure")

        if len(rsp_pdu) >= 5 and rsp_opcode == ATTOpcode.ATT_ERROR_RSP and rsp_pdu[1] == ATTOpcode.ATT_SIGNED_WRITE_CMD:
            return (OracleResult.UNPAIRED, "ATT_ERROR_RSP rejected signed write")

        if response_frame.source_mac.upper() != self.target_mac:
            return (OracleResult.INDETERMINATE, "Response did not originate from target MAC")

        self.last_counter = counter
        return (OracleResult.PAIRED, "Data signature verified via CSRK ACK")


class AppAuthOracleEvaluator:
    """Audits application-layer GATT challenge-response authentication state leakage."""

    def __init__(self, target_mac: str, auth_handle: int = 0xFFF1) -> None:
        """Initialize GATT application authentication state machine evaluator.

        Args:
            target_mac: Target peripheral MAC or RPA address to audit.
            auth_handle: 16-bit GATT characteristic handle used for auth token submission.
        """
        self.target_mac: str = target_mac.upper()
        self.auth_handle: int = auth_handle
        self.state: str = "AWAITING_SERVICE_DISCOVERY"

    def reset(self) -> None:
        """Reset GATT authentication workflow state."""
        self.state = "AWAITING_SERVICE_DISCOVERY"

    def process_att_frame(self, frame: BLEFrame) -> tuple[OracleResult, str]:
        """Process an ATT or Link-Layer control frame with strict per-opcode bounds checks.

        Args:
            frame: Captured or synthesized BLEFrame in the GATT session.

        Returns:
            Tuple of (OracleResult classification, diagnostic explanation string).
        """
        if not frame.crc_valid:
            return (OracleResult.INDETERMINATE, "Invalid CRC: frame ignored")

        if self.target_mac not in (frame.source_mac.upper(), frame.dest_mac.upper()):
            return (OracleResult.INDETERMINATE, "MAC address mismatch")

        pdu = frame.payload
        if not pdu:
            if self.state in ("AWAITING_AUTH_WRITE", "AUTH_SUBMITTED"):
                return (OracleResult.UNPAIRED, "Empty PDU during active GATT authentication")
            return (OracleResult.INDETERMINATE, "Empty PDU")

        opcode = pdu[0]

        # Guarded check for LL_TERMINATE_IND (1-2 bytes, or non-ATT control PDU)
        if opcode == LLOpcode.LL_TERMINATE_IND and (len(pdu) <= 2 or frame.pdu_type.upper() != "ATT"):
            self.state = "TERMINATED"
            return (OracleResult.UNPAIRED, "Connection terminated prior to GATT auth completion")

        if opcode == ATTOpcode.ATT_ERROR_RSP:
            self.state = "REJECTED"
            return (OracleResult.UNPAIRED, "GATT authentication rejected via ATT_ERROR_RSP")

        if opcode in (
            ATTOpcode.ATT_READ_RSP,
            ATTOpcode.ATT_READ_BY_TYPE_RSP,
            ATTOpcode.ATT_FIND_INFO_RSP,
        ):
            if self.state == "AWAITING_SERVICE_DISCOVERY":
                self.state = "AWAITING_AUTH_WRITE"
            return (OracleResult.INDETERMINATE, "GATT service discovery response observed")

        if opcode in (ATTOpcode.ATT_WRITE_CMD, ATTOpcode.ATT_WRITE_REQ):
            if len(pdu) < 3:
                return (OracleResult.INDETERMINATE, "Truncated ATT write PDU")
            handle = struct.unpack("<H", pdu[1:3])[0]
            if handle == self.auth_handle:
                self.state = "AUTH_SUBMITTED"
                return (OracleResult.INDETERMINATE, f"Auth token submitted to 0x{handle:04X}")
            return (OracleResult.INDETERMINATE, f"ATT write to non-auth handle 0x{handle:04X}")

        if opcode == ATTOpcode.ATT_HANDLE_VALUE_NOTI:
            if len(pdu) < 3:
                return (OracleResult.INDETERMINATE, "Truncated ATT_HANDLE_VALUE_NOTI PDU")
            handle = struct.unpack("<H", pdu[1:3])[0]
            noti_value = pdu[3:]
            if self.state == "AUTH_SUBMITTED":
                if noti_value.upper() in (b"ERR", b"ERROR", b"FAIL", b"DENIED"):
                    self.state = "REJECTED"
                    return (OracleResult.UNPAIRED, "GATT Auth rejected via error notification")
                self.state = "AUTHENTICATED"
                return (OracleResult.PAIRED, "GATT Auth succeeded: NOTIFY(OK) received")
            return (
                OracleResult.INDETERMINATE,
                f"Notification on 0x{handle:04X} outside AUTH_SUBMITTED state",
            )

        return (OracleResult.INDETERMINATE, f"Unhandled ATT/LL opcode 0x{opcode:02X}")


@dataclass
class IdentityRecord:
    """Correlated identity record mapping rotating RPAs to a canonical audit identifier.

    Attributes:
        canonical_id: Stable identifier representing a single tracked hardware entity.
        observed_rpas: Ordered list of distinct RPAs linked to this identity.
        last_seen: Most recent correlation timestamp in seconds.
    """

    canonical_id: str
    observed_rpas: list[str] = field(default_factory=list)
    last_seen: float = 0.0


class ActiveRelayProbeOrchestrator:
    """Models multi-window RPA correlation across BLE rotation intervals (~15 minutes)."""

    def __init__(
        self,
        canonical_target_id: str,
        rpa_rotation_window_sec: float = 900.0,
    ) -> None:
        """Initialize multi-window RPA privacy audit orchestrator.

        Args:
            canonical_target_id: Canonical label for the audited target session.
            rpa_rotation_window_sec: Expected BLE RPA rotation interval in seconds (default 900s).

        Raises:
            ValueError: If rpa_rotation_window_sec is not strictly positive.
        """
        if rpa_rotation_window_sec <= 0.0:
            raise ValueError(f"rpa_rotation_window_sec must be > 0, got {rpa_rotation_window_sec}")
        self.canonical_target_id: str = canonical_target_id
        self.rpa_rotation_window_sec: float = rpa_rotation_window_sec
        self.identity_record: IdentityRecord = IdentityRecord(
            canonical_id=canonical_target_id,
            observed_rpas=[],
            last_seen=0.0,
        )
        self.rotation_intervals: list[float] = []
        self._rpa_observations: list[tuple[str, float]] = []
        self.probe_count: int = 0

    def relay_probe_frame(self, captured_frame: BLEFrame, target_rpa: str) -> BLEFrame:
        """Construct an offline audit frame retargeted to a candidate rotating RPA.

        Args:
            captured_frame: Reference protocol frame from an earlier observation window.
            target_rpa: Candidate Resolvable Private Address under evaluation.

        Returns:
            New BLEFrame retargeted to target_rpa for evaluator simulation.
        """
        self.probe_count += 1
        return BLEFrame(
            timestamp=captured_frame.timestamp,
            channel=captured_frame.channel,
            rssi=captured_frame.rssi,
            source_mac=captured_frame.source_mac,
            dest_mac=target_rpa,
            pdu_type=captured_frame.pdu_type,
            payload=captured_frame.payload,
            crc_valid=captured_frame.crc_valid,
        )

    def evaluate_and_correlate(
        self,
        target_rpa: str,
        oracle_result: OracleResult,
        timestamp: float | None = None,
    ) -> bool:
        """Record correlation outcome and track cross-window RPA rotation intervals.

        Args:
            target_rpa: Candidate RPA evaluated by a side-channel oracle.
            oracle_result: Outcome returned by the side-channel evaluator.
            timestamp: Optional observation timestamp in seconds (defaults to current clock).

        Returns:
            True if target_rpa was confirmed PAIRED and correlated, False otherwise.
        """
        if oracle_result != OracleResult.PAIRED:
            return False

        obs_ts = float(timestamp) if timestamp is not None else time.time()
        already_seen = any(existing.upper() == target_rpa.upper() for existing in self.identity_record.observed_rpas)

        if not already_seen:
            if self._rpa_observations and obs_ts >= self.identity_record.last_seen:
                self.rotation_intervals.append(obs_ts - self.identity_record.last_seen)
            self.identity_record.observed_rpas.append(target_rpa)
            self._rpa_observations.append((target_rpa, obs_ts))

        if obs_ts >= self.identity_record.last_seen:
            self.identity_record.last_seen = obs_ts

        return True

    def correlation_summary(self) -> dict[str, Any]:
        """Summarize multi-window RPA linkability across Delta_RPA (~15 min) boundaries.

        Returns:
            Dictionary containing correlated RPA counts, intervals, and privacy leak status.
        """
        mean_interval = sum(self.rotation_intervals) / len(self.rotation_intervals) if self.rotation_intervals else 0.0
        tolerance = self.rpa_rotation_window_sec * 0.25
        aligned_rotations = sum(
            1 for dt in self.rotation_intervals if abs(dt - self.rpa_rotation_window_sec) <= tolerance
        )
        return {
            "canonical_id": self.canonical_target_id,
            "correlated_rpa_count": len(self.identity_record.observed_rpas),
            "observed_rpas": list(self.identity_record.observed_rpas),
            "rotation_intervals": list(self.rotation_intervals),
            "mean_rotation_interval_sec": mean_interval,
            "rpa_rotation_window_sec": self.rpa_rotation_window_sec,
            "aligned_15min_transitions": aligned_rotations,
            "last_seen": self.identity_record.last_seen,
            "privacy_leak_detected": len(self.identity_record.observed_rpas) > 1,
        }


def ble_packet_record_to_frame(
    record: BlePacketRecord,
    source_mac: str | None = None,
    dest_mac: str | None = None,
) -> BLEFrame:
    """Convert an AirTell BlePacketRecord into a normalized BLEFrame for specification auditing.

    Args:
        record: AirTell BlePacketRecord (or compatible packet object).
        source_mac: Optional resolved transmitter MAC address for data-channel packets.
        dest_mac: Optional resolved receiver MAC address for data-channel packets.

    Returns:
        Normalized BLEFrame with extracted inner LL Control or ATT PDU payload.
    """
    coerced = BlePacketRecord.coerce(record)
    crc_valid = not coerced.crc_err
    ts = coerced.timestamp

    if coerced.access_address == BLE_ADV_AA or coerced.channel >= 37:
        adv = dissect_advertising_pdu(coerced.body)
        if adv is None:
            return BLEFrame(
                timestamp=ts,
                channel=coerced.channel,
                rssi=coerced.rssi,
                source_mac=source_mac or "00:00:00:00:00:00",
                dest_mac=dest_mac or "FF:FF:FF:FF:FF:FF",
                pdu_type="MALFORMED",
                payload=b"",
                crc_valid=crc_valid,
            )

        if adv.pdu_type == 0x05:  # CONNECT_IND
            src = source_mac or adv.init_a or "00:00:00:00:00:00"
            dst = dest_mac or adv.adv_a or "FF:FF:FF:FF:FF:FF"
            inner = coerced.body[2:]
        elif adv.pdu_type == 0x03:  # SCAN_REQ
            src = source_mac or adv.scan_a or "00:00:00:00:00:00"
            dst = dest_mac or adv.adv_a or "FF:FF:FF:FF:FF:FF"
            inner = coerced.body[2:]
        elif adv.pdu_type == 0x01:  # ADV_DIRECT_IND
            src = source_mac or adv.adv_a or "00:00:00:00:00:00"
            dst = dest_mac or adv.target_a or "FF:FF:FF:FF:FF:FF"
            inner = coerced.body[2:]
        else:
            src = source_mac or adv.adv_a or "00:00:00:00:00:00"
            dst = dest_mac or "FF:FF:FF:FF:FF:FF"
            inner = adv.data

        return BLEFrame(
            timestamp=ts,
            channel=coerced.channel,
            rssi=coerced.rssi,
            source_mac=src,
            dest_mac=dst,
            pdu_type=adv.pdu_name,
            payload=inner,
            crc_valid=crc_valid,
        )

    central_default = f"CENTRAL_{coerced.access_address:08X}"
    periph_default = f"PERIPH_{coerced.access_address:08X}"
    src = source_mac or (central_default if coerced.direction == 0 else periph_default)
    dst = dest_mac or (periph_default if coerced.direction == 0 else central_default)

    raw = coerced.body
    if len(raw) < 2:
        return BLEFrame(
            timestamp=ts,
            channel=coerced.channel,
            rssi=coerced.rssi,
            source_mac=src,
            dest_mac=dst,
            pdu_type="MALFORMED",
            payload=b"",
            crc_valid=crc_valid,
        )

    llid = raw[0] & 0x03
    length = raw[1]
    ll_payload = raw[2 : 2 + length] if len(raw) >= 2 + length else raw[2:]

    if llid == 0b11:
        pdu_type = "LL_CONTROL"
        inner_payload = ll_payload
    elif llid == 0b10:
        if len(ll_payload) >= 4:
            l2cap_len, cid = struct.unpack("<HH", ll_payload[0:4])
            l2cap_body = ll_payload[4 : 4 + l2cap_len] if len(ll_payload) >= 4 + l2cap_len else ll_payload[4:]
            pdu_type = "ATT" if cid == L2CAP_CID_ATT else "L2CAP"
            inner_payload = l2cap_body
        else:
            pdu_type = "L2CAP_TRUNCATED"
            inner_payload = ll_payload
    else:
        if not ll_payload:
            pdu_type = "LL_EMPTY"
            inner_payload = b""
        else:
            pdu_type = "LL_DATA"
            inner_payload = ll_payload

    return BLEFrame(
        timestamp=ts,
        channel=coerced.channel,
        rssi=coerced.rssi,
        source_mac=src,
        dest_mac=dst,
        pdu_type=pdu_type,
        payload=inner_payload,
        crc_valid=crc_valid,
    )


class IdbleedVerificationAnalyzer(SideChannelAnalyzer):
    """AirTell SideChannelAnalyzer adapter auditing BlePacketRecord streams with IDBLEED oracles."""

    def __init__(
        self,
        target_mac: str | None = None,
        auth_handle: int = 0xFFF1,
        timeout_seconds: float = 2.0,
        csrk: bytes | None = None,
        rpa_rotation_window_sec: float = 900.0,
    ) -> None:
        """Initialize the stream-compatible IDBLEED side-channel verification analyzer.

        Args:
            target_mac: Optional peripheral/central MAC address filter.
            auth_handle: GATT characteristic handle audited for application auth workflows.
            timeout_seconds: Link-Layer encryption handshake timeout threshold.
            csrk: Optional 16-byte CSRK for cryptographic ATT signed write verification.
            rpa_rotation_window_sec: Expected RPA rotation interval for identity correlation.
        """
        self.target_mac: str | None = target_mac.upper() if target_mac else None
        self.auth_handle: int = auth_handle
        self.timeout_seconds: float = timeout_seconds
        self.csrk: bytes | None = csrk
        self.rpa_rotation_window_sec: float = rpa_rotation_window_sec

        self._conn_map: dict[int, tuple[str, str]] = {}
        self._ll_evaluators: dict[int, LLEncryptionOracleEvaluator] = {}
        self._csrk_evaluators: dict[str, CSRKSigningOracleEvaluator] = {}
        self._app_evaluators: dict[int, AppAuthOracleEvaluator] = {}
        self._pending_signed_req: dict[int, BLEFrame] = {}
        self._orchestrator: ActiveRelayProbeOrchestrator = ActiveRelayProbeOrchestrator(
            canonical_target_id=self.target_mac or "SESSION_TARGET",
            rpa_rotation_window_sec=rpa_rotation_window_sec,
        )
        self._findings: list[SideChannelFinding] = []
        self._packets_processed: int = 0
        self._paired_count: int = 0
        self._unpaired_count: int = 0

    def reset(self) -> None:
        """Reset all per-connection evaluators and accumulated telemetry."""
        self._conn_map.clear()
        self._ll_evaluators.clear()
        self._csrk_evaluators.clear()
        self._app_evaluators.clear()
        self._pending_signed_req.clear()
        self._orchestrator = ActiveRelayProbeOrchestrator(
            canonical_target_id=self.target_mac or "SESSION_TARGET",
            rpa_rotation_window_sec=self.rpa_rotation_window_sec,
        )
        self._findings.clear()
        self._packets_processed = 0
        self._paired_count = 0
        self._unpaired_count = 0

    def _emit_finding(
        self,
        timestamp: float,
        periph_addr: str,
        central_addr: str,
        evaluator_name: str,
        result: OracleResult,
        reason: str,
    ) -> SideChannelFinding:
        if result == OracleResult.PAIRED:
            self._paired_count += 1
            self._orchestrator.evaluate_and_correlate(periph_addr, result, timestamp=timestamp)
            verdict = Verdict.PAIRED_SHARED_LTK.value
        else:
            self._unpaired_count += 1
            verdict = Verdict.REJECTED_UNTRUSTED.value

        finding = SideChannelFinding(
            finding_type=FINDING_TYPE_IDBLEED,
            timestamp=timestamp,
            device_addr=periph_addr,
            target_addr=central_addr,
            verdict=verdict,
            confidence=1.0,
            details={
                "evaluator": evaluator_name,
                "oracle_result": result.name,
                "reason": reason,
            },
        )
        self._findings.append(finding)
        return finding

    def process_packet(self, packet: BlePacketRecord | Any) -> list[SideChannelFinding]:
        """Process a single BlePacketRecord and emit any triggered side-channel findings.

        Args:
            packet: BlePacketRecord or coercible packet event.

        Returns:
            List of newly triggered SideChannelFinding instances.
        """
        record = BlePacketRecord.coerce(packet)
        self._packets_processed += 1
        emitted: list[SideChannelFinding] = []

        if record.access_address == BLE_ADV_AA or record.channel >= 37:
            adv_frame = ble_packet_record_to_frame(record)
            if adv_frame.pdu_type == "CONNECT_IND":
                adv = dissect_advertising_pdu(record.body)
                if adv and adv.conn_aa is not None and adv.init_a and adv.adv_a:
                    self._conn_map[adv.conn_aa] = (adv.init_a.upper(), adv.adv_a.upper())
            return emitted

        aa = record.access_address
        central_addr, periph_addr = self._conn_map.get(
            aa,
            (f"CENTRAL_{aa:08X}", f"PERIPH_{aa:08X}"),
        )
        if self.target_mac and self.target_mac not in (central_addr, periph_addr):
            return emitted

        src = central_addr if record.direction == 0 else periph_addr
        dst = periph_addr if record.direction == 0 else central_addr
        frame = ble_packet_record_to_frame(record, source_mac=src, dest_mac=dst)

        # Resolve pending CSRK signed write request when target responds on the link
        if aa in self._pending_signed_req and src == periph_addr:
            req_frame = self._pending_signed_req.pop(aa)
            rsp_frame = frame
            if frame.pdu_type == "LL_EMPTY" and len(record.body) >= 2:
                # Over-the-air Link-Layer empty data PDU from peripheral acknowledges the write
                rsp_frame = BLEFrame(
                    timestamp=frame.timestamp,
                    channel=frame.channel,
                    rssi=frame.rssi,
                    source_mac=frame.source_mac,
                    dest_mac=frame.dest_mac,
                    pdu_type="LL_ACK",
                    payload=record.body[:2],
                    crc_valid=frame.crc_valid,
                )
            csrk_eval = self._csrk_evaluators.setdefault(
                periph_addr,
                CSRKSigningOracleEvaluator(target_mac=periph_addr, csrk=self.csrk),
            )
            csrk_res, csrk_reason = csrk_eval.evaluate_signature_response(req_frame, rsp_frame)
            if csrk_res in (OracleResult.PAIRED, OracleResult.UNPAIRED):
                emitted.append(
                    self._emit_finding(
                        frame.timestamp,
                        periph_addr,
                        central_addr,
                        "CSRKSigningOracleEvaluator",
                        csrk_res,
                        csrk_reason,
                    )
                )

        if frame.pdu_type == "LL_CONTROL":
            ll_eval = self._ll_evaluators.setdefault(
                aa,
                LLEncryptionOracleEvaluator(
                    target_mac=periph_addr,
                    timeout_seconds=self.timeout_seconds,
                ),
            )
            ll_res, ll_reason = ll_eval.process_frame(frame)
            if ll_res in (OracleResult.PAIRED, OracleResult.UNPAIRED):
                emitted.append(
                    self._emit_finding(
                        frame.timestamp,
                        periph_addr,
                        central_addr,
                        "LLEncryptionOracleEvaluator",
                        ll_res,
                        ll_reason,
                    )
                )

            if aa in self._app_evaluators and frame.payload and (frame.payload[0] == LLOpcode.LL_TERMINATE_IND):
                app_res, app_reason = self._app_evaluators[aa].process_att_frame(frame)
                if app_res in (OracleResult.PAIRED, OracleResult.UNPAIRED):
                    emitted.append(
                        self._emit_finding(
                            frame.timestamp,
                            periph_addr,
                            central_addr,
                            "AppAuthOracleEvaluator",
                            app_res,
                            app_reason,
                        )
                    )

        elif frame.pdu_type == "ATT":
            if frame.payload and frame.payload[0] == ATTOpcode.ATT_SIGNED_WRITE_CMD:
                self._pending_signed_req[aa] = frame
            else:
                app_eval = self._app_evaluators.setdefault(
                    aa,
                    AppAuthOracleEvaluator(target_mac=periph_addr, auth_handle=self.auth_handle),
                )
                app_res, app_reason = app_eval.process_att_frame(frame)
                if app_res in (OracleResult.PAIRED, OracleResult.UNPAIRED):
                    emitted.append(
                        self._emit_finding(
                            frame.timestamp,
                            periph_addr,
                            central_addr,
                            "AppAuthOracleEvaluator",
                            app_res,
                            app_reason,
                        )
                    )

        return emitted

    def finalize(self) -> AnalyzerReport:
        """Aggregate all evaluator observations into an AirTell AnalyzerReport.

        Returns:
            AnalyzerReport summarizing side-channel audit outcomes and RPA correlation metrics.
        """
        summary_data = self._orchestrator.correlation_summary()
        if self._paired_count > 0 and self._unpaired_count > 0:
            verdict = Verdict.CONFIRMED_EXCLUSIVE.value
            summary = (
                f"Differential side-channel behavior confirmed ({self._paired_count} PAIRED, "
                f"{self._unpaired_count} UNPAIRED across {self._packets_processed} packets)."
            )
        elif self._paired_count > 0:
            verdict = Verdict.PAIRED_SHARED_LTK.value
            summary = (
                f"Verified {self._paired_count} PAIRED protocol state observation(s) across "
                f"{self._packets_processed} packets."
            )
        elif self._unpaired_count > 0:
            verdict = Verdict.REJECTED_UNTRUSTED.value
            summary = (
                f"Verified {self._unpaired_count} UNPAIRED rejection/termination observation(s) "
                f"across {self._packets_processed} packets."
            )
        else:
            verdict = Verdict.INCONCLUSIVE.value
            summary = f"No decisive side-channel state transitions in {self._packets_processed} packets."

        return AnalyzerReport(
            analyzer_name="IdbleedVerificationAnalyzer",
            verdict=verdict,
            summary=summary,
            findings=list(self._findings),
            metrics={
                "packets_processed": self._packets_processed,
                "paired_verdicts": self._paired_count,
                "unpaired_verdicts": self._unpaired_count,
                "correlated_rpas": summary_data["observed_rpas"],
                "rotation_intervals": summary_data["rotation_intervals"],
                "findings_count": len(self._findings),
            },
        )


class TestIDBLEEDSpecification(unittest.TestCase):
    """Canonical verification test suite for the IDBLEED side-channel specification."""

    def test_ll_encryption_oracle_paired(self) -> None:
        """Verify 4-step Link-Layer encryption handshake confirms shared LTK (PAIRED)."""
        target_mac = "5A:11:22:33:44:55"
        central_mac = "AA:BB:CC:DD:EE:01"
        evaluator = LLEncryptionOracleEvaluator(target_mac=target_mac, timeout_seconds=2.0)

        enc_req = LLEncryptionReqPayload(
            rand=b"\x10\x20\x30\x40\x50\x60\x70\x80",
            ediv=0x1A2B,
            skd_c=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            iv_c=b"\xa1\xb2\xc3\xd4",
        ).serialize()

        frames = [
            BLEFrame(1.00, 12, -52, central_mac, target_mac, "LL_CONTROL", enc_req),
            BLEFrame(
                1.03,
                12,
                -54,
                target_mac,
                central_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_ENC_RSP]) + b"\x11" * 12,
            ),
            BLEFrame(
                1.06,
                12,
                -53,
                central_mac,
                target_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_START_ENC_REQ]),
            ),
            BLEFrame(
                1.09,
                12,
                -54,
                target_mac,
                central_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_START_ENC_RSP]),
            ),
        ]

        outcomes = [evaluator.process_frame(f) for f in frames]
        self.assertEqual(outcomes[0][0], OracleResult.INDETERMINATE)
        self.assertEqual(outcomes[1][0], OracleResult.INDETERMINATE)
        self.assertEqual(outcomes[2][0], OracleResult.INDETERMINATE)
        self.assertEqual(
            outcomes[3],
            (OracleResult.PAIRED, "Observed LL_START_ENC_RSP: Matching LTK verified"),
        )

    def test_ll_encryption_oracle_unpaired(self) -> None:
        """Verify LL_REJECT_IND (0x0D) during encryption setup identifies missing LTK (UNPAIRED)."""
        target_mac = "5A:11:22:33:44:55"
        central_mac = "DE:AD:00:11:22:33"
        evaluator = LLEncryptionOracleEvaluator(target_mac=target_mac, timeout_seconds=2.0)

        enc_req = LLEncryptionReqPayload(
            rand=b"\xaa" * 8,
            ediv=0x9999,
            skd_c=b"\xbb" * 8,
            iv_c=b"\xcc" * 4,
        ).serialize()

        res_req, _ = evaluator.process_frame(BLEFrame(2.00, 8, -60, central_mac, target_mac, "LL_CONTROL", enc_req))
        self.assertEqual(res_req, OracleResult.INDETERMINATE)

        res_rej, reason = evaluator.process_frame(
            BLEFrame(
                2.04,
                8,
                -60,
                target_mac,
                central_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_REJECT_IND, 0x06]),
            )
        )
        self.assertEqual(res_rej, OracleResult.UNPAIRED)
        self.assertEqual(reason, "Observed rejection opcode 0x0D: Missing LTK")

    def test_csrk_signing_oracle_success(self) -> None:
        """Verify AES-CMAC signed write serialization, verification, and target ACK evaluation."""
        target_mac = "6B:22:33:44:55:66"
        central_mac = "AA:BB:CC:DD:EE:02"
        csrk = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        handle = 0x0018
        value = b"\x01\x02\x03"
        counter = 1

        mac = compute_csrk_cmac(csrk, handle, value, counter)
        signed_payload = ATTSignedWritePayload(
            handle=handle,
            value=value,
            signature_counter=counter,
            cmac=mac,
        )
        self.assertTrue(signed_payload.verify_cmac(csrk))

        req_frame = BLEFrame(
            timestamp=5.00,
            channel=15,
            rssi=-55,
            source_mac=central_mac,
            dest_mac=target_mac,
            pdu_type="ATT",
            payload=signed_payload.serialize(),
        )
        ack_frame = BLEFrame(
            timestamp=5.02,
            channel=15,
            rssi=-56,
            source_mac=target_mac,
            dest_mac=central_mac,
            pdu_type="LL_ACK",
            payload=b"\x01\x00",
        )

        evaluator = CSRKSigningOracleEvaluator(target_mac=target_mac)
        result, reason = evaluator.evaluate_signature_response(req_frame, ack_frame)
        self.assertEqual(result, OracleResult.PAIRED)
        self.assertEqual(reason, "Data signature verified via CSRK ACK")
        self.assertEqual(evaluator.last_counter, counter)

    def test_app_auth_oracle_workflow(self) -> None:
        """Verify GATT discovery, auth write, and notification state machine transitions."""
        target_mac = "7C:33:44:55:66:77"
        central_mac = "AA:BB:CC:DD:EE:03"
        evaluator = AppAuthOracleEvaluator(target_mac=target_mac, auth_handle=0xFFF1)

        # Step 1: 2-byte ATT_READ_RSP transitions to AWAITING_AUTH_WRITE
        res1, _ = evaluator.process_att_frame(
            BLEFrame(10.0, 20, -50, target_mac, central_mac, "ATT", bytes([ATTOpcode.ATT_READ_RSP, 0x01]))
        )
        self.assertEqual(res1, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AWAITING_AUTH_WRITE")

        # Step 2: ATT_WRITE_CMD to 0xFFF1 transitions to AUTH_SUBMITTED
        write_pdu = bytes([ATTOpcode.ATT_WRITE_CMD]) + struct.pack("<H", 0xFFF1) + b"CHALLENGE_RESP"
        res2, _ = evaluator.process_att_frame(BLEFrame(10.1, 20, -50, central_mac, target_mac, "ATT", write_pdu))
        self.assertEqual(res2, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AUTH_SUBMITTED")

        # Step 3: ATT_HANDLE_VALUE_NOTI confirms authentication (PAIRED)
        noti_pdu = bytes([ATTOpcode.ATT_HANDLE_VALUE_NOTI]) + struct.pack("<H", 0xFFF1) + b"OK"
        res3, reason3 = evaluator.process_att_frame(BLEFrame(10.2, 20, -50, target_mac, central_mac, "ATT", noti_pdu))
        self.assertEqual(res3, OracleResult.PAIRED)
        self.assertEqual(reason3, "GATT Auth succeeded: NOTIFY(OK) received")

    def test_active_relay_correlation(self) -> None:
        """Verify multi-window RPA correlation links paired RPAs across 15-minute windows."""
        orchestrator = ActiveRelayProbeOrchestrator(
            canonical_target_id="audited-peripheral-01",
            rpa_rotation_window_sec=900.0,
        )
        central_mac = "AA:BB:CC:DD:EE:04"
        enc_req = LLEncryptionReqPayload(
            rand=b"\x01" * 8,
            ediv=0x0007,
            skd_c=b"\x02" * 8,
            iv_c=b"\x03" * 4,
        ).serialize()
        captured_req = BLEFrame(100.0, 9, -55, central_mac, "50:00:00:00:00:01", "LL_CONTROL", enc_req)

        rpa_window_1 = "5A:AA:BB:CC:DD:01"
        rpa_window_2 = "6E:AA:BB:CC:DD:02"
        unpaired_rpa = "71:FF:EE:DD:CC:99"

        # Window 1 (t = 100.0s): target RPA_1 confirms LTK
        probed_1 = orchestrator.relay_probe_frame(captured_req, rpa_window_1)
        eval_1 = LLEncryptionOracleEvaluator(target_mac=rpa_window_1)
        eval_1.process_frame(probed_1)
        res_1, _ = eval_1.process_frame(
            BLEFrame(100.05, 9, -55, rpa_window_1, central_mac, "LL_CONTROL", bytes([LLOpcode.LL_START_ENC_RSP]))
        )
        self.assertTrue(orchestrator.evaluate_and_correlate(rpa_window_1, res_1, timestamp=100.0))

        # Bystander RPA rejects encryption (UNPAIRED -> not correlated)
        probed_unpaired = orchestrator.relay_probe_frame(captured_req, unpaired_rpa)
        eval_unpaired = LLEncryptionOracleEvaluator(target_mac=unpaired_rpa)
        eval_unpaired.process_frame(probed_unpaired)
        res_unpaired, _ = eval_unpaired.process_frame(
            BLEFrame(
                200.05,
                9,
                -65,
                unpaired_rpa,
                central_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_REJECT_IND, 0x06]),
            )
        )
        self.assertFalse(orchestrator.evaluate_and_correlate(unpaired_rpa, res_unpaired, timestamp=200.0))

        # Window 2 (t = 1000.0s, +900s Delta_RPA): rotated RPA_2 confirms LTK
        probed_2 = orchestrator.relay_probe_frame(captured_req, rpa_window_2)
        probed_2.timestamp = 1000.0
        eval_2 = LLEncryptionOracleEvaluator(target_mac=rpa_window_2)
        eval_2.process_frame(probed_2)
        res_2, _ = eval_2.process_frame(
            BLEFrame(
                1000.05,
                9,
                -54,
                rpa_window_2,
                central_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_START_ENC_RSP]),
            )
        )
        self.assertTrue(orchestrator.evaluate_and_correlate(rpa_window_2, res_2, timestamp=1000.0))

        self.assertEqual(orchestrator.identity_record.observed_rpas, [rpa_window_1, rpa_window_2])
        self.assertEqual(orchestrator.rotation_intervals, [900.0])


__all__ = [
    "OracleResult",
    "LLOpcode",
    "ATTOpcode",
    "BLEFrame",
    "LLEncryptionReqPayload",
    "ATTSignedWritePayload",
    "compute_csrk_cmac",
    "LLEncryptionOracleEvaluator",
    "CSRKSigningOracleEvaluator",
    "AppAuthOracleEvaluator",
    "IdentityRecord",
    "ActiveRelayProbeOrchestrator",
    "ble_packet_record_to_frame",
    "IdbleedVerificationAnalyzer",
    "TestIDBLEEDSpecification",
]
