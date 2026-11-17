"""Link-layer protocol hardening and IDBLEED boolean side-channel suppression.

Implements constant-time suppression of explicit BLE Link-Layer rejection PDUs
(`LL_REJECT_IND=0x0D`, `LL_REJECT_EXT_IND=0x11`), unauthenticated handshake
terminations (`LL_TERMINATE_IND=0x02`), unpaired CSRK signed-write drops
(`ATT_SIGNED_WRITE_CMD=0xD2`), and deterministic response-window normalization
so external observers cannot distinguish `PAIRED` from `UNPAIRED` bonds.
"""

from __future__ import annotations

import hmac
import math
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from airtell.sidechannel.ll_dissector import DissectedDataPdu, dissect_ble_pdu
from airtell.sidechannel.models import BlePacketRecord
from airtell.sidechannel.synthetic import L2CAP_CID_ATT, compute_csrk_mac

# Link-Layer Control Opcodes (Bluetooth Core Spec Vol 6, Part B, §2.4.2)
LL_TERMINATE_IND: int = 0x02
LL_ENC_REQ: int = 0x03
LL_ENC_RSP: int = 0x04
LL_START_ENC_REQ: int = 0x05
LL_START_ENC_RSP: int = 0x06
LL_REJECT_IND: int = 0x0D
LL_REJECT_EXT_IND: int = 0x11

# Attribute Protocol (ATT) Opcodes (Bluetooth Core Spec Vol 3, Part F, §3.4)
ATT_ERROR_RSP: int = 0x01
ATT_READ_REQ: int = 0x0A
ATT_READ_RSP: int = 0x0B
ATT_WRITE_REQ: int = 0x12
ATT_HANDLE_VALUE_NOTI: int = 0x1B
ATT_WRITE_CMD: int = 0x52
ATT_SIGNED_WRITE_CMD: int = 0xD2


@runtime_checkable
class BLEFrameProtocol(Protocol):
    """Structural protocol compatible with `airtell.sidechannel.idbleed_spec.BLEFrame`."""

    timestamp: float
    channel: int
    rssi: int
    source_mac: str
    dest_mac: str
    pdu_type: str
    payload: bytes
    crc_valid: bool


@dataclass
class MonitorBLEFrame:
    """Standalone BLE frame container compatible with `idbleed_spec.BLEFrame`.

    Attributes:
        timestamp: Frame capture or scheduling timestamp in seconds.
        channel: BLE logical channel index (0-39).
        rssi: Received signal strength indicator in dBm.
        source_mac: Transmitter MAC or Resolvable Private Address.
        dest_mac: Receiver MAC or Resolvable Private Address.
        pdu_type: Logical protocol layer label (e.g. ``"LL_CONTROL"``, ``"ATT"``).
        payload: Protocol payload starting with the 1-byte LL or ATT opcode.
        crc_valid: Whether Link-Layer 24-bit CRC validation succeeded.
    """

    timestamp: float = 0.0
    channel: int = 37
    rssi: int = -60
    source_mac: str = "00:00:00:00:00:00"
    dest_mac: str = "00:00:00:00:00:00"
    pdu_type: str = "LL_CONTROL"
    payload: bytes = b""
    crc_valid: bool = True


@dataclass(frozen=True)
class LinkLayerHardeningConfig:
    """Configuration controlling Link-Layer and ATT side-channel hardening.

    Attributes:
        suppress_explicit_rejections: Convert explicit rejection PDUs (`0x0D`, `0x11`,
            unauthenticated `ATT_ERROR_RSP`) into constant-time silent drops.
        constant_time_window_ms: Target uniform response window in milliseconds.
        mask_unauthenticated_terminations: Suppress `LL_TERMINATE_IND` (`0x02`) emitted
            before mutual link encryption completes.
        suppress_unpaired_csrk_drops: Suppress observable error/drop differentials on
            unpaired, malformed, or replayed `ATT_SIGNED_WRITE_CMD` (`0xD2`) PDUs.
    """

    suppress_explicit_rejections: bool = True
    constant_time_window_ms: float = 25.0
    mask_unauthenticated_terminations: bool = True
    suppress_unpaired_csrk_drops: bool = True

    def __post_init__(self) -> None:
        if math.isnan(self.constant_time_window_ms) or math.isinf(self.constant_time_window_ms):
            raise ValueError("constant_time_window_ms must be a finite non-negative float")
        if self.constant_time_window_ms < 0.0:
            raise ValueError(f"constant_time_window_ms must be >= 0.0, got {self.constant_time_window_ms}")


class FrameAction(str, Enum):
    """Enforcement action applied by `IDBLEEDSideChannelMonitor` to a BLE PDU."""

    FORWARD = "forward"
    SILENT_DROP_CONSTANT_TIME = "silent_drop_constant_time"
    DELAY_UNIFORM = "delay_uniform"


@dataclass(frozen=True)
class MonitoredFrameDecision:
    """Per-frame enforcement decision produced by `IDBLEEDSideChannelMonitor`.

    Attributes:
        action: Selected `FrameAction` (`FORWARD`, `SILENT_DROP_CONSTANT_TIME`, `DELAY_UNIFORM`).
        scheduled_delay_ms: Deterministic delay padding in milliseconds (`>= 0.0`).
        suppressed_opcode: Intercepted LL/ATT opcode when dropped, else `None`.
        sanitized_payload: Outbound/inbound payload if permitted, or `None` when dropped.
        reason: Human-readable audit rationale for the decision.
    """

    action: FrameAction
    scheduled_delay_ms: float
    suppressed_opcode: int | None
    sanitized_payload: bytes | None
    reason: str


@dataclass(frozen=True)
class SideChannelExposureReport:
    """Aggregated telemetry quantifying link-layer boolean oracle distinguishability.

    Attributes:
        total_frames: Total frames inspected by the monitor.
        suppressed_rejections: Count of rejection/error/termination PDUs silently dropped.
        uniform_delays_applied: Count of frames padded with positive constant-time delay.
        oracle_distinguishability_before: Unhardened boolean oracle advantage in `[0.0, 1.0]`.
        oracle_distinguishability_after: Residual boolean oracle advantage after hardening.
    """

    total_frames: int
    suppressed_rejections: int
    uniform_delays_applied: int
    oracle_distinguishability_before: float
    oracle_distinguishability_after: float

    def to_dict(self) -> dict[str, int | float]:
        """Return a JSON-serializable dictionary of exposure metrics."""
        return {
            "total_frames": self.total_frames,
            "suppressed_rejections": self.suppressed_rejections,
            "uniform_delays_applied": self.uniform_delays_applied,
            "oracle_distinguishability_before": self.oracle_distinguishability_before,
            "oracle_distinguishability_after": self.oracle_distinguishability_after,
        }


@dataclass
class _LinkHandshakeState:
    """Internal per-link encryption and probe timing tracker."""

    authenticated: bool = False
    enc_handshake_pending: bool = False
    probe_start_ts: float | None = None


def coerce_ble_frame(packet: BLEFrameProtocol | BlePacketRecord | Any) -> MonitorBLEFrame:
    """Coerce an `idbleed_spec.BLEFrame`, `MonitorBLEFrame`, or `BlePacketRecord` into `MonitorBLEFrame`.

    Args:
        packet: Frame or raw packet record to normalize.

    Returns:
        Normalized `MonitorBLEFrame` ready for opcode-level inspection.

    Raises:
        TypeError: If `packet` cannot be coerced into a BLE frame representation.
    """
    if isinstance(packet, MonitorBLEFrame):
        return packet

    if (
        hasattr(packet, "payload")
        and hasattr(packet, "source_mac")
        and hasattr(packet, "dest_mac")
        and hasattr(packet, "timestamp")
    ):
        raw_payload = getattr(packet, "payload")
        if not isinstance(raw_payload, (bytes, bytearray)):
            raise TypeError("Frame payload must be bytes or bytearray")
        return MonitorBLEFrame(
            timestamp=float(getattr(packet, "timestamp")),
            channel=int(getattr(packet, "channel", 37)),
            rssi=int(getattr(packet, "rssi", -60)),
            source_mac=str(getattr(packet, "source_mac")),
            dest_mac=str(getattr(packet, "dest_mac")),
            pdu_type=str(getattr(packet, "pdu_type", "LL_CONTROL")),
            payload=bytes(raw_payload),
            crc_valid=bool(getattr(packet, "crc_valid", True)),
        )

    record = BlePacketRecord.coerce(packet)
    aa_mac = (
        f"AA:{(record.access_address >> 24) & 0xFF:02X}:"
        f"{(record.access_address >> 16) & 0xFF:02X}:"
        f"{(record.access_address >> 8) & 0xFF:02X}:"
        f"{record.access_address & 0xFF:02X}"
    )
    src_mac = f"{aa_mac}:01" if record.direction == 1 else f"{aa_mac}:00"
    dst_mac = f"{aa_mac}:00" if record.direction == 1 else f"{aa_mac}:01"

    dissected = dissect_ble_pdu(record.body, access_address=record.access_address)
    if isinstance(dissected, DissectedDataPdu):
        if dissected.control_frame is not None:
            return MonitorBLEFrame(
                timestamp=record.timestamp,
                channel=record.channel,
                rssi=record.rssi,
                source_mac=src_mac,
                dest_mac=dst_mac,
                pdu_type="LL_CONTROL",
                payload=dissected.control_frame.raw_bytes,
                crc_valid=not record.crc_err,
            )
        if dissected.llid == 2 and len(dissected.raw_payload) >= 4:
            l2cap_len, cid = struct.unpack("<HH", dissected.raw_payload[0:4])
            if cid == L2CAP_CID_ATT:
                att_body = dissected.raw_payload[4 : 4 + l2cap_len]
                return MonitorBLEFrame(
                    timestamp=record.timestamp,
                    channel=record.channel,
                    rssi=record.rssi,
                    source_mac=src_mac,
                    dest_mac=dst_mac,
                    pdu_type="ATT",
                    payload=att_body,
                    crc_valid=not record.crc_err,
                )
        return MonitorBLEFrame(
            timestamp=record.timestamp,
            channel=record.channel,
            rssi=record.rssi,
            source_mac=src_mac,
            dest_mac=dst_mac,
            pdu_type="LL_DATA",
            payload=dissected.raw_payload,
            crc_valid=not record.crc_err,
        )

    return MonitorBLEFrame(
        timestamp=record.timestamp,
        channel=record.channel,
        rssi=record.rssi,
        source_mac=src_mac,
        dest_mac=dst_mac,
        pdu_type="BLE_ADV",
        payload=record.body,
        crc_valid=not record.crc_err,
    )


class IDBLEEDSideChannelMonitor:
    """Stateful Link-Layer and ATT monitor suppressing IDBLEED boolean & timing side-channels.

    Intercepts deterministic status/rejection frames (`LL_REJECT_IND=0x0D`,
    `LL_REJECT_EXT_IND=0x11`, unauthenticated `LL_TERMINATE_IND=0x02`, and invalid
    `ATT_SIGNED_WRITE_CMD=0xD2` probes), converting them into constant-time silent
    drops (`SILENT_DROP_CONSTANT_TIME`) while pacing valid authentication responses
    to a uniform timing window (`DELAY_UNIFORM`).
    """

    def __init__(
        self,
        config: LinkLayerHardeningConfig | None = None,
        *,
        authenticated_peers: set[str] | None = None,
        valid_csrk: bytes | None = None,
    ) -> None:
        """Initialize the side-channel monitor.

        Args:
            config: Hardening parameters; defaults to `LinkLayerHardeningConfig()`.
            authenticated_peers: Optional set of locally authorized peer MAC addresses.
            valid_csrk: Optional 16-byte CSRK for cryptographic verification of `0xD2` writes.

        Raises:
            ValueError: If `valid_csrk` is provided and is not 16 bytes.
        """
        if valid_csrk is not None and len(valid_csrk) != 16:
            raise ValueError(f"valid_csrk must be exactly 16 bytes, got {len(valid_csrk)}")

        self.config: LinkLayerHardeningConfig = config or LinkLayerHardeningConfig()
        self._authenticated_peers: set[str] = {mac.upper() for mac in (authenticated_peers or set())}
        self._valid_csrk: bytes | None = valid_csrk
        self._links: dict[frozenset[str], _LinkHandshakeState] = {}
        self._csrk_counters: dict[str, int] = {}

        self._total_frames: int = 0
        self._suppressed_rejections: int = 0
        self._uniform_delays_applied: int = 0
        self._leakable_events: int = 0
        self._mitigated_events: int = 0

    def register_authenticated_peer(self, peer_mac: str) -> None:
        """Register an authorized peer MAC address for local session responses."""
        self._authenticated_peers.add(peer_mac.upper())

    def reset(self) -> None:
        """Reset per-link handshake state and exposure telemetry counters."""
        self._links.clear()
        self._csrk_counters.clear()
        self._total_frames = 0
        self._suppressed_rejections = 0
        self._uniform_delays_applied = 0
        self._leakable_events = 0
        self._mitigated_events = 0

    def _link_key(self, source_mac: str, dest_mac: str) -> frozenset[str]:
        return frozenset((source_mac.upper(), dest_mac.upper()))

    def _compute_scheduled_delay(
        self,
        elapsed_ms: float | None,
        link_state: _LinkHandshakeState,
        frame_ts: float,
    ) -> float:
        if elapsed_ms is not None:
            resolved_elapsed = max(0.0, float(elapsed_ms))
        elif link_state.probe_start_ts is not None and frame_ts >= link_state.probe_start_ts:
            resolved_elapsed = (frame_ts - link_state.probe_start_ts) * 1000.0
        else:
            resolved_elapsed = 0.0
        return max(0.0, self.config.constant_time_window_ms - resolved_elapsed)

    def _classify_layer(self, pdu_type: str, payload: bytes) -> str:
        kind = pdu_type.upper()
        opcode = payload[0]
        if opcode in (ATT_SIGNED_WRITE_CMD, ATT_HANDLE_VALUE_NOTI, ATT_WRITE_CMD):
            return "ATT"
        if "ATT" in kind or "GATT" in kind or "L2CAP" in kind:
            if opcode == LL_TERMINATE_IND and len(payload) <= 2:
                return "LL_CONTROL"
            return "ATT"
        return "LL_CONTROL"

    def _verify_signed_write(
        self,
        frame: MonitorBLEFrame,
        link_state: _LinkHandshakeState,
        payload: bytes,
    ) -> tuple[bool, str]:
        if len(payload) < 15:
            return False, "Truncated ATT_SIGNED_WRITE_CMD (< 15 bytes)"

        handle = struct.unpack("<H", payload[1:3])[0]
        val_len = len(payload) - 15
        value = payload[3 : 3 + val_len]
        sig_offset = 3 + val_len
        sign_counter = struct.unpack("<I", payload[sig_offset : sig_offset + 4])[0]
        mac = payload[sig_offset + 4 : sig_offset + 12]

        peer_key = frame.source_mac.upper()
        peer_paired = (
            peer_key in self._authenticated_peers
            or frame.dest_mac.upper() in self._authenticated_peers
            or link_state.authenticated
        )
        if not peer_paired and self._valid_csrk is None:
            return False, "Unpaired peer attempted ATT_SIGNED_WRITE_CMD without CSRK bond"
        if self._authenticated_peers and not peer_paired:
            return False, "Unpaired peer attempted ATT_SIGNED_WRITE_CMD"

        if self._valid_csrk is not None:
            expected_mac = compute_csrk_mac(
                csrk=self._valid_csrk,
                opcode=ATT_SIGNED_WRITE_CMD,
                handle=handle,
                value=value,
                counter=sign_counter,
            )
            if not hmac.compare_digest(mac, expected_mac):
                return False, "Invalid CSRK AES-CMAC signature on ATT_SIGNED_WRITE_CMD"

        prev_counter = self._csrk_counters.get(peer_key)
        if prev_counter is not None and sign_counter <= prev_counter:
            return (
                False,
                f"Non-monotonic CSRK SignCounter ({sign_counter} <= {prev_counter})",
            )

        self._csrk_counters[peer_key] = sign_counter
        return True, f"Verified ATT_SIGNED_WRITE_CMD (counter={sign_counter})"

    def _silent_drop(
        self,
        *,
        opcode: int | None,
        delay_ms: float,
        reason: str,
        count_rejection: bool = True,
    ) -> MonitoredFrameDecision:
        if count_rejection:
            self._suppressed_rejections += 1
        if delay_ms > 0.0:
            self._uniform_delays_applied += 1
        return MonitoredFrameDecision(
            action=FrameAction.SILENT_DROP_CONSTANT_TIME,
            scheduled_delay_ms=delay_ms,
            suppressed_opcode=opcode,
            sanitized_payload=None,
            reason=reason,
        )

    def _pace_or_forward(
        self,
        *,
        payload: bytes,
        delay_ms: float,
        reason_paced: str,
        reason_forward: str,
    ) -> MonitoredFrameDecision:
        if self.config.constant_time_window_ms > 0.0 and delay_ms > 0.0:
            self._uniform_delays_applied += 1
            return MonitoredFrameDecision(
                action=FrameAction.DELAY_UNIFORM,
                scheduled_delay_ms=delay_ms,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason=reason_paced,
            )
        return MonitoredFrameDecision(
            action=FrameAction.FORWARD,
            scheduled_delay_ms=0.0,
            suppressed_opcode=None,
            sanitized_payload=payload,
            reason=reason_forward,
        )

    def inspect_frame(
        self,
        frame: BLEFrameProtocol | BlePacketRecord | Any,
        *,
        elapsed_ms: float | None = None,
        suppress_unauthenticated_handshakes: bool = False,
    ) -> MonitoredFrameDecision:
        """Inspect a BLE Link-Layer or ATT frame and enforce side-channel hardening.

        Args:
            frame: `BLEFrame`, `MonitorBLEFrame`, or `BlePacketRecord` to inspect.
            elapsed_ms: Optional elapsed processing latency since the triggering probe.
                When omitted, computed automatically from the link's recorded probe
                timestamp if available, else `0.0`.
            suppress_unauthenticated_handshakes: When `True` (e.g. under a gateway
                software flow denial), also suppresses outbound encryption/GATT auth
                completions for unauthenticated active relay probes.

        Returns:
            `MonitoredFrameDecision` specifying forwarding, uniform delay, or silent drop.
        """
        coerced = coerce_ble_frame(frame)
        self._total_frames += 1

        key = self._link_key(coerced.source_mac, coerced.dest_mac)
        link_state = self._links.setdefault(key, _LinkHandshakeState())
        payload = coerced.payload

        if not coerced.crc_valid:
            delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, coerced.timestamp)
            opcode = payload[0] if payload else None
            return self._silent_drop(
                opcode=opcode,
                delay_ms=delay_ms,
                reason="Invalid CRC PDU silently dropped within constant-time envelope",
                count_rejection=False,
            )

        if not payload:
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=b"",
                reason="Empty Link-Layer PDU forwarded",
            )

        opcode = payload[0]
        layer = self._classify_layer(coerced.pdu_type, payload)

        if layer == "LL_CONTROL":
            return self._inspect_ll_control(
                coerced,
                link_state,
                opcode,
                elapsed_ms=elapsed_ms,
                suppress_unauthenticated_handshakes=suppress_unauthenticated_handshakes,
            )
        return self._inspect_att(
            coerced,
            link_state,
            opcode,
            elapsed_ms=elapsed_ms,
            suppress_unauthenticated_handshakes=suppress_unauthenticated_handshakes,
        )

    def _inspect_ll_control(
        self,
        frame: MonitorBLEFrame,
        link_state: _LinkHandshakeState,
        opcode: int,
        *,
        elapsed_ms: float | None,
        suppress_unauthenticated_handshakes: bool,
    ) -> MonitoredFrameDecision:
        payload = frame.payload

        # 1. Explicit Link-Layer rejections (0x0D LL_REJECT_IND, 0x11 LL_REJECT_EXT_IND)
        if opcode in (LL_REJECT_IND, LL_REJECT_EXT_IND):
            self._leakable_events += 1
            link_state.enc_handshake_pending = False
            if self.config.suppress_explicit_rejections:
                self._mitigated_events += 1
                delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
                return self._silent_drop(
                    opcode=opcode,
                    delay_ms=delay_ms,
                    reason=(f"Suppressed explicit Link-Layer rejection 0x{opcode:02X} via constant-time silent drop"),
                )
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason=f"Forwarded explicit rejection 0x{opcode:02X} (hardening disabled)",
            )

        # 2. Link-Layer Termination (0x02 LL_TERMINATE_IND)
        if opcode == LL_TERMINATE_IND:
            if not link_state.authenticated:
                self._leakable_events += 1
                link_state.enc_handshake_pending = False
                if self.config.mask_unauthenticated_terminations:
                    self._mitigated_events += 1
                    delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
                    return self._silent_drop(
                        opcode=LL_TERMINATE_IND,
                        delay_ms=delay_ms,
                        reason="Masked unauthenticated LL_TERMINATE_IND via constant-time silent drop",
                    )
                return MonitoredFrameDecision(
                    action=FrameAction.FORWARD,
                    scheduled_delay_ms=0.0,
                    suppressed_opcode=None,
                    sanitized_payload=payload,
                    reason="Forwarded unauthenticated LL_TERMINATE_IND (masking disabled)",
                )

            link_state.authenticated = False
            link_state.enc_handshake_pending = False
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason="Post-authentication LL_TERMINATE_IND forwarded",
            )

        # 3. Inbound Encryption Probe (0x03 LL_ENC_REQ)
        if opcode == LL_ENC_REQ:
            link_state.probe_start_ts = frame.timestamp
            link_state.enc_handshake_pending = True
            link_state.authenticated = False
            note = "valid 23B PDU" if len(payload) >= 23 else f"short {len(payload)}B PDU"
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason=f"Recorded LL_ENC_REQ handshake start ({note})",
            )

        # 4. Encryption Handshake Responses (0x04, 0x05, 0x06)
        if opcode in (LL_ENC_RSP, LL_START_ENC_REQ, LL_START_ENC_RSP):
            peer_authorized = (
                frame.dest_mac.upper() in self._authenticated_peers
                or frame.source_mac.upper() in self._authenticated_peers
            )
            if suppress_unauthenticated_handshakes and not peer_authorized:
                self._leakable_events += 1
                self._mitigated_events += 1
                delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
                link_state.enc_handshake_pending = False
                return self._silent_drop(
                    opcode=opcode,
                    delay_ms=delay_ms,
                    reason=(
                        f"Suppressed unauthenticated handshake response 0x{opcode:02X} under gateway privacy policy"
                    ),
                )

            if opcode == LL_START_ENC_RSP:
                link_state.authenticated = True
                link_state.enc_handshake_pending = False

            self._leakable_events += 1
            if self.config.constant_time_window_ms > 0.0:
                self._mitigated_events += 1
            delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
            return self._pace_or_forward(
                payload=payload,
                delay_ms=delay_ms,
                reason_paced=f"Paced Link-Layer handshake PDU 0x{opcode:02X} to uniform window",
                reason_forward=f"Forwarded Link-Layer handshake PDU 0x{opcode:02X}",
            )

        return MonitoredFrameDecision(
            action=FrameAction.FORWARD,
            scheduled_delay_ms=0.0,
            suppressed_opcode=None,
            sanitized_payload=payload,
            reason=f"Benign Link-Layer control opcode 0x{opcode:02X} forwarded",
        )

    def _inspect_att(
        self,
        frame: MonitorBLEFrame,
        link_state: _LinkHandshakeState,
        opcode: int,
        *,
        elapsed_ms: float | None,
        suppress_unauthenticated_handshakes: bool,
    ) -> MonitoredFrameDecision:
        payload = frame.payload

        # 1. CSRK Signed Write Command (0xD2)
        if opcode == ATT_SIGNED_WRITE_CMD:
            link_state.probe_start_ts = frame.timestamp
            if suppress_unauthenticated_handshakes:
                is_valid, detail = False, "Blocked unauthenticated CSRK probe under gateway policy"
            else:
                is_valid, detail = self._verify_signed_write(frame, link_state, payload)

            self._leakable_events += 1
            delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
            if not is_valid:
                if self.config.suppress_unpaired_csrk_drops:
                    self._mitigated_events += 1
                    return self._silent_drop(
                        opcode=ATT_SIGNED_WRITE_CMD,
                        delay_ms=delay_ms,
                        reason=f"Suppressed unpaired/invalid CSRK write ({detail})",
                    )
                return MonitoredFrameDecision(
                    action=FrameAction.FORWARD,
                    scheduled_delay_ms=0.0,
                    suppressed_opcode=None,
                    sanitized_payload=payload,
                    reason=f"Forwarded invalid CSRK write ({detail}; suppression disabled)",
                )

            if self.config.constant_time_window_ms > 0.0:
                self._mitigated_events += 1
            return self._pace_or_forward(
                payload=payload,
                delay_ms=delay_ms,
                reason_paced=f"{detail}; paced ACK window uniformly",
                reason_forward=detail,
            )

        # 2. ATT Error Response (0x01) on unauthenticated link
        if opcode == ATT_ERROR_RSP and not link_state.authenticated:
            self._leakable_events += 1
            if self.config.suppress_explicit_rejections:
                self._mitigated_events += 1
                delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)
                return self._silent_drop(
                    opcode=ATT_ERROR_RSP,
                    delay_ms=delay_ms,
                    reason="Suppressed unauthenticated ATT_ERROR_RSP via constant-time silent drop",
                )
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason="Forwarded ATT_ERROR_RSP (suppression disabled)",
            )

        # 3. GATT Auth Write Request / Command (0x12 / 0x52)
        if opcode in (ATT_WRITE_REQ, ATT_WRITE_CMD):
            link_state.probe_start_ts = frame.timestamp
            return MonitoredFrameDecision(
                action=FrameAction.FORWARD,
                scheduled_delay_ms=0.0,
                suppressed_opcode=None,
                sanitized_payload=payload,
                reason=f"Recorded ATT write probe 0x{opcode:02X}",
            )

        # 4. GATT Handle Value Notification (0x1B, e.g. application-layer auth token response)
        if opcode == ATT_HANDLE_VALUE_NOTI:
            peer_authorized = (
                frame.dest_mac.upper() in self._authenticated_peers
                or frame.source_mac.upper() in self._authenticated_peers
            )
            self._leakable_events += 1
            delay_ms = self._compute_scheduled_delay(elapsed_ms, link_state, frame.timestamp)

            if len(payload) < 3 or (suppress_unauthenticated_handshakes and not peer_authorized):
                if self.config.suppress_explicit_rejections:
                    self._mitigated_events += 1
                    return self._silent_drop(
                        opcode=ATT_HANDLE_VALUE_NOTI,
                        delay_ms=delay_ms,
                        reason="Suppressed malformed or unauthenticated GATT auth notification",
                    )
                return MonitoredFrameDecision(
                    action=FrameAction.FORWARD,
                    scheduled_delay_ms=0.0,
                    suppressed_opcode=None,
                    sanitized_payload=payload,
                    reason="Forwarded GATT notification (suppression disabled)",
                )

            if self.config.constant_time_window_ms > 0.0:
                self._mitigated_events += 1
            return self._pace_or_forward(
                payload=payload,
                delay_ms=delay_ms,
                reason_paced="Paced GATT auth notification (0x1B) to constant-time window",
                reason_forward="Forwarded GATT auth notification (0x1B)",
            )

        return MonitoredFrameDecision(
            action=FrameAction.FORWARD,
            scheduled_delay_ms=0.0,
            suppressed_opcode=None,
            sanitized_payload=payload,
            reason=f"Benign ATT PDU 0x{opcode:02X} forwarded",
        )

    def compute_exposure_report(self) -> SideChannelExposureReport:
        """Compute before/after boolean oracle distinguishability across inspected frames.

        Returns:
            `SideChannelExposureReport` summarizing suppression counts and oracle advantage.
        """
        if self._leakable_events == 0:
            before = 0.0
            after = 0.0
        else:
            before = 1.0
            unmitigated = max(0, self._leakable_events - self._mitigated_events)
            after = unmitigated / float(self._leakable_events)

        return SideChannelExposureReport(
            total_frames=self._total_frames,
            suppressed_rejections=self._suppressed_rejections,
            uniform_delays_applied=self._uniform_delays_applied,
            oracle_distinguishability_before=before,
            oracle_distinguishability_after=after,
        )
