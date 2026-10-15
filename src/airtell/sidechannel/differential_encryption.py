"""Differential Encryption Initiation side-channel analyzer.

Analyzes Link-Layer encryption handshakes to infer whether a central and peripheral
share a valid Long Term Key (LTK) or whether untrusted pairing attempts are rejected.

Targets the boolean oracle created by differential Link-Layer control responses:
- Positive branch: LL_START_ENC_RSP (0x06) confirming shared LTK possession.
- Negative branch: LL_REJECT_IND (0x0D) or LL_REJECT_EXT_IND (0x11) with error code
  0x06 (PIN_OR_KEY_MISSING) exposing untrusted / non-bonded credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from airtell.sidechannel.ll_dissector import (
    DissectedDataPdu,
    dissect_advertising_pdu,
    dissect_data_channel_pdu,
)
from airtell.sidechannel.models import (
    AnalyzerReport,
    BlePacketRecord,
    EncryptionInitiationFinding,
    SideChannelAnalyzer,
    SideChannelType,
    Verdict,
)
from airtell.sidechannel.synthetic import (
    ERROR_PIN_OR_KEY_MISSING,
    ERROR_UNSUPPORTED_REMOTE_FEATURE,
    OPCODE_LL_ENC_REQ,
    OPCODE_LL_ENC_RSP,
    OPCODE_LL_REJECT_EXT_IND,
    OPCODE_LL_REJECT_IND,
    OPCODE_LL_START_ENC_REQ,
    OPCODE_LL_START_ENC_RSP,
    OPCODE_LL_TERMINATE_IND,
)
from airtell.sniff.pcap import BLE_ADV_AA


class EncryptionSessionState(str, Enum):
    """Link-Layer encryption handshake state machine states."""

    IDLE = "IDLE"
    ENC_REQUESTED = "ENC_REQUESTED"
    ENC_RESPONDED = "ENC_RESPONDED"
    START_ENC_REQUESTED = "START_ENC_REQUESTED"
    ENCRYPTION_ESTABLISHED = "ENCRYPTION_ESTABLISHED"
    ENCRYPTION_REJECTED = "ENCRYPTION_REJECTED"
    TERMINATED = "TERMINATED"


@dataclass
class EncryptionSession:
    """Tracks state and parameters for a single BLE connection session."""

    conn_aa: int
    central_addr: str = "UNKNOWN"
    periph_addr: str = "UNKNOWN"
    state: EncryptionSessionState = EncryptionSessionState.IDLE
    ediv: int | None = None
    rand_hex: str | None = None
    skdm_hex: str | None = None
    skds_hex: str | None = None
    ivm_hex: str | None = None
    ivs_hex: str | None = None
    error_code: int | None = None
    reject_opcode: int | None = None
    start_ts: float = 0.0
    last_ts: float = 0.0
    findings_emitted: list[EncryptionInitiationFinding] = field(default_factory=list)


class DifferentialEncryptionAnalyzer(SideChannelAnalyzer):
    """Link-Layer Differential Encryption Initiation side-channel analyzer."""

    def __init__(self, target_mac: str | None = None) -> None:
        """Initialize analyzer.

        Args:
            target_mac: Optional target peripheral or central MAC address to filter on.
        """
        self.target_mac = target_mac.upper() if target_mac else None
        self._sessions: dict[int, EncryptionSession] = {}
        self._all_findings: list[EncryptionInitiationFinding] = []
        self._addr_to_aa: dict[str, int] = {}
        self._packets_processed = 0

    def reset(self) -> None:
        """Reset internal tracking state."""
        self._sessions.clear()
        self._all_findings.clear()
        self._addr_to_aa.clear()
        self._packets_processed = 0

    def _get_or_create_session(self, aa: int, ts: float) -> EncryptionSession:
        if aa not in self._sessions:
            session = EncryptionSession(
                conn_aa=aa,
                central_addr=f"CENTRAL_{aa:08X}",
                periph_addr=f"PERIPH_{aa:08X}",
                start_ts=ts,
                last_ts=ts,
            )
            self._sessions[aa] = session
        session = self._sessions[aa]
        session.last_ts = ts
        return session

    def process_packet(self, packet: BlePacketRecord | Any) -> list[EncryptionInitiationFinding]:
        """Process a single BLE packet and return any newly generated findings."""
        record = BlePacketRecord.coerce(packet)
        self._packets_processed += 1
        new_findings: list[EncryptionInitiationFinding] = []

        # 1. Check for connection establishment on advertising channels
        if record.access_address == BLE_ADV_AA or record.channel >= 37:
            adv_pdu = dissect_advertising_pdu(record.body)
            if adv_pdu and adv_pdu.pdu_type == 0x05:  # CONNECT_IND
                if adv_pdu.conn_aa is not None and adv_pdu.init_a and adv_pdu.adv_a:
                    session = self._get_or_create_session(adv_pdu.conn_aa, record.timestamp)
                    session.central_addr = adv_pdu.init_a.upper()
                    session.periph_addr = adv_pdu.adv_a.upper()
                    self._addr_to_aa[session.central_addr] = adv_pdu.conn_aa
                    self._addr_to_aa[session.periph_addr] = adv_pdu.conn_aa
            return new_findings

        # 2. Data channel packets
        data_pdu: DissectedDataPdu | None = dissect_data_channel_pdu(record.body)
        if not data_pdu or not data_pdu.control_frame:
            return new_findings

        ctrl = data_pdu.control_frame
        session = self._get_or_create_session(record.access_address, record.timestamp)

        # Apply target filter if configured
        if self.target_mac:
            target_aa = self._addr_to_aa.get(self.target_mac)
            matches_addr = (
                session.periph_addr == self.target_mac
                or session.central_addr == self.target_mac
            )
            matches_aa = target_aa is not None and record.access_address == target_aa
            if not matches_addr and not matches_aa:
                return new_findings

        opcode = ctrl.opcode
        payload = ctrl.payload

        if opcode == OPCODE_LL_ENC_REQ:
            session.state = EncryptionSessionState.ENC_REQUESTED
            session.ediv = payload.get("ediv")
            session.rand_hex = payload.get("rand_hex")
            session.skdm_hex = payload.get("skdm_hex")
            session.ivm_hex = payload.get("ivm_hex")

        elif opcode == OPCODE_LL_ENC_RSP:
            session.state = EncryptionSessionState.ENC_RESPONDED
            session.skds_hex = payload.get("skds_hex")
            session.ivs_hex = payload.get("ivs_hex")

        elif opcode == OPCODE_LL_START_ENC_REQ:
            session.state = EncryptionSessionState.START_ENC_REQUESTED

        elif opcode == OPCODE_LL_START_ENC_RSP:
            # Positive branch: Shared LTK confirmed
            if (
                session.state == EncryptionSessionState.ENCRYPTION_ESTABLISHED
                or any(f.details.get("is_shared_ltk") is True for f in session.findings_emitted)
            ):
                # Suppress duplicate finding on retransmission or peer's LL_START_ENC_RSP
                session.state = EncryptionSessionState.ENCRYPTION_ESTABLISHED
                return new_findings

            session.state = EncryptionSessionState.ENCRYPTION_ESTABLISHED
            finding = EncryptionInitiationFinding(
                finding_type=SideChannelType.DIFFERENTIAL_ENCRYPTION.value,
                timestamp=record.timestamp,
                device_addr=session.periph_addr,
                target_addr=session.central_addr,
                verdict=Verdict.PAIRED_SHARED_LTK.value,
                confidence=1.0,
                details={
                    "stage": "ENCRYPTION_ESTABLISHED",
                    "opcode": opcode,
                    "opcode_name": ctrl.name,
                    "is_shared_ltk": True,
                    "session_aa": session.conn_aa,
                    "ediv": session.ediv,
                    "rand": session.rand_hex,
                    "summary": (
                        f"Device {session.periph_addr} accepted encryption with "
                        f"central {session.central_addr} confirming possession of shared LTK."
                    ),
                },
            )
            session.findings_emitted.append(finding)
            self._all_findings.append(finding)
            new_findings.append(finding)

        elif opcode in (OPCODE_LL_REJECT_IND, OPCODE_LL_REJECT_EXT_IND):
            # For LL_REJECT_EXT_IND, only treat as encryption rejection if reject_opcode is LL_ENC_REQ (0x03)
            reject_op = payload.get("reject_opcode")
            if opcode == OPCODE_LL_REJECT_EXT_IND and reject_op != OPCODE_LL_ENC_REQ:
                # Disregard rejections of other control opcodes (e.g. conn param, channel map)
                return new_findings

            # In-session state isolation: A connection that already established encryption
            # retains its PAIRED_SHARED_LTK status and cannot be demoted by later rejections.
            if session.state == EncryptionSessionState.ENCRYPTION_ESTABLISHED:
                return new_findings

            # Suppress duplicate rejection findings on retransmissions
            if session.state == EncryptionSessionState.ENCRYPTION_REJECTED:
                return new_findings

            session.state = EncryptionSessionState.ENCRYPTION_REJECTED
            error_code = payload.get("error_code")
            session.error_code = error_code
            session.reject_opcode = reject_op

            is_missing_key = error_code == ERROR_PIN_OR_KEY_MISSING
            is_unsupported = error_code == ERROR_UNSUPPORTED_REMOTE_FEATURE

            verdict = (
                Verdict.REJECTED_UNTRUSTED.value
                if is_missing_key
                else Verdict.UNPAIRED_KEY_REJECTED.value
            )
            confidence = 1.0 if is_missing_key else 0.85

            err_str = f"0x{error_code:02X}" if error_code is not None else "UNKNOWN"
            finding = EncryptionInitiationFinding(
                finding_type=SideChannelType.DIFFERENTIAL_ENCRYPTION.value,
                timestamp=record.timestamp,
                device_addr=session.periph_addr,
                target_addr=session.central_addr,
                verdict=verdict,
                confidence=confidence,
                details={
                    "stage": "ENCRYPTION_REJECTED",
                    "opcode": opcode,
                    "opcode_name": ctrl.name,
                    "is_shared_ltk": False,
                    "session_aa": session.conn_aa,
                    "error_code": error_code,
                    "reject_opcode": reject_op,
                    "is_pin_or_key_missing": is_missing_key,
                    "is_unsupported_feature": is_unsupported,
                    "ediv": session.ediv,
                    "rand": session.rand_hex,
                    "summary": (
                        f"Device {session.periph_addr} rejected encryption setup from "
                        f"central {session.central_addr} (ErrorCode={err_str} "
                        f"{'PIN_OR_KEY_MISSING' if is_missing_key else ''})."
                    ).rstrip(),
                },
            )
            session.findings_emitted.append(finding)
            self._all_findings.append(finding)
            new_findings.append(finding)

        elif opcode == OPCODE_LL_TERMINATE_IND:
            if session.state not in (
                EncryptionSessionState.ENCRYPTION_ESTABLISHED,
                EncryptionSessionState.ENCRYPTION_REJECTED,
            ):
                session.state = EncryptionSessionState.TERMINATED
            if session.error_code is None:
                session.error_code = payload.get("error_code")

        return new_findings

    def finalize(self) -> AnalyzerReport:
        """Produce the aggregated Differential Encryption analysis report."""
        total_sessions = len(self._sessions)
        shared_ltk_sessions = [
            s
            for s in self._sessions.values()
            if any(f.details.get("is_shared_ltk") is True for f in s.findings_emitted)
        ]
        rejected_sessions = [
            s
            for s in self._sessions.values()
            if s not in shared_ltk_sessions
            and any(f.details.get("is_shared_ltk") is False for f in s.findings_emitted)
        ]
        shared_ltk_count = len(shared_ltk_sessions)
        rejected_count = len(rejected_sessions)
        pin_missing_count = sum(
            1
            for s in rejected_sessions
            if any(
                f.details.get("error_code") == ERROR_PIN_OR_KEY_MISSING
                for f in s.findings_emitted
            )
        )

        if shared_ltk_count > 0 and rejected_count == 0:
            overall_verdict = Verdict.PAIRED_SHARED_LTK.value
            summary = (
                f"Observed {shared_ltk_count} session(s) with confirmed shared LTK possession "
                f"via LL_START_ENC_RSP across {total_sessions} connection(s)."
            )
        elif rejected_count > 0 and shared_ltk_count == 0:
            if pin_missing_count > 0:
                overall_verdict = Verdict.REJECTED_UNTRUSTED.value
                summary = (
                    f"Observed {rejected_count} session(s) with untrusted encryption rejection "
                    f"({pin_missing_count} with PIN_OR_KEY_MISSING error 0x06)."
                )
            else:
                overall_verdict = Verdict.UNPAIRED_KEY_REJECTED.value
                summary = (
                    f"Observed {rejected_count} session(s) with encryption rejection "
                    f"(non-PIN error, e.g. unsupported feature or auth failure)."
                )
        elif shared_ltk_count > 0 and rejected_count > 0:
            overall_verdict = Verdict.CONFIRMED_EXCLUSIVE.value
            summary = (
                f"Differential encryption side-channel confirmed: {shared_ltk_count} session(s) "
                f"accepted with shared LTK, {rejected_count} session(s) rejected as untrusted."
            )
        else:
            overall_verdict = Verdict.INCONCLUSIVE.value
            summary = (
                f"No complete encryption initiation handshakes observed across {total_sessions} "
                f"connection session(s)."
            )

        metrics = {
            "packets_processed": self._packets_processed,
            "total_connections": total_sessions,
            "shared_ltk_sessions": shared_ltk_count,
            "rejected_sessions": rejected_count,
            "pin_missing_errors": pin_missing_count,
            "findings_count": len(self._all_findings),
        }

        return AnalyzerReport(
            analyzer_name="DifferentialEncryptionAnalyzer",
            verdict=overall_verdict,
            summary=summary,
            findings=list(self._all_findings),
            metrics=metrics,
        )
