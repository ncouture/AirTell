"""CSRK Data Signing & 32-bit SignCounter Monotonicity side-channel analyzer.

Tracks Attribute Protocol (ATT) Signed Write commands (Opcode 0xD2) and evaluates:
1. 32-bit SignCounter (SC) strictly monotonic increments (Delta SC = 1).
2. Cross-RPA linking: correlating rotating MAC addresses exhibiting continuous counter
   trajectories to deanonymize devices bypassing address randomization.
3. Cryptographic integrity: verifying 64-bit truncated AES-CMAC signatures when CSRK is known.
4. Anomaly detection: flagging replay attacks (Delta SC = 0), rollbacks (Delta SC < 0),
   and gaps/jumps (Delta SC > 1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from airtell.sidechannel.ll_dissector import (
    dissect_advertising_pdu,
    dissect_data_channel_pdu,
)
from airtell.sidechannel.models import (
    AnalyzerReport,
    BlePacketRecord,
    CsrkCounterFinding,
    SideChannelAnalyzer,
    SideChannelType,
    Verdict,
)
from airtell.sniff.pcap import BLE_ADV_AA


@dataclass
class SenderCounterState:
    """Tracks counter progression for a specific sender address or identity."""

    sender_addr: str
    last_counter: int | None = None
    seen_counters: set[int] = field(default_factory=set)
    counter_history: list[int] = field(default_factory=list)
    packet_count: int = 0
    replay_count: int = 0
    rollback_count: int = 0
    jump_count: int = 0
    mac_failure_count: int = 0


@dataclass
class RecentSenderRecord:
    """Tracks recent sender counter state for scoped cross-RPA linking."""

    sender_addr: str
    target_addr: str
    last_sc: int
    timestamp: float
    handle: int
    access_address: int


class CsrkCounterAnalyzer(SideChannelAnalyzer):
    """CSRK 32-bit SignCounter monotonicity and integrity analyzer."""

    def __init__(
        self,
        csrk: bytes | None = None,
        target_mac: str | None = None,
        gap_threshold: int = 1,
    ) -> None:
        """Initialize analyzer.

        Args:
            csrk: Optional 16-byte Connection Signature Resolving Key for MAC verification.
            target_mac: Optional target device MAC address to filter on.
            gap_threshold: Maximum delta considered normal before flagging as jump anomaly (default 1).
        """
        if csrk is not None and len(csrk) != 16:
            raise ValueError(f"CSRK must be 16 bytes, got {len(csrk)}")
        self.csrk = csrk
        self.target_mac = target_mac.upper() if target_mac else None
        self.gap_threshold = gap_threshold

        self._senders: dict[str, SenderCounterState] = {}
        self._conn_map: dict[int, tuple[str, str]] = {}  # conn_aa -> (central, periph)
        self._all_findings: list[CsrkCounterFinding] = []
        self._linked_rpas: list[list[str]] = []  # groups of linked addresses
        self._recent_senders: list[RecentSenderRecord] = []
        self._packets_processed = 0

    def reset(self) -> None:
        """Reset internal tracking state."""
        self._senders.clear()
        self._conn_map.clear()
        self._all_findings.clear()
        self._linked_rpas.clear()
        self._recent_senders.clear()
        self._packets_processed = 0

    def _get_or_create_sender(self, addr: str) -> SenderCounterState:
        if addr not in self._senders:
            self._senders[addr] = SenderCounterState(sender_addr=addr)
        return self._senders[addr]

    def _check_cross_rpa_link(
        self,
        current_sender: str,
        target_addr: str,
        counter: int,
        timestamp: float,
        handle: int,
        access_address: int,
    ) -> str | None:
        """Check if current counter continues a previous sender's counter sequence.

        Requires shared context:
        - Same target peripheral address (target_addr)
        - Realistic temporal window (dt <= 300.0s)
        - Sequential counter progression (1 <= delta <= 5)
        """
        for prev in reversed(self._recent_senders):
            if prev.sender_addr == current_sender:
                continue
            # Scoped to the same target peripheral
            if prev.target_addr != target_addr:
                continue
            # Temporal window check (e.g. <= 300 seconds)
            dt = timestamp - prev.timestamp
            if dt < 0 or dt > 300.0:
                continue
            delta = counter - prev.last_sc
            # If delta is sequential (+1) or small gap (e.g. +2)
            if 1 <= delta <= 5:
                # Link prev.sender_addr and current_sender
                self._record_linked_rpas(prev.sender_addr, current_sender)
                return prev.sender_addr
        return None

    def _add_recent_sender(
        self,
        sender_addr: str,
        target_addr: str,
        counter: int,
        timestamp: float,
        handle: int,
        access_address: int,
    ) -> None:
        rec = RecentSenderRecord(
            sender_addr=sender_addr,
            target_addr=target_addr,
            last_sc=counter,
            timestamp=timestamp,
            handle=handle,
            access_address=access_address,
        )
        self._recent_senders.append(rec)
        # Cap recent senders to 500 entries
        if len(self._recent_senders) > 500:
            self._recent_senders.pop(0)

    def _record_linked_rpas(self, addr1: str, addr2: str) -> None:
        """Group linked addresses together."""
        for group in self._linked_rpas:
            if addr1 in group or addr2 in group:
                if addr1 not in group:
                    group.append(addr1)
                if addr2 not in group:
                    group.append(addr2)
                return
        self._linked_rpas.append([addr1, addr2])

    def process_packet(self, packet: BlePacketRecord | Any) -> list[CsrkCounterFinding]:
        """Process a single BLE packet and return any new findings."""
        record = BlePacketRecord.coerce(packet)
        self._packets_processed += 1
        new_findings: list[CsrkCounterFinding] = []

        # 1. Advertising channel: track connection setup (CONNECT_IND)
        if record.access_address == BLE_ADV_AA or record.channel >= 37:
            adv_pdu = dissect_advertising_pdu(record.body)
            if adv_pdu and adv_pdu.pdu_type == 0x05:  # CONNECT_IND
                if adv_pdu.conn_aa is not None and adv_pdu.init_a and adv_pdu.adv_a:
                    self._conn_map[adv_pdu.conn_aa] = (
                        adv_pdu.init_a.upper(),
                        adv_pdu.adv_a.upper(),
                    )
            return new_findings

        # 2. Data channel: inspect for ATT Signed Write (Opcode 0xD2)
        data_pdu = dissect_data_channel_pdu(record.body, csrk=self.csrk)
        if not data_pdu:
            return new_findings

        # Check for ATT Error Response (0x01) on signed write
        if data_pdu.att_error:
            err = data_pdu.att_error
            central_addr, periph_addr = self._conn_map.get(
                record.access_address,
                (f"CENTRAL_{record.access_address:08X}", f"PERIPH_{record.access_address:08X}"),
            )
            finding = CsrkCounterFinding(
                finding_type=SideChannelType.CSRK_COUNTER.value,
                timestamp=record.timestamp,
                device_addr=central_addr,
                target_addr=periph_addr,
                verdict=Verdict.VERIFICATION_FAILED.value,
                confidence=1.0,
                details={
                    "stage": "ATT_ERROR_RESPONSE",
                    "req_opcode": err.req_opcode,
                    "handle": err.handle,
                    "error_code": err.error_code,
                    "summary": f"Receiver returned ATT Error 0x{err.error_code:02X} for opcode 0x{err.req_opcode:02X}",
                },
            )
            self._all_findings.append(finding)
            new_findings.append(finding)
            return new_findings

        if not data_pdu.att_frame:
            return new_findings

        att = data_pdu.att_frame
        counter = att.sign_counter
        handle = att.handle

        # Resolve sender address
        central_addr, periph_addr = self._conn_map.get(
            record.access_address,
            (f"CENTRAL_{record.access_address:08X}", f"PERIPH_{record.access_address:08X}"),
        )
        sender_addr = central_addr if record.direction == 0 else periph_addr
        receiver_addr = periph_addr if record.direction == 0 else central_addr

        if self.target_mac and self.target_mac != sender_addr and self.target_mac != receiver_addr:
            return new_findings

        sender_state = self._get_or_create_sender(sender_addr)
        sender_state.packet_count += 1

        # A. Check cryptographic MAC verification if checked
        if att.mac_valid is False:
            sender_state.mac_failure_count += 1
            finding = CsrkCounterFinding(
                finding_type=SideChannelType.CSRK_COUNTER.value,
                timestamp=record.timestamp,
                device_addr=sender_addr,
                target_addr=receiver_addr,
                verdict=Verdict.VERIFICATION_FAILED.value,
                confidence=1.0,
                details={
                    "counter": counter,
                    "handle": handle,
                    "mac_hex": att.mac.hex(),
                    "mac_valid": False,
                    "is_anomaly": True,
                    "summary": f"Cryptographic signature verification failed for counter {counter} on {sender_addr}.",
                },
            )
            self._all_findings.append(finding)
            new_findings.append(finding)
            # Prevent state poisoning: immediately abort without updating counter progression!
            return new_findings

        sender_state.counter_history.append(counter)

        # B. Check for Cross-RPA address linking if this sender is seeing its first packet
        if sender_state.last_counter is None:
            linked_prev = self._check_cross_rpa_link(
                current_sender=sender_addr,
                target_addr=receiver_addr,
                counter=counter,
                timestamp=record.timestamp,
                handle=handle,
                access_address=record.access_address,
            )
            if linked_prev:
                finding = CsrkCounterFinding(
                    finding_type=SideChannelType.CSRK_COUNTER.value,
                    timestamp=record.timestamp,
                    device_addr=sender_addr,
                    target_addr=receiver_addr,
                    verdict=Verdict.CROSS_RPA_LINKED.value,
                    confidence=0.98,
                    details={
                        "counter": counter,
                        "linked_from": linked_prev,
                        "delta": counter - (self._senders[linked_prev].last_counter or 0),
                        "summary": (
                            f"Cross-RPA link established: {sender_addr} continued sequential "
                            f"counter trajectory from previous RPA {linked_prev} at SC={counter}."
                        ),
                    },
                )
                self._all_findings.append(finding)
                new_findings.append(finding)

        # C. Evaluate counter delta for monotonicity and anomalies
        if sender_state.last_counter is not None:
            delta = counter - sender_state.last_counter
            if 1 <= delta <= self.gap_threshold:
                # Strictly monotonic sequential increment
                sender_state.seen_counters.add(counter)
                sender_state.last_counter = counter
                finding = CsrkCounterFinding(
                    finding_type=SideChannelType.CSRK_COUNTER.value,
                    timestamp=record.timestamp,
                    device_addr=sender_addr,
                    target_addr=receiver_addr,
                    verdict=Verdict.SEQUENTIAL_MONOTONIC.value,
                    confidence=1.0,
                    details={
                        "counter": counter,
                        "prev_counter": sender_state.last_counter,
                        "delta": delta,
                        "handle": handle,
                        "mac_valid": att.mac_valid,
                        "is_anomaly": False,
                    },
                )
                self._all_findings.append(finding)
                new_findings.append(finding)

            elif delta <= 0:
                # Replay vs Rollback
                is_replay = counter in sender_state.seen_counters or delta == 0
                if is_replay:
                    sender_state.replay_count += 1
                    verdict = Verdict.ANOMALY_REPLAY.value
                    summary = f"Replayed SignCounter detected: SC={counter} retransmitted by {sender_addr}."
                else:
                    sender_state.rollback_count += 1
                    verdict = Verdict.ANOMALY_ROLLBACK.value
                    summary = f"SignCounter rollback detected: SC decreased from {sender_state.last_counter} to {counter}."

                finding = CsrkCounterFinding(
                    finding_type=SideChannelType.CSRK_COUNTER.value,
                    timestamp=record.timestamp,
                    device_addr=sender_addr,
                    target_addr=receiver_addr,
                    verdict=verdict,
                    confidence=1.0,
                    details={
                        "counter": counter,
                        "prev_counter": sender_state.last_counter,
                        "delta": delta,
                        "handle": handle,
                        "is_anomaly": True,
                        "summary": summary,
                    },
                )
                self._all_findings.append(finding)
                new_findings.append(finding)
                # Monotonic high-water mark: do NOT regress last_counter downwards!
                # sender_state.last_counter remains max(sender_state.last_counter, counter)

            elif delta > self.gap_threshold:
                # Gap / Jump anomaly
                sender_state.jump_count += 1
                sender_state.seen_counters.add(counter)
                sender_state.last_counter = max(sender_state.last_counter, counter)
                finding = CsrkCounterFinding(
                    finding_type=SideChannelType.CSRK_COUNTER.value,
                    timestamp=record.timestamp,
                    device_addr=sender_addr,
                    target_addr=receiver_addr,
                    verdict=Verdict.ANOMALY_JUMP.value,
                    confidence=0.9,
                    details={
                        "counter": counter,
                        "prev_counter": sender_state.last_counter,
                        "delta": delta,
                        "handle": handle,
                        "is_anomaly": True,
                        "summary": f"SignCounter gap/jump detected: delta={delta} ({sender_state.last_counter} -> {counter}).",
                    },
                )
                self._all_findings.append(finding)
                new_findings.append(finding)

        else:
            # First packet for this sender: record initial counter observation
            sender_state.seen_counters.add(counter)
            sender_state.last_counter = counter
            finding = CsrkCounterFinding(
                finding_type=SideChannelType.CSRK_COUNTER.value,
                timestamp=record.timestamp,
                device_addr=sender_addr,
                target_addr=receiver_addr,
                verdict=Verdict.SEQUENTIAL_MONOTONIC.value,
                confidence=0.9,
                details={
                    "counter": counter,
                    "initial_counter": True,
                    "handle": handle,
                    "mac_valid": att.mac_valid,
                    "is_anomaly": False,
                },
            )
            self._all_findings.append(finding)
            new_findings.append(finding)

        self._add_recent_sender(
            sender_addr=sender_addr,
            target_addr=receiver_addr,
            counter=counter,
            timestamp=record.timestamp,
            handle=handle,
            access_address=record.access_address,
        )

        return new_findings

    def finalize(self) -> AnalyzerReport:
        """Produce the aggregated CSRK Counter analysis report."""
        total_signed_writes = sum(s.packet_count for s in self._senders.values())
        total_replays = sum(s.replay_count for s in self._senders.values())
        total_rollbacks = sum(s.rollback_count for s in self._senders.values())
        total_jumps = sum(s.jump_count for s in self._senders.values())
        total_mac_fails = sum(s.mac_failure_count for s in self._senders.values())
        total_anomalies = total_replays + total_rollbacks + total_jumps + total_mac_fails
        linked_groups = list(self._linked_rpas)

        if total_signed_writes == 0:
            overall_verdict = Verdict.INCONCLUSIVE.value
            summary = "No ATT Signed Write commands observed."
        elif total_mac_fails > 0:
            overall_verdict = Verdict.VERIFICATION_FAILED.value
            summary = f"Detected {total_mac_fails} cryptographic signature verification failure(s) across {total_signed_writes} writes."
        elif total_replays > 0:
            overall_verdict = Verdict.ANOMALY_REPLAY.value
            summary = f"Detected {total_replays} counter replay anomaly(ies) across {total_signed_writes} writes."
        elif total_rollbacks > 0:
            overall_verdict = Verdict.ANOMALY_ROLLBACK.value
            summary = f"Detected {total_rollbacks} counter rollback anomaly(ies) across {total_signed_writes} writes."
        elif total_jumps > 0:
            overall_verdict = Verdict.ANOMALY_JUMP.value
            summary = f"Detected {total_jumps} counter jump/gap anomaly(ies) across {total_signed_writes} writes."
        elif len(linked_groups) > 0:
            overall_verdict = Verdict.CROSS_RPA_LINKED.value
            summary = (
                f"Successfully linked {len(linked_groups)} group(s) of rotating RPAs via continuous "
                f"SignCounter progression across {total_signed_writes} valid sequential writes."
            )
        else:
            overall_verdict = Verdict.SEQUENTIAL_MONOTONIC.value
            summary = f"Observed {total_signed_writes} strictly monotonic sequential signed write(s) with 0 anomalies."

        metrics = {
            "packets_processed": self._packets_processed,
            "total_signed_writes": total_signed_writes,
            "total_senders": len(self._senders),
            "total_anomalies": total_anomalies,
            "replay_anomalies": total_replays,
            "rollback_anomalies": total_rollbacks,
            "jump_anomalies": total_jumps,
            "mac_verification_failures": total_mac_fails,
            "linked_rpa_groups": linked_groups,
            "findings_count": len(self._all_findings),
        }

        return AnalyzerReport(
            analyzer_name="CsrkCounterAnalyzer",
            verdict=overall_verdict,
            summary=summary,
            findings=list(self._all_findings),
            metrics=metrics,
        )
