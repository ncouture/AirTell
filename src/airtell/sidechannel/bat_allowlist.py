"""Bluetooth Address Tracking (BAT) and Auto-Connection Allowlist analyzer.

Implements detection and analysis for:
1. Selective Allowlist Probe Responses (ACM CCS 2022 BAT Attack):
   - Quantifies differential response timing (selective 150us T_IFS response to allowed RPAs
     versus complete radio silence for foreign/unauthorized RPAs).
2. Directed Exclusive Advertising:
   - Detection of ADV_DIRECT_IND high-duty and low-duty bursts declaring exclusive bonding.
3. Fast vs. Slow Advertising Transition Tracking:
   - Distinguishes post-disconnect fast advertising bursts (20-50ms) from slow background standby (1000-2500ms).
4. Connection Parameter Fingerprinting:
   - Extracts connection parameter 4-tuples <Interval, Latency, Timeout, Hop> to identify
     exclusive-use peripherals across RPA address rotations.
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
    BatAllowlistFinding,
    BlePacketRecord,
    SideChannelAnalyzer,
    SideChannelType,
    Verdict,
)
from airtell.sniff.pcap import BLE_ADV_AA


@dataclass
class PendingProbe:
    """Tracks a pending SCAN_REQ awaiting a SCAN_RSP."""

    scanner_addr: str
    target_addr: str
    timestamp_usec: int


@dataclass
class PeripheralAllowlistState:
    """Tracks advertising and allowlist behavior for a specific peripheral."""

    peripheral_addr: str
    adv_timestamps: list[int] = field(default_factory=list)
    measured_intervals_ms: list[float] = field(default_factory=list)
    probes_responded: dict[str, int] = field(default_factory=dict)  # scanner -> count
    probes_silenced: dict[str, int] = field(default_factory=dict)  # scanner -> count
    response_delays_usec: dict[str, list[int]] = field(default_factory=dict)
    directed_targets: set[str] = field(default_factory=set)
    directed_burst_count: int = 0
    connection_profiles: list[tuple[int, int, int, int]] = field(default_factory=list)
    fast_adv_observed: bool = False
    slow_adv_observed: bool = False


class BatAllowlistAnalyzer(SideChannelAnalyzer):
    """Bluetooth Address Tracking (BAT) and Allowlist behavior analyzer."""

    def __init__(self, target_mac: str | None = None) -> None:
        """Initialize analyzer.

        Args:
            target_mac: Optional target peripheral or scanner MAC address to filter on.
        """
        self.target_mac = target_mac.upper() if target_mac else None
        self._peripherals: dict[str, PeripheralAllowlistState] = {}
        self._pending_probes: list[PendingProbe] = []
        self._all_findings: list[BatAllowlistFinding] = []
        self._packets_processed = 0

    def reset(self) -> None:
        """Reset internal tracking state."""
        self._peripherals.clear()
        self._pending_probes.clear()
        self._all_findings.clear()
        self._packets_processed = 0

    def _get_or_create_periph(self, addr: str) -> PeripheralAllowlistState:
        if addr not in self._peripherals:
            self._peripherals[addr] = PeripheralAllowlistState(peripheral_addr=addr)
        return self._peripherals[addr]

    def _flush_expired_probes(self, current_usec: int) -> list[BatAllowlistFinding]:
        """Check for pending probes that received no response within T_IFS window (> 1000us)."""
        findings: list[BatAllowlistFinding] = []
        remaining: list[PendingProbe] = []

        for probe in self._pending_probes:
            # BLE T_IFS is 150us; if over 5000us (5ms) elapsed without SCAN_RSP, probe was silenced
            if current_usec - probe.timestamp_usec > 5000:
                p_state = self._get_or_create_periph(probe.target_addr)
                p_state.probes_silenced[probe.scanner_addr] = (
                    p_state.probes_silenced.get(probe.scanner_addr, 0) + 1
                )

                # Check if this peripheral has also responded to another scanner
                has_allowed = bool(p_state.probes_responded)
                if has_allowed:
                    # Clear selective allowlist behavior: responded to allowed peer, silent to this probe
                    allowed_peers = list(p_state.probes_responded.keys())
                    finding = BatAllowlistFinding(
                        finding_type=SideChannelType.BAT_ALLOWLIST.value,
                        timestamp=probe.timestamp_usec / 1_000_000.0,
                        device_addr=probe.target_addr,
                        target_addr=probe.scanner_addr,
                        verdict=Verdict.ALLOWLIST_CONFIRMED.value,
                        confidence=1.0,
                        details={
                            "mechanism": "SELECTIVE_PROBE_SILENCE",
                            "scanner_addr": probe.scanner_addr,
                            "allowed_peers": allowed_peers,
                            "silenced_count": p_state.probes_silenced[probe.scanner_addr],
                            "responded_count": sum(p_state.probes_responded.values()),
                            "summary": (
                                f"BAT Allowlist confirmed on {probe.target_addr}: peripheral selectively "
                                f"dropped SCAN_REQ from {probe.scanner_addr} while responding to {allowed_peers}."
                            ),
                        },
                    )
                    self._all_findings.append(finding)
                    findings.append(finding)
            else:
                remaining.append(probe)

        self._pending_probes = remaining
        return findings

    def process_packet(self, packet: BlePacketRecord | Any) -> list[BatAllowlistFinding]:
        """Process a single BLE packet and return any newly detected allowlist findings."""
        record = BlePacketRecord.coerce(packet)
        self._packets_processed += 1
        new_findings: list[BatAllowlistFinding] = []

        # Flush probes that expired before this packet's timestamp
        new_findings.extend(self._flush_expired_probes(record.timestamp_usec))

        # 1. Advertising Channel Packets
        if record.access_address == BLE_ADV_AA or record.channel >= 37:
            adv_pdu = dissect_advertising_pdu(record.body)
            if not adv_pdu:
                return new_findings

            pdu_type = adv_pdu.pdu_type

            # A. General Advertising (ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND)
            if pdu_type in (0x00, 0x02, 0x06) and adv_pdu.adv_a:
                adv_a = adv_pdu.adv_a.upper()
                if not self.target_mac or self.target_mac == adv_a:
                    p_state = self._get_or_create_periph(adv_a)
                    if p_state.adv_timestamps:
                        delta_ms = (record.timestamp_usec - p_state.adv_timestamps[-1]) / 1000.0
                        if delta_ms > 0:
                            p_state.measured_intervals_ms.append(delta_ms)
                            if len(p_state.measured_intervals_ms) > 100:
                                p_state.measured_intervals_ms.pop(0)
                            if 15.0 <= delta_ms <= 65.0:
                                p_state.fast_adv_observed = True
                            elif 700.0 <= delta_ms <= 3000.0:
                                p_state.slow_adv_observed = True
                    p_state.adv_timestamps.append(record.timestamp_usec)
                    if len(p_state.adv_timestamps) > 10:
                        p_state.adv_timestamps.pop(0)

            # B. Directed Advertising (ADV_DIRECT_IND)
            elif pdu_type == 0x01 and adv_pdu.adv_a and adv_pdu.target_a:
                adv_a = adv_pdu.adv_a.upper()
                target_a = adv_pdu.target_a.upper()
                if not self.target_mac or self.target_mac in (adv_a, target_a):
                    p_state = self._get_or_create_periph(adv_a)
                    p_state.directed_targets.add(target_a)
                    p_state.directed_burst_count += 1
                    finding = BatAllowlistFinding(
                        finding_type=SideChannelType.BAT_ALLOWLIST.value,
                        timestamp=record.timestamp,
                        device_addr=adv_a,
                        target_addr=target_a,
                        verdict=Verdict.DIRECTED_EXCLUSIVE.value,
                        confidence=1.0,
                        details={
                            "mechanism": "ADV_DIRECT_IND_BURST",
                            "peripheral_addr": adv_a,
                            "target_addr": target_a,
                            "burst_count": p_state.directed_burst_count,
                            "summary": (
                                f"Exclusive-use directed advertising detected from {adv_a} "
                                f"targeting companion address {target_a}."
                            ),
                        },
                    )
                    self._all_findings.append(finding)
                    new_findings.append(finding)

            # C. Active Probe (SCAN_REQ)
            elif pdu_type == 0x03 and adv_pdu.scan_a and adv_pdu.adv_a:
                scan_a = adv_pdu.scan_a.upper()
                adv_a = adv_pdu.adv_a.upper()
                if not self.target_mac or self.target_mac in (adv_a, scan_a):
                    self._pending_probes.append(
                        PendingProbe(
                            scanner_addr=scan_a,
                            target_addr=adv_a,
                            timestamp_usec=record.timestamp_usec,
                        )
                    )

            # D. Scan Response (SCAN_RSP)
            elif pdu_type == 0x04 and adv_pdu.adv_a:
                adv_a = adv_pdu.adv_a.upper()
                # Find matching pending probe minimizing |delay - 150us| within bounded tolerance [-50, 5000] us
                matched_idx = None
                best_diff = float("inf")
                for idx, probe in enumerate(self._pending_probes):
                    if probe.target_addr == adv_a:
                        delay_usec = record.timestamp_usec - probe.timestamp_usec
                        if -50 <= delay_usec <= 5000:  # Within bounded tolerance including clock skew
                            diff = abs(delay_usec - 150)
                            if diff < best_diff:
                                best_diff = diff
                                matched_idx = idx

                if matched_idx is not None:
                    probe = self._pending_probes.pop(matched_idx)
                    delay = record.timestamp_usec - probe.timestamp_usec
                    p_state = self._get_or_create_periph(adv_a)
                    p_state.probes_responded[probe.scanner_addr] = (
                        p_state.probes_responded.get(probe.scanner_addr, 0) + 1
                    )
                    if probe.scanner_addr not in p_state.response_delays_usec:
                        p_state.response_delays_usec[probe.scanner_addr] = []
                    p_state.response_delays_usec[probe.scanner_addr].append(delay)
                    if len(p_state.response_delays_usec[probe.scanner_addr]) > 50:
                        p_state.response_delays_usec[probe.scanner_addr].pop(0)

                    # Check if this peripheral has silenced any other scanner
                    if p_state.probes_silenced:
                        # Allowlist confirmed: responded to this one, but silenced others!
                        finding = BatAllowlistFinding(
                            finding_type=SideChannelType.BAT_ALLOWLIST.value,
                            timestamp=record.timestamp,
                            device_addr=adv_a,
                            target_addr=probe.scanner_addr,
                            verdict=Verdict.ALLOWLIST_CONFIRMED.value,
                            confidence=1.0,
                            details={
                                "mechanism": "SELECTIVE_PROBE_RESPONSE",
                                "scanner_addr": probe.scanner_addr,
                                "response_delay_usec": delay,
                                "silenced_scanners": list(p_state.probes_silenced.keys()),
                                "summary": (
                                    f"BAT Allowlist confirmed on {adv_a}: answered {probe.scanner_addr} "
                                    f"in {delay}us while silencing unauthorized scanners."
                                ),
                            },
                        )
                        self._all_findings.append(finding)
                        new_findings.append(finding)
                    else:
                        # Responded, but we haven't seen silent probes yet (could be open or allowed)
                        finding = BatAllowlistFinding(
                            finding_type=SideChannelType.BAT_ALLOWLIST.value,
                            timestamp=record.timestamp,
                            device_addr=adv_a,
                            target_addr=probe.scanner_addr,
                            verdict=Verdict.OPEN_ADVERTISER.value,
                            confidence=0.7,
                            details={
                                "mechanism": "PROBE_RESPONSE",
                                "scanner_addr": probe.scanner_addr,
                                "response_delay_usec": delay,
                                "summary": f"Peripheral {adv_a} responded to SCAN_REQ from {probe.scanner_addr} in {delay}us.",
                            },
                        )
                        self._all_findings.append(finding)
                        new_findings.append(finding)

            # E. Connection Request (CONNECT_IND)
            elif pdu_type == 0x05 and adv_pdu.adv_a and adv_pdu.init_a:
                adv_a = adv_pdu.adv_a.upper()
                init_a = adv_pdu.init_a.upper()
                if (
                    adv_pdu.interval is not None
                    and adv_pdu.latency is not None
                    and adv_pdu.timeout is not None
                    and adv_pdu.hop is not None
                ):
                    profile = (
                        adv_pdu.interval,
                        adv_pdu.latency,
                        adv_pdu.timeout,
                        adv_pdu.hop,
                    )
                    p_state = self._get_or_create_periph(adv_a)
                    p_state.connection_profiles.append(profile)

                    finding = BatAllowlistFinding(
                        finding_type=SideChannelType.BAT_ALLOWLIST.value,
                        timestamp=record.timestamp,
                        device_addr=adv_a,
                        target_addr=init_a,
                        verdict=Verdict.PROFILE_MATCH.value,
                        confidence=0.95,
                        details={
                            "mechanism": "CONNECTION_PARAMETERS",
                            "interval": adv_pdu.interval,
                            "interval_ms": adv_pdu.interval * 1.25,
                            "latency": adv_pdu.latency,
                            "timeout": adv_pdu.timeout,
                            "timeout_ms": adv_pdu.timeout * 10,
                            "hop": adv_pdu.hop,
                            "profile_tuple": profile,
                            "summary": (
                                f"Connection established with profile <Interval={adv_pdu.interval*1.25}ms, "
                                f"Latency={adv_pdu.latency}, Timeout={adv_pdu.timeout*10}ms, Hop={adv_pdu.hop}>."
                            ),
                        },
                    )
                    self._all_findings.append(finding)
                    new_findings.append(finding)

        # 2. Data Channel Packets (e.g. LL_CONNECTION_UPDATE_IND)
        else:
            data_pdu = dissect_data_channel_pdu(record.body)
            if data_pdu and data_pdu.control_frame:
                ctrl = data_pdu.control_frame
                if ctrl.opcode == 0x00:  # LL_CONNECTION_UPDATE_IND
                    payload = ctrl.payload
                    finding = BatAllowlistFinding(
                        finding_type=SideChannelType.BAT_ALLOWLIST.value,
                        timestamp=record.timestamp,
                        device_addr=f"CONN_{record.access_address:08X}",
                        target_addr=None,
                        verdict=Verdict.PROFILE_MATCH.value,
                        confidence=0.9,
                        details={
                            "mechanism": "LL_CONNECTION_UPDATE",
                            "interval": payload.get("interval"),
                            "interval_ms": payload.get("interval_ms"),
                            "latency": payload.get("latency"),
                            "timeout": payload.get("timeout"),
                            "timeout_ms": payload.get("timeout_ms"),
                            "summary": f"Connection parameters updated: Interval={payload.get('interval_ms')}ms",
                        },
                    )
                    self._all_findings.append(finding)
                    new_findings.append(finding)

        return new_findings

    def finalize(self) -> AnalyzerReport:
        """Produce the aggregated BAT / Allowlist analysis report."""
        # Flush any remaining pending probes
        if self._pending_probes:
            last_ts = max(p.timestamp_usec for p in self._pending_probes) + 10_000
            self._flush_expired_probes(last_ts)

        allowlist_confirmed_count = sum(
            1
            for p in self._peripherals.values()
            if bool(p.probes_silenced) and bool(p.probes_responded)
        )
        directed_count = sum(
            1 for p in self._peripherals.values() if p.directed_burst_count > 0
        )
        profile_count = sum(len(p.connection_profiles) for p in self._peripherals.values())
        fast_slow_transition_count = sum(
            1
            for p in self._peripherals.values()
            if p.fast_adv_observed and p.slow_adv_observed
        )

        # Determine overall verdict
        if allowlist_confirmed_count > 0:
            overall_verdict = Verdict.ALLOWLIST_CONFIRMED.value
            summary = (
                f"BAT Allowlist side-channel confirmed: {allowlist_confirmed_count} peripheral(s) "
                f"exhibited selective probe response to allowed peers and silence to unbonded scanners."
            )
        elif directed_count > 0:
            overall_verdict = Verdict.DIRECTED_EXCLUSIVE.value
            summary = (
                f"Detected exclusive bonding via {directed_count} directed advertising burst(s) (ADV_DIRECT_IND)."
            )
        elif profile_count > 0:
            overall_verdict = Verdict.PROFILE_MATCH.value
            summary = f"Extracted {profile_count} connection parameter profile(s) across monitored connections."
        elif any(bool(p.probes_responded) for p in self._peripherals.values()) and not any(
            bool(p.probes_silenced) for p in self._peripherals.values()
        ):
            overall_verdict = Verdict.OPEN_ADVERTISER.value
            summary = "Peripherals responded indiscriminately to all active probes (open advertising)."
        else:
            overall_verdict = Verdict.INCONCLUSIVE.value
            summary = "No decisive allowlist, directed advertising, or timing differential observed."

        metrics = {
            "packets_processed": self._packets_processed,
            "monitored_peripherals": len(self._peripherals),
            "allowlist_confirmed_peripherals": allowlist_confirmed_count,
            "directed_advertising_events": directed_count,
            "fast_slow_transition_peripherals": fast_slow_transition_count,
            "connection_profiles_extracted": profile_count,
            "findings_count": len(self._all_findings),
        }

        return AnalyzerReport(
            analyzer_name="BatAllowlistAnalyzer",
            verdict=overall_verdict,
            summary=summary,
            findings=list(self._all_findings),
            metrics=metrics,
        )
