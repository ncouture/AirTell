"""Cross-domain threat coupling verifier between software CI logic and BLE link-layer.

Models and deterministically verifies the cross-domain privacy failure and its
unified mitigation:
1. An ambient application requests user location data; the neurosymbolic privacy
   solver denies the software API flow (`inappropriate`).
2. Unhardened peripheral baseline: across rotating Resolvable Private Addresses
   (`C_1 -> C_2 -> C_3` over `Delta_RPA = 15 min` windows), Link-Layer boolean
   handshake responses leak `PAIRED` (while non-targets emit `0x0D`/`0x11`),
   linking all rotating RPAs to one canonical identity (`privacy_preserved = False`).
3. Hardened Integrated Defense Gateway mode: software denial couples directly into
   `IDBLEEDSideChannelMonitor`, suppressing deterministic rejections and unauthenticated
   handshake completions via constant-time silent drops (`INDETERMINATE` oracle outcome,
   `0` correlated RPAs, `privacy_preserved = True`).
"""

from __future__ import annotations

import importlib
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from airtell.defense.gateway import (
    DefenseDecisionLabel,
    DefenseOntologySet,
    DefenseParameterOntology,
    FlowRequest,
    IntegratedDefenseGateway,
    PriorRecord,
    UserMemory,
)
from airtell.defense.monitor import (
    LL_ENC_REQ,
    LL_ENC_RSP,
    LL_REJECT_EXT_IND,
    LL_REJECT_IND,
    LL_START_ENC_REQ,
    LL_START_ENC_RSP,
    LL_TERMINATE_IND,
    FrameAction,
    IDBLEEDSideChannelMonitor,
    LinkLayerHardeningConfig,
    MonitorBLEFrame,
    MonitoredFrameDecision,
    SideChannelExposureReport,
)
from airtell.sidechannel.synthetic import ERROR_PIN_OR_KEY_MISSING

DEFAULT_RPA_ROTATION_WINDOW_SEC: float = 900.0
DEFAULT_ROTATING_RPAS: tuple[str, str, str] = (
    "5A:01:02:03:04:C1",
    "6B:01:02:03:04:C2",
    "7C:01:02:03:04:C3",
)
PROBER_MAC: str = "E0:AA:BB:CC:DD:99"
BYSTANDER_MAC: str = "4E:99:88:77:66:00"


class StandaloneOracleOutcome(Enum):
    """Fallback boolean oracle enumeration matching `idbleed_spec.OracleResult`."""

    UNPAIRED = 0
    PAIRED = 1
    INDETERMINATE = 2


@runtime_checkable
class LinkLayerOracleEvaluatorProtocol(Protocol):
    """Protocol compatible with `idbleed_spec.LLEncryptionOracleEvaluator`."""

    def process_frame(self, frame: Any) -> tuple[Any, str]:
        """Process a single BLE frame and return `(oracle_result_enum, reason)`."""


@runtime_checkable
class RelayProbeOrchestratorProtocol(Protocol):
    """Protocol compatible with `idbleed_spec.ActiveRelayProbeOrchestrator`."""

    def evaluate_and_correlate(
        self,
        target_rpa: str,
        oracle_result: Any,
        timestamp: float | None = None,
    ) -> bool:
        """Correlate `target_rpa` into the canonical identity record if `PAIRED`."""


class _StandaloneLLEncryptionOracle:
    """Reference Link-Layer encryption oracle evaluator used when running standalone."""

    def __init__(self, target_mac: str, timeout_seconds: float = 2.0) -> None:
        self.target_mac = target_mac.upper()
        self.timeout_seconds = timeout_seconds
        self._start_time: float | None = None

    def process_frame(self, frame: MonitorBLEFrame | Any) -> tuple[StandaloneOracleOutcome, str]:
        if not getattr(frame, "crc_valid", True):
            return StandaloneOracleOutcome.INDETERMINATE, "Invalid CRC"

        src = str(getattr(frame, "source_mac", "")).upper()
        dst = str(getattr(frame, "dest_mac", "")).upper()
        if self.target_mac not in (src, dst):
            return StandaloneOracleOutcome.INDETERMINATE, "Address mismatch"

        payload: bytes = bytes(getattr(frame, "payload", b""))
        if not payload:
            return StandaloneOracleOutcome.INDETERMINATE, "Empty PDU"

        ts = float(getattr(frame, "timestamp", 0.0))
        if self._start_time is not None and (ts - self._start_time) > self.timeout_seconds:
            return StandaloneOracleOutcome.INDETERMINATE, "Handshake timed out"

        opcode = payload[0]
        if opcode == LL_ENC_REQ:
            self._start_time = ts
            return StandaloneOracleOutcome.INDETERMINATE, "Observed LL_ENC_REQ"
        if opcode in (LL_ENC_RSP, LL_START_ENC_REQ):
            return StandaloneOracleOutcome.INDETERMINATE, "Encryption handshake progressing"
        if opcode == LL_START_ENC_RSP:
            return (
                StandaloneOracleOutcome.PAIRED,
                "Observed LL_START_ENC_RSP: Matching LTK verified",
            )
        if opcode in (LL_REJECT_IND, LL_REJECT_EXT_IND):
            return (
                StandaloneOracleOutcome.UNPAIRED,
                f"Observed rejection opcode 0x{opcode:02X}: Missing LTK",
            )
        if opcode == LL_TERMINATE_IND:
            return (
                StandaloneOracleOutcome.UNPAIRED,
                "Connection terminated during encryption handshake",
            )
        return StandaloneOracleOutcome.INDETERMINATE, "Unrelated control opcode"


class _StandaloneRelayOrchestrator:
    """Reference active relay probe orchestrator tracking correlated rotating RPAs."""

    def __init__(
        self,
        canonical_target_id: str,
        rpa_rotation_window_sec: float = DEFAULT_RPA_ROTATION_WINDOW_SEC,
    ) -> None:
        self.canonical_target_id = canonical_target_id
        self.rpa_rotation_window_sec = rpa_rotation_window_sec
        self.observed_rpas: list[str] = []

    def evaluate_and_correlate(
        self,
        target_rpa: str,
        oracle_result: Any,
        timestamp: float | None = None,
    ) -> bool:
        _ = timestamp
        name = getattr(oracle_result, "name", str(oracle_result)).upper()
        if name == "PAIRED":
            if target_rpa not in self.observed_rpas:
                self.observed_rpas.append(target_rpa)
            return True
        return False


def _resolve_runtime_idbleed_factories() -> tuple[
    Callable[[str], LinkLayerOracleEvaluatorProtocol],
    Callable[[str, float], RelayProbeOrchestratorProtocol],
    Callable[..., Any],
]:
    """Load `airtell.sidechannel.idbleed_spec` classes at runtime if merged, else standalone."""
    try:
        spec_mod = importlib.import_module("airtell.sidechannel.idbleed_spec")
        oracle_cls = getattr(spec_mod, "LLEncryptionOracleEvaluator")
        orch_cls = getattr(spec_mod, "ActiveRelayProbeOrchestrator")
        frame_cls = getattr(spec_mod, "BLEFrame")
        return (
            lambda mac: oracle_cls(target_mac=mac),
            lambda cid, win: orch_cls(canonical_target_id=cid, rpa_rotation_window_sec=win),
            frame_cls,
        )
    except (ModuleNotFoundError, AttributeError):
        return (
            lambda mac: _StandaloneLLEncryptionOracle(target_mac=mac),
            lambda cid, win: _StandaloneRelayOrchestrator(canonical_target_id=cid, rpa_rotation_window_sec=win),
            MonitorBLEFrame,
        )


@dataclass(frozen=True)
class RPARotationWindowResult:
    """Per-window cross-domain outcome for a single rotating RPA (`C_k`)."""

    window_index: int
    rpa_label: str
    rpa_address: str
    timestamp_sec: float
    software_decision: str
    monitor_decision: MonitoredFrameDecision | None
    oracle_outcome: str
    correlated_to_canonical: bool


@dataclass(frozen=True)
class CouplingVerificationReport:
    """End-to-end verification report for one cross-domain operational mode."""

    mode: str
    canonical_identity: str
    rpa_rotation_delta_minutes: float
    software_decision: str
    software_flow_denied: bool
    window_results: tuple[RPARotationWindowResult, ...]
    correlated_rpas: tuple[str, ...]
    correlated_rpa_count: int
    oracle_outcomes: tuple[str, ...]
    exposure_report: SideChannelExposureReport
    privacy_preserved: bool


@dataclass(frozen=True)
class CrossDomainComparisonSummary:
    """Side-by-side comparison proving cross-domain RPA linkage mitigation."""

    unhardened: CouplingVerificationReport
    hardened: CouplingVerificationReport
    rpa_linkage_eliminated: bool
    oracle_advantage_collapsed: bool


def _default_ambient_location_scenario() -> tuple[
    DefenseOntologySet,
    FlowRequest,
    UserMemory,
]:
    ontology = DefenseOntologySet(
        domain="ambient_location",
        parameters={
            "data_type": DefenseParameterOntology(
                parameter="data_type",
                levels={
                    "L1": ("coarse_location",),
                    "L2": ("precise_location",),
                },
            ),
            "data_subject": DefenseParameterOntology(
                parameter="data_subject",
                levels={"L1": ("user",)},
            ),
            "data_sender": DefenseParameterOntology(
                parameter="data_sender",
                levels={"L1": ("mobile_os",)},
            ),
            "data_recipient": DefenseParameterOntology(
                parameter="data_recipient",
                levels={
                    "L1": ("navigation_service",),
                    "L2": ("ambient_analytics_sdk",),
                },
            ),
            "transmission_principle": DefenseParameterOntology(
                parameter="transmission_principle",
                levels={
                    "L1": ("with subject's consent",),
                    "L2": ("for ambient proximity tracking",),
                },
            ),
        },
    )
    prior_denied = FlowRequest(
        data_type="coarse_location",
        data_subject="user",
        data_sender="mobile_os",
        data_recipient="ambient_analytics_sdk",
        transmission_principle="for ambient proximity tracking",
    )
    incoming_ambient_request = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="mobile_os",
        data_recipient="ambient_analytics_sdk",
        transmission_principle="for ambient proximity tracking",
    )
    memory = UserMemory(
        user_id="target_user",
        records=[PriorRecord(request=prior_denied, label=DefenseDecisionLabel.INAPPROPRIATE)],
    )
    return ontology, incoming_ambient_request, memory


def _build_enc_req_bytes() -> bytes:
    rand = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    ediv = struct.pack("<H", 0xBEEF)
    skd_c = b"\x10\x20\x30\x40\x50\x60\x70\x80"
    iv_c = b"\xaa\xbb\xcc\xdd"
    return bytes([LL_ENC_REQ]) + rand + ediv + skd_c + iv_c


def _build_enc_rsp_bytes() -> bytes:
    skd_s = b"\x80\x70\x60\x50\x40\x30\x20\x10"
    iv_s = b"\xdd\xcc\xbb\xaa"
    return bytes([LL_ENC_RSP]) + skd_s + iv_s


class CrossDomainCouplingVerifier:
    """Deterministic verifier for cross-domain software-to-BLE privacy coupling."""

    def __init__(
        self,
        *,
        canonical_identity: str = "user_canonical_identity_01",
        rpa_rotation_window_sec: float = DEFAULT_RPA_ROTATION_WINDOW_SEC,
        oracle_factory: Callable[[str], LinkLayerOracleEvaluatorProtocol] | None = None,
        orchestrator_factory: Callable[..., RelayProbeOrchestratorProtocol] | None = None,
    ) -> None:
        """Initialize the cross-domain coupling verifier.

        Args:
            canonical_identity: Canonical target identifier tracked across RPA rotations.
            rpa_rotation_window_sec: BLE RPA rotation interval in seconds (default `900.0` = 15 min).
            oracle_factory: Optional factory `(target_mac) -> LinkLayerOracleEvaluatorProtocol`.
            orchestrator_factory: Optional factory `(canonical_id, window_sec) -> RelayProbeOrchestratorProtocol`.
        """
        self.canonical_identity = canonical_identity
        self.rpa_rotation_window_sec = rpa_rotation_window_sec

        rt_oracle, rt_orch, rt_frame_cls = _resolve_runtime_idbleed_factories()
        self._oracle_factory = oracle_factory or rt_oracle
        self._orchestrator_factory = orchestrator_factory or rt_orch
        self._frame_cls = MonitorBLEFrame if oracle_factory is not None else rt_frame_cls

    def _make_frame(
        self,
        *,
        timestamp: float,
        source_mac: str,
        dest_mac: str,
        payload: bytes,
        pdu_type: str = "LL_CONTROL",
    ) -> Any:
        return self._frame_cls(
            timestamp=timestamp,
            channel=12,
            rssi=-52,
            source_mac=source_mac,
            dest_mac=dest_mac,
            pdu_type=pdu_type,
            payload=payload,
            crc_valid=True,
        )

    def _run_simulation(
        self,
        *,
        hardened: bool,
        rpa_sequence: Sequence[str],
        ontology_set: Any | None = None,
        ambient_request: Any | None = None,
        user_memory: Any | None = None,
    ) -> CouplingVerificationReport:
        default_ont, default_req, default_mem = _default_ambient_location_scenario()
        active_ont = ontology_set if ontology_set is not None else default_ont
        active_req = ambient_request if ambient_request is not None else default_req
        active_mem = user_memory if user_memory is not None else default_mem

        if hardened:
            monitor = IDBLEEDSideChannelMonitor(
                LinkLayerHardeningConfig(
                    suppress_explicit_rejections=True,
                    constant_time_window_ms=25.0,
                    mask_unauthenticated_terminations=True,
                    suppress_unpaired_csrk_drops=True,
                )
            )
        else:
            monitor = IDBLEEDSideChannelMonitor(
                LinkLayerHardeningConfig(
                    suppress_explicit_rejections=False,
                    constant_time_window_ms=0.0,
                    mask_unauthenticated_terminations=False,
                    suppress_unpaired_csrk_drops=False,
                )
            )

        gateway = IntegratedDefenseGateway(
            ontology_set=active_ont,
            side_channel_monitor=monitor,
            domain="ambient_location",
        )
        orchestrator = self._orchestrator_factory(
            self.canonical_identity,
            self.rpa_rotation_window_sec,
        )

        window_results: list[RPARotationWindowResult] = []
        correlated_rpas: list[str] = []
        oracle_outcomes: list[str] = []

        for idx, rpa_addr in enumerate(rpa_sequence):
            rpa_label = f"C_{idx + 1}"
            base_ts = float(idx) * self.rpa_rotation_window_sec

            # Step 1: Software privacy evaluation on ambient location flow
            sw_verdict = gateway.evaluate_and_enforce(
                active_req,
                active_mem,
                is_ambient_flow=True,
                active_agent_authorized=False,
            )
            sw_decision = sw_verdict.decision
            suppress_handshakes = hardened and (not sw_verdict.flow_allowed)

            # Step 2: Active relay probe against rotating target RPA C_{idx+1}
            oracle = self._oracle_factory(rpa_addr)
            probe_req = self._make_frame(
                timestamp=base_ts,
                source_mac=PROBER_MAC,
                dest_mac=rpa_addr,
                payload=_build_enc_req_bytes(),
            )
            monitor.inspect_frame(
                probe_req,
                suppress_unauthenticated_handshakes=suppress_handshakes,
            )
            latest_oracle_res, _ = oracle.process_frame(probe_req)

            candidate_target_responses = [
                self._make_frame(
                    timestamp=base_ts + 0.003,
                    source_mac=rpa_addr,
                    dest_mac=PROBER_MAC,
                    payload=_build_enc_rsp_bytes(),
                ),
                self._make_frame(
                    timestamp=base_ts + 0.005,
                    source_mac=rpa_addr,
                    dest_mac=PROBER_MAC,
                    payload=bytes([LL_START_ENC_REQ]),
                ),
                self._make_frame(
                    timestamp=base_ts + 0.008,
                    source_mac=rpa_addr,
                    dest_mac=PROBER_MAC,
                    payload=bytes([LL_START_ENC_RSP]),
                ),
            ]

            last_mon_decision: MonitoredFrameDecision | None = None
            for resp_frame in candidate_target_responses:
                mon_dec = monitor.inspect_frame(
                    resp_frame,
                    suppress_unauthenticated_handshakes=suppress_handshakes,
                )
                last_mon_decision = mon_dec
                if mon_dec.action is not FrameAction.SILENT_DROP_CONSTANT_TIME:
                    latest_oracle_res, _ = oracle.process_frame(resp_frame)

            # Step 3: Bystander unpaired control probe demonstrating 0x0D / 0x11 suppression
            bystander_probe = self._make_frame(
                timestamp=base_ts + 0.100,
                source_mac=PROBER_MAC,
                dest_mac=BYSTANDER_MAC,
                payload=_build_enc_req_bytes(),
            )
            monitor.inspect_frame(
                bystander_probe,
                suppress_unauthenticated_handshakes=suppress_handshakes,
            )
            reject_opcode = LL_REJECT_IND if idx % 2 == 0 else LL_REJECT_EXT_IND
            reject_payload = (
                bytes([LL_REJECT_IND, ERROR_PIN_OR_KEY_MISSING])
                if reject_opcode == LL_REJECT_IND
                else bytes([LL_REJECT_EXT_IND, LL_ENC_REQ, ERROR_PIN_OR_KEY_MISSING])
            )
            bystander_reject = self._make_frame(
                timestamp=base_ts + 0.104,
                source_mac=BYSTANDER_MAC,
                dest_mac=PROBER_MAC,
                payload=reject_payload,
            )
            monitor.inspect_frame(
                bystander_reject,
                suppress_unauthenticated_handshakes=suppress_handshakes,
            )

            outcome_name = getattr(latest_oracle_res, "name", str(latest_oracle_res)).upper()
            is_linked = orchestrator.evaluate_and_correlate(
                rpa_addr,
                latest_oracle_res,
                timestamp=base_ts,
            )
            if is_linked:
                correlated_rpas.append(rpa_addr)
            oracle_outcomes.append(outcome_name)

            window_results.append(
                RPARotationWindowResult(
                    window_index=idx,
                    rpa_label=rpa_label,
                    rpa_address=rpa_addr,
                    timestamp_sec=base_ts,
                    software_decision=sw_decision,
                    monitor_decision=last_mon_decision,
                    oracle_outcome=outcome_name,
                    correlated_to_canonical=is_linked,
                )
            )

        exposure = monitor.compute_exposure_report()
        software_denied = all(w.software_decision == DefenseDecisionLabel.INAPPROPRIATE.value for w in window_results)
        privacy_preserved = (
            software_denied and len(correlated_rpas) == 0 and exposure.oracle_distinguishability_after == 0.0
        )

        return CouplingVerificationReport(
            mode="hardened" if hardened else "unhardened",
            canonical_identity=self.canonical_identity,
            rpa_rotation_delta_minutes=self.rpa_rotation_window_sec / 60.0,
            software_decision=window_results[0].software_decision
            if window_results
            else DefenseDecisionLabel.INAPPROPRIATE.value,
            software_flow_denied=software_denied,
            window_results=tuple(window_results),
            correlated_rpas=tuple(correlated_rpas),
            correlated_rpa_count=len(correlated_rpas),
            oracle_outcomes=tuple(oracle_outcomes),
            exposure_report=exposure,
            privacy_preserved=privacy_preserved,
        )

    def verify_unhardened_baseline(
        self,
        rpa_sequence: Sequence[str] = DEFAULT_ROTATING_RPAS,
        *,
        ontology_set: Any | None = None,
        ambient_request: Any | None = None,
        user_memory: Any | None = None,
    ) -> CouplingVerificationReport:
        """Simulate unhardened BLE peripheral where software blocks flow but RPAs leak `PAIRED`."""
        return self._run_simulation(
            hardened=False,
            rpa_sequence=rpa_sequence,
            ontology_set=ontology_set,
            ambient_request=ambient_request,
            user_memory=user_memory,
        )

    def verify_hardened_gateway(
        self,
        rpa_sequence: Sequence[str] = DEFAULT_ROTATING_RPAS,
        *,
        ontology_set: Any | None = None,
        ambient_request: Any | None = None,
        user_memory: Any | None = None,
    ) -> CouplingVerificationReport:
        """Simulate hardened Integrated Defense Gateway suppressing side-channel linkage."""
        return self._run_simulation(
            hardened=True,
            rpa_sequence=rpa_sequence,
            ontology_set=ontology_set,
            ambient_request=ambient_request,
            user_memory=user_memory,
        )

    def verify_coupling_mitigation(
        self,
        rpa_sequence: Sequence[str] = DEFAULT_ROTATING_RPAS,
        *,
        ontology_set: Any | None = None,
        ambient_request: Any | None = None,
        user_memory: Any | None = None,
    ) -> CrossDomainComparisonSummary:
        """Run both unhardened and hardened scenarios across `C_1 -> C_2 -> C_3` and compare."""
        unhardened = self.verify_unhardened_baseline(
            rpa_sequence=rpa_sequence,
            ontology_set=ontology_set,
            ambient_request=ambient_request,
            user_memory=user_memory,
        )
        hardened = self.verify_hardened_gateway(
            rpa_sequence=rpa_sequence,
            ontology_set=ontology_set,
            ambient_request=ambient_request,
            user_memory=user_memory,
        )
        linkage_eliminated = (
            unhardened.correlated_rpa_count == len(rpa_sequence)
            and hardened.correlated_rpa_count == 0
            and not unhardened.privacy_preserved
            and hardened.privacy_preserved
        )
        advantage_collapsed = (
            unhardened.exposure_report.oracle_distinguishability_before == 1.0
            and hardened.exposure_report.oracle_distinguishability_after == 0.0
        )
        return CrossDomainComparisonSummary(
            unhardened=unhardened,
            hardened=hardened,
            rpa_linkage_eliminated=linkage_eliminated,
            oracle_advantage_collapsed=advantage_collapsed,
        )
