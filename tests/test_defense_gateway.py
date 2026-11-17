"""Unit and cross-domain scenario tests for the AirTell Unified Defense Gateway.

Covers:
1. Link-layer protocol hardening and constant-time suppression (`monitor.py`):
   - `LL_REJECT_IND` (0x0D) and `LL_REJECT_EXT_IND` (0x11) constant-time silent drops
   - Deterministic uniform delay padding (`max(0.0, constant_time_window_ms - elapsed_ms)`)
   - Unauthenticated `LL_TERMINATE_IND` (0x02) and unpaired CSRK `ATT_SIGNED_WRITE_CMD` (0xD2) suppression
   - Boolean oracle distinguishability collapse (`1.0 -> 0.0`)
   - Bounds-checked parsing of truncated/malformed PDUs and `BlePacketRecord` coercion
2. Cross-domain threat coupling verification (`coupling.py`):
   - Software API denial (`inappropriate`) coupled with rotating RPAs (`C_1 -> C_2 -> C_3`, `Delta_RPA = 15 min`)
   - Unhardened baseline leakage (`PAIRED`, 3 correlated RPAs, `privacy_preserved = False`)
   - Hardened Integrated Defense Gateway suppression (`INDETERMINATE`, 0 correlated RPAs, `privacy_preserved = True`)
3. Systemic failure mode taxonomy & edge deployment architecture (`gateway.py`):
   - `DEFAULT_TO_INAPPROPRIATE`, `CONTRADICTORY_PRIORS`, `ONTOLOGY_HIERARCHY_MISALIGNMENT`, `IMPLICIT_CONSENT_TRAP`
   - `CryptographicLocalOptOutSwitch` HMAC-SHA256 verification and tamper fail-closed behavior
   - `LightweightEdgeOntologyOffloader` strict Pydantic JSON validation and deterministic host `<=_O` execution
   - Duck-typed compatibility with `airtell.ariel` and `airtell.sidechannel.idbleed_spec` protocols
"""

from __future__ import annotations

import dataclasses
import json
import struct
from enum import Enum

import pytest

from airtell.defense import (
    ATT_ERROR_RSP,
    ATT_HANDLE_VALUE_NOTI,
    ATT_READ_REQ,
    ATT_SIGNED_WRITE_CMD,
    ATT_WRITE_REQ,
    LL_ENC_REQ,
    LL_REJECT_EXT_IND,
    LL_REJECT_IND,
    LL_START_ENC_RSP,
    LL_TERMINATE_IND,
    CouplingVerificationReport,
    CrossDomainCouplingVerifier,
    CryptographicLocalOptOutSwitch,
    DefenseDecisionLabel,
    DefenseOntologySet,
    DefenseParameterOntology,
    EdgeModelProfile,
    FailureMode,
    FlowRequest,
    FrameAction,
    GatewayDefenseVerdict,
    IDBLEEDSideChannelMonitor,
    IntegratedDefenseGateway,
    LightweightEdgeOntologyOffloader,
    LinkLayerHardeningConfig,
    MonitorBLEFrame,
    MonitoredFrameDecision,
    PriorRecord,
    SideChannelExposureReport,
    StandaloneOracleOutcome,
    UserMemory,
    coerce_ble_frame,
)
from airtell.sidechannel.models import BlePacketRecord
from airtell.sidechannel.synthetic import (
    ERROR_PIN_OR_KEY_MISSING,
    build_att_signed_write,
    build_ll_reject_ext_ind,
    build_ll_reject_ind,
    compute_csrk_mac,
)

# ---------------------------------------------------------------------------
# Fixtures & Helpers
# ---------------------------------------------------------------------------


def _build_spa_ontology() -> DefenseOntologySet:
    """Construct a representative Smart Device Assistant ontology set."""
    return DefenseOntologySet(
        domain="spa",
        parameters={
            "data_type": DefenseParameterOntology(
                parameter="data_type",
                levels={
                    "L1": ("weather_preference", "coarse_location"),
                    "L2": ("calendar_availability", "precise_location"),
                    "L3": ("health_vitals", "full_ssn"),
                },
            ),
            "data_subject": DefenseParameterOntology(
                parameter="data_subject",
                levels={"L1": ("user",)},
            ),
            "data_sender": DefenseParameterOntology(
                parameter="data_sender",
                levels={"L1": ("assistant provider",)},
            ),
            "data_recipient": DefenseParameterOntology(
                parameter="data_recipient",
                levels={
                    # Static ontology intentionally places "housemate" at L1 alongside "family"
                    # so tests can verify dynamic role anchoring against user memory D_u.
                    "L1": ("family", "housemate"),
                    "L2": ("work_colleague", "fitness_coach"),
                    "L3": ("ambient_retail_tracker", "advertising_agency"),
                },
            ),
            "transmission_principle": DefenseParameterOntology(
                parameter="transmission_principle",
                levels={
                    "L1": ("with subject's consent",),
                    "L2": ("with requirement of confidentiality",),
                    "L3": ("for targeted tracking", "passive_ambient_sensing"),
                },
            ),
        },
    )


def _make_enc_req_payload() -> bytes:
    """Build a 23-byte LL_ENC_REQ PDU starting with opcode 0x03."""
    rand = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    ediv = struct.pack("<H", 0x1234)
    skd_m = b"\xaa" * 8
    iv_m = b"\xbb" * 4
    return bytes([LL_ENC_REQ]) + rand + ediv + skd_m + iv_m


def _make_signed_write_pdu(csrk: bytes, handle: int = 0x0012, value: bytes = b"\x42", counter: int = 1) -> bytes:
    """Build a raw ATT_SIGNED_WRITE_CMD PDU (opcode 0xD2 + handle + value + counter + 8B CMAC)."""
    mac = compute_csrk_mac(csrk=csrk, opcode=ATT_SIGNED_WRITE_CMD, handle=handle, value=value, counter=counter)
    return bytes([ATT_SIGNED_WRITE_CMD]) + struct.pack("<H", handle) + value + struct.pack("<I", counter) + mac


# ---------------------------------------------------------------------------
# 1. Link-Layer Protocol Hardening & Side-Channel Suppression (`monitor.py`)
# ---------------------------------------------------------------------------


def test_hardening_config_defaults_and_validation() -> None:
    """Verify LinkLayerHardeningConfig default values and validation bounds."""
    cfg = LinkLayerHardeningConfig()
    assert cfg.suppress_explicit_rejections is True
    assert cfg.constant_time_window_ms == 25.0
    assert cfg.mask_unauthenticated_terminations is True
    assert cfg.suppress_unpaired_csrk_drops is True

    with pytest.raises(ValueError, match="constant_time_window_ms"):
        LinkLayerHardeningConfig(constant_time_window_ms=-1.0)


def test_constant_time_suppression_of_explicit_rejections_0x0d_and_0x11() -> None:
    """Verify 0x0D and 0x11 rejections are converted into constant-time silent drops."""
    monitor = IDBLEEDSideChannelMonitor(LinkLayerHardeningConfig(constant_time_window_ms=25.0))

    f_reject = MonitorBLEFrame(
        timestamp=10.004,
        channel=12,
        rssi=-55,
        source_mac="5A:01:02:03:04:C1",
        dest_mac="AA:BB:CC:DD:EE:FF",
        pdu_type="LL_CONTROL",
        payload=bytes([LL_REJECT_IND, ERROR_PIN_OR_KEY_MISSING]),
    )
    dec_0d = monitor.inspect_frame(f_reject, elapsed_ms=6.5)
    assert isinstance(dec_0d, MonitoredFrameDecision)
    assert dec_0d.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_0d.scheduled_delay_ms == pytest.approx(18.5)
    assert dec_0d.suppressed_opcode == LL_REJECT_IND
    assert dec_0d.sanitized_payload is None

    f_reject_ext = MonitorBLEFrame(
        timestamp=10.050,
        channel=12,
        rssi=-55,
        source_mac="5A:01:02:03:04:C1",
        dest_mac="AA:BB:CC:DD:EE:FF",
        pdu_type="LL_CONTROL",
        payload=bytes([LL_REJECT_EXT_IND, LL_ENC_REQ, ERROR_PIN_OR_KEY_MISSING]),
    )
    dec_11 = monitor.inspect_frame(f_reject_ext, elapsed_ms=30.0)
    assert dec_11.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_11.scheduled_delay_ms == 0.0
    assert dec_11.suppressed_opcode == LL_REJECT_EXT_IND
    assert dec_11.sanitized_payload is None

    report = monitor.compute_exposure_report()
    assert isinstance(report, SideChannelExposureReport)
    assert report.total_frames == 2
    assert report.suppressed_rejections == 2
    assert report.uniform_delays_applied == 1
    assert report.oracle_distinguishability_before == pytest.approx(1.0)
    assert report.oracle_distinguishability_after == pytest.approx(0.0)


def test_automatic_elapsed_ms_and_delay_normalization_across_handshake() -> None:
    """Verify automatic elapsed_ms tracking from LL_ENC_REQ and uniform delay on LL_START_ENC_RSP."""
    peer_mac = "11:22:33:44:55:66"
    dev_mac = "5A:01:02:03:04:C1"
    monitor = IDBLEEDSideChannelMonitor(
        LinkLayerHardeningConfig(constant_time_window_ms=25.0),
        authenticated_peers={peer_mac},
    )

    # 1. Inbound LL_ENC_REQ at t = 100.000s
    enc_req = MonitorBLEFrame(
        timestamp=100.000,
        channel=5,
        rssi=-50,
        source_mac=peer_mac,
        dest_mac=dev_mac,
        pdu_type="LL_CONTROL",
        payload=_make_enc_req_payload(),
    )
    d_req = monitor.inspect_frame(enc_req)
    assert d_req.action is FrameAction.FORWARD
    assert d_req.scheduled_delay_ms == 0.0

    # 2. Outbound LL_START_ENC_RSP at t = 100.009s (9.0 ms elapsed -> 16.0 ms uniform delay)
    start_enc_rsp = MonitorBLEFrame(
        timestamp=100.009,
        channel=5,
        rssi=-50,
        source_mac=dev_mac,
        dest_mac=peer_mac,
        pdu_type="LL_CONTROL",
        payload=bytes([LL_START_ENC_RSP]),
    )
    d_rsp = monitor.inspect_frame(start_enc_rsp)
    assert d_rsp.action is FrameAction.DELAY_UNIFORM
    assert d_rsp.scheduled_delay_ms == pytest.approx(16.0)
    assert d_rsp.suppressed_opcode is None
    assert d_rsp.sanitized_payload == bytes([LL_START_ENC_RSP])

    # 3. Subsequent LL_TERMINATE_IND on this NOW-authenticated link is forwarded cleanly
    term_post_auth = MonitorBLEFrame(
        timestamp=102.000,
        channel=5,
        rssi=-50,
        source_mac=dev_mac,
        dest_mac=peer_mac,
        pdu_type="LL_CONTROL",
        payload=bytes([LL_TERMINATE_IND, 0x13]),
    )
    d_term = monitor.inspect_frame(term_post_auth)
    assert d_term.action is FrameAction.FORWARD


def test_unauthenticated_termination_and_gatt_auth_notification_normalization() -> None:
    """Verify unauthenticated LL_TERMINATE_IND is masked while GATT auth notification is delay-normalized."""
    monitor = IDBLEEDSideChannelMonitor(LinkLayerHardeningConfig(constant_time_window_ms=25.0))

    # Unauthenticated LL_TERMINATE_IND immediately after unauthenticated probe -> silent drop
    probe = MonitorBLEFrame(
        timestamp=50.000,
        channel=8,
        rssi=-62,
        source_mac="DE:AD:BE:EF:00:01",
        dest_mac="5A:01:02:03:04:C1",
        pdu_type="LL_CONTROL",
        payload=_make_enc_req_payload(),
    )
    monitor.inspect_frame(probe)

    unauth_term = MonitorBLEFrame(
        timestamp=50.005,
        channel=8,
        rssi=-62,
        source_mac="5A:01:02:03:04:C1",
        dest_mac="DE:AD:BE:EF:00:01",
        pdu_type="LL_CONTROL",
        payload=bytes([LL_TERMINATE_IND, 0x3D]),
    )
    dec_term = monitor.inspect_frame(unauth_term)
    assert dec_term.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_term.scheduled_delay_ms == pytest.approx(20.0)
    assert dec_term.suppressed_opcode == LL_TERMINATE_IND

    # Authorized peer GATT auth notification (0x1B) normalized to constant-time window
    auth_peer = "AA:11:22:33:44:55"
    monitor.register_authenticated_peer(auth_peer)
    gatt_noti = MonitorBLEFrame(
        timestamp=60.000,
        channel=9,
        rssi=-48,
        source_mac="5A:01:02:03:04:C1",
        dest_mac=auth_peer,
        pdu_type="ATT",
        payload=bytes([ATT_HANDLE_VALUE_NOTI, 0xF1, 0xFF, 0x01]),
    )
    dec_noti = monitor.inspect_frame(gatt_noti, elapsed_ms=10.0)
    assert dec_noti.action is FrameAction.DELAY_UNIFORM
    assert dec_noti.scheduled_delay_ms == pytest.approx(15.0)
    assert dec_noti.sanitized_payload == bytes([ATT_HANDLE_VALUE_NOTI, 0xF1, 0xFF, 0x01])


def test_csrk_signed_write_verification_and_unpaired_suppression() -> None:
    """Verify ATT_SIGNED_WRITE_CMD CMAC + replay checks and constant-time suppression of bad signatures."""
    csrk = b"\x01\x23\x45\x67\x89\xab\xcd\xef" * 2
    trusted_peer = "22:33:44:55:66:77"
    monitor = IDBLEEDSideChannelMonitor(
        LinkLayerHardeningConfig(constant_time_window_ms=25.0, suppress_unpaired_csrk_drops=True),
        authenticated_peers={trusted_peer},
        valid_csrk=csrk,
    )

    # Valid counter=1 signed write -> forwarded / normalized
    valid_pdu = _make_signed_write_pdu(csrk=csrk, handle=0x0012, value=b"\x01", counter=1)
    f_valid = MonitorBLEFrame(
        timestamp=1.0,
        channel=4,
        rssi=-50,
        source_mac=trusted_peer,
        dest_mac="5A:01:02:03:04:C1",
        pdu_type="ATT",
        payload=valid_pdu,
    )
    dec_ok = monitor.inspect_frame(f_valid, elapsed_ms=5.0)
    assert dec_ok.action is FrameAction.DELAY_UNIFORM
    assert dec_ok.scheduled_delay_ms == pytest.approx(20.0)

    # Replayed counter=1 -> constant-time silent drop
    dec_replay = monitor.inspect_frame(f_valid, elapsed_ms=5.0)
    assert dec_replay.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_replay.suppressed_opcode == ATT_SIGNED_WRITE_CMD

    # Forged CMAC with wrong CSRK -> constant-time silent drop
    wrong_csrk = b"\xff" * 16
    bad_pdu = _make_signed_write_pdu(csrk=wrong_csrk, handle=0x0012, value=b"\x01", counter=2)
    f_bad = MonitorBLEFrame(
        timestamp=2.0,
        channel=4,
        rssi=-50,
        source_mac="99:88:77:66:55:44",
        dest_mac="5A:01:02:03:04:C1",
        pdu_type="ATT",
        payload=bad_pdu,
    )
    dec_forged = monitor.inspect_frame(f_bad, elapsed_ms=8.0)
    assert dec_forged.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_forged.scheduled_delay_ms == pytest.approx(17.0)
    assert dec_forged.suppressed_opcode == ATT_SIGNED_WRITE_CMD

    # Truncated ATT_SIGNED_WRITE_CMD (< 15 bytes) -> safe constant-time silent drop without struct error
    f_trunc = MonitorBLEFrame(
        timestamp=3.0,
        channel=4,
        rssi=-50,
        source_mac="99:88:77:66:55:44",
        dest_mac="5A:01:02:03:04:C1",
        pdu_type="ATT",
        payload=bytes([ATT_SIGNED_WRITE_CMD, 0x12, 0x00]),
    )
    dec_trunc = monitor.inspect_frame(f_trunc, elapsed_ms=3.0)
    assert dec_trunc.action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert dec_trunc.suppressed_opcode == ATT_SIGNED_WRITE_CMD


def test_monitor_ble_packet_record_coercion_and_malformed_bounds() -> None:
    """Verify BlePacketRecord coercion from AirTell wire/PCAP packets and safe handling of malformed frames."""
    monitor = IDBLEEDSideChannelMonitor()

    # Coerce raw Data Channel LL_REJECT_IND and LL_REJECT_EXT_IND via BlePacketRecord
    pkt_0d = BlePacketRecord(
        body=build_ll_reject_ind(ERROR_PIN_OR_KEY_MISSING),
        channel=11,
        rssi=-64,
        timestamp_usec=1_000_000,
        access_address=0x12345678,
        direction=1,
    )
    pkt_11 = BlePacketRecord(
        body=build_ll_reject_ext_ind(LL_ENC_REQ, ERROR_PIN_OR_KEY_MISSING),
        channel=11,
        rssi=-64,
        timestamp_usec=1_010_000,
        access_address=0x12345678,
        direction=1,
    )
    pkt_csrk = BlePacketRecord(
        body=build_att_signed_write(csrk=b"\xaa" * 16, corrupt_mac=True),
        channel=11,
        rssi=-64,
        timestamp_usec=1_020_000,
        access_address=0x12345678,
        direction=0,
    )

    assert monitor.inspect_frame(pkt_0d, elapsed_ms=2.0).action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert monitor.inspect_frame(pkt_11, elapsed_ms=2.0).action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert monitor.inspect_frame(pkt_csrk, elapsed_ms=2.0).action is FrameAction.SILENT_DROP_CONSTANT_TIME

    # Empty payload and invalid CRC frames never raise exceptions
    empty_frame = MonitorBLEFrame(timestamp=2.0, payload=b"")
    crc_bad_frame = MonitorBLEFrame(
        timestamp=2.1,
        payload=bytes([LL_REJECT_IND, 0x06]),
        crc_valid=False,
    )
    assert monitor.inspect_frame(empty_frame).action is FrameAction.FORWARD
    assert monitor.inspect_frame(crc_bad_frame).action is FrameAction.SILENT_DROP_CONSTANT_TIME

    # Unhardened configuration leaves oracle distinguishability at 1.0
    unhardened_monitor = IDBLEEDSideChannelMonitor(
        LinkLayerHardeningConfig(
            suppress_explicit_rejections=False,
            constant_time_window_ms=0.0,
            mask_unauthenticated_terminations=False,
            suppress_unpaired_csrk_drops=False,
        )
    )
    dec_pass = unhardened_monitor.inspect_frame(pkt_0d)
    assert dec_pass.action is FrameAction.FORWARD
    unhardened_report = unhardened_monitor.compute_exposure_report()
    assert unhardened_report.oracle_distinguishability_before == pytest.approx(1.0)
    assert unhardened_report.oracle_distinguishability_after == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 2. Cross-Domain Threat Coupling Verifier (`coupling.py`)
# ---------------------------------------------------------------------------


def test_cross_domain_rpa_rotation_coupling_unhardened_vs_hardened() -> None:
    """Verify C_1 -> C_2 -> C_3 cross-domain threat coupling across 15-minute RPA windows."""
    verifier = CrossDomainCouplingVerifier()
    comparison = verifier.verify_coupling_mitigation()

    # Software layer denies ambient location request in BOTH modes
    unhardened: CouplingVerificationReport = comparison.unhardened
    hardened: CouplingVerificationReport = comparison.hardened

    assert unhardened.software_decision == DefenseDecisionLabel.INAPPROPRIATE.value
    assert unhardened.software_flow_denied is True
    assert unhardened.rpa_rotation_delta_minutes == pytest.approx(15.0)
    assert len(unhardened.window_results) == 3
    assert [w.rpa_label for w in unhardened.window_results] == ["C_1", "C_2", "C_3"]
    assert [w.timestamp_sec for w in unhardened.window_results] == [0.0, 900.0, 1800.0]

    # Unhardened peripheral leaks PAIRED across all 3 rotating RPAs despite software denial
    assert unhardened.oracle_outcomes == ("PAIRED", "PAIRED", "PAIRED")
    assert unhardened.correlated_rpa_count == 3
    assert len(unhardened.correlated_rpas) == 3
    assert unhardened.privacy_preserved is False
    assert unhardened.exposure_report.oracle_distinguishability_after == pytest.approx(1.0)

    # Hardened Integrated Defense Gateway suppresses side-channel -> INDETERMINATE & 0 linked RPAs
    assert hardened.software_decision == DefenseDecisionLabel.INAPPROPRIATE.value
    assert hardened.software_flow_denied is True
    assert hardened.oracle_outcomes == ("INDETERMINATE", "INDETERMINATE", "INDETERMINATE")
    assert hardened.correlated_rpa_count == 0
    assert hardened.correlated_rpas == ()
    assert hardened.privacy_preserved is True
    assert hardened.exposure_report.oracle_distinguishability_before == pytest.approx(1.0)
    assert hardened.exposure_report.oracle_distinguishability_after == pytest.approx(0.0)

    assert comparison.rpa_linkage_eliminated is True
    assert comparison.oracle_advantage_collapsed is True


def test_coupling_duck_typed_idbleed_oracle_and_orchestrator_integration() -> None:
    """Verify coupling verifier integrates cleanly with duck-typed idbleed_spec evaluators."""

    class MockOracleResult(Enum):
        UNPAIRED = 0
        PAIRED = 1
        INDETERMINATE = 2

    class MockLLEncryptionOracleEvaluator:
        def __init__(self, target_mac: str, timeout_seconds: float = 2.0) -> None:
            self.target_mac = target_mac
            self.timeout_seconds = timeout_seconds

        def process_frame(self, frame: object) -> tuple[MockOracleResult, str]:
            payload = getattr(frame, "payload", b"")
            if not payload:
                return MockOracleResult.INDETERMINATE, "Empty"
            op = payload[0]
            if op == LL_START_ENC_RSP:
                return MockOracleResult.PAIRED, "Observed LL_START_ENC_RSP: Matching LTK verified"
            if op in (LL_REJECT_IND, LL_REJECT_EXT_IND, LL_TERMINATE_IND):
                return MockOracleResult.UNPAIRED, "Rejected"
            return MockOracleResult.INDETERMINATE, "Handshake in progress"

    class MockActiveRelayProbeOrchestrator:
        def __init__(self, canonical_target_id: str, rpa_rotation_window_sec: float = 900.0) -> None:
            self.canonical_target_id = canonical_target_id
            self.rpa_rotation_window_sec = rpa_rotation_window_sec
            self.observed_rpas: list[str] = []

        def evaluate_and_correlate(
            self,
            target_rpa: str,
            oracle_result: MockOracleResult,
            timestamp: float | None = None,
        ) -> bool:
            _ = timestamp
            if oracle_result.name == "PAIRED":
                self.observed_rpas.append(target_rpa)
                return True
            return False

    verifier = CrossDomainCouplingVerifier(
        oracle_factory=MockLLEncryptionOracleEvaluator,
        orchestrator_factory=MockActiveRelayProbeOrchestrator,
    )
    summary = verifier.verify_coupling_mitigation(
        rpa_sequence=("5A:AA:BB:CC:DD:01", "6B:AA:BB:CC:DD:02", "7C:AA:BB:CC:DD:03")
    )
    assert summary.unhardened.correlated_rpa_count == 3
    assert summary.unhardened.privacy_preserved is False
    assert summary.hardened.correlated_rpa_count == 0
    assert summary.hardened.privacy_preserved is True


# ---------------------------------------------------------------------------
# 3. Systemic Failure Mode Taxonomy & Edge Architecture (`gateway.py`)
# ---------------------------------------------------------------------------


def test_failure_mode_1_default_to_inappropriate_mitigation() -> None:
    """Verify unsatisfied <=_O bounds abstain (`undetermined`) rather than defaulting to `inappropriate`."""
    ontology = _build_spa_ontology()
    gateway = IntegratedDefenseGateway(ontology_set=ontology, domain="spa")

    # User previously approved L1 coarse_location; incoming asks for L2 precise_location.
    # Rule 2 requires R <=_O R' (L2 <= L1 is False), Rule 1 does not apply (no INAPPROPRIATE prior).
    memory = UserMemory(
        user_id="alice",
        records=[
            PriorRecord(
                request=FlowRequest(
                    data_type="coarse_location",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="family",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.APPROPRIATE,
            )
        ],
    )
    incoming = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )

    verdict: GatewayDefenseVerdict = gateway.evaluate_and_enforce(incoming, memory)
    assert verdict.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert verdict.flow_allowed is False
    assert verdict.escalate_to_user is True
    assert verdict.c_plus == 0
    assert verdict.c_minus == 0
    assert FailureMode.DEFAULT_TO_INAPPROPRIATE in verdict.mitigated_failure_modes

    # Also verify gateway overrides a faulty legacy solver that tries to default to `inappropriate` with c_minus=0
    class LegacyDefaultDenySolver:
        def evaluate(self, request: object, user_memory: object) -> tuple[str, object]:
            _ = (request, user_memory)
            return "inappropriate", dataclasses.make_dataclass(
                "LegacyProof",
                [
                    ("c_plus", int),
                    ("c_minus", int),
                    ("abstention_reason", str | None),
                    ("escalate_to_user", bool),
                ],
            )(0, 0, None, False)

    guarded_gateway = IntegratedDefenseGateway(
        ontology_set=ontology,
        solver=LegacyDefaultDenySolver(),
        domain="spa",
    )
    overridden = guarded_gateway.evaluate_and_enforce(incoming, memory)
    assert overridden.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert overridden.escalate_to_user is True
    assert FailureMode.DEFAULT_TO_INAPPROPRIATE in overridden.mitigated_failure_modes


def test_failure_mode_2_contradictory_priors_halts_execution() -> None:
    """Verify simultaneous c_plus > 0 and c_minus > 0 halts execution and escalates as `undetermined`."""
    ontology = _build_spa_ontology()
    gateway = IntegratedDefenseGateway(ontology_set=ontology, domain="spa")

    # Incoming L2 precise_location to family:
    # - Prior 1: L3 health_vitals to family -> APPROPRIATE (R <=_O R' => L2 <= L3 => c_plus = 1)
    # - Prior 2: L1 coarse_location to family -> INAPPROPRIATE (R' <=_O R => L1 <= L2 => c_minus = 1)
    memory = UserMemory(
        user_id="alice",
        records=[
            PriorRecord(
                request=FlowRequest(
                    data_type="health_vitals",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="family",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.APPROPRIATE,
            ),
            PriorRecord(
                request=FlowRequest(
                    data_type="coarse_location",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="family",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.INAPPROPRIATE,
            ),
        ],
    )
    incoming = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )

    verdict = gateway.evaluate_and_enforce(incoming, memory)
    assert verdict.c_plus == 1
    assert verdict.c_minus == 1
    assert verdict.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert verdict.abstention_reason == "contradictory_priors"
    assert verdict.automated_execution_halted is True
    assert verdict.escalate_to_user is True
    assert verdict.flow_allowed is False
    assert FailureMode.CONTRADICTORY_PRIORS in verdict.mitigated_failure_modes


def test_failure_mode_3_ontology_hierarchy_misalignment_housemate_anchoring() -> None:
    """Verify dynamic role `housemate` is anchored to explicit user memory D_u rather than static rank."""
    ontology = _build_spa_ontology()
    gateway = IntegratedDefenseGateway(ontology_set=ontology, domain="spa")

    # Static ontology placed "housemate" at L1 alongside "family".
    # Case A: User approved sharing precise_location with "family", and has NO prior approval for "housemate".
    # Without dynamic role anchoring, static rank(housemate)=1 <= rank(family)=1 would falsely entail APPROPRIATE!
    memory_unanchored = UserMemory(
        user_id="bob",
        records=[
            PriorRecord(
                request=FlowRequest(
                    data_type="precise_location",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="family",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.APPROPRIATE,
            )
        ],
    )
    housemate_req = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="housemate",
        transmission_principle="with subject's consent",
    )
    verdict_unanchored = gateway.evaluate_and_enforce(housemate_req, memory_unanchored)
    assert verdict_unanchored.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert verdict_unanchored.flow_allowed is False
    assert FailureMode.ONTOLOGY_HIERARCHY_MISALIGNMENT in verdict_unanchored.mitigated_failure_modes

    # Case B: User explicitly rejected sharing coarse_location with "housemate" while approving "family".
    # Iterative memory tuning anchors "housemate" strictly higher risk than "family" and entails INAPPROPRIATE
    # for precise_location to "housemate" without causing a false contradiction with "family"!
    memory_anchored = UserMemory(
        user_id="bob",
        records=[
            PriorRecord(
                request=FlowRequest(
                    data_type="precise_location",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="family",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.APPROPRIATE,
            ),
            PriorRecord(
                request=FlowRequest(
                    data_type="coarse_location",
                    data_subject="user",
                    data_sender="assistant provider",
                    data_recipient="housemate",
                    transmission_principle="with subject's consent",
                ),
                label=DefenseDecisionLabel.INAPPROPRIATE,
            ),
        ],
    )
    verdict_anchored = gateway.evaluate_and_enforce(housemate_req, memory_anchored)
    assert verdict_anchored.decision == DefenseDecisionLabel.INAPPROPRIATE.value
    assert verdict_anchored.c_plus == 0
    assert verdict_anchored.c_minus == 1
    assert verdict_anchored.flow_allowed is False
    assert FailureMode.ONTOLOGY_HIERARCHY_MISALIGNMENT in verdict_anchored.mitigated_failure_modes


def test_failure_mode_4_hmac_local_opt_out_and_ambient_consent_trap() -> None:
    """Verify HMAC-SHA256 local opt-out switch, tamper detection, and active authorization for ambient flows."""
    with pytest.raises(ValueError, match="at least 16 bytes"):
        CryptographicLocalOptOutSwitch(b"short_key")

    secret = b"airtell-local-opt-out-hmac-key-32b!"
    switch = CryptographicLocalOptOutSwitch(secret)
    directive = switch.set_opt_out("carol", "spa", opted_out=True, timestamp=1700000000.0, nonce="n1")
    assert switch.verify_directive(directive) is True
    assert switch.is_opted_out("carol", "spa") is True
    assert switch.is_opted_out("carol", "other_domain") is False

    # Tampered signature must fail HMAC verification and trigger fail-closed blocking
    tampered = dataclasses.replace(directive, opted_out=False)
    assert switch.verify_directive(tampered) is False

    ontology = _build_spa_ontology()
    gateway = IntegratedDefenseGateway(ontology_set=ontology, opt_out_switch=switch, domain="spa")

    # Even if user memory has an exact APPROPRIATE match, local cryptographic opt-out overrides and blocks!
    req = FlowRequest(
        data_type="weather_preference",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )
    memory = UserMemory(
        user_id="carol",
        records=[PriorRecord(request=req, label=DefenseDecisionLabel.APPROPRIATE)],
    )
    ble_reject = MonitorBLEFrame(
        timestamp=1.0,
        payload=bytes([LL_REJECT_IND, ERROR_PIN_OR_KEY_MISSING]),
    )
    verdict_optout = gateway.evaluate_and_enforce(req, memory, ble_frames=[ble_reject], elapsed_ms_per_frame=5.0)
    assert verdict_optout.opted_out is True
    assert verdict_optout.opt_out_verified is True
    assert verdict_optout.decision == DefenseDecisionLabel.INAPPROPRIATE.value
    assert verdict_optout.flow_allowed is False
    assert verdict_optout.automated_execution_halted is True
    assert FailureMode.IMPLICIT_CONSENT_TRAP in verdict_optout.mitigated_failure_modes
    assert verdict_optout.frame_decisions[0].action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert verdict_optout.frame_decisions[0].scheduled_delay_ms == pytest.approx(20.0)

    # Clear opt-out (signed opted_out=False), then test ambient sensing flow WITHOUT active agent authorization
    switch.set_opt_out("carol", "spa", opted_out=False)
    assert switch.is_opted_out("carol", "spa") is False

    verdict_ambient_unauth = gateway.evaluate_and_enforce(
        req,
        memory,
        is_ambient_flow=True,
        active_agent_authorized=False,
    )
    assert verdict_ambient_unauth.flow_allowed is False
    assert verdict_ambient_unauth.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert verdict_ambient_unauth.escalate_to_user is True
    assert verdict_ambient_unauth.automated_execution_halted is True
    assert FailureMode.IMPLICIT_CONSENT_TRAP in verdict_ambient_unauth.mitigated_failure_modes

    # Once active agent authorization is explicitly provided, legitimate entailed flow succeeds
    verdict_ambient_auth = gateway.evaluate_and_enforce(
        req,
        memory,
        is_ambient_flow=True,
        active_agent_authorized=True,
    )
    assert verdict_ambient_auth.flow_allowed is True
    assert verdict_ambient_auth.decision == DefenseDecisionLabel.APPROPRIATE.value


def test_tampered_opt_out_store_fails_closed() -> None:
    """Verify corrupted/tampered stored opt-out directive fails closed with opt_out_verified=False."""
    secret = b"0123456789abcdef0123456789abcdef"
    switch = CryptographicLocalOptOutSwitch(secret)
    directive = switch.set_opt_out("dave", "spa", opted_out=True)
    forged = dataclasses.replace(directive, opted_out=False, signature_hex="00" * 32)
    switch.inject_directive_for_audit(forged)

    assert switch.is_opted_out("dave", "spa") is True
    ontology = _build_spa_ontology()
    gateway = IntegratedDefenseGateway(ontology_set=ontology, opt_out_switch=switch, domain="spa")
    req = FlowRequest(
        data_type="weather_preference",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )
    mem = UserMemory(user_id="dave", records=[PriorRecord(request=req, label=DefenseDecisionLabel.APPROPRIATE)])
    verdict = gateway.evaluate_and_enforce(req, mem)
    assert verdict.opt_out_verified is False
    assert verdict.flow_allowed is False
    assert verdict.escalate_to_user is True
    assert FailureMode.IMPLICIT_CONSENT_TRAP in verdict.mitigated_failure_modes


def test_lightweight_edge_ontology_offloader_strict_json_and_host_partial_order() -> None:
    """Verify Gemma 3 4B IT edge extraction with strict Pydantic JSON validation and host <=_O runtime."""
    ontology = _build_spa_ontology()
    offloader = LightweightEdgeOntologyOffloader(profile=EdgeModelProfile(model_id="gemma-3-4b-it"))
    assert offloader.profile.model_id == "gemma-3-4b-it"

    # Valid extraction via default deterministic edge JSON emitter
    rank_coarse = offloader.map_parameter(ontology, "data_type", "coarse_location")
    rank_precise = offloader.map_parameter(ontology, "data_type", "precise_location")
    assert rank_coarse == 1
    assert rank_precise == 2

    r_low = FlowRequest(
        data_type="coarse_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )
    r_high = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="family",
        transmission_principle="with subject's consent",
    )
    assert offloader.compare_partial_order(r_low, r_high, ontology) is True
    assert offloader.compare_partial_order(r_high, r_low, ontology) is False

    # Multi-parameter d=2 transition must NOT fire single-parameter Algorithm 1 entailment in gateway
    r_two_shifts = FlowRequest(
        data_type="precise_location",
        data_subject="user",
        data_sender="assistant provider",
        data_recipient="work_colleague",
        transmission_principle="with subject's consent",
    )
    gateway = IntegratedDefenseGateway(ontology_set=ontology, edge_offloader=offloader, domain="spa")
    mem = UserMemory(user_id="eve", records=[PriorRecord(request=r_low, label=DefenseDecisionLabel.INAPPROPRIATE)])
    verdict_d2 = gateway.evaluate_and_enforce(r_two_shifts, mem)
    assert verdict_d2.decision == DefenseDecisionLabel.UNDETERMINED.value
    assert verdict_d2.edge_offloaded is True

    # Malformed / hallucinated JSON outputs from edge model are strictly rejected (returning None -> False on <=_O)
    bad_payloads = [
        "not valid json {{{",
        json.dumps({"parameter": "data_type", "value": "coarse_location", "level": "L1", "rank": 2}),  # mismatch L1!=2
        json.dumps(
            {
                "parameter": "data_type",
                "value": "coarse_location",
                "level": "L1",
                "rank": 1,
                "hallucinated_extra": True,
            }
        ),
        json.dumps({"parameter": "data_type", "value": "coarse_location", "level": "L99", "rank": 99}),  # out-of-domain
    ]
    for bad_raw in bad_payloads:
        bad_offloader = LightweightEdgeOntologyOffloader(edge_inference_fn=lambda _param, _val, _ont, raw=bad_raw: raw)
        assert bad_offloader.map_parameter(ontology, "data_type", "coarse_location") is None
        assert bad_offloader.compare_partial_order(r_low, r_high, ontology) is False
        assert bad_offloader.validation_rejections >= 1


def test_duck_typed_ariel_engine_interoperability() -> None:
    """Verify IntegratedDefenseGateway accepts duck-typed airtell.ariel models and solver seamlessly."""

    class ExternalDecisionLabel(str, Enum):
        APPROPRIATE = "appropriate"
        INAPPROPRIATE = "inappropriate"
        UNDETERMINED = "undetermined"

    @dataclasses.dataclass(frozen=True)
    class ExternalInformationFlowRequest:
        data_type: str
        data_subject: str
        data_sender: str
        data_recipient: str
        transmission_principle: str

    @dataclasses.dataclass
    class ExternalEntailmentProof:
        neighbors_checked: int
        entailed_steps: list[str]
        c_plus: int
        c_minus: int
        abstention_reason: str | None
        escalate_to_user: bool

    class ExternalARIELSolver:
        def solve(
            self,
            request: ExternalInformationFlowRequest,
            memory: object,
        ) -> tuple[ExternalDecisionLabel, ExternalEntailmentProof]:
            _ = (request, memory)
            return (
                ExternalDecisionLabel.INAPPROPRIATE,
                ExternalEntailmentProof(
                    neighbors_checked=1,
                    entailed_steps=["Rule 1 entailed"],
                    c_plus=0,
                    c_minus=1,
                    abstention_reason=None,
                    escalate_to_user=False,
                ),
            )

    ext_req = ExternalInformationFlowRequest(
        data_type="precise_location",
        data_subject="student",
        data_sender="registrar",
        data_recipient="advertising agencies",
        transmission_principle="for targeted tracking",
    )
    ext_mem = dataclasses.make_dataclass("ExtMem", [("user_id", str), ("records", list)])("student_1", [])

    gateway = IntegratedDefenseGateway(solver=ExternalARIELSolver(), domain="education")
    verdict = gateway.evaluate_and_enforce(
        ext_req,
        ext_mem,
        ble_frames=[MonitorBLEFrame(timestamp=5.0, payload=bytes([LL_REJECT_EXT_IND, LL_ENC_REQ, 0x06]))],
        elapsed_ms_per_frame=[12.0],
    )
    assert verdict.decision == "inappropriate"
    assert verdict.flow_allowed is False
    assert verdict.c_minus == 1
    assert verdict.frame_decisions[0].action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert verdict.frame_decisions[0].scheduled_delay_ms == pytest.approx(13.0)


def test_monitor_att_branches_reset_and_frame_coercion_edges() -> None:
    """Verify ATT error/write/notification branches, reset(), to_dict(), and duck-typed frame coercion."""
    with pytest.raises(ValueError, match="finite"):
        LinkLayerHardeningConfig(constant_time_window_ms=float("nan"))

    with pytest.raises(ValueError, match="exactly 16 bytes"):
        IDBLEEDSideChannelMonitor(valid_csrk=b"too_short")

    monitor = IDBLEEDSideChannelMonitor()
    # Benign trace before any leakable frame yields 0.0 -> 0.0 exposure
    benign_ll = MonitorBLEFrame(timestamp=1.0, pdu_type="LL_CONTROL", payload=bytes([0x12]))
    benign_att = MonitorBLEFrame(timestamp=1.1, pdu_type="ATT", payload=bytes([ATT_READ_REQ, 0x01, 0x00]))
    write_att = MonitorBLEFrame(timestamp=1.2, pdu_type="ATT", payload=bytes([ATT_WRITE_REQ, 0xF1, 0xFF, 0x01]))
    assert monitor.inspect_frame(benign_ll).action is FrameAction.FORWARD
    assert monitor.inspect_frame(benign_att).action is FrameAction.FORWARD
    assert monitor.inspect_frame(write_att).action is FrameAction.FORWARD
    zero_rep = monitor.compute_exposure_report()
    assert zero_rep.oracle_distinguishability_before == 0.0
    assert zero_rep.oracle_distinguishability_after == 0.0
    assert zero_rep.to_dict()["total_frames"] == 3

    # ATT_ERROR_RSP and short ATT_HANDLE_VALUE_NOTI and 2-byte LL_TERMINATE_IND inside ATT stream
    err_att = MonitorBLEFrame(timestamp=1.205, pdu_type="ATT", payload=bytes([ATT_ERROR_RSP, 0x0A, 0x01, 0x00, 0x05]))
    short_noti = MonitorBLEFrame(timestamp=1.210, pdu_type="ATT", payload=bytes([ATT_HANDLE_VALUE_NOTI, 0x01]))
    term_in_att = MonitorBLEFrame(timestamp=1.215, pdu_type="ATT", payload=bytes([LL_TERMINATE_IND, 0x13]))
    assert monitor.inspect_frame(err_att).action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert monitor.inspect_frame(short_noti).action is FrameAction.SILENT_DROP_CONSTANT_TIME
    assert monitor.inspect_frame(term_in_att).action is FrameAction.SILENT_DROP_CONSTANT_TIME

    monitor.reset()
    assert monitor.compute_exposure_report().total_frames == 0

    # Duck-typed external BLEFrame and invalid payload type
    ext_frame = dataclasses.make_dataclass(
        "ExtBLEFrame",
        [("timestamp", float), ("source_mac", str), ("dest_mac", str), ("payload", object)],
    )
    coerced = coerce_ble_frame(ext_frame(2.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", b"\x0d\x06"))
    assert coerced.payload == b"\x0d\x06"
    with pytest.raises(TypeError, match="bytes or bytearray"):
        coerce_ble_frame(ext_frame(2.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "not_bytes"))

    # Coerce advertising and generic non-ATT data channel BlePacketRecord
    adv_pkt = BlePacketRecord(body=b"\x00\x06\x01\x02\x03\x04\x05\x06", channel=37, rssi=-70, timestamp_usec=500)
    data_pkt = BlePacketRecord(
        body=b"\x01\x02\xaa\xbb",
        channel=4,
        rssi=-60,
        timestamp_usec=600,
        access_address=0xAABBCCDD,
    )
    assert coerce_ble_frame(adv_pkt).pdu_type == "BLE_ADV"
    assert coerce_ble_frame(data_pkt).pdu_type == "LL_DATA"


def test_models_memory_helpers_and_alternative_ontology_shapes() -> None:
    """Verify FlowRequest/UserMemory methods, wildcard opt-out, and duck-typed OntologySet variants."""
    r1 = FlowRequest("coarse_location", "user", "assistant provider", "family", "with subject's consent")
    r2 = FlowRequest("precise_location", "user", "assistant provider", "housemate", "with subject's consent")
    assert r1.as_dict()["data_type"] == "coarse_location"
    assert r1.hamming_distance(r2) == 2
    assert r1.differing_parameters(r2) == [
        ("data_type", "coarse_location", "precise_location"),
        ("data_recipient", "family", "housemate"),
    ]

    with pytest.raises(ValueError, match="appropriate"):
        PriorRecord(request=r1, label="undetermined")

    mem = UserMemory(user_id="u1")
    mem.add_record(r1, DefenseDecisionLabel.APPROPRIATE)
    assert len(mem.neighbors(r1, max_distance=0)) == 1
    assert len(mem.slice_memory(0).records) == 0

    ont = _build_spa_ontology()
    dt_ont = ont.get_parameter_ontology("data_type")
    assert dt_ont is not None
    assert dt_ont.rank_of("coarse_location") == 1

    # Duck-typed OntologySet using `ontologies` + `value_to_rank` and integer `levels`
    alt_ont = dataclasses.make_dataclass("AltOntSet", [("ontologies", dict)])(
        {
            "data_type": dataclasses.make_dataclass("P1", [("value_to_rank", dict)])(
                {"coarse_location": 1, "precise_location": 2}
            ),
            "data_subject": dataclasses.make_dataclass("P2", [("levels", dict)])({1: ["user"]}),
            "data_sender": dataclasses.make_dataclass("P3", [("levels", dict)])({"L1": ["assistant provider"]}),
            "data_recipient": dataclasses.make_dataclass("P4", [("levels", dict)])(
                {"L1": ["family"], "L2": ["work_colleague"], "L3": ["housemate"]}
            ),
            "transmission_principle": dataclasses.make_dataclass("P5", [("levels", dict)])(
                {"L1": ["with subject's consent"]}
            ),
        }
    )
    offloader = LightweightEdgeOntologyOffloader()
    assert offloader.map_parameter(alt_ont, "data_type", "precise_location") == 2
    assert offloader.map_parameter(None, "data_type", "precise_location") is None

    # Dynamic role positive-approval anchoring when user approved "housemate" (static L3)
    # and denied "work_colleague" (L2)
    mem_pos = UserMemory(
        user_id="u2",
        records=[
            PriorRecord(
                FlowRequest("precise_location", "user", "assistant provider", "housemate", "with subject's consent"),
                DefenseDecisionLabel.APPROPRIATE,
            ),
            PriorRecord(
                FlowRequest(
                    "precise_location", "user", "assistant provider", "work_colleague", "with subject's consent"
                ),
                DefenseDecisionLabel.INAPPROPRIATE,
            ),
        ],
    )
    gw = IntegratedDefenseGateway(ontology_set=alt_ont, domain="spa")
    v_pos = gw.evaluate_and_enforce(
        FlowRequest("coarse_location", "user", "assistant provider", "housemate", "with subject's consent"),
        mem_pos,
    )
    assert v_pos.decision == "appropriate"
    assert FailureMode.ONTOLOGY_HIERARCHY_MISALIGNMENT in v_pos.mitigated_failure_modes

    # Wildcard opt-out and input validation, plus callable/single-object solver adapters
    sw = CryptographicLocalOptOutSwitch(b"a" * 32)
    with pytest.raises(ValueError, match="user_id"):
        sw.set_opt_out("   ", "spa")
    with pytest.raises(ValueError, match="domain"):
        sw.set_opt_out("u2", "   ")
    sw.set_opt_out("u2", "*", opted_out=True)
    assert sw.is_opted_out("u2", "any_domain") is True

    callable_gw = IntegratedDefenseGateway(
        solver=lambda _req, _mem: dataclasses.make_dataclass(
            "SingleOut",
            [("decision", str), ("c_plus", int), ("c_minus", int)],
        )("appropriate", 1, 0)
    )
    assert callable_gw.evaluate_and_enforce(r1, mem_pos).decision == "appropriate"

    bad_gw = IntegratedDefenseGateway(solver=object())
    with pytest.raises(TypeError, match="Unsupported solver"):
        bad_gw.evaluate_and_enforce(r1, mem_pos)


def test_standalone_ll_oracle_edge_cases() -> None:
    """Verify standalone link-layer encryption oracle handles CRC, MAC mismatch, empty, reject, and timeout."""
    from airtell.defense.coupling import _StandaloneLLEncryptionOracle

    oracle = _StandaloneLLEncryptionOracle("5A:01:02:03:04:C1", timeout_seconds=1.0)
    assert oracle.process_frame(MonitorBLEFrame(crc_valid=False))[0] is StandaloneOracleOutcome.INDETERMINATE
    assert (
        oracle.process_frame(MonitorBLEFrame(source_mac="11:11:11:11:11:11", dest_mac="22:22:22:22:22:22"))[0]
        is StandaloneOracleOutcome.INDETERMINATE
    )
    assert (
        oracle.process_frame(MonitorBLEFrame(source_mac="5A:01:02:03:04:C1", payload=b""))[0]
        is StandaloneOracleOutcome.INDETERMINATE
    )
    assert (
        oracle.process_frame(
            MonitorBLEFrame(timestamp=10.0, source_mac="5A:01:02:03:04:C1", payload=_make_enc_req_payload())
        )[0]
        is StandaloneOracleOutcome.INDETERMINATE
    )
    assert (
        oracle.process_frame(
            MonitorBLEFrame(timestamp=10.1, source_mac="5A:01:02:03:04:C1", payload=bytes([LL_REJECT_IND, 0x06]))
        )[0]
        is StandaloneOracleOutcome.UNPAIRED
    )
    assert (
        oracle.process_frame(
            MonitorBLEFrame(timestamp=10.2, source_mac="5A:01:02:03:04:C1", payload=bytes([LL_TERMINATE_IND, 0x13]))
        )[0]
        is StandaloneOracleOutcome.UNPAIRED
    )
    assert (
        oracle.process_frame(MonitorBLEFrame(timestamp=10.3, source_mac="5A:01:02:03:04:C1", payload=bytes([0x12])))[0]
        is StandaloneOracleOutcome.INDETERMINATE
    )
    # Timeout after 1.0s
    assert (
        oracle.process_frame(
            MonitorBLEFrame(timestamp=12.5, source_mac="5A:01:02:03:04:C1", payload=bytes([LL_START_ENC_RSP]))
        )[0]
        is StandaloneOracleOutcome.INDETERMINATE
    )
