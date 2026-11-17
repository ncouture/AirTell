"""End-to-end integration tests for ARIEL entailment, IDBLEED verification, CLI, and Defense Gateway."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from unittest.mock import MagicMock, patch

import plotly.graph_objects as go
import pytest

import airtell.sidechannel as sidechannel_pkg
from airtell.ariel import (
    ABSTENTION_CONTRADICTORY_PRIORS,
    AdaptiveMemoryAnchoredMapper,
    ARIELSolver,
    DecisionLabel,
    InformationFlowRequest,
    PriorDecisionRecord,
    UserDecisionMemory,
    build_spa_ontology,
)
from airtell.cli import main
from airtell.defense import (
    CrossDomainCouplingVerifier,
    CryptographicLocalOptOutSwitch,
    FailureMode,
    FrameAction,
    IDBLEEDSideChannelMonitor,
    IntegratedDefenseGateway,
    LightweightEdgeOntologyOffloader,
    LinkLayerHardeningConfig,
)
from airtell.sidechannel import (
    ActiveRelayProbeOrchestrator,
    AppAuthOracleEvaluator,
    ATTOpcode,
    ATTSignedWritePayload,
    BLEFrame,
    CSRKSigningOracleEvaluator,
    IdbleedVerificationAnalyzer,
    IdentityRecord,
    LLEncryptionOracleEvaluator,
    LLEncryptionReqPayload,
    LLOpcode,
    OracleResult,
    ble_packet_record_to_frame,
    compute_csrk_cmac,
    generate_encryption_trace,
)
from app.components.navigation import (
    ALL_NAVIGATION_VIEWS,
    NAVIGATION_VIEWS,
    PRIVACY_DEFENSE_VIEW,
    render_navigation,
)
from app.queue_bridge import EventQueue
from app.views.privacy_defense import (
    build_ariel_ablation_figure,
    build_coupling_suppression_figure,
    render_privacy_defense,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSidechannelPackageExports:
    """Verify public IDBLEED verification API re-exports from airtell.sidechannel."""

    def test_all_expected_symbols_exported(self) -> None:
        expected_exports = {
            "OracleResult",
            "LLOpcode",
            "ATTOpcode",
            "BLEFrame",
            "LLEncryptionReqPayload",
            "ATTSignedWritePayload",
            "LLEncryptionOracleEvaluator",
            "CSRKSigningOracleEvaluator",
            "AppAuthOracleEvaluator",
            "IdentityRecord",
            "ActiveRelayProbeOrchestrator",
            "IdbleedVerificationAnalyzer",
            "ble_packet_record_to_frame",
            "compute_csrk_cmac",
        }
        assert expected_exports.issubset(set(sidechannel_pkg.__all__))
        for name in expected_exports:
            assert hasattr(sidechannel_pkg, name), f"Missing attribute {name} on airtell.sidechannel"

        assert OracleResult.PAIRED.value == 1
        assert LLOpcode.LL_REJECT_IND == 0x0D
        assert LLOpcode.LL_REJECT_EXT_IND == 0x11
        assert ATTOpcode.ATT_SIGNED_WRITE_CMD == 0xD2
        assert IdentityRecord is not None
        assert ATTSignedWritePayload is not None
        assert LLEncryptionOracleEvaluator is not None
        assert AppAuthOracleEvaluator is not None
        assert CSRKSigningOracleEvaluator is not None
        assert IdbleedVerificationAnalyzer is not None
        assert callable(ble_packet_record_to_frame)
        assert callable(compute_csrk_cmac)


class TestArielCliSubcommand:
    """Verify `airtell ariel` and `airtell entailment` CLI modes, formats, and error bounds."""

    def test_single_tuple_entailment_json_and_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_json = tmp_path / "ariel_single.json"
        rc = main(
            [
                "ariel",
                "--domain",
                "spa",
                "--data-type",
                "public weather forecast",
                "--data-subject",
                "user",
                "--data-sender",
                "assistant provider",
                "--data-recipient",
                "device owner",
                "--transmission-principle",
                "with subject's consent",
                "--json",
                "-o",
                str(out_json),
            ]
        )
        assert rc == 0
        assert out_json.is_file()
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["mode"] == "entailment"
        assert parsed["domain"] == "SPA"
        assert parsed["decision"] in ("appropriate", "inappropriate", "undetermined")
        assert json.loads(out_json.read_text(encoding="utf-8")) == parsed

    def test_entailment_alias_with_anchor_role_markdown(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(
            [
                "entailment",
                "--domain",
                "spa",
                "--data-type",
                "calendar availability",
                "--data-recipient",
                "housemate",
                "--anchor-role",
                "housemate=L4",
                "--markdown",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "# ARIEL Entailment Verdict (`SPA`)" in out
        assert "`housemate`" in out

    def test_benchmark_mode_edge_offload_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(
            [
                "ariel",
                "--domain",
                "education",
                "--benchmark",
                "--edge-offload",
                "--seed",
                "42",
                "--json",
            ]
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "benchmark"
        assert data["domain"] == "Education"
        assert data["edge_offload"] is True
        assert data["edge_mapper_parity"] == 1.0
        assert data["metrics"]["ariel_edge_lightweight"]["contradiction_escalation_rate"] == 1.0

    def test_ablation_mode_memory_scaling_stability(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_md = tmp_path / "ablation.md"
        rc_md = main(
            [
                "ariel",
                "--domain",
                "spa",
                "--ablation",
                "--memory-sizes",
                "10,20,40,60",
                "--md",
                "--output",
                str(out_md),
            ]
        )
        assert rc_md == 0
        assert out_md.is_file()
        assert "# ARIEL Memory-Scaling Ablation (SPA)" in out_md.read_text(encoding="utf-8")
        _ = capsys.readouterr()

        rc_json = main(["ariel", "--domain", "spa", "--ablation", "--memory-sizes", "10,20,40,60", "--json"])
        assert rc_json == 0
        ab = json.loads(capsys.readouterr().out)
        assert ab["memory_sizes"] == [10, 20, 40, 60]
        assert ab["results"]["ariel"]["20"]["f1_inappropriate"] >= 0.95
        assert ab["results"]["ariel"]["20"]["f1_inappropriate"] > ab["results"]["ariel"]["10"]["f1_inappropriate"]

    @pytest.mark.parametrize(
        "bad_args",
        [
            ["ariel"],
            ["ariel", "--data-type", "full SSN", "--anchor-role", "malformed_role"],
            ["ariel", "--ablation", "--memory-sizes", "10,-5"],
            ["ariel", "--ablation", "--memory-sizes", "not_ints"],
        ],
    )
    def test_ariel_cli_validation_errors_return_two(self, bad_args: list[str]) -> None:
        assert main(bad_args) == 2


class TestIdbleedVerifyCliSubcommand:
    """Verify `airtell idbleed-verify` and `airtell idbleed` CLI modes."""

    def test_selftest_json_and_markdown(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        out_file = tmp_path / "selftest.json"
        rc = main(["idbleed-verify", "--selftest", "--json", "-o", str(out_file)])
        assert rc == 0
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["mode"] == "selftest"
        assert parsed["tests_run"] == 5
        assert parsed["passed"] == 5
        assert parsed["success"] is True
        assert out_file.is_file()

        rc_md = main(["idbleed", "--selftest", "--markdown"])
        assert rc_md == 0
        assert "# IDBLEED Specification Canonical Self-Test" in capsys.readouterr().out

    @pytest.mark.parametrize("feature", ["all", "ll-enc", "csrk", "app-auth", "relay"])
    def test_mock_feature_selection(self, feature: str, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(
            [
                "idbleed-verify",
                "--mock",
                "--feature",
                feature,
                "--target-mac",
                "5A:11:22:33:44:55",
                "--json",
            ]
        )
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "mock"
        assert data["feature"] == feature
        assert data["findings_count"] >= 1
        assert data["leakage_detected"] is True

    def test_pcap_audit_mode(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        pcap_path = tmp_path / "paired_handshake.pcap"
        pcap_path.write_bytes(generate_encryption_trace(shared_ltk=True))
        rc = main(["idbleed-verify", "--pcap", str(pcap_path), "--feature", "ll-enc", "--json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["mode"] == "pcap"
        assert data["verdict"] == "PAIRED_SHARED_LTK"
        assert len(data["findings"]) >= 1

    @pytest.mark.parametrize(
        "bad_args",
        [
            ["idbleed-verify"],
            ["idbleed-verify", "--mock", "--selftest"],
            ["idbleed-verify", "--mock", "--target-mac", "NOT_A_MAC"],
            ["idbleed-verify", "--pcap", "/nonexistent/path/idbleed.pcap"],
        ],
    )
    def test_idbleed_cli_validation_errors_return_two(self, bad_args: list[str]) -> None:
        assert main(bad_args) == 2


class TestDefenseGatewayCliSubcommand:
    """Verify `airtell defense-gateway` and `airtell gateway` CLI modes."""

    def test_mock_and_coupling_sim_json(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        out_json = tmp_path / "gateway.json"
        rc = main(
            [
                "defense-gateway",
                "--mock",
                "--coupling-sim",
                "--domain",
                "spa",
                "--constant-time-ms",
                "25.0",
                "--json",
                "--output",
                str(out_json),
            ]
        )
        assert rc == 0
        assert out_json.is_file()
        data = json.loads(capsys.readouterr().out)
        gw = data["gateway_verdict"]
        assert gw["flow_allowed"] is False
        assert gw["exposure_report"]["suppressed_rejections"] >= 3
        assert gw["exposure_report"]["oracle_distinguishability_after"] == 0.0

        sim = data["coupling_simulation"]
        assert sim["rpa_linkage_eliminated"] is True
        assert sim["oracle_advantage_collapsed"] is True
        assert sim["unhardened"]["correlated_rpa_count"] == 3
        assert sim["unhardened"]["privacy_preserved"] is False
        assert sim["hardened"]["correlated_rpa_count"] == 0
        assert sim["hardened"]["privacy_preserved"] is True

    def test_gateway_alias_opt_out_and_markdown(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(
            [
                "gateway",
                "--mock",
                "--domain",
                "education",
                "--opt-out",
                "--anchor-role",
                "housemate=L4",
                "--markdown",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "# AirTell Integrated Defense Gateway (`Education`)" in out
        assert "`implicit_consent_trap`" in out

    @pytest.mark.parametrize(
        "bad_args",
        [
            ["defense-gateway"],
            ["defense-gateway", "--mock", "--constant-time-ms", "-1.0"],
            ["defense-gateway", "--mock", "--anchor-role", "bad_role_spec"],
        ],
    )
    def test_gateway_cli_validation_errors_return_two(self, bad_args: list[str]) -> None:
        assert main(bad_args) == 2


class TestPrivacyDefenseDashboardView:
    """Verify Streamlit navigation invariants and `render_privacy_defense` execution."""

    def test_navigation_preserves_core_views_and_exposes_privacy_defense(self) -> None:
        assert set(NAVIGATION_VIEWS.keys()) == {
            "telemetry",
            "rssi",
            "alerts",
            "inspector",
            "controls",
            "adversarial",
        }
        assert "privacy_defense" in PRIVACY_DEFENSE_VIEW
        assert ALL_NAVIGATION_VIEWS["privacy_defense"]["label"] == "Privacy & Defense"

        with (
            patch("streamlit.html"),
            patch("streamlit.sidebar.markdown"),
            patch("streamlit.sidebar.divider"),
            patch("streamlit.sidebar.radio", return_value="privacy_defense") as mock_radio,
        ):
            selected = render_navigation()
            assert selected == "privacy_defense"
            offered_options = mock_radio.call_args.kwargs["options"]
            assert "privacy_defense" in offered_options

    def test_render_privacy_defense_executes_cleanly(self) -> None:
        queue = EventQueue(maxsize=20)
        queue.push({"raw_payload": "020106", "channel": 37, "rssi": -55})

        def mock_columns(spec: int | list[int]) -> list[MagicMock]:
            count = spec if isinstance(spec, int) else len(spec)
            return [MagicMock() for _ in range(count)]

        with (
            patch("streamlit.subheader"),
            patch("streamlit.caption"),
            patch("streamlit.tabs", side_effect=lambda tabs: [MagicMock() for _ in tabs]),
            patch("streamlit.columns", side_effect=mock_columns),
            patch(
                "streamlit.selectbox",
                side_effect=lambda label, options, index=0, **kw: options[index],
            ),
            patch("streamlit.checkbox", side_effect=[True, True, False]),
            patch("streamlit.text_input", side_effect=["housemate=L4", "5A:11:22:33:44:55"]),
            patch("streamlit.slider", return_value=25),
            patch("streamlit.metric"),
            patch("streamlit.dataframe"),
            patch("streamlit.download_button"),
            patch("streamlit.plotly_chart") as mock_plotly,
        ):
            summary = render_privacy_defense(event_queue=queue)

        assert summary["idbleed_findings"] == 5
        assert summary["live_packets_analyzed"] == 1
        assert summary["gateway_allowed"] is False
        assert summary["suppressed_rejections"] >= 3
        assert summary["rpa_linkage_eliminated"] is True
        assert mock_plotly.call_count == 2
        for call in mock_plotly.call_args_list:
            assert isinstance(call.args[0], go.Figure)

    def test_streamlit_app_routes_privacy_defense_view(self) -> None:
        from app import streamlit_app

        mock_conn = MagicMock()
        with (
            patch.object(streamlit_app, "get_db_connection", return_value=mock_conn),
            patch.object(streamlit_app, "get_event_queue", return_value=MagicMock()),
            patch.object(streamlit_app, "render_top_app_bar"),
            patch.object(streamlit_app, "render_navigation", return_value="privacy_defense"),
            patch("streamlit.sidebar", MagicMock()),
            patch("streamlit.checkbox", return_value=False),
            patch("streamlit.slider", return_value=5),
            patch("streamlit.divider"),
            patch("streamlit.expander", return_value=MagicMock()),
            patch.object(streamlit_app, "render_privacy_defense") as mock_view,
        ):
            streamlit_app.main()
            mock_view.assert_called_once()
        mock_conn.close.assert_called_once()


class TestCrossPackageEndToEndWorkflow:
    """Verify live cross-package ARIEL + IDBLEED + IntegratedDefenseGateway workflows."""

    def test_ariel_solver_idbleed_frames_and_defense_gateway_e2e(self) -> None:
        ontology = build_spa_ontology()

        # 1. Dynamic social role misalignment check ('housemate' anchored to D_u)
        r_colleague_ok = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="work colleague",
            transmission_principle="with subject's consent",
        )
        r_housemate_no = InformationFlowRequest(
            data_type="calendar availability",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="housemate",
            transmission_principle="with subject's consent",
        )
        r_housemate_gps = InformationFlowRequest(
            data_type="exact GPS location",
            data_subject="user",
            data_sender="assistant provider",
            data_recipient="housemate",
            transmission_principle="with subject's consent",
        )
        memory = UserDecisionMemory(
            user_id="e2e-user",
            records=[
                PriorDecisionRecord(r_colleague_ok, DecisionLabel.APPROPRIATE),
                PriorDecisionRecord(r_housemate_no, DecisionLabel.INAPPROPRIATE),
            ],
        )

        anchored_mapper = AdaptiveMemoryAnchoredMapper(memory=memory)
        tuned_ontology = anchored_mapper.build_tuned_ontology(
            ontology,
            candidate_values={"data_recipient": ["housemate"]},
        )
        ariel_solver = ARIELSolver(tuned_ontology, anchored_mapper)
        entailment_res = ariel_solver.evaluate(r_housemate_gps, memory)
        assert entailment_res.label is DecisionLabel.INAPPROPRIATE
        assert entailment_res.c_minus == 1

        # 2. Construct live BLEFrame probes from airtell.sidechannel.idbleed_spec
        prober_mac = "E0:AA:BB:CC:DD:99"
        target_rpa = "5A:01:02:03:04:C1"
        enc_req_bytes = LLEncryptionReqPayload(
            rand=b"\x01" * 8,
            ediv=0x1234,
            skd_c=b"\x02" * 8,
            iv_c=b"\x03" * 4,
        ).serialize()
        ble_frames = [
            BLEFrame(1.000, 12, -54, prober_mac, target_rpa, "LL_CONTROL", enc_req_bytes),
            BLEFrame(
                1.004,
                12,
                -54,
                target_rpa,
                prober_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_REJECT_IND, 0x06]),
            ),
            BLEFrame(
                1.009,
                12,
                -54,
                target_rpa,
                prober_mac,
                "LL_CONTROL",
                bytes([LLOpcode.LL_REJECT_EXT_IND, LLOpcode.LL_ENC_REQ, 0x06]),
            ),
        ]

        monitor = IDBLEEDSideChannelMonitor(LinkLayerHardeningConfig(constant_time_window_ms=25.0))
        opt_switch = CryptographicLocalOptOutSwitch(secrets.token_bytes(32))
        gateway = IntegratedDefenseGateway(
            ontology_set=tuned_ontology,
            solver=ariel_solver,
            edge_offloader=LightweightEdgeOntologyOffloader(),
            side_channel_monitor=monitor,
            opt_out_switch=opt_switch,
            domain="SPA",
        )

        verdict = gateway.evaluate_and_enforce(
            r_housemate_gps,
            memory,
            ble_frames=ble_frames,
            is_ambient_flow=True,
            active_agent_authorized=False,
        )
        assert verdict.decision == "inappropriate"
        assert verdict.flow_allowed is False
        assert FailureMode.IMPLICIT_CONSENT_TRAP in verdict.mitigated_failure_modes
        assert verdict.frame_decisions[1].action is FrameAction.SILENT_DROP_CONSTANT_TIME
        assert verdict.frame_decisions[2].action is FrameAction.SILENT_DROP_CONSTANT_TIME
        assert verdict.exposure_report.oracle_distinguishability_after == 0.0

        # 3. Verify contradictory priors trigger explicit abstention + execution halt
        contra_memory = UserDecisionMemory(
            user_id="e2e-contra",
            records=[
                PriorDecisionRecord(
                    InformationFlowRequest(
                        "calendar availability",
                        "user",
                        "assistant provider",
                        "work colleague",
                        "with subject's consent",
                    ),
                    DecisionLabel.APPROPRIATE,
                ),
                PriorDecisionRecord(
                    InformationFlowRequest(
                        "calendar availability",
                        "user",
                        "assistant provider",
                        "family member",
                        "with subject's consent",
                    ),
                    DecisionLabel.INAPPROPRIATE,
                ),
            ],
        )
        contra_query = InformationFlowRequest(
            "calendar availability",
            "user",
            "assistant provider",
            "close friend",
            "with subject's consent",
        )
        contra_verdict = gateway.evaluate_and_enforce(contra_query, contra_memory)
        assert contra_verdict.decision == "undetermined"
        assert contra_verdict.abstention_reason == ABSTENTION_CONTRADICTORY_PRIORS
        assert contra_verdict.automated_execution_halted is True
        assert FailureMode.CONTRADICTORY_PRIORS in contra_verdict.mitigated_failure_modes

        # 4. Verify CrossDomainCouplingVerifier uses merged idbleed_spec evaluators at runtime
        coupling = CrossDomainCouplingVerifier().verify_coupling_mitigation()
        assert coupling.rpa_linkage_eliminated is True
        assert coupling.oracle_advantage_collapsed is True
        assert isinstance(build_coupling_suppression_figure(coupling), go.Figure)

        # 5. Verify ActiveRelayProbeOrchestrator rejects INDETERMINATE frames cleanly
        orch = ActiveRelayProbeOrchestrator("canonical-dev", rpa_rotation_window_sec=900.0)
        assert orch.evaluate_and_correlate(target_rpa, OracleResult.INDETERMINATE, timestamp=100.0) is False
        assert orch.correlation_summary()["correlated_rpa_count"] == 0

    def test_blueprint_and_conductor_track_artifacts_exist(self) -> None:
        blueprint = REPO_ROOT / "docs" / "ariel_idbleed_blueprint.md"
        assert blueprint.is_file()
        text = blueprint.read_text(encoding="utf-8")
        assert "A_\\theta(D_u, R_u)" in text
        assert "idbleed_spec.py" in text
        assert "Gemma 3 4B IT" in text

        track_dir = REPO_ROOT / "conductor" / "tracks" / "ariel_idbleed_defense_20261117"
        for fname in ("index.md", "metadata.json", "spec.md", "plan.md"):
            assert (track_dir / fname).is_file(), f"Missing {fname} in {track_dir}"
        meta = json.loads((track_dir / "metadata.json").read_text(encoding="utf-8"))
        assert meta["track_id"] == "ariel_idbleed_defense_20261117"
        assert meta["status"] == "completed"
        assert "ariel_idbleed_defense_20261117" in (REPO_ROOT / "conductor" / "tracks.md").read_text(
            encoding="utf-8"
        )
        assert build_ariel_ablation_figure is not None
