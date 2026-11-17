"""Material Design v3 Tactical View for ARIEL Privacy Entailment, IDBLEED Auditing, and Edge Defense Gateway."""

from __future__ import annotations

import json
import secrets
import struct
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from airtell.ariel import (
    AdaptiveMemoryAnchoredMapper,
    ARIELSolver,
    InformationFlowRequest,
    LightweightEdgeOntologyMapper,
    MemoryAblationReport,
    OntologyMapper,
    StructuredOntologyMapper,
    build_education_benchmark,
    build_spa_benchmark,
    level_to_rank,
    run_memory_ablation,
)
from airtell.defense import (
    ATT_SIGNED_WRITE_CMD,
    LL_ENC_REQ,
    LL_REJECT_EXT_IND,
    LL_REJECT_IND,
    LL_TERMINATE_IND,
    CrossDomainComparisonSummary,
    CrossDomainCouplingVerifier,
    CryptographicLocalOptOutSwitch,
    IDBLEEDSideChannelMonitor,
    IntegratedDefenseGateway,
    LightweightEdgeOntologyOffloader,
    LinkLayerHardeningConfig,
    MonitorBLEFrame,
)
from airtell.sidechannel import (
    ActiveRelayProbeOrchestrator,
    AppAuthOracleEvaluator,
    ATTOpcode,
    ATTSignedWritePayload,
    BLEFrame,
    CSRKSigningOracleEvaluator,
    IdbleedVerificationAnalyzer,
    LLEncryptionOracleEvaluator,
    LLEncryptionReqPayload,
    LLOpcode,
    OracleResult,
    compute_csrk_cmac,
)


def build_ariel_ablation_figure(ablation: MemoryAblationReport) -> go.Figure:
    """Build Material Design v3 Plotly chart comparing ARIEL vs baselines across |D_u|."""
    sizes = list(ablation.memory_sizes)
    ariel_f1_i = [ablation.results["ariel"][s].f1_inappropriate for s in sizes]
    edge_f1_i = [ablation.results["ariel_edge_lightweight"][s].f1_inappropriate for s in sizes]
    norms_f1_i = [ablation.results["general_ci_norms"][s].f1_inappropriate for s in sizes]
    icl_f1_i = [ablation.results["simulated_icl"][s].f1_inappropriate for s in sizes]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=sizes,
            y=ariel_f1_i,
            mode="lines+markers",
            name="ARIEL Host Solver (F1_I)",
            line={"color": "#A8C7FA", "width": 3},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=sizes,
            y=edge_f1_i,
            mode="lines+markers",
            name="ARIEL Edge Mapper (Gemma 3 4B IT)",
            line={"color": "#A8E8BA", "width": 2, "dash": "dash"},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=sizes,
            y=icl_f1_i,
            mode="lines+markers",
            name="Pure LLM ICL Baseline",
            line={"color": "#F9DEDC", "width": 2},
        )
    )
    fig.add_trace(
        go.Scatter(
            x=sizes,
            y=norms_f1_i,
            mode="lines+markers",
            name="General CI Norms Baseline",
            line={"color": "#F2B8B5", "width": 2, "dash": "dot"},
        )
    )
    fig.update_layout(
        title=f"Memory Scaling Ablation ({ablation.domain}): Privacy F1_I vs |D_u|",
        xaxis_title="User Prior Decision Memory Size |D_u|",
        yaxis_title="Privacy F1 Score (F1_I)",
        yaxis={"range": [0.0, 1.05]},
        paper_bgcolor="#0F141C",
        plot_bgcolor="#1B2028",
        font={"color": "#E1E2E8"},
        margin={"l": 40, "r": 20, "t": 45, "b": 40},
    )
    return fig


def build_coupling_suppression_figure(comparison: CrossDomainComparisonSummary) -> go.Figure:
    """Build Material Design v3 Plotly chart comparing unhardened vs hardened BLE side-channel exposure."""
    categories = ["Correlated RPAs (C1..C3)", "Oracle Distinguishability"]
    unhardened_vals = [
        float(comparison.unhardened.correlated_rpa_count),
        float(comparison.unhardened.exposure_report.oracle_distinguishability_before),
    ]
    hardened_vals = [
        float(comparison.hardened.correlated_rpa_count),
        float(comparison.hardened.exposure_report.oracle_distinguishability_after),
    ]

    fig = go.Figure(
        data=[
            go.Bar(
                name="Unhardened Peripheral",
                x=categories,
                y=unhardened_vals,
                marker_color="#F2B8B5",
            ),
            go.Bar(
                name="Hardened Defense Gateway",
                x=categories,
                y=hardened_vals,
                marker_color="#A8E8BA",
            ),
        ]
    )
    fig.update_layout(
        barmode="group",
        title="Cross-Domain RPA Linkage & Boolean Oracle Suppression (Delta_RPA = 15 min)",
        paper_bgcolor="#0F141C",
        plot_bgcolor="#1B2028",
        font={"color": "#E1E2E8"},
        margin={"l": 40, "r": 20, "t": 45, "b": 40},
    )
    return fig


def run_idbleed_dashboard_audit(target_mac: str = "5A:11:22:33:44:55") -> dict[str, Any]:
    """Execute deterministic IDBLEED verification across Feature Sets I-IV for dashboard inspection."""
    resolved_mac = target_mac.strip().upper() if target_mac.strip() else "5A:11:22:33:44:55"
    central_mac = "AA:BB:CC:DD:EE:01"

    # Feature I: LL Encryption Handshake
    ll_eval = LLEncryptionOracleEvaluator(target_mac=resolved_mac)
    enc_req = LLEncryptionReqPayload(
        rand=b"\x10\x20\x30\x40\x50\x60\x70\x80",
        ediv=0x1A2B,
        skd_c=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        iv_c=b"\xa1\xb2\xc3\xd4",
    ).serialize()
    ll_eval.process_frame(BLEFrame(1.0, 12, -52, central_mac, resolved_mac, "LL_CONTROL", enc_req))
    ll_paired_res, ll_paired_msg = ll_eval.process_frame(
        BLEFrame(1.05, 12, -53, resolved_mac, central_mac, "LL_CONTROL", bytes([LLOpcode.LL_START_ENC_RSP]))
    )

    ll_unpaired = LLEncryptionOracleEvaluator(target_mac=resolved_mac)
    ll_unpaired.process_frame(BLEFrame(2.0, 12, -58, central_mac, resolved_mac, "LL_CONTROL", enc_req))
    ll_rej_res, ll_rej_msg = ll_unpaired.process_frame(
        BLEFrame(2.04, 12, -58, resolved_mac, central_mac, "LL_CONTROL", bytes([LLOpcode.LL_REJECT_IND, 0x06]))
    )

    # Feature II: CSRK 64-bit AES-CMAC Signing Oracle
    csrk_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    cmac_tag = compute_csrk_cmac(csrk_key, 0x0018, b"\x01\x02\x03", 1)
    signed_pdu = ATTSignedWritePayload(
        handle=0x0018,
        value=b"\x01\x02\x03",
        signature_counter=1,
        cmac=cmac_tag,
    ).serialize()
    csrk_eval = CSRKSigningOracleEvaluator(target_mac=resolved_mac, csrk=csrk_key)
    csrk_res, csrk_msg = csrk_eval.evaluate_signature_response(
        BLEFrame(5.0, 15, -55, central_mac, resolved_mac, "ATT", signed_pdu),
        BLEFrame(5.02, 15, -56, resolved_mac, central_mac, "LL_ACK", b"\x01\x00"),
    )

    # Feature III: GATT 0xFFF1 Application Authentication
    app_eval = AppAuthOracleEvaluator(target_mac=resolved_mac, auth_handle=0xFFF1)
    app_eval.process_att_frame(
        BLEFrame(10.0, 20, -50, resolved_mac, central_mac, "ATT", bytes([ATTOpcode.ATT_READ_RSP, 0x01]))
    )
    app_eval.process_att_frame(
        BLEFrame(
            10.1,
            20,
            -50,
            central_mac,
            resolved_mac,
            "ATT",
            bytes([ATTOpcode.ATT_WRITE_CMD]) + struct.pack("<H", 0xFFF1) + b"CHALLENGE",
        )
    )
    app_res, app_msg = app_eval.process_att_frame(
        BLEFrame(
            10.2,
            20,
            -50,
            resolved_mac,
            central_mac,
            "ATT",
            bytes([ATTOpcode.ATT_HANDLE_VALUE_NOTI]) + struct.pack("<H", 0xFFF1) + b"OK",
        )
    )

    # Feature IV: Spatial Relay & Multi-Window RPA Correlation (Delta_RPA = 900s)
    orch = ActiveRelayProbeOrchestrator(canonical_target_id=resolved_mac, rpa_rotation_window_sec=900.0)
    orch.evaluate_and_correlate(resolved_mac, OracleResult.PAIRED, timestamp=100.0)
    orch.evaluate_and_correlate("6E:AA:BB:CC:DD:02", OracleResult.PAIRED, timestamp=1000.0)
    orch.evaluate_and_correlate("71:FF:EE:DD:CC:99", OracleResult.UNPAIRED, timestamp=200.0)
    corr_summary = orch.correlation_summary()

    rows = [
        {"Feature Set": "I. LL Encryption (Shared LTK)", "Verdict": ll_paired_res.name, "Detail": ll_paired_msg},
        {"Feature Set": "I. LL Encryption (0x0D Reject)", "Verdict": ll_rej_res.name, "Detail": ll_rej_msg},
        {"Feature Set": "II. CSRK 64-bit AES-CMAC", "Verdict": csrk_res.name, "Detail": csrk_msg},
        {"Feature Set": "III. GATT 0xFFF1 App Auth", "Verdict": app_res.name, "Detail": app_msg},
        {
            "Feature Set": "IV. Active Relay RPA Correlation",
            "Verdict": "PAIRED",
            "Detail": f"Linked {corr_summary['correlated_rpa_count']} RPAs over Delta_RPA = 900s",
        },
    ]
    return {
        "target_mac": resolved_mac,
        "rows": rows,
        "correlation": corr_summary,
    }


def render_privacy_defense(
    conn: Any = None,
    tracker_db: Any = None,
    event_queue: Any = None,
    backend: Any = None,
) -> dict[str, Any]:
    """Render the Privacy & Defense tactical dashboard view.

    Showcases ARIEL 5-tuple Contextual Integrity entailment proofs (<=_O),
    IDBLEED Link-Layer boolean side-channel verification, and the Integrated
    Edge Defense Gateway constant-time suppression metrics.
    """
    del conn, tracker_db, backend

    st.subheader("🛡️ Privacy & Defense // ARIEL Entailment & IDBLEED Hardening")
    st.caption(
        "Neurosymbolic Contextual Integrity (`<=_O`) privacy proofs coupled with constant-time BLE Link-Layer "
        "side-channel suppression (`0x0D`/`0x11`/`0x02`/`0xD2`)."
    )

    tab_ariel, tab_idbleed, tab_gateway = st.tabs(
        [
            "🧠 ARIEL Entailment Proofs (<=_O)",
            "📡 IDBLEED Side-Channel Verification",
            "🛡️ Edge Defense Gateway & Coupling",
        ]
    )

    # ------------------------------------------------------------------
    # Tab 1: ARIEL 5-Tuple Entailment Proofs & Memory Scaling
    # ------------------------------------------------------------------
    with tab_ariel:
        col_cfg1, col_cfg2, col_cfg3 = st.columns(3)
        with col_cfg1:
            selected_domain = st.selectbox("CI Domain Ontology", ["SPA", "Education"], index=0)
        with col_cfg2:
            use_edge_mapper = st.checkbox("Edge Lightweight Mapper (Gemma 3 4B IT)", value=False)
        with col_cfg3:
            anchor_spec = st.text_input("Dynamic Role Anchor (ROLE=LEVEL)", value="")

        dataset = (
            build_spa_benchmark(seed=42)
            if str(selected_domain).upper() == "SPA"
            else build_education_benchmark(seed=42)
        )
        ontology = dataset.ontology
        user_memory = dataset.users[0].memory

        dt_options = list(ontology.get_parameter_ontology("data_type").ranks.keys())  # type: ignore[union-attr]
        ds_options = list(ontology.get_parameter_ontology("data_sender").ranks.keys())  # type: ignore[union-attr]
        dr_options = list(ontology.get_parameter_ontology("data_recipient").ranks.keys())  # type: ignore[union-attr]
        tp_options = list(ontology.get_parameter_ontology("transmission_principle").ranks.keys())  # type: ignore[union-attr]
        subj_default = "user" if ontology.domain == "SPA" else "student"

        c_p1, c_p2, c_p3, c_p4 = st.columns(4)
        with c_p1:
            sel_dt = st.selectbox("Data Type (d_u)", dt_options, index=0)
        with c_p2:
            sel_ds = st.selectbox("Data Sender (s)", ds_options, index=0)
        with c_p3:
            sel_dr = st.selectbox("Data Recipient (r)", dr_options, index=0)
        with c_p4:
            sel_tp = st.selectbox("Transmission Principle (t)", tp_options, index=0)

        tuned_ranks: dict[tuple[str, str], int] = {}
        if isinstance(anchor_spec, str) and "=" in anchor_spec:
            r_part, l_part = anchor_spec.split("=", 1)
            if r_part.strip() and l_part.strip():
                try:
                    rank_val = int(l_part.strip()) if l_part.strip().isdigit() else level_to_rank(l_part.strip())
                    ontology = ontology.with_updated_rank("data_recipient", r_part.strip(), rank_val)
                    tuned_ranks[("data_recipient", r_part.strip())] = rank_val
                except ValueError:
                    pass

        mapper: OntologyMapper
        if tuned_ranks:
            mapper = AdaptiveMemoryAnchoredMapper(memory=user_memory, tuned_ranks=tuned_ranks)
        elif use_edge_mapper:
            mapper = LightweightEdgeOntologyMapper()
        else:
            mapper = StructuredOntologyMapper()

        ariel_solver = ARIELSolver(ontology_set=ontology, mapper=mapper)
        flow_req = InformationFlowRequest(
            data_type=str(sel_dt) if sel_dt in dt_options else dt_options[0],
            data_subject=subj_default,
            data_sender=str(sel_ds) if sel_ds in ds_options else ds_options[0],
            data_recipient=str(sel_dr) if sel_dr in dr_options else dr_options[0],
            transmission_principle=str(sel_tp) if sel_tp in tp_options else tp_options[0],
        )
        entailment_res = ariel_solver.evaluate(flow_req, user_memory)

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Entailment Verdict", entailment_res.label.value.upper())
        with m2:
            st.metric("Rule 2 (c_plus)", entailment_res.c_plus)
        with m3:
            st.metric("Rule 1 (c_minus)", entailment_res.c_minus)
        with m4:
            st.metric("Neighborhood |E| (d <= 1)", entailment_res.proof.neighbors_checked)

        step_rows = [
            {
                "Rule": s.rule,
                "Entailed": s.entailed_label.value,
                "Distance": s.hamming_distance,
                "Varied Param": s.varied_parameter or "exact_match",
                "Prior Rank": s.prior_rank,
                "Incoming Rank": s.incoming_rank,
            }
            for s in entailment_res.proof.entailed_steps
        ]
        st.dataframe(pd.DataFrame(step_rows) if step_rows else pd.DataFrame(columns=["Rule", "Entailed", "Distance"]))

        ablation_report = run_memory_ablation(dataset, memory_sizes=(10, 20, 40, 60))
        st.plotly_chart(build_ariel_ablation_figure(ablation_report), width="stretch")

    # ------------------------------------------------------------------
    # Tab 2: IDBLEED Boolean Side-Channel Verification
    # ------------------------------------------------------------------
    with tab_idbleed:
        target_mac_in = st.text_input("Audited Target Peripheral MAC / RPA", value="5A:11:22:33:44:55")
        idbleed_summary = run_idbleed_dashboard_audit(
            target_mac=target_mac_in if isinstance(target_mac_in, str) else "5A:11:22:33:44:55"
        )

        live_packets_analyzed = 0
        if event_queue is not None and hasattr(event_queue, "drain_all"):
            live_analyzer = IdbleedVerificationAnalyzer()
            for item in event_queue.drain_all():
                if isinstance(item, dict) and "raw_payload" in item:
                    live_packets_analyzed += 1
            _ = live_analyzer.finalize()

        i1, i2, i3 = st.columns(3)
        with i1:
            st.metric("Evaluated Feature Oracles", len(idbleed_summary["rows"]))
        with i2:
            st.metric("Correlated Rotating RPAs", idbleed_summary["correlation"]["correlated_rpa_count"])
        with i3:
            st.metric("RPA Rotation Window", f"{idbleed_summary['correlation']['rpa_rotation_window_sec']:.0f}s")

        st.dataframe(pd.DataFrame(idbleed_summary["rows"]))
        st.download_button(
            label="Export IDBLEED Audit JSON",
            data=json.dumps(idbleed_summary, indent=2),
            file_name="idbleed_verification_report.json",
            mime="application/json",
        )

    # ------------------------------------------------------------------
    # Tab 3: Integrated Edge Defense Gateway & Threat Coupling
    # ------------------------------------------------------------------
    with tab_gateway:
        g_col1, g_col2, g_col3 = st.columns(3)
        with g_col1:
            window_ms = st.slider("Constant-Time BLE Window (ms)", min_value=0, max_value=100, value=25)
        with g_col2:
            enable_opt_out = st.checkbox("HMAC-SHA256 Local Opt-Out Active", value=False)
        with g_col3:
            ambient_auth = st.checkbox("Active User Agent Ambient Authorization", value=False)

        resolved_window = float(window_ms) if isinstance(window_ms, (int, float)) else 25.0
        monitor = IDBLEEDSideChannelMonitor(
            LinkLayerHardeningConfig(constant_time_window_ms=max(0.0, resolved_window))
        )
        opt_switch = CryptographicLocalOptOutSwitch(secrets.token_bytes(32))
        if enable_opt_out:
            opt_switch.set_opt_out(user_memory.user_id, ontology.domain, opted_out=True)

        gateway = IntegratedDefenseGateway(
            ontology_set=ontology,
            solver=ariel_solver,
            edge_offloader=LightweightEdgeOntologyOffloader(),
            side_channel_monitor=monitor,
            opt_out_switch=opt_switch,
            domain=ontology.domain,
        )

        probe_frames = [
            MonitorBLEFrame(
                1.000,
                12,
                -55,
                "E0:AA:BB:CC:DD:99",
                "5A:01:02:03:04:C1",
                "LL_CONTROL",
                bytes([LL_ENC_REQ]) + b"\x11" * 22,
            ),
            MonitorBLEFrame(
                1.004,
                12,
                -55,
                "5A:01:02:03:04:C1",
                "E0:AA:BB:CC:DD:99",
                "LL_CONTROL",
                bytes([LL_REJECT_IND, 0x06]),
            ),
            MonitorBLEFrame(
                1.010,
                12,
                -56,
                "5A:01:02:03:04:C1",
                "E0:AA:BB:CC:DD:99",
                "LL_CONTROL",
                bytes([LL_REJECT_EXT_IND, LL_ENC_REQ, 0x06]),
            ),
            MonitorBLEFrame(
                1.015,
                12,
                -56,
                "5A:01:02:03:04:C1",
                "E0:AA:BB:CC:DD:99",
                "LL_CONTROL",
                bytes([LL_TERMINATE_IND, 0x13]),
            ),
            MonitorBLEFrame(
                1.020,
                12,
                -56,
                "E0:AA:BB:CC:DD:99",
                "5A:01:02:03:04:C1",
                "ATT",
                bytes([ATT_SIGNED_WRITE_CMD]) + b"\x18\x00\x01" + b"\x00" * 12,
            ),
        ]
        gw_verdict = gateway.evaluate_and_enforce(
            flow_req,
            user_memory,
            ble_frames=probe_frames,
            domain=ontology.domain,
            is_ambient_flow=True,
            active_agent_authorized=bool(ambient_auth),
        )

        coupling_comparison = CrossDomainCouplingVerifier().verify_coupling_mitigation()

        d1, d2, d3, d4 = st.columns(4)
        with d1:
            st.metric("Gateway Flow Allowed", "YES" if gw_verdict.flow_allowed else "BLOCKED")
        with d2:
            st.metric("Suppressed Rejections", gw_verdict.exposure_report.suppressed_rejections)
        with d3:
            adv_drop = (
                gw_verdict.exposure_report.oracle_distinguishability_before
                - gw_verdict.exposure_report.oracle_distinguishability_after
            )
            st.metric(
                "Oracle Advantage",
                f"{gw_verdict.exposure_report.oracle_distinguishability_after:.2f}",
                delta=f"-{adv_drop:.2f}",
            )
        with d4:
            st.metric(
                "Correlated RPAs (Hardened)",
                f"{coupling_comparison.hardened.correlated_rpa_count} / 3",
            )

        st.plotly_chart(build_coupling_suppression_figure(coupling_comparison), width="stretch")

    return {
        "ariel_decision": entailment_res.label.value,
        "idbleed_findings": len(idbleed_summary["rows"]),
        "live_packets_analyzed": live_packets_analyzed,
        "gateway_allowed": gw_verdict.flow_allowed,
        "suppressed_rejections": gw_verdict.exposure_report.suppressed_rejections,
        "rpa_linkage_eliminated": coupling_comparison.rpa_linkage_eliminated,
    }
