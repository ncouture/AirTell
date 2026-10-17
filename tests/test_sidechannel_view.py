"""Automated unit and integration test suite for Streamlit side-channel visualizer tab.

Validates:
1. Plotly Timing Oracle scatter plot generation, styling, reference bands, and empty states.
2. Plotly CSRK 32-bit SignCounter trajectory chart generation, cross-RPA linking, and anomalies.
3. Encryption handshake classification DataFrame generation with status badges and PDU dissections.
4. EventQueue item to BlePacketRecord coercion across dictionaries and wire messages.
5. Cached PCAP analysis runner (@st.cache_data) with synthetic capture buffers.
6. SideChannelSuiteReport Markdown and JSON export serialization.
7. Full view rendering under Streamlit tabs, mock streams, and live queue ingestion modes.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pandas as pd
import plotly.graph_objects as go
import pytest

from airtell.protocol.wire import PacketMessage
from airtell.sidechannel import (
    AnalyzerReport,
    BatAllowlistFinding,
    BlePacketRecord,
    CsrkCounterFinding,
    EncryptionInitiationFinding,
    SideChannelSuiteReport,
    SideChannelType,
    Verdict,
    generate_encryption_trace,
)
from app.queue_bridge import EventQueue
from app.views.adversarial_evaluation import (
    build_csrk_trajectory_figure,
    build_handshake_classification_df,
    build_timing_oracle_figure,
    cached_analyze_pcap,
    queue_item_to_packet_record,
    render_adversarial_evaluation,
    render_sidechannel_metrics,
    render_sidechannel_tab,
)


@pytest.fixture
def mock_suite_report() -> SideChannelSuiteReport:
    """Fixture providing a populated SideChannelSuiteReport with findings across all 3 analyzers."""
    rep = SideChannelSuiteReport(
        timestamp=1729000000.0,
        target_mac="AA:BB:CC:DD:EE:02",
        total_packets=120,
    )

    # 1. Differential Encryption Findings
    enc_finding_pos = EncryptionInitiationFinding(
        finding_type=SideChannelType.DIFFERENTIAL_ENCRYPTION.value,
        timestamp=1729000010.0,
        device_addr="AA:BB:CC:DD:EE:02",
        target_addr="AA:BB:CC:DD:EE:01",
        verdict=Verdict.PAIRED_SHARED_LTK.value,
        confidence=1.0,
        details={
            "session_aa": 0x12345678,
            "opcode": 0x06,
            "opcode_name": "LL_START_ENC_RSP",
            "is_shared_ltk": True,
            "ediv": 0x1234,
            "rand": "0102030405060708",
            "summary": "Shared LTK established via LL_START_ENC_RSP.",
        },
    )
    enc_finding_neg = EncryptionInitiationFinding(
        finding_type=SideChannelType.DIFFERENTIAL_ENCRYPTION.value,
        timestamp=1729000020.0,
        device_addr="AA:BB:CC:DD:EE:03",
        target_addr="AA:BB:CC:DD:EE:01",
        verdict=Verdict.REJECTED_UNTRUSTED.value,
        confidence=1.0,
        details={
            "session_aa": 0x87654321,
            "opcode": 0x0D,
            "opcode_name": "LL_REJECT_IND",
            "is_shared_ltk": False,
            "error_code": 0x06,
            "is_pin_or_key_missing": True,
            "summary": "Encryption rejected with PIN_OR_KEY_MISSING.",
        },
    )
    rep.reports["differential_encryption"] = AnalyzerReport(
        analyzer_name="DifferentialEncryptionAnalyzer",
        verdict=Verdict.PAIRED_SHARED_LTK.value,
        summary="Confirmed shared LTK possession.",
        findings=[enc_finding_pos, enc_finding_neg],
        metrics={"total_sessions": 2, "shared_ltk_sessions": 1, "rejected_sessions": 1},
    )

    # 2. CSRK Counter Findings
    csrk_finding_1 = CsrkCounterFinding(
        finding_type=SideChannelType.CSRK_COUNTER.value,
        timestamp=1729000030.0,
        device_addr="40:11:22:33:44:01",
        target_addr="AA:BB:CC:DD:EE:02",
        verdict=Verdict.SEQUENTIAL_MONOTONIC.value,
        confidence=1.0,
        details={"counter": 100, "delta": 1, "mac_valid": True, "summary": "Strictly monotonic increment."},
    )
    csrk_finding_2 = CsrkCounterFinding(
        finding_type=SideChannelType.CSRK_COUNTER.value,
        timestamp=1729000031.0,
        device_addr="40:11:22:33:44:01",
        target_addr="AA:BB:CC:DD:EE:02",
        verdict=Verdict.SEQUENTIAL_MONOTONIC.value,
        confidence=1.0,
        details={"counter": 101, "delta": 1, "mac_valid": True, "summary": "Strictly monotonic increment."},
    )
    csrk_finding_cross = CsrkCounterFinding(
        finding_type=SideChannelType.CSRK_COUNTER.value,
        timestamp=1729000035.0,
        device_addr="40:11:22:33:44:02",  # Rotated RPA!
        target_addr="AA:BB:CC:DD:EE:02",
        verdict=Verdict.CROSS_RPA_LINKED.value,
        confidence=0.98,
        details={
            "counter": 102,
            "delta": 1,
            "linked_from": "40:11:22:33:44:01",
            "summary": "Cross-RPA trajectory continuation.",
        },
    )
    csrk_finding_anomaly = CsrkCounterFinding(
        finding_type=SideChannelType.CSRK_COUNTER.value,
        timestamp=1729000040.0,
        device_addr="40:11:22:33:44:02",
        target_addr="AA:BB:CC:DD:EE:02",
        verdict=Verdict.ANOMALY_REPLAY.value,
        confidence=1.0,
        details={"counter": 102, "delta": 0, "is_anomaly": True, "summary": "Replay detected."},
    )
    rep.reports["csrk_counter"] = AnalyzerReport(
        analyzer_name="CsrkCounterAnalyzer",
        verdict=Verdict.CROSS_RPA_LINKED.value,
        summary="Cross-RPA device re-identification confirmed.",
        findings=[csrk_finding_1, csrk_finding_2, csrk_finding_cross, csrk_finding_anomaly],
        metrics={"monitored_senders": 2, "cross_rpa_links": 1, "replays": 1},
    )

    # 3. BAT Allowlist Findings
    bat_finding_probe = BatAllowlistFinding(
        finding_type=SideChannelType.BAT_ALLOWLIST.value,
        timestamp=1729000050.0,
        device_addr="AA:BB:CC:DD:EE:02",
        target_addr="AA:BB:CC:DD:EE:01",
        verdict=Verdict.ALLOWLIST_CONFIRMED.value,
        confidence=1.0,
        details={
            "mechanism": "SELECTIVE_PROBE_RESPONSE",
            "scanner_addr": "AA:BB:CC:DD:EE:01",
            "response_delay_usec": 150,
            "rssi": -52,
            "summary": "Responded to allowed scanner in 150us.",
        },
    )
    bat_finding_silence = BatAllowlistFinding(
        finding_type=SideChannelType.BAT_ALLOWLIST.value,
        timestamp=1729000055.0,
        device_addr="AA:BB:CC:DD:EE:02",
        target_addr="99:88:77:66:55:44",
        verdict=Verdict.ALLOWLIST_CONFIRMED.value,
        confidence=1.0,
        details={
            "mechanism": "SELECTIVE_PROBE_SILENCE",
            "scanner_addr": "99:88:77:66:55:44",
            "silenced_count": 2,
            "summary": "Silenced foreign probe requests.",
        },
    )
    bat_finding_conn = BatAllowlistFinding(
        finding_type=SideChannelType.BAT_ALLOWLIST.value,
        timestamp=1729000060.0,
        device_addr="AA:BB:CC:DD:EE:02",
        target_addr="AA:BB:CC:DD:EE:01",
        verdict=Verdict.PROFILE_MATCH.value,
        confidence=0.9,
        details={
            "mechanism": "CONNECTION_PARAMETERS",
            "interval_ms": 30.0,
            "profile_tuple": (24, 0, 100, 5),
            "summary": "Profile extracted.",
        },
    )
    rep.reports["bat_allowlist"] = AnalyzerReport(
        analyzer_name="BatAllowlistAnalyzer",
        verdict=Verdict.ALLOWLIST_CONFIRMED.value,
        summary="BAT allowlist confirmed via 150us probe response timing oracle.",
        findings=[bat_finding_probe, bat_finding_silence, bat_finding_conn],
        metrics={"allowlist_confirmed_peripherals": 1, "probes_silenced": 2},
    )

    return rep


# =============================================================================
# 1. Plotly Figure Generator Tests
# =============================================================================
class TestPlotlyFigureGenerators:
    """Tests verifying Timing Oracle and CSRK Trajectory figure generation."""

    def test_build_timing_oracle_figure_empty(self) -> None:
        """Empty report generates a styled empty Plotly figure without exceptions."""
        fig = build_timing_oracle_figure(report=None)
        assert isinstance(fig, go.Figure)
        assert fig.layout.paper_bgcolor in ["#0F141C", "rgba(15, 20, 28, 1)"]
        assert fig.layout.plot_bgcolor in ["#1B2028", "rgba(27, 32, 40, 1)"]
        assert "No Timing Oracle" in fig.layout.title.text

    def test_build_timing_oracle_figure_with_data(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Populated report renders scatter traces, 150us reference band, and hover tooltips."""
        fig = build_timing_oracle_figure(report=mock_suite_report)
        assert isinstance(fig, go.Figure)
        assert "Timing Oracle Distribution" in fig.layout.title.text
        # Traces: Allowed Peer, Silent Drop, Connection Interval Profile
        trace_names = [t.name for t in fig.data]
        assert any("Allowed Peer" in name for name in trace_names)
        assert any("Silent Drop" in name for name in trace_names)
        # Shapes: hrect for 148-152us and hline for 150us and 1000us
        assert len(fig.layout.shapes) >= 2

    def test_build_timing_oracle_figure_custom_points(self) -> None:
        """Directly passing custom data_points generates scatter trace accurately."""
        points = [
            {
                "seq": 1,
                "time": 100.0,
                "delta_t_usec": 150.0,
                "device_addr": "AA:BB:CC:DD:EE:02",
                "peer_addr": "AA:BB:CC:DD:EE:01",
                "classification": "Allowed Peer (T_IFS ~150µs)",
                "pdu_type": "SCAN_RSP",
                "rssi": -50,
                "status": "Responded (Allowed)",
            }
        ]
        fig = build_timing_oracle_figure(data_points=points)
        assert len(fig.data) == 1
        assert fig.data[0].y[0] == 150.0

    def test_build_csrk_trajectory_figure_empty(self) -> None:
        """Empty report generates a styled empty CSRK trajectory figure."""
        fig = build_csrk_trajectory_figure(report=None)
        assert isinstance(fig, go.Figure)
        assert "No CSRK Counter" in fig.layout.title.text
        assert fig.layout.paper_bgcolor in ["#0F141C", "rgba(15, 20, 28, 1)"]

    def test_build_csrk_trajectory_figure_with_data(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Populated report renders trajectory line, RPA marker groups, and anomaly markers."""
        fig = build_csrk_trajectory_figure(report=mock_suite_report)
        assert isinstance(fig, go.Figure)
        assert "SignCounter Trajectory" in fig.layout.title.text
        trace_names = [t.name for t in fig.data]
        # Line trace + RPA traces + Anomaly trace
        assert "SignCounter Trajectory" in trace_names
        assert any("RPA: 40:11:22:33:44:01" in name for name in trace_names)
        assert any("RPA: 40:11:22:33:44:02" in name for name in trace_names)
        assert any("Anomaly" in name for name in trace_names)


# =============================================================================
# 2. Handshake Classification Table Tests
# =============================================================================
class TestHandshakeClassificationTable:
    """Tests verifying Handshake classification DataFrame construction."""

    def test_build_handshake_classification_df_empty(self) -> None:
        """Empty report returns an empty DataFrame with required column headers."""
        df = build_handshake_classification_df(report=None)
        assert isinstance(df, pd.DataFrame)
        assert df.empty
        assert "Session AA" in df.columns
        assert "Classification Badge" in df.columns

    def test_build_handshake_classification_df_with_data(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Populated report categorizes PAIRED_SHARED_LTK vs REJECTED_UNTRUSTED correctly."""
        df = build_handshake_classification_df(report=mock_suite_report)
        assert len(df) == 2
        # Check positive session
        pos_row = df[df["Handshake State"] == "PAIRED_SHARED_LTK"].iloc[0]
        assert "🟢 PAIRED" in pos_row["Classification Badge"]
        assert "LL_START_ENC_RSP" in pos_row["LL Control PDU"]
        assert pos_row["Session AA"] == "0x12345678"

        # Check rejected session
        neg_row = df[df["Handshake State"] == "REJECTED_UNTRUSTED"].iloc[0]
        assert "🔴 REJECTED" in neg_row["Classification Badge"]
        assert "PIN_OR_KEY_MISSING" in neg_row["Error Code"]
        assert neg_row["Session AA"] == "0x87654321"


def mock_columns(spec: Any) -> list[MagicMock]:
    """Helper to mock st.columns accepting either an integer count or a list of width ratios."""
    count = spec if isinstance(spec, int) else len(spec)
    return [MagicMock() for _ in range(count)]


# =============================================================================
# 3. Packet Coercion and Queue Bridge Tests
# =============================================================================
class TestPacketCoercion:
    """Tests verifying coercion of queue items into unified BlePacketRecord."""

    def test_coerce_ble_packet_record_passthrough(self) -> None:
        rec = BlePacketRecord(body=b"\x00\x06\x11\x22\x33\x44\x55\x66", channel=37, rssi=-60, timestamp_usec=1000)
        coerced = queue_item_to_packet_record(rec)
        assert coerced is rec

    def test_coerce_packet_message(self) -> None:
        raw = PacketMessage.pack(
            body=b"\x00\x06\x11\x22\x33\x44\x55\x66",
            chan=38,
            rssi=-55,
            ts=2000,
            direction=0,
            crc_err=False,
        )
        msg = PacketMessage(raw)
        coerced = queue_item_to_packet_record(msg)
        assert isinstance(coerced, BlePacketRecord)
        assert coerced.channel == 38
        assert coerced.timestamp_usec == 2000


    def test_coerce_dictionary_event(self) -> None:
        item = {
            "timestamp": 1729000000.123,
            "channel": 39,
            "rssi": -48,
            "mac_address": "AA:BB:CC:DD:EE:02",
            "raw_payload": "020106",
        }
        coerced = queue_item_to_packet_record(item)
        assert isinstance(coerced, BlePacketRecord)
        assert coerced.channel == 39
        assert coerced.rssi == -48
        assert coerced.timestamp_usec == 1729000000123000

    def test_coerce_invalid_type(self) -> None:
        assert queue_item_to_packet_record("invalid_string") is None
        assert queue_item_to_packet_record(None) is None


# =============================================================================
# 4. Cached PCAP Analysis & Report Exports
# =============================================================================
class TestCachedPcapAndReportExports:
    """Tests verifying cached analysis execution and Markdown/JSON report generation."""

    def test_cached_analyze_pcap_with_synthetic_trace(self) -> None:
        """Run cached_analyze_pcap on synthetic differential encryption trace bytes."""
        pcap_bytes = generate_encryption_trace(shared_ltk=True)
        report = cached_analyze_pcap(
            file_bytes=pcap_bytes,
            analyzers_tuple=("encryption",),
            target_mac=None,
            csrk_hex=None,
        )
        assert isinstance(report, SideChannelSuiteReport)
        assert report.total_packets > 0
        assert "differential_encryption" in report.reports
        assert report.has_detections is True
        assert report.overall_verdict == Verdict.PAIRED_SHARED_LTK.value

    def test_markdown_summary_structure(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Verify to_markdown_summary outputs expected Markdown structure and tables."""
        md = mock_suite_report.to_markdown_summary()
        assert "# AirTell – BLE Exclusive-Use Side-Channel Vulnerability Assessment Report" in md
        assert "## 1. Executive Summary & PoPETs Empirical Indicators" in md
        assert "## 2. Active Analyzer Reports" in md
        assert "## 3. Discrete Link-Layer Findings" in md
        assert "## 4. Countermeasures & Remediation Guidance" in md
        assert "Differential Encryption Initiation" in md
        assert "CSRK 32-bit SignCounter Monotonicity" in md
        assert "Allowlist Timing Oracle" in md
        assert "AA:BB:CC:DD:EE:02" in md

    def test_json_serialization(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Verify to_json produces valid JSON with expected top-level keys."""
        import json

        data = json.loads(mock_suite_report.to_json())
        assert data["has_detections"] is True
        assert data["total_findings"] == 9
        assert "differential_encryption" in data["reports"]


# =============================================================================
# 5. Full Dashboard View & Tab Rendering Tests
# =============================================================================
class TestSideChannelDashboardViewRendering:
    """Tests verifying Streamlit component rendering across all ingestion modes."""

    def test_render_sidechannel_metrics(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Verify metrics cards render with accurate values."""
        with (
            patch("streamlit.columns", side_effect=mock_columns),
            patch("streamlit.metric") as mock_metric,
            patch("streamlit.markdown"),
        ):
            render_sidechannel_metrics(mock_suite_report)
            assert mock_metric.call_count >= 8

    def test_render_sidechannel_tab_empty_state(self) -> None:
        """Rendering when no report has been run displays info box and empty charts."""
        with (
            patch("streamlit.markdown"),
            patch("streamlit.caption"),
            patch("streamlit.radio", return_value="📁 Offline PCAP/PCAPNG Upload"),
            patch("streamlit.columns", side_effect=mock_columns),
            patch("streamlit.text_input", return_value=""),
            patch("streamlit.multiselect", return_value=["Differential Encryption"]),
            patch("streamlit.file_uploader", return_value=None),
            patch("streamlit.session_state", {}),
            patch("streamlit.info") as mock_info,
            patch("streamlit.plotly_chart") as mock_chart,
            patch("streamlit.dataframe") as mock_df,
            patch("streamlit.divider"),
        ):
            render_sidechannel_tab()
            mock_info.assert_called_once()
            assert mock_chart.call_count == 2
            mock_df.assert_called_once()

    def test_render_sidechannel_tab_with_active_report(self, mock_suite_report: SideChannelSuiteReport) -> None:
        """Rendering with active report displays threat banner, metrics, charts, table, and download buttons."""
        with (
            patch("streamlit.markdown"),
            patch("streamlit.caption"),
            patch("streamlit.radio", return_value="📁 Offline PCAP/PCAPNG Upload"),
            patch("streamlit.columns", side_effect=mock_columns),
            patch("streamlit.text_input", return_value=""),
            patch("streamlit.multiselect", return_value=["Differential Encryption", "CSRK SignCounter", "BAT Allowlist"]),
            patch("streamlit.file_uploader", return_value=None),
            patch("streamlit.session_state", {"sc_last_report": mock_suite_report}),
            patch("streamlit.error") as mock_error,
            patch("streamlit.plotly_chart") as mock_chart,
            patch("streamlit.dataframe") as mock_df,
            patch("streamlit.download_button") as mock_dl,
            patch("streamlit.expander", return_value=MagicMock()),
            patch("streamlit.divider"),
            patch("streamlit.metric"),
        ):
            render_sidechannel_tab()
            mock_error.assert_called_once()
            assert "CRITICAL VULNERABILITY" in mock_error.call_args[0][0]
            assert mock_chart.call_count == 2
            mock_df.assert_called_once()
            assert mock_dl.call_count == 2

    def test_render_sidechannel_tab_synthetic_simulation(self) -> None:
        """Synthetic mock stream mode runs simulation and populates session_state."""
        session_state = {}
        with (
            patch("streamlit.markdown"),
            patch("streamlit.caption"),
            patch("streamlit.radio", return_value="🧪 Synthetic Mock Stream"),
            patch("streamlit.columns", side_effect=mock_columns),
            patch("streamlit.text_input", return_value=""),
            patch("streamlit.multiselect", return_value=["Differential Encryption", "CSRK SignCounter", "BAT Allowlist"]),
            patch("streamlit.selectbox", return_value="All Analyzers (Positive Detections)"),
            patch("streamlit.button", return_value=True),
            patch("streamlit.session_state", session_state),
            patch("streamlit.error"),
            patch("streamlit.plotly_chart"),
            patch("streamlit.dataframe"),
            patch("streamlit.download_button"),
            patch("streamlit.expander", return_value=MagicMock()),
            patch("streamlit.divider"),
            patch("streamlit.metric"),
        ):
            render_sidechannel_tab()
            assert "sc_last_report" in session_state
            assert session_state["sc_last_report"].has_detections is True

    def test_render_sidechannel_tab_live_queue_ingestion(self) -> None:
        """Live Queue ingestion extracts packets from EventQueue and runs analysis."""
        queue = EventQueue(maxsize=50)
        queue.push({
            "timestamp": 1729000000.0,
            "channel": 37,
            "rssi": -55,
            "mac_address": "AA:BB:CC:DD:EE:02",
            "raw_payload": "020106",
        })
        session_state = {}

        def mock_button(label, key=None):
            return label == "⚡ Ingest & Analyze Live Queue"

        with (
            patch("streamlit.markdown"),
            patch("streamlit.caption"),
            patch("streamlit.radio", return_value="📡 Live Radio / EventQueue Ingestion"),
            patch("streamlit.columns", side_effect=mock_columns),
            patch("streamlit.text_input", return_value=""),
            patch("streamlit.multiselect", return_value=["Differential Encryption", "BAT Allowlist"]),
            patch("streamlit.button", side_effect=mock_button),
            patch("streamlit.session_state", session_state),
            patch("streamlit.success"),
            patch("streamlit.info"),
            patch("streamlit.plotly_chart"),
            patch("streamlit.dataframe"),
            patch("streamlit.download_button"),
            patch("streamlit.expander", return_value=MagicMock()),
            patch("streamlit.divider"),
            patch("streamlit.metric"),
        ):
            render_sidechannel_tab(event_queue=queue)
            assert "sc_last_report" in session_state
            assert session_state["sc_last_report"].total_packets == 1

    def test_render_adversarial_evaluation_includes_4th_tab(self) -> None:
        """Validate render_adversarial_evaluation initializes 4 tabs including Exclusive-Use Side-Channels."""
        mock_tabs = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        captured_tabs = []

        def capture_tabs(tab_names):
            captured_tabs.extend(tab_names)
            return mock_tabs

        with (
            patch("streamlit.tabs", side_effect=capture_tabs),
            patch("streamlit.columns", side_effect=lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]),
            patch("streamlit.metric"),
            patch("streamlit.dataframe"),
            patch("streamlit.subheader"),
            patch("streamlit.markdown"),
            patch("streamlit.caption"),
            patch("streamlit.divider"),
            patch("streamlit.selectbox", return_value="Apple Find My"),
            patch("streamlit.slider", return_value=5),
            patch("streamlit.button", return_value=False),
            patch("streamlit.radio", return_value="📁 Offline PCAP/PCAPNG Upload"),
            patch("streamlit.text_input", return_value=""),
            patch("streamlit.multiselect", return_value=["Differential Encryption"]),
            patch("streamlit.file_uploader", return_value=None),
            patch("streamlit.plotly_chart"),
            patch("streamlit.download_button"),
            patch("streamlit.expander", return_value=MagicMock()),
        ):
            render_adversarial_evaluation(conn=None)
            assert len(captured_tabs) == 4
            assert "⚡ Exclusive-Use Side-Channels" in captured_tabs[3]
