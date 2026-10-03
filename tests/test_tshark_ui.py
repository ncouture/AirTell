"""Integration tests for Streamlit Radio Controls Live Tshark Extcap Streaming Panel."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd

from app.views.radio_controls import (
    build_live_packet_dataframe,
    build_tshark_live_chart,
    check_tshark_dependencies,
    format_preflight_badge,
    map_ui_to_tshark_config,
)


class TestTsharkUIDependencyDiagnostics:
    """Tests for preflight checks and dependency verification."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dependencies_detected_successfully(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """When tshark and sniffle extcap are present, report all available."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "1. en0\n15. sniffle (Sniffle BLE sniffer)\n"
        mock_run.return_value = mock_proc

        diag = check_tshark_dependencies()
        assert diag["tshark_available"] is True
        assert diag["sniffle_extcap_available"] is True
        assert diag["tshark_path"] == "/usr/bin/tshark"
        assert diag["error"] is None

    @patch("shutil.which", return_value=None)
    def test_tshark_missing_reports_error(self, mock_which: MagicMock) -> None:
        """When tshark executable is missing, report descriptive error."""
        diag = check_tshark_dependencies()
        assert diag["tshark_available"] is False
        assert diag["sniffle_extcap_available"] is False
        assert "tshark not found" in diag["error"].lower()

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_sniffle_extcap_missing_interface(
        self, mock_run: MagicMock, mock_which: MagicMock
    ) -> None:
        """When tshark is present but sniffle plugin is missing from interfaces."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "1. en0\n2. lo\n"
        mock_run.return_value = mock_proc

        diag = check_tshark_dependencies()
        assert diag["tshark_available"] is True
        assert diag["sniffle_extcap_available"] is False
        assert "sniffle" in diag["error"].lower()


class TestPreflightBadgesAndParameterBinding:
    """Tests for UI status badges and extcap parameter form mapping."""

    def test_preflight_status_badges(self) -> None:
        """Badges should format according to port availability."""
        assert "AVAILABLE" in format_preflight_badge(True, "Available")
        assert "BUSY" in format_preflight_badge(False, "Port is currently locked by PID 1234")
        assert "OFFLINE" in format_preflight_badge(False, "Device node does not exist")

    def test_map_ui_to_tshark_config(self) -> None:
        """Form inputs should map directly to TsharkConfig."""
        config = map_ui_to_tshark_config(
            serport="/dev/ttyUSB0",
            mode="passive_scan",
            advchan=37,
            rssi_floor=-80,
            mac_filter="AA:BB:CC:DD:EE:FF",
            irk_filter="11223344556677889900aabbccddeeff",
            payload_str="FindMy",
            extadv=True,
            longrange=False,
            crcerr=True,
            output_format="ek",
        )
        assert config.serport == "/dev/ttyUSB0"
        assert config.mode == "passive_scan"
        assert config.advchan == 37
        assert config.rssi == -80
        assert config.mac == "AA:BB:CC:DD:EE:FF"
        assert config.irk == "11223344556677889900aabbccddeeff"
        assert config.string == "FindMy"
        assert config.extadv is True
        assert config.longrange is False
        assert config.crcerr is True
        assert config.output_format == "ek"


class TestLiveTableAndPlotlyVisualizations:
    """Tests for data frame transformations and dynamic Plotly chart rendering."""

    def test_build_live_packet_dataframe(self) -> None:
        """Drained packets should form a well-structured DataFrame."""
        packets = [
            {
                "timestamp": 1790000000.0,
                "datetime_str": "2026-10-02 20:00:00",
                "channel": 37,
                "rssi": -65,
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "network_type": "Apple Find My",
                "ephemeral_key": "4c001219_abc",
                "pdu_type": "ADV_IND",
                "company_id": "0x004c",
            }
        ]
        df = build_live_packet_dataframe(packets)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert "datetime_str" in df.columns
        assert "channel" in df.columns
        assert "mac_address" in df.columns
        assert "rssi" in df.columns
        assert "network_type" in df.columns
        assert "pdu_type" in df.columns

    def test_build_live_packet_dataframe_empty(self) -> None:
        """Empty input should return empty DataFrame with expected columns."""
        df = build_live_packet_dataframe([])
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
        assert "mac_address" in df.columns

    def test_build_tshark_live_chart(self) -> None:
        """Plotly chart should render correctly from live packet DataFrame."""
        df = pd.DataFrame([
            {
                "datetime_str": "2026-10-02 20:00:00",
                "rssi": -65,
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "network_type": "Apple Find My",
                "channel": 37,
            },
            {
                "datetime_str": "2026-10-02 20:00:01",
                "rssi": -62,
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "network_type": "Apple Find My",
                "channel": 37,
            },
        ])
        fig = build_tshark_live_chart(df)
        assert fig is not None
        assert hasattr(fig, "data")
        assert len(fig.data) >= 1
