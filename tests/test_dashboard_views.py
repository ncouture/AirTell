"""Unit tests for dashboard views, alert categorization, and Plotly visualizations."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import plotly.graph_objects as go

from app.queue_bridge import EventQueue
from app.views.alert_feed import ThreatCategory, categorize_alert, render_alert_feed
from app.views.packet_inspector import decode_ad_structures, render_packet_inspector
from app.views.rssi_trends import build_rssi_figure, render_rssi_trends
from app.views.telemetry_overview import compute_telemetry_metrics


def test_alert_categorization_levels() -> None:
    """Validate multi-level alert categorization rules and badge styling."""
    # High Proximity test
    high_prox = {
        "identifier": "apple_tag_001",
        "network_type": "Apple Find My",
        "observation_count": 10,
        "max_rssi": -45,
        "first_seen": 1000.0,
        "last_seen": 1500.0,
        "static_mac_leak": False,
    }
    cat_prox = categorize_alert(high_prox)
    assert cat_prox.category == ThreatCategory.HIGH_PROXIMITY
    assert cat_prox.badge_color == "#F2B8B5"  # M3 Error/Critical token

    # Unlinkability Hazard test
    hazard = {
        "identifier": "google_tag_002",
        "network_type": "Google Find Hub",
        "observation_count": 4,
        "max_rssi": -75,
        "first_seen": 1000.0,
        "last_seen": 1200.0,
        "static_mac_leak": True,
    }
    cat_hazard = categorize_alert(hazard)
    assert cat_hazard.category == ThreatCategory.UNLINKABILITY_HAZARD
    assert "Unlinkability" in cat_hazard.label

    # Suspicious persistence test
    suspicious = {
        "identifier": "tile_tag_003",
        "network_type": "Tile",
        "observation_count": 12,
        "max_rssi": -68,
        "first_seen": 1000.0,
        "last_seen": 1800.0,
        "static_mac_leak": False,
    }
    cat_susp = categorize_alert(suspicious)
    assert cat_susp.category == ThreatCategory.SUSPICIOUS
    assert "Suspicious" in cat_susp.label


def test_rssi_figure_generation_and_styling() -> None:
    """Validate Plotly RSSI time-series figure structure and dark tactical tokens."""
    data = {
        "datetime_str": ["2026-10-02 12:00:00", "2026-10-02 12:01:00", "2026-10-02 12:02:00"],
        "rssi": [-70, -52, -48],
        "key_short": ["tag_a", "tag_a", "tag_a"],
        "network_type": ["Apple Find My", "Apple Find My", "Apple Find My"],
    }
    df = pd.DataFrame(data)
    fig = build_rssi_figure(df)

    assert isinstance(fig, go.Figure)
    layout = fig.layout
    # Verify dark tactical background colors
    assert layout.paper_bgcolor in ["#0F141C", "rgba(15, 20, 28, 1)"]
    assert layout.plot_bgcolor in ["#1B2028", "rgba(27, 32, 40, 1)"]
    assert layout.yaxis.range[0] <= -100
    assert layout.yaxis.range[1] >= -20
    # Must have at least 1 trace for the data
    assert len(fig.data) >= 1


def test_telemetry_metrics_computation() -> None:
    """Validate computation of total packets, channel splits, and network tracker counts."""
    observations = [
        {"channel": 37, "network_type": "Apple Find My", "mac_address": "c0:11:22:33:44:01"},
        {"channel": 37, "network_type": "Apple Find My", "mac_address": "c0:11:22:33:44:02"},
        {"channel": 38, "network_type": "Google Find Hub", "mac_address": "c0:11:22:33:44:03"},
        {"channel": 39, "network_type": "Tile", "mac_address": "c0:11:22:33:44:04"},
        {"channel": 37, "network_type": "Unknown", "mac_address": "c0:11:22:33:44:05"},
    ]
    metrics = compute_telemetry_metrics(observations)

    assert metrics["total_packets"] == 5
    assert metrics["channel_counts"][37] == 3
    assert metrics["channel_counts"][38] == 1
    assert metrics["channel_counts"][39] == 1
    assert metrics["known_trackers_count"] == 4
    assert metrics["network_counts"]["Apple Find My"] == 2
    assert metrics["network_counts"]["Google Find Hub"] == 1
    assert metrics["network_counts"]["Tile"] == 1


def test_packet_inspector_ad_structures_decoding() -> None:
    """Validate decoding of BLE Advertising Data (AD) structures from raw payload."""
    # Standard iBeacon payload with Flags (0x01) and Manufacturer Specific Data (0xFF)
    # 02 01 06 -> len 2, type 0x01 (Flags), val 06
    # 05 09 54 65 73 74 -> len 5, type 0x09 (Complete Local Name), val "Test"
    raw_payload = "020106050954657374"
    structures = decode_ad_structures(raw_payload)

    assert len(structures) == 2
    # First structure: Flags
    assert structures[0]["ad_type_hex"] == "0x01"
    assert "Flags" in structures[0]["ad_type_name"]
    assert structures[0]["data_hex"] == "06"

    # Second structure: Local name
    assert structures[1]["ad_type_hex"] == "0x09"
    assert "Local Name" in structures[1]["ad_type_name"]
    assert structures[1]["data_hex"] == "54657374"
    assert structures[1]["data_ascii"] == "Test"


def test_render_adversarial_evaluation_structure() -> None:
    """Validate adversarial evaluation view renders cleanly without runtime exceptions."""
    from unittest.mock import MagicMock, patch

    from app.views.adversarial_evaluation import render_adversarial_evaluation

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        ("40:11:22:33:44:55", "apple_key_01", 1727870400.0, -65, "Apple Find My"),
        ("40:11:22:33:44:56", "apple_key_02", 1727870405.0, -63, "Apple Find My"),
    ]
    mock_conn.cursor.return_value = mock_cursor

    mock_tracker_db = MagicMock()
    mock_event_queue = MagicMock()

    def mock_columns(spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MagicMock() for _ in range(count)]

    with (
        patch("streamlit.tabs", return_value=[MagicMock(), MagicMock(), MagicMock()]),
        patch("streamlit.columns", side_effect=mock_columns),
        patch("streamlit.metric"),
        patch("streamlit.dataframe"),
        patch("streamlit.subheader"),
        patch("streamlit.markdown"),
        patch("streamlit.caption"),
        patch("streamlit.divider"),
        patch("streamlit.selectbox", return_value="Apple Find My"),
        patch("streamlit.slider", return_value=5),
        patch("streamlit.button", return_value=False),
    ):
        render_adversarial_evaluation(mock_conn, mock_tracker_db, mock_event_queue)


def test_render_rssi_trends_with_event_queue() -> None:
    """Validate render_rssi_trends correctly incorporates live EventQueue observations."""
    queue = EventQueue(maxsize=50)
    queue.push({
        "timestamp": 1727870400.0,
        "datetime_str": "2026-10-02 12:00:00",
        "mac_address": "40:11:22:33:44:55",
        "channel": 37,
        "rssi": -48,
        "network_type": "Apple Find My",
        "ephemeral_key": "aabbccddeeff001122334455",
        "raw_payload": "020106",
    })

    def mock_columns(spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MagicMock() for _ in range(count)]

    with (
        patch("streamlit.subheader"),
        patch("streamlit.markdown"),
        patch("streamlit.caption") as mock_caption,
        patch("streamlit.columns", side_effect=mock_columns),
        patch("streamlit.multiselect", return_value=["Apple Find My"]),
        patch("streamlit.slider", return_value=-95),
        patch("streamlit.plotly_chart") as mock_chart,
    ):
        render_rssi_trends(conn=None, event_queue=queue)
        mock_caption.assert_called()
        caption_text = mock_caption.call_args[0][0]
        assert "Live Stream Active" in caption_text
        mock_chart.assert_called_once()
        fig = mock_chart.call_args[0][0]
        assert isinstance(fig, go.Figure)


def test_render_packet_inspector_with_event_queue() -> None:
    """Validate render_packet_inspector correctly displays live EventQueue packets."""
    queue = EventQueue(maxsize=50)
    queue.push({
        "timestamp": 1727870400.0,
        "datetime_str": "2026-10-02 12:00:00",
        "mac_address": "40:11:22:33:44:55",
        "channel": 37,
        "rssi": -48,
        "network_type": "Apple Find My",
        "ephemeral_key": "aabbccddeeff001122334455",
        "raw_payload": "020106",
    })

    def mock_columns(spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MagicMock() for _ in range(count)]

    with (
        patch("streamlit.subheader"),
        patch("streamlit.markdown"),
        patch("streamlit.columns", side_effect=mock_columns),
        patch("streamlit.selectbox", side_effect=lambda label, options=None, **kwargs: options[0] if options else "All"),
        patch("streamlit.text_input", return_value=""),
        patch("streamlit.caption") as mock_caption,
        patch("streamlit.write"),
        patch("streamlit.dataframe") as mock_df,
        patch("streamlit.code"),
        patch("streamlit.expander", return_value=MagicMock()),
    ):
        render_packet_inspector(conn=None, event_queue=queue)
        mock_caption.assert_called()
        caption_text = mock_caption.call_args[0][0]
        assert "Live Stream Active" in caption_text
        mock_df.assert_called_once()
        df_passed = mock_df.call_args[0][0]
        assert "LIVE-001" in df_passed["id"].values


def test_render_alert_feed_with_event_queue() -> None:
    """Validate render_alert_feed detects real-time threats from live EventQueue packets."""
    queue = EventQueue(maxsize=50)
    queue.push({
        "timestamp": 1727870400.0,
        "datetime_str": "2026-10-02 12:00:00",
        "mac_address": "40:11:22:33:44:55",
        "channel": 37,
        "rssi": -45,  # > -55 dBm threshold for proximity threat
        "network_type": "Apple Find My",
        "ephemeral_key": "aabbccddeeff001122334455",
        "raw_payload": "020106",
    })

    def mock_columns(spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MagicMock() for _ in range(count)]

    with (
        patch("streamlit.subheader"),
        patch("streamlit.markdown") as mock_markdown,
        patch("streamlit.caption") as mock_caption,
        patch("streamlit.columns", side_effect=mock_columns),
        patch("streamlit.download_button"),
        patch("streamlit.write"),
        patch("streamlit.container", return_value=MagicMock()),
        patch("streamlit.button", return_value=False),
        patch("streamlit.expander", return_value=MagicMock()),
    ):
        render_alert_feed(conn=None, tracker_db=None, event_queue=queue)
        mock_caption.assert_called()
        caption_text = mock_caption.call_args[0][0]
        assert "Live Threat Monitor" in caption_text
        # Ensure markdown called with LIVE STREAM badge
        calls = [c[0][0] for c in mock_markdown.call_args_list if c[0] and isinstance(c[0][0], str)]
        assert any("[LIVE STREAM]" in c for c in calls)


