"""Unit tests for dashboard views, alert categorization, and Plotly visualizations."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from app.views.alert_feed import ThreatCategory, categorize_alert
from app.views.packet_inspector import decode_ad_structures
from app.views.rssi_trends import build_rssi_figure
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
