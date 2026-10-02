"""RSSI Signal Trends view rendering interactive Plotly time series for BLE trackers."""

from __future__ import annotations

import sqlite3
from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

TACTICAL_PALETTE = [
    "#A8C7FA",  # Primary Blue
    "#F2B8B5",  # Threat Pink/Red
    "#A8E8BA",  # Tactical Green
    "#F5D990",  # Alert Yellow
    "#D0BCFF",  # Beacon Purple
    "#7FCFFF",  # Cyan
    "#FFB4AB",  # Coral
]


def build_rssi_figure(df: pd.DataFrame) -> go.Figure:
    """Build an interactive Plotly line chart displaying RSSI trends over time.

    Args:
        df: DataFrame containing datetime_str, rssi, key_short, network_type.

    Returns:
        Plotly Figure with Material Design v3 dark tactical styling.
    """
    if df.empty or "rssi" not in df.columns:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#0F141C",
            plot_bgcolor="#1B2028",
            font_color="#E1E2E8",
            title="No Signal Telemetry Available",
            yaxis_range=[-100, -20],
        )
        return fig

    fig = px.line(
        df,
        x="datetime_str",
        y="rssi",
        color="key_short" if "key_short" in df.columns else None,
        symbol="network_type" if "network_type" in df.columns else None,
        title="BLE Tracker RSSI Signal Strength Over Time",
        labels={
            "datetime_str": "Timestamp",
            "rssi": "RSSI (dBm)",
            "key_short": "Tracker Key / Identifier",
            "network_type": "Network",
        },
        markers=True,
        color_discrete_sequence=TACTICAL_PALETTE,
    )

    # Add Proximity Danger Threshold (-55 dBm)
    fig.add_hline(
        y=-55,
        line_dash="dash",
        line_color="#F2B8B5",
        annotation_text="High Proximity Threat Threshold (-55 dBm)",
        annotation_position="bottom right",
        annotation_font_color="#F2B8B5",
    )

    fig.update_layout(
        paper_bgcolor="#0F141C",
        plot_bgcolor="#1B2028",
        font=dict(family="Roboto Mono, monospace", color="#E1E2E8"),
        xaxis=dict(
            gridcolor="#2D3440",
            linecolor="#2D3440",
            zerolinecolor="#2D3440",
        ),
        yaxis=dict(
            range=[-100, -20],
            gridcolor="#2D3440",
            linecolor="#2D3440",
            zerolinecolor="#2D3440",
            title="Signal Strength (dBm)",
        ),
        legend=dict(
            bgcolor="rgba(27, 32, 40, 0.8)",
            bordercolor="#2D3440",
            borderwidth=1,
        ),
        margin=dict(l=40, r=40, t=50, b=40),
    )
    return fig


def render_rssi_trends(conn: Optional[sqlite3.Connection]) -> None:
    """Render the RSSI Trends view with interactive filtering and Plotly graphs."""
    st.subheader("📈 RSSI Signal Strength & Tracker Trajectories")
    st.markdown(
        "Chronological signal strength tracking across ephemeral public keys to detect following behaviors and proximity spikes."
    )

    if not conn:
        st.warning("Database unavailable. Awaiting packet recording.")
        return

    query = """
    SELECT id, datetime_str, timestamp, mac_address, rssi, network_type,
           SUBSTR(COALESCE(NULLIF(ephemeral_key, ''), mac_address), 1, 16) as key_short,
           ephemeral_key, channel
    FROM observations
    WHERE network_type != 'Unknown'
    ORDER BY id DESC
    LIMIT 2000
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        st.error(f"Error loading signal telemetry: {e}")
        return

    if df.empty:
        st.info("No crowdsourced tracking beacons (Apple, Google, Tile, Samsung) recorded yet.")
        return

    # Filter controls
    f_col1, f_col2 = st.columns([2, 1])
    with f_col1:
        networks = list(df["network_type"].unique())
        selected_nets = st.multiselect("Filter by Network:", options=networks, default=networks)
    with f_col2:
        min_rssi = st.slider("Minimum Signal (dBm):", min_value=-100, max_value=-30, value=-95, step=5)

    filtered_df = df[(df["network_type"].isin(selected_nets)) & (df["rssi"] >= min_rssi)]

    fig = build_rssi_figure(filtered_df)
    st.plotly_chart(fig, width="stretch")
