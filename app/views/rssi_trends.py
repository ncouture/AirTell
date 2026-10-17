"""RSSI Signal Trends view rendering interactive Plotly time series for BLE trackers."""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from app.queue_bridge import EventQueue

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


def render_rssi_trends(
    conn: Optional[sqlite3.Connection],
    event_queue: Optional[EventQueue] = None,
    backend: Optional[Any] = None,
) -> None:
    """Render the RSSI Trends view with interactive filtering and Plotly graphs."""
    st.subheader("📈 RSSI Signal Strength & Tracker Trajectories")
    st.markdown(
        "Chronological signal strength tracking across ephemeral public keys to detect following behaviors and proximity spikes."
    )

    # 1. Collect live real-time tracker packets from event queue
    live_rows: list[dict[str, Any]] = []
    if event_queue is not None:
        items = event_queue.get_recent(max_items=1000) if hasattr(event_queue, "get_recent") else []
        for idx, item in enumerate(items, start=1):
            net = item.get("network_type", "Unknown")
            if net and net != "Unknown":
                mac = item.get("mac_address", "Unknown")
                e_key = item.get("ephemeral_key", "")
                k_short = (e_key if e_key else mac)[:16]
                live_rows.append({
                    "id": f"live-{idx}",
                    "datetime_str": item.get("datetime_str", ""),
                    "timestamp": float(item.get("timestamp", 0.0)),
                    "mac_address": mac,
                    "rssi": int(item.get("rssi", -100)),
                    "network_type": net,
                    "key_short": k_short,
                    "ephemeral_key": e_key,
                    "channel": item.get("channel", 37),
                })

    df_db = pd.DataFrame()
    db_loaded = False
    if backend is not None:
        try:
            res = backend.get_rssi_timeseries(limit=2000, as_df=True)
            df_db = res if isinstance(res, pd.DataFrame) else pd.DataFrame(res)
            db_loaded = True
        except Exception as e:
            st.error(f"Error loading signal telemetry from DuckDB analytics backend: {e}")
            df_db = pd.DataFrame()

    if not db_loaded and conn:
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
            df_db = pd.read_sql_query(query, conn)
        except Exception as e:
            st.error(f"Error loading signal telemetry from database: {e}")


    # 2. Combine historical DB records with live streaming packets
    frames_to_concat = []
    if not df_db.empty:
        frames_to_concat.append(df_db)
    if live_rows:
        df_live = pd.DataFrame(live_rows)
        frames_to_concat.append(df_live)

    if not frames_to_concat:
        st.info("No crowdsourced tracking beacons (Apple, Google, Tile, Samsung) recorded yet. Start Tshark capture in Radio Controls or inject beacon bursts.")
        return

    df = pd.concat(frames_to_concat, ignore_index=True)
    if "datetime_str" in df.columns:
        df = df.sort_values(by="datetime_str", ascending=True)

    if live_rows:
        st.caption(f"⚡ **Live Stream Active:** {len(live_rows)} in-memory tracker observations plotted alongside historical data.")

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
