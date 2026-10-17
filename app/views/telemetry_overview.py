"""Live Telemetry Overview view displaying packet throughput and channel distributions."""

from __future__ import annotations

import collections
import sqlite3
from typing import Any, Optional

import pandas as pd
import streamlit as st

from app.queue_bridge import EventQueue


def compute_telemetry_metrics(
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate aggregate telemetry metrics from packet observation records.

    Args:
        observations: List of observation dictionaries containing channel and network_type.

    Returns:
        Dictionary containing total packets, channel counts, and network breakdown.
    """
    total = len(observations)
    channel_counts: dict[int, int] = collections.defaultdict(int)
    network_counts: dict[str, int] = collections.defaultdict(int)
    known_count = 0

    for obs in observations:
        ch = obs.get("channel")
        if ch is not None:
            try:
                channel_counts[int(ch)] += 1
            except (ValueError, TypeError):
                pass

        net = obs.get("network_type", "Unknown")
        if net and net != "Unknown":
            known_count += 1
            network_counts[net] += 1

    return {
        "total_packets": total,
        "channel_counts": dict(channel_counts),
        "known_trackers_count": known_count,
        "network_counts": dict(network_counts),
    }


def render_telemetry_overview(
    conn: Optional[sqlite3.Connection],
    event_queue: Optional[EventQueue] = None,
    backend: Optional[Any] = None,
) -> None:
    """Render the Live Telemetry Overview dashboard view."""
    st.subheader("📡 Live Radio Telemetry & Signal Throughput")
    st.markdown(
        "Real-time packet throughput, multi-channel distribution, and active tracking network monitors."
    )

    # Ingest live queue items into a snapshot without destructive draining
    live_items: list[dict[str, Any]] = []
    if event_queue is not None:
        if hasattr(event_queue, "get_recent"):
            live_items = event_queue.get_recent(max_items=500)
        else:
            live_items = event_queue.drain(max_items=200)

    # Query observations from accelerated backend or database connection
    obs_list: list[dict[str, Any]] = []
    db_loaded = False
    if backend is not None:
        try:
            res = backend.get_observations(limit=1000)
            if isinstance(res, pd.DataFrame):
                obs_list = res.to_dict(orient="records")
            elif isinstance(res, list):
                obs_list = [dict(r) for r in res]
            else:
                obs_list = list(res)
            db_loaded = True
        except Exception as e:
            st.error(f"Error querying DuckDB analytics backend: {e}")
            obs_list = []

    if not db_loaded and conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT channel, network_type, mac_address, rssi, datetime_str
                FROM observations
                ORDER BY id DESC
                LIMIT 1000
                """
            )
            for row in cursor.fetchall():
                obs_list.append({
                    "channel": row[0],
                    "network_type": row[1],
                    "mac_address": row[2],
                    "rssi": row[3],
                    "datetime_str": row[4],
                })
        except Exception as e:
            st.error(f"Error querying telemetry observations: {e}")

    # Combine with any in-flight live items
    all_observations = live_items + obs_list
    metrics = compute_telemetry_metrics(all_observations)


    # Metric Cards Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            label="Total Packets Analyzed",
            value=f"{metrics['total_packets']:,}",
            help="Total BLE advertising packets recorded in active window.",
        )
    with col2:
        st.metric(
            label="Identified Trackers",
            value=f"{metrics['known_trackers_count']:,}",
            help="Packets matching known tracking networks (Apple, Google, Tile, Samsung).",
        )
    with col3:
        ch_text = (
            f"37: {metrics['channel_counts'].get(37, 0)} | "
            f"38: {metrics['channel_counts'].get(38, 0)} | "
            f"39: {metrics['channel_counts'].get(39, 0)}"
        )
        st.metric(
            label="Channels Monitored",
            value="37 / 38 / 39",
            delta=ch_text,
            delta_color="off",
        )
    with col4:
        live_count = event_queue.size() if event_queue else 0
        st.metric(
            label="Queue Buffer",
            value=f"{live_count:,} pkts",
            delta="Streaming" if live_count > 0 else "Idle",
            delta_color="normal" if live_count > 0 else "off",
        )

    st.divider()

    # Network breakdown & channel columns
    net_col, chan_col = st.columns(2)
    with net_col:
        st.markdown("#### 🌐 Tracking Networks Detected")
        net_counts = metrics["network_counts"]
        if net_counts:
            for net_name, count in sorted(net_counts.items(), key=lambda x: x[1], reverse=True):
                pct = int((count / max(1, metrics["known_trackers_count"])) * 100)
                st.write(f"**{net_name}**: {count:,} ({pct}%)")
                st.progress(pct / 100)
        else:
            st.info("No crowdsourced tracking networks active in recent window.")

    with chan_col:
        st.markdown("#### 📻 Channel Distribution")
        chans = metrics["channel_counts"]
        for ch in [37, 38, 39]:
            count = chans.get(ch, 0)
            pct = int((count / max(1, metrics["total_packets"])) * 100)
            st.write(f"**Channel {ch}**: {count:,} packets ({pct}%)")
            st.progress(pct / 100)
