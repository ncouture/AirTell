"""Material Design v3 Dark Tactical PWA Dashboard for Bluetooth-Sniffle."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

import streamlit as st

from app.components.navigation import render_navigation, render_top_app_bar
from app.components.pwa import inject_pwa_assets
from app.queue_bridge import get_event_queue
from app.views.adversarial_evaluation import render_adversarial_evaluation
from app.views.alert_feed import render_alert_feed
from app.views.offline_replay import render_offline_replay
from app.views.packet_inspector import render_packet_inspector
from app.views.radio_controls import (
    get_tshark_topology_manager,
    render_radio_controls,
)
from app.views.rssi_trends import render_rssi_trends
from app.views.telemetry_overview import render_telemetry_overview
from bluetooth_sniffle.device.serial_port import check_device_usage
from scripts.ble_antistalking_tracker import BLETrackerDB

# 1. Page Configuration (Must be first Streamlit call)
st.set_page_config(
    page_title="Sniffle Tactical M3",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 2. Inject PWA Manifest and Service Worker Assets
inject_pwa_assets()

# 3. Resolve Database Path
DEFAULT_DB = "data/ble_tracker.db"
DB_PATH = os.environ.get("DATABASE", DEFAULT_DB)
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

tracker_db = BLETrackerDB(DB_PATH)


def get_db_connection() -> Optional[sqlite3.Connection]:
    """Establish connection to SQLite tracker database."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        return conn
    except Exception as e:
        st.error(f"Failed to connect to database: {e}")
        return None


def main() -> None:
    """Main dashboard entrypoint routing views through M3 Navigation Rail."""
    conn = get_db_connection()
    event_queue = get_event_queue()

    # Determine real-time device usage using lsof system command
    dev0_in_use = check_device_usage("/dev/ttyUSB0")
    dev1_in_use = check_device_usage("/dev/ttyUSB1")

    # Real-Time Dongle & Tshark Status for Top App Bar
    tshark_mgr = get_tshark_topology_manager()
    t_status = tshark_mgr.get_status()
    if t_status["running"]:
        d1 = f"/dev/ttyUSB0: ACTIVE ({t_status['topology']})"
        d2 = f"/dev/ttyUSB1: {'ACTIVE' if 'Topology A' in t_status['topology'] else 'STANDBY'}"
        chans = "LIVE TSHARK STREAM"
        d1_active = True
        d2_active = "Topology A" in t_status["topology"] or dev1_in_use
    else:
        d1 = f"/dev/ttyUSB0: {'IN USE' if dev0_in_use else 'IDLE'}"
        d2 = f"/dev/ttyUSB1: {'IN USE' if dev1_in_use else 'IDLE'}"
        chans = "CH 37 / 38 / 39"
        d1_active = dev0_in_use
        d2_active = dev1_in_use

    dongle1_status = d1
    dongle2_status = d2

    # M3 Top App Bar
    render_top_app_bar(
        dongle1_status=dongle1_status,
        dongle2_status=dongle2_status,
        active_channels=chans,
        dongle1_active=d1_active,
        dongle2_active=d2_active,
    )

    # Sidebar Navigation Rail
    active_view = render_navigation(
        dongle1_status=dongle1_status,
        dongle2_status=dongle2_status,
    )

    # Auto-refresh controls in sidebar
    with st.sidebar:
        st.markdown("#### ⚙️ Live Controls")
        auto_refresh = st.checkbox("Auto Refresh Stream", value=False)
        refresh_rate = st.slider("Interval (s)", min_value=3, max_value=30, value=5)

        # Offline replay quick access
        st.divider()
        with st.expander("📁 Offline Replay"):
            render_offline_replay(tracker_db=tracker_db, conn=conn)

    # Route active operational view with live real-time event queue
    if active_view == "telemetry":
        render_telemetry_overview(conn=conn, event_queue=event_queue)
    elif active_view == "rssi":
        render_rssi_trends(conn=conn, event_queue=event_queue)
    elif active_view == "alerts":
        render_alert_feed(conn=conn, tracker_db=tracker_db, event_queue=event_queue)
    elif active_view == "inspector":
        render_packet_inspector(conn=conn, event_queue=event_queue)
    elif active_view == "controls":
        render_radio_controls(tracker_db=tracker_db, event_queue=event_queue)
    elif active_view == "adversarial":
        render_adversarial_evaluation(conn=conn, tracker_db=tracker_db, event_queue=event_queue)

    if conn:
        conn.close()

    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()


if __name__ == "__main__":
    main()
