"""Multi-Level Alert Feed view for anti-stalking threat triage and analyst actions."""

from __future__ import annotations

import enum
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

import pandas as pd
import streamlit as st

from scripts.ble_antistalking_tracker import BLETrackerDB


class ThreatCategory(str, enum.Enum):
    """Anti-stalking threat classification levels."""

    HIGH_PROXIMITY = "High Proximity"
    UNLINKABILITY_HAZARD = "Unlinkability Hazard"
    SUSPICIOUS = "Suspicious Persistence"


@dataclass
class CategorizedAlert:
    """Metadata container for a categorized anti-stalking alert."""

    category: ThreatCategory
    label: str
    badge_color: str
    description: str


def categorize_alert(alert: dict[str, Any]) -> CategorizedAlert:
    """Classify alert into a threat category and assign M3 tactical badge styling.

    Args:
        alert: Dictionary of alert attributes including max_rssi and flags.

    Returns:
        CategorizedAlert containing category, display label, and hex badge color.
    """
    if alert.get("static_mac_leak") or alert.get("unlinkability_hazard"):
        return CategorizedAlert(
            category=ThreatCategory.UNLINKABILITY_HAZARD,
            label="Unlinkability Hazard",
            badge_color="#F5D990",  # M3 Warning yellow
            description="Static Bluetooth MAC address or payload key rotation failure detected.",
        )

    max_rssi = alert.get("max_rssi", -100)
    if max_rssi > -55:
        return CategorizedAlert(
            category=ThreatCategory.HIGH_PROXIMITY,
            label="High Proximity Threat",
            badge_color="#F2B8B5",  # M3 Error/Critical coral
            description=f"Strong RF beaconing at {max_rssi} dBm indicates immediate close physical presence.",
        )

    return CategorizedAlert(
        category=ThreatCategory.SUSPICIOUS,
        label="Suspicious Persistent Tracking",
        badge_color="#A8C7FA",  # M3 Primary blue
        description="Persistent beacon transmissions across multiple time windows.",
    )


def render_alert_feed(
    conn: Optional[sqlite3.Connection],
    tracker_db: Optional[BLETrackerDB] = None,
) -> None:
    """Render the Multi-Level Alert Feed view with analyst triage capabilities."""
    st.subheader("🚨 Anti-Stalking Threat Feed & Triage")
    st.markdown(
        "Categorized threat alerts with severity badges, analyst incident logging, and identifier whitelisting."
    )

    if not conn:
        st.warning("Database unavailable.")
        return

    query = """
    SELECT id, datetime_str, timestamp, identifier, network_type,
           observation_count, first_seen, last_seen, max_rssi, alert_message
    FROM alerts
    ORDER BY id DESC
    LIMIT 200
    """
    try:
        alerts_df = pd.read_sql_query(query, conn)
    except Exception as e:
        st.error(f"Error loading alerts: {e}")
        return

    if alerts_df.empty:
        st.success("No active anti-stalking threats logged in the current operational session.")
        return

    # Export Button in Top Row
    exp_col1, exp_col2 = st.columns([3, 1])
    with exp_col2:
        csv_data = alerts_df.to_csv(index=False)
        st.download_button(
            label="📥 Export Alerts (CSV)",
            data=csv_data,
            file_name="sniffle_stalking_alerts.csv",
            mime="text/csv",
        )

    st.write(f"**Total Logged Incidents:** {len(alerts_df):,}")

    for _, row in alerts_df.iterrows():
        alert_dict = row.to_dict()
        cat = categorize_alert(alert_dict)
        alert_id = int(row["id"])
        identifier = str(row["identifier"])
        net_type = str(row["network_type"])

        with st.container():
            st.markdown(
                f"""
                <div style="border-left: 4px solid {cat.badge_color}; background-color: #1B2028; padding: 0.85rem 1.25rem; border-radius: 8px; margin-bottom: 0.75rem;">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: {cat.badge_color}; font-size: 0.85rem; text-transform: uppercase;">
                      ● {cat.label}
                    </span>
                    <span style="font-family: monospace; font-size: 0.75rem; color: #8E919A;">
                      {row['datetime_str']}
                    </span>
                  </div>
                  <div style="margin-top: 0.4rem; font-size: 0.95rem; font-weight: 600; color: #E1E2E8;">
                    {net_type} Beacon: <code style="color: #A8C7FA;">{identifier}</code>
                  </div>
                  <div style="font-size: 0.82rem; color: #C4C7D0; margin-top: 0.2rem;">
                    Observations: <b>{row['observation_count']}</b> | Max Signal: <b>{row['max_rssi']} dBm</b>
                  </div>
                  <div style="font-size: 0.8rem; color: #8E919A; margin-top: 0.3rem;">
                    {cat.description}
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Action Buttons Row
            btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 2])
            with btn_col1:
                if st.button("✓ Acknowledge", key=f"ack_{alert_id}"):
                    if tracker_db:
                        tracker_db.record_alert_action(alert_id, "acknowledged", "Acknowledged in feed.")
                    st.success(f"Alert #{alert_id} acknowledged.")
            with btn_col2:
                if st.button("🛡️ Whitelist Key", key=f"white_{alert_id}"):
                    if tracker_db:
                        tracker_db.add_whitelist("ephemeral_key", identifier, f"Whitelisted from Alert #{alert_id}")
                    st.info(f"Identifier {identifier[:12]}... whitelisted.")
            with btn_col3:
                with st.expander("Tag Incident Note"):
                    note_text = st.text_input("Analyst Note:", key=f"note_input_{alert_id}")
                    if st.button("Save Note", key=f"save_note_{alert_id}"):
                        if tracker_db and note_text:
                            tracker_db.record_alert_action(alert_id, "note_added", note_text)
                            st.success("Note saved.")
