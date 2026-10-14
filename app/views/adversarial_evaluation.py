"""Adversarial evaluation view for pairing relay, identity deanonymization, and evasion benchmarks."""

from __future__ import annotations

import sqlite3
import time
from typing import Optional

import pandas as pd
import streamlit as st

from app.queue_bridge import EventQueue
from bluetooth_sniffle.adversarial.deanonymizer import (
    LinkabilityObservation,
    RotationDesyncAnalyzer,
    StaticLeakageDetector,
    TrajectoryReconstructor,
)
from bluetooth_sniffle.adversarial.relay import (
    PairingRelayBridge,
    RelayedLinkLayerPacket,
)
from bluetooth_sniffle.adversarial.rogue_beacon import (
    AntiStalkingEvasionEvaluator,
)
from bluetooth_sniffle.device.serial_port import check_device_usage
from scripts.ble_antistalking_tracker import BLETrackerDB


def render_adversarial_evaluation(
    conn: Optional[sqlite3.Connection],
    tracker_db: Optional[BLETrackerDB] = None,
    event_queue: Optional[EventQueue] = None,
) -> None:
    """Render the Adversarial Testbed view in the Streamlit dashboard."""
    st.subheader("⚡ Adversarial Testbed & Protocol Evaluation")
    st.markdown(
        "Pairing relay analysis, rotating identifier linkability, and anti-stalking heuristic evasion benchmarks."
    )

    tab_deanon, tab_relay, tab_evasion = st.tabs([
        "🔍 Identity Deanonymization",
        "🔄 Pairing Relay",
        "🎯 Evasion Benchmarks",
    ])

    # --- TAB 1: Identity Deanonymization ---
    with tab_deanon:
        st.markdown("#### Rotating Identifier Linkability & Desynchronization Analysis")
        st.caption(
            "Detects static address leakage, measures AdvA vs payload rotation delay divergence, and reconstructs movement trajectories across address cycles."
        )

        detector = StaticLeakageDetector()
        desync_analyzer = RotationDesyncAnalyzer()
        reconstructor = TrajectoryReconstructor(max_time_gap=45.0, max_rssi_delta=15.0)

        # Ingest recent observations from DB
        observations: list[LinkabilityObservation] = []
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT mac_address, ephemeral_key, timestamp, rssi, network_type
                    FROM observations
                    ORDER BY id DESC
                    LIMIT 200
                    """
                )
                for row in cursor.fetchall():
                    obs = LinkabilityObservation(
                        mac_address=row[0],
                        mac_type="RPA",
                        ephemeral_key=row[1] or "",
                        timestamp=float(row[2] or time.time()),
                        rssi=int(row[3] or -70),
                        network_type=row[4] or "Unknown",
                    )
                    observations.append(obs)
                    detector.analyze(obs)
                    desync_analyzer.feed(obs)
                    reconstructor.add_observation(obs)
            except Exception as e:
                st.warning(f"Error reading observations for linkability analysis: {e}")

        trajectories = reconstructor.reconstruct_trajectories()

        # Metric cards
        m_col1, m_col2, m_col3 = st.columns(3)
        with m_col1:
            st.metric("Total Observations Analyzed", len(observations))
        with m_col2:
            multi_mac_trajs = [t for t in trajectories if len(t.mac_addresses) > 1]
            st.metric("Correlated Rotating Trajectories", len(multi_mac_trajs))
        with m_col3:
            avg_conf = (
                sum(t.confidence for t in trajectories) / max(1, len(trajectories))
                if trajectories
                else 0.0
            )
            st.metric("Mean Linkability Confidence", f"{avg_conf:.0%}")

        st.divider()

        if trajectories:
            traj_data = []
            for idx, traj in enumerate(trajectories[:20], start=1):
                traj_data.append({
                    "Trajectory #": idx,
                    "Distinct MACs": len(traj.mac_addresses),
                    "MAC Addresses": ", ".join(list(traj.mac_addresses)[:3]) + ("..." if len(traj.mac_addresses) > 3 else ""),
                    "Packets": len(traj.observations),
                    "Primary Network": traj.observations[0].network_type,
                    "Linkability Confidence": f"{traj.confidence:.0%}",
                })
            st.dataframe(pd.DataFrame(traj_data), width="stretch")
        else:
            st.info("No active trajectories reconstructed yet. Inject rogue bursts or connect live Sniffle radios.")

    # --- TAB 2: Pairing Relay ---
    with tab_relay:
        st.markdown("#### Two-Ended BLE Pairing Relay Testbed")
        st.caption(
            "Captures pairing handshakes (`CONNECT_IND`, `SMP_PAIRING_REQ`), relays frames across dual dongles, and extracts failure error codes to link rotating addresses."
        )

        r_col1, r_col2 = st.columns([2, 1])
        with r_col1:
            relay_status = "IDLE (Awaiting Connection)"
            st.markdown(f"**Current Handshake State:** `{relay_status}`")
            st.markdown("**Active Bridge Topology:** `Relay Master (/dev/ttyUSB0) ➔ TCP (Port 7352) ➔ Relay Slave (/dev/ttyUSB1)`")
            m_used = check_device_usage("/dev/ttyUSB0")
            s_used = check_device_usage("/dev/ttyUSB1")
            m_badge = "🟢 IN USE (open)" if m_used else "⚪ IDLE (not open)"
            s_badge = "🟢 IN USE (open)" if s_used else "⚪ IDLE (not open)"
            st.markdown(f"**Hardware Status:** Master (`/dev/ttyUSB0`): `{m_badge}` | Slave (`/dev/ttyUSB1`): `{s_badge}`")

        with r_col2:
            if st.button("Simulate Relay Handshake Burst", key="btn_sim_relay"):
                bridge = PairingRelayBridge()
                now_us = int(time.time() * 1_000_000)
                pkt = RelayedLinkLayerPacket(
                    channel=37,
                    rssi=-54,
                    timestamp_usec=now_us,
                    pdu_type="SMP",
                    initiator_mac="40:11:22:33:44:11",
                    target_mac="50:AA:BB:CC:DD:EE",
                    raw_pdu=bytes([0x05, 0x05]),  # Pairing Not Supported
                )
                bridge.ingest_sniffed_packet(pkt)
                bridge.feed_pdu(pkt.pdu_type, pkt.initiator_mac, pkt.target_mac, pkt.raw_pdu, pkt.timestamp_usec)
                st.success("Simulated pairing handshake event forwarded through relay bridge.")

    # --- TAB 3: Evasion Benchmarks ---
    with tab_evasion:
        st.markdown("#### Anti-Stalking Heuristic Evasion Benchmark")
        st.caption(
            "Evaluate anti-stalking detection algorithms against adversarial burst-and-sleep tactics and key dilution patterns."
        )

        b_col1, b_col2 = st.columns([1, 1])
        with b_col1:
            net_choice = st.selectbox(
                "Target Beacon Network:",
                options=["Apple Find My", "Google Find Hub", "Samsung SmartThings Find", "Tile"],
            )
            scenario_choice = st.selectbox(
                "Benchmark Scenario:",
                options=[
                    "standard_persistence (Normal Stalking Tag)",
                    "burst_and_sleep (Evasion: Short Burst + Long Sleep)",
                    "fast_rotation_dilution (Evasion: Rapid Key Rotation)",
                ],
            )
        with b_col2:
            burst_count = st.slider("Burst Packets Count:", min_value=3, max_value=20, value=10)
            duration_span = st.slider("Duration Span (Minutes):", min_value=1, max_value=15, value=8)

        if st.button("🚀 Run Evasion Benchmark", key="btn_run_benchmark"):
            if tracker_db:
                evaluator = AntiStalkingEvasionEvaluator(tracker_db)
                scenario_name = scenario_choice.split()[0]
                rot_interval = 2.0 if "fast_rotation" in scenario_name else 30.0
                result = evaluator.evaluate_scenario(
                    scenario_name=scenario_name,
                    packets_count=burst_count,
                    duration_minutes=float(duration_span),
                    rotation_interval_minutes=rot_interval,
                    network_type=net_choice,
                )

                if result.is_detected:
                    st.error(f"🚨 **Detection Triggered**: Heuristics logged {result.alert_count} threat alert(s)!")
                else:
                    st.success("🛡️ **Evasion Successful**: Threat heuristics bypassed (0 alerts generated)!")

                st.json({
                    "Scenario": result.scenario_name,
                    "Detected": result.is_detected,
                    "Alerts Count": result.alert_count,
                    "Packets Injected": result.packets_injected,
                    "Duration (Minutes)": result.duration_minutes,
                })
            else:
                st.warning("Tracker DB unavailable.")
