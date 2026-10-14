"""Testbed & Radio Controls view allowing topology orchestration and beacon burst injection."""

from __future__ import annotations

import io
import shutil
import subprocess
import threading
import time
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import serial.tools.list_ports
import streamlit as st

from app.queue_bridge import EventQueue, get_event_queue
from bluetooth_sniffle.device.serial_port import check_device_usage, is_sniffle_device
from bluetooth_sniffle.extcap.runner import TsharkConfig
from bluetooth_sniffle.extcap.topology import (
    TsharkTopologyManager,
    check_port_availability,
)
from bluetooth_sniffle.protocol.beacons import (
    build_altbeacon,
    build_eddystone_uid,
    build_gaen,
    build_ibeacon,
)
from bluetooth_sniffle.sniff.pcap import PcapBleWriter
from scripts.ble_antistalking_tracker import BLETrackerDB


def discover_available_dongles() -> list[dict[str, Any]]:
    """Scan host system for attached USB serial devices and identify Sniffle CC2652P dongles.

    Returns:
        List of dictionaries with device path, description, VID/PID, is_sniffle, and in_use flag.
    """
    discovered: list[dict[str, Any]] = []
    try:
        ports = serial.tools.list_ports.comports()
        for p in ports:
            is_sniffle = is_sniffle_device(p)
            in_use = check_device_usage(p.device)
            discovered.append({
                "device": p.device,
                "description": getattr(p, "description", "") or "Serial Device",
                "is_sniffle": is_sniffle,
                "in_use": in_use,
                "vid": getattr(p, "vid", None),
                "pid": getattr(p, "pid", None),
                "manufacturer": getattr(p, "manufacturer", "Unknown"),
            })
    except Exception:
        pass
    return discovered


class RadioOrchestrator:
    """Manages Sniffle radio topologies, background sniffers, and beacon injection."""

    def __init__(self, event_queue: Optional[EventQueue] = None) -> None:
        self.event_queue: EventQueue = event_queue or get_event_queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._active_topology = "None"
        self._packets_captured = 0
        self.port1: str = "/dev/ttyUSB0"
        self.port2: str = "/dev/ttyUSB1"
        self._lock = threading.Lock()

    def set_ports(self, port1: str, port2: str) -> None:
        """Assign serial device ports for primary and secondary dongles."""
        with self._lock:
            self.port1 = port1
            self.port2 = port2

    def is_running(self) -> bool:
        """Check if a background topology runner is active."""
        with self._lock:
            return self._running

    def get_status(self) -> dict[str, Any]:
        """Return topology runner execution metrics."""
        with self._lock:
            return {
                "running": self._running,
                "active_topology": self._active_topology,
                "packets_captured": self._packets_captured,
                "port1": self.port1,
                "port2": self.port2,
            }

    def trigger_beacon_burst(
        self,
        beacon_type: str = "iBeacon",
        count: int = 5,
        channel: int = 37,
    ) -> list[dict[str, Any]]:
        """Synthesize and inject a burst of rogue or standard beacon packets.

        Args:
            beacon_type: One of 'iBeacon', 'AltBeacon', 'Eddystone-UID', 'GAEN'.
            count: Number of packet instances to inject in burst.
            channel: Target advertising channel (37, 38, 39).

        Returns:
            List of generated packet telemetry records.
        """
        now = time.time()
        packets: list[dict[str, Any]] = []

        for i in range(count):
            if beacon_type == "iBeacon":
                raw_bytes = build_ibeacon(
                    uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                    major=1,
                    minor=i + 1,
                )
                net_type = "Apple Find My"
                e_key = f"4c000215_{i:04x}"
            elif beacon_type == "AltBeacon":
                raw_bytes = build_altbeacon()
                net_type = "Radius Networks"
                e_key = f"beac_{i:04x}"
            elif beacon_type == "Eddystone-UID":
                raw_bytes = build_eddystone_uid(
                    namespace="0102030405060708090a",
                    instance=f"{i:012x}",
                )
                net_type = "Google Find Hub"
                e_key = f"feaa00_{i:04x}"
            elif beacon_type == "GAEN":
                raw_bytes = build_gaen(
                    rpi=f"0102030405060708090a0b0c0d0e{i:04x}",
                    aem="11223344",
                )
                net_type = "Exposure Notification"
                e_key = f"fd6f_{i:04x}"
            else:
                raw_bytes = build_ibeacon(
                    uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                    major=1,
                    minor=1,
                )
                net_type = "Unknown"
                e_key = f"raw_{i:04x}"

            mac_str = f"C0:11:22:33:44:{(i % 256):02X}"
            pkt = {
                "timestamp": now + (i * 0.05),
                "datetime_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "channel": channel,
                "rssi": -50 - (i % 15),
                "mac_address": mac_str,
                "network_type": net_type,
                "ephemeral_key": e_key,
                "raw_payload": raw_bytes.hex(),
            }
            self.event_queue.push(pkt)
            packets.append(pkt)

        with self._lock:
            self._packets_captured += len(packets)
        return packets

    def start_topology(
        self,
        topology: str = "topology-a",
        mock: bool = True,
        duration_sec: float = 2.0,
    ) -> bool:
        """Start a background topology runner thread."""
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._active_topology = topology
            self._stop_event.clear()

        def _worker() -> None:
            start_t = time.time()
            seq = 0
            while not self._stop_event.is_set():
                if duration_sec > 0 and (time.time() - start_t) >= duration_sec:
                    break
                self.trigger_beacon_burst(
                    beacon_type="iBeacon" if seq % 2 == 0 else "Eddystone-UID",
                    count=2,
                    channel=37 if seq % 2 == 0 else 38,
                )
                seq += 1
                time.sleep(0.1)

            with self._lock:
                self._running = False

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def stop_topology(self) -> bool:
        """Halt the active background topology runner."""
        with self._lock:
            if not self._running:
                return False
            self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        with self._lock:
            self._running = False
        return True


@st.cache_resource
def get_radio_orchestrator() -> RadioOrchestrator:
    """Return singleton RadioOrchestrator instance."""
    return RadioOrchestrator()


def export_queue_to_pcap(event_queue: EventQueue) -> bytes:
    """Serialize current buffered queue events into a valid DLT 256 PCAP binary."""
    buf = io.BytesIO()
    writer = PcapBleWriter(buf)
    items = event_queue.drain_all()
    for item in items:
        raw_hex = item.get("raw_payload", "")
        try:
            body = bytes.fromhex(raw_hex) if raw_hex else b""
        except ValueError:
            body = b""
        # Synthesize standard ADV_IND PDU: Header (2B) + AdvA (6B) + AdvData
        adv_pdu = bytes([0x00, len(body) + 6]) + bytes.fromhex("C01122334455") + body
        ts_usec = int(item.get("timestamp", time.time()) * 1_000_000)
        writer.write_packet(
            ts_usec=ts_usec,
            chan=item.get("channel", 37),
            rssi=item.get("rssi", -60),
            packet=adv_pdu,
        )
    writer.flush()
    return buf.getvalue()


def check_tshark_dependencies() -> dict[str, Any]:
    """Verify presence of tshark binary and sniffle extcap plugin interface.

    Returns:
        Dictionary indicating availability, path, and error string if any.
    """
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        return {
            "tshark_available": False,
            "sniffle_extcap_available": False,
            "tshark_path": "",
            "error": "Tshark not found in system PATH. Please install Wireshark/tshark.",
        }

    try:
        res = subprocess.run(
            [tshark_bin, "-D"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if "sniffle" in res.stdout.lower():
            return {
                "tshark_available": True,
                "sniffle_extcap_available": True,
                "tshark_path": tshark_bin,
                "error": None,
            }
        return {
            "tshark_available": True,
            "sniffle_extcap_available": False,
            "tshark_path": tshark_bin,
            "error": "Sniffle extcap plugin not detected in tshark -D interfaces.",
        }
    except Exception as exc:
        return {
            "tshark_available": True,
            "sniffle_extcap_available": False,
            "tshark_path": tshark_bin,
            "error": f"Error querying tshark interfaces: {exc}",
        }


def format_preflight_badge(is_available: bool, reason: str) -> str:
    """Format human-readable preflight badge for port availability.

    Args:
        is_available: True if port is free to acquire.
        reason: Detail message explaining availability or conflict.

    Returns:
        Formatted badge text with tactical emoji.
    """
    if is_available:
        return "🟢 AVAILABLE"
    if "not found" in reason.lower() or "not exist" in reason.lower():
        return "⚪ OFFLINE"
    return "🔴 BUSY"


def map_ui_to_tshark_config(
    serport: str = "/dev/ttyUSB0",
    mode: str = "passive_scan",
    advchan: int | str = 37,
    rssi_floor: int = -128,
    mac_filter: str = "",
    irk_filter: str = "",
    payload_str: str = "",
    extadv: bool = False,
    longrange: bool = False,
    crcerr: bool = False,
    output_format: str = "ek",
) -> TsharkConfig:
    """Map UI widget parameters to a typed TsharkConfig instance."""
    return TsharkConfig(
        serport=serport,
        mode=mode,
        advchan=advchan,
        rssi=rssi_floor if rssi_floor > -128 else None,
        mac=mac_filter.strip() if mac_filter.strip() else None,
        irk=irk_filter.strip() if irk_filter.strip() else None,
        string=payload_str.strip() if payload_str.strip() else None,
        extadv=extadv,
        longrange=longrange,
        crcerr=crcerr,
        output_format=output_format,
    )


def build_live_packet_dataframe(packets: list[dict[str, Any]]) -> pd.DataFrame:
    """Transform list of packet observations into structured display DataFrame."""
    columns = [
        "datetime_str",
        "channel",
        "mac_address",
        "rssi",
        "pdu_type",
        "network_type",
        "company_id",
        "ephemeral_key",
    ]
    if not packets:
        return pd.DataFrame(columns=columns)

    rows: list[dict[str, Any]] = []
    for p in packets:
        rows.append({
            "datetime_str": p.get("datetime_str", ""),
            "channel": p.get("channel", 37),
            "mac_address": p.get("mac_address", "Unknown"),
            "rssi": p.get("rssi", -128),
            "pdu_type": p.get("pdu_type", "ADV_IND"),
            "network_type": p.get("network_type", "Unknown"),
            "company_id": p.get("company_id", ""),
            "ephemeral_key": p.get("ephemeral_key", ""),
        })
    return pd.DataFrame(rows)


def build_tshark_live_chart(df: pd.DataFrame) -> go.Figure:
    """Build Plotly line chart displaying live signal strength trends."""
    if df.empty or "rssi" not in df.columns:
        fig = go.Figure()
        fig.update_layout(
            paper_bgcolor="#0F141C",
            plot_bgcolor="#1B2028",
            font_color="#E1E2E8",
            title="Awaiting Live Tshark Stream...",
            yaxis_range=[-105, -20],
        )
        return fig

    fig = px.line(
        df,
        x="datetime_str" if "datetime_str" in df.columns else None,
        y="rssi",
        color="mac_address" if "mac_address" in df.columns else None,
        title="Live BLE Signal Strength Trends (Tshark Stream)",
        labels={"datetime_str": "Time", "rssi": "RSSI (dBm)", "mac_address": "MAC Address"},
        markers=True,
    )
    fig.update_layout(
        paper_bgcolor="#0F141C",
        plot_bgcolor="#1B2028",
        font_color="#E1E2E8",
        yaxis_range=[-105, -20],
        margin=dict(l=20, r=20, t=40, b=20),
    )
    return fig


@st.cache_resource
def get_tshark_topology_manager() -> TsharkTopologyManager:
    """Return singleton TsharkTopologyManager instance."""
    return TsharkTopologyManager(event_queue=get_event_queue())


def render_radio_controls(
    tracker_db: Optional[BLETrackerDB] = None,
    event_queue: Optional[EventQueue] = None,
) -> None:
    """Render the Testbed & Radio Controls view."""
    st.subheader("🎛️ Testbed & Radio Controls")
    st.markdown(
        "Orchestrate dual-dongle Sniffle topologies, inject synthetic adversarial beacon bursts, and capture live PCAPs."
    )

    orchestrator = get_radio_orchestrator()
    status = orchestrator.get_status()

    # Hardware Status & Topology Controls
    top_col1, top_col2 = st.columns([2, 1])
    with top_col1:
        st.markdown("#### ⚡ Hardware Topologies")
        selected_topo = st.radio(
            "Topology Configuration:",
            options=["Topology A: Dual-Channel Primary/Secondary", "Topology B: Cross-Band BLE/Cellular Interception"],
            index=0,
        )
        topo_key = "topology-a" if "Topology A" in selected_topo else "topology-b"

        ctl_col1, ctl_col2 = st.columns(2)
        with ctl_col1:
            if not status["running"]:
                if st.button("▶ Start Topology Sniffing", type="primary"):
                    orchestrator.start_topology(topology=topo_key, mock=True, duration_sec=30.0)
                    st.success(f"Started {topo_key}!")
                    st.rerun()
            else:
                if st.button("⏹ Stop Topology Sniffing"):
                    orchestrator.stop_topology()
                    st.info("Stopped topology sniffing.")
                    st.rerun()

    with top_col2:
        st.markdown("#### 📊 Hardware Status")
        st.write(f"**State:** `{'ACTIVE' if status.get('running', False) else 'IDLE'}`")
        st.write(f"**Topology:** `{status.get('active_topology', 'None')}`")
        p1 = status.get("port1", "/dev/ttyUSB0")
        p2 = status.get("port2", "/dev/ttyUSB1")
        p1_used = check_device_usage(p1)
        p2_used = check_device_usage(p2)
        st.write(f"**Primary Port ({p1}):** `{'IN USE (open)' if p1_used else 'IDLE (not open)'}`")
        st.write(f"**Secondary Port ({p2}):** `{'IN USE (open)' if p2_used else 'IDLE (not open)'}`")
        st.write(f"**Buffer Packets:** `{status.get('packets_captured', 0)}`")

    st.divider()

    # USB Dongle Auto-Discovery Panel
    st.markdown("#### 🔌 Hardware USB Dongle Auto-Discovery")
    st.caption("Automatically scan host USB serial buses for attached Sonoff CC2652P or Ti XDS110 Sniffle dongles.")
    discovered_dongles = discover_available_dongles()
    sniffle_dongles = [d for d in discovered_dongles if d.get("is_sniffle")]

    disc_col1, disc_col2 = st.columns(2)
    with disc_col1:
        if sniffle_dongles:
            st.success(f"Detected **{len(sniffle_dongles)}** Sniffle-compatible radio hardware dongle(s) on host.")
            options = [d["device"] for d in sniffle_dongles]
            port1 = st.selectbox("Primary Sniffle Dongle (Ch 37):", options=options, index=0)
            p2_idx = min(1, len(options) - 1)
            port2 = st.selectbox("Secondary Sniffle Dongle (Ch 38/39):", options=options, index=p2_idx)
            orchestrator.set_ports(port1, port2)
        else:
            st.info("No physical CC2652P USB dongles detected on host. High-Fidelity Mock Mode enabled.")
            port1 = st.text_input("Primary Dongle Port (or Mock):", value=status.get("port1", "/dev/ttyUSB0"))
            port2 = st.text_input("Secondary Dongle Port (or Mock):", value=status.get("port2", "/dev/ttyUSB1"))
            orchestrator.set_ports(port1, port2)

    with disc_col2:
        with st.expander("Discovered USB Device Telemetry", expanded=bool(discovered_dongles)):
            if discovered_dongles:
                for d in discovered_dongles:
                    status_badge = "✅ Sniffle CC2652P" if d.get("is_sniffle") else "ℹ️ Other Serial"
                    usage_badge = " [IN USE]" if d.get("in_use") else " [IDLE]"
                    st.write(f"- `{d['device']}`: **{d['description']}** ({status_badge}{usage_badge})")
            else:
                st.write("No active USB serial bridges currently enumerated.")

    st.divider()

    # Beacon Burst Injection Panel
    st.markdown("#### 📡 Rogue Beacon Burst Injection")
    st.caption("Generate synthetic BLE advertising bursts to test tracker parsers and anti-stalking heuristics.")

    b_col1, b_col2, b_col3, b_col4 = st.columns(4)
    with b_col1:
        beacon_type = st.selectbox(
            "Beacon Type:",
            options=["iBeacon", "AltBeacon", "Eddystone-UID", "GAEN"],
        )
    with b_col2:
        burst_count = st.slider("Burst Count:", min_value=1, max_value=50, value=10)
    with b_col3:
        target_chan = st.selectbox("Advertising Channel:", options=[37, 38, 39], index=0)
    with b_col4:
        st.write("")
        st.write("")
        if st.button("🚀 Fire Burst", type="secondary"):
            pkts = orchestrator.trigger_beacon_burst(
                beacon_type=beacon_type,
                count=burst_count,
                channel=target_chan,
            )
            # Log to DB if present
            if tracker_db:
                for p in pkts:
                    tracker_db.insert_observation(
                        mac_address=p["mac_address"],
                        rssi=p["rssi"],
                        network_type=p["network_type"],
                        ephemeral_key=p["ephemeral_key"],
                        channel=p["channel"],
                        raw_payload=p["raw_payload"],
                        timestamp=p["timestamp"],
                    )
            st.success(f"Injected {len(pkts)} {beacon_type} packets on Ch {target_chan}!")

    st.divider()

    # Live Tshark Extcap Streaming Panel
    st.markdown("#### 🦈 Live BLE JSON Streaming via Tshark & Extcap")
    st.caption(
        "Wrap sniffle_extcap.py with Tshark (-T ek / -T json) to stream live dissected BLE frames directly into the EventQueue without interrupting background processes."
    )

    tshark_manager = get_tshark_topology_manager()
    tshark_status = tshark_manager.get_status()
    deps = check_tshark_dependencies()

    port1 = orchestrator.port1
    port2 = orchestrator.port2
    avail1, reason1 = check_port_availability(port1)
    avail2, reason2 = check_port_availability(port2)

    # Diagnostics Card Row
    d_col1, d_col2, d_col3, d_col4 = st.columns(4)
    with d_col1:
        st.metric(
            label="Tshark Binary",
            value="INSTALLED" if deps["tshark_available"] else "MISSING",
            delta="Available" if deps["tshark_available"] else "Not in PATH",
        )
    with d_col2:
        st.metric(
            label="Sniffle Extcap Plugin",
            value="REGISTERED" if deps["sniffle_extcap_available"] else "UNREGISTERED",
            delta="Ready" if deps["sniffle_extcap_available"] else "Missing from tshark -D",
        )
    with d_col3:
        st.metric(
            label=f"Port 1 ({port1})",
            value=format_preflight_badge(avail1, reason1),
            help=reason1,
        )
    with d_col4:
        st.metric(
            label=f"Port 2 ({port2})",
            value=format_preflight_badge(avail2, reason2),
            help=reason2,
        )

    if deps.get("error"):
        st.warning(f"⚠️ **Preflight Notice:** {deps['error']}")

    ts_topo = st.radio(
        "Tshark Orchestration Topology:",
        options=[
            "Topology A: Dual-Channel Aggregation (Radio 1 + Radio 2)",
            "Topology B: Single-Channel Sniffing (Dedicated Radio)",
        ],
        index=0,
        key="tshark_topology_select",
    )
    is_topo_a = "Topology A" in ts_topo

    # Form parameters
    p_col1, p_col2, p_col3 = st.columns([1, 1, 1])
    with p_col1:
        ts_chan1 = st.selectbox("Primary Radio Channel:", options=[37, 38, 39, "auto", "all"], index=0, key="ts_c1")
        ts_chan2 = 38
        if is_topo_a:
            ts_chan2 = st.selectbox("Secondary Radio Channel:", options=[37, 38, 39], index=1, key="ts_c2")
        ts_rssi = st.slider("RSSI Floor Cutoff (dBm):", min_value=-128, max_value=0, value=-80, key="ts_rssi")

    with p_col2:
        ts_mac = st.text_input("Target Advertiser MAC Filter:", placeholder="e.g. AA:BB:CC:DD:EE:FF", key="ts_mac")
        ts_irk = st.text_input("Advertiser IRK (32 Hex Digits):", placeholder="Optional 16-byte IRK", key="ts_irk")
        ts_string = st.text_input("Payload String Search:", placeholder="e.g. FindMy", key="ts_str")

    with p_col3:
        ts_extadv = st.checkbox("BT5 Extended Advertising (--extadv)", value=False, key="ts_extadv")
        ts_longrange = st.checkbox("Coded PHY Long Range (--longrange)", value=False, key="ts_lr")
        ts_crcerr = st.checkbox("Capture Packets with CRC Errors (--crcerr)", value=False, key="ts_crc")
        ts_format = st.selectbox("JSON Output Format:", options=["ek", "json"], index=0, key="ts_fmt")

    # Start/Stop Buttons
    btn_col1, btn_col2 = st.columns([1, 3])
    with btn_col1:
        if not tshark_status["running"]:
            if st.button("▶ Start Tshark Capture", type="primary", key="btn_start_tshark"):
                if is_topo_a:
                    started = tshark_manager.start_topology_a(
                        port1=port1,
                        port2=port2,
                        chan1=ts_chan1 if isinstance(ts_chan1, int) else 37,
                        chan2=ts_chan2 if isinstance(ts_chan2, int) else 38,
                        rssi_cutoff=ts_rssi,
                        mac=ts_mac if ts_mac.strip() else None,
                        irk=ts_irk if ts_irk.strip() else None,
                        string=ts_string if ts_string.strip() else None,
                        extadv=ts_extadv,
                        longrange=ts_longrange,
                        crcerr=ts_crcerr,
                        output_format=ts_format,
                    )
                else:
                    started = tshark_manager.start_topology_b(
                        port=port1,
                        chan=ts_chan1 if isinstance(ts_chan1, int) else 37,
                        rssi_cutoff=ts_rssi,
                        mac=ts_mac if ts_mac.strip() else None,
                        irk=ts_irk if ts_irk.strip() else None,
                        string=ts_string if ts_string.strip() else None,
                        extadv=ts_extadv,
                        longrange=ts_longrange,
                        crcerr=ts_crcerr,
                        output_format=ts_format,
                    )
                if started:
                    st.success("Tshark live capturing started successfully!")
                    st.rerun()
                else:
                    st.error(tshark_manager.get_status().get("error") or "Failed to start Tshark process.")
        else:
            if st.button("⏹ Stop Tshark Capture", type="secondary", key="btn_stop_tshark"):
                tshark_manager.stop()
                st.info("Tshark capture stopped.")
                st.rerun()

    # Telemetry and stream visualization
    t_col1, t_col2, t_col3, t_col4 = st.columns(4)
    with t_col1:
        st.metric("Capture State", "ACTIVE" if tshark_status["running"] else "IDLE")
    with t_col2:
        st.metric("Active Topology", tshark_status["topology"])
    with t_col3:
        st.metric("Packets Dissected", tshark_status["packets_captured"])
    with t_col4:
        st.metric("Queue Depth", event_queue.size() if event_queue else 0)

    # Live packet dataframe and Plotly chart
    recent_packets = list(tshark_manager.parser.buffered_observations)
    df_live = build_live_packet_dataframe(recent_packets)

    st.markdown("##### 📡 Live Streamed BLE Observations")
    if not df_live.empty:
        st.dataframe(df_live, use_container_width=True, height=220)
        st.plotly_chart(build_tshark_live_chart(df_live), use_container_width=True)
    else:
        st.info("No packets currently streamed. Start Tshark capture or inject beacon burst to view telemetry.")

    with st.expander("🔬 Tshark Process Metrics & Diagnostics Log", expanded=False):
        st.json(tshark_status)
        for p, r in tshark_manager.runners.items():
            st.markdown(f"**Logs for `{p}`:**")
            logs = r.get_stderr_logs()
            if logs:
                st.code("\n".join(logs[-10:]), language="text")
            else:
                st.write("No diagnostic stderr messages recorded.")

    st.divider()

    # Live PCAP Export
    st.markdown("#### 💾 Live PCAP Capture Download")
    q = event_queue or get_event_queue()
    pcap_data = export_queue_to_pcap(q)
    st.download_button(
        label="📥 Download Active Session PCAP (DLT 256)",
        data=pcap_data,
        file_name="sniffle_live_capture.pcap",
        mime="application/vnd.tcpdump.pcap",
    )

