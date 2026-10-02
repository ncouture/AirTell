"""Testbed & Radio Controls view allowing topology orchestration and beacon burst injection."""

from __future__ import annotations

import io
import threading
import time
from typing import Any, Optional

import streamlit as st

from app.queue_bridge import EventQueue, get_event_queue
from bluetooth_sniffle.protocol.beacons import (
    build_altbeacon,
    build_eddystone_uid,
    build_gaen,
    build_ibeacon,
)
from bluetooth_sniffle.sniff.pcap import PcapBleWriter
from scripts.ble_antistalking_tracker import BLETrackerDB


class RadioOrchestrator:
    """Manages Sniffle radio topologies, background sniffers, and beacon injection."""

    def __init__(self, event_queue: Optional[EventQueue] = None) -> None:
        self.event_queue: EventQueue = event_queue or get_event_queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._active_topology = "None"
        self._packets_captured = 0
        self._lock = threading.Lock()

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
        st.write(f"**State:** `{'ACTIVE' if status['running'] else 'IDLE'}`")
        st.write(f"**Topology:** `{status['active_topology']}`")
        st.write(f"**Buffer Packets:** `{status['packets_captured']}`")

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
