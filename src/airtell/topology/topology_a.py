"""Topology A: Stimulator (Device 1) + Observer (Device 2).

Coordinates Device 1 as an active beacon transmitter/stimulator broadcasting
synthesized advertising payloads and palindromic MAC addresses, while Device 2
passively captures over-the-air BLE frames on primary advertising channels.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from typing import Any

from airtell.device.controller import SniffleDeviceController
from airtell.device.mock import VirtualRadioBus
from airtell.device.serial_port import allocate_dual_ports, discover_sniffle_ports
from airtell.protocol.wire import PacketMessage
from airtell.topology.base import BaseTopology

logger = logging.getLogger(__name__)


class TopologyAOrchestrator(BaseTopology):
    """Orchestrates Topology A (Stimulator + Observer or Single-Dongle Passive Observer)."""

    def __init__(
        self,
        device1: SniffleDeviceController | None,
        device2: SniffleDeviceController,
        observer_channel: int = 37,
        observer_hop: bool = False,
        event_queue: Any | None = None,
    ) -> None:
        super().__init__(device1=device1, device2=device2)
        self.stimulator: SniffleDeviceController | None = device1
        self.observer: SniffleDeviceController = device2
        self.observer_channel: int = observer_channel
        self.observer_hop: bool = observer_hop
        self.event_queue: Any | None = event_queue

        self.stimuli_count: int = 0
        self.captured_packets: list[PacketMessage] = []

    @property
    def is_single_dongle(self) -> bool:
        """True if running in passive single-dongle observer mode without stimulator."""
        return self.stimulator is None

    def set_event_queue(self, event_queue: Any | None) -> None:
        """Attach an EventQueue instance for live streaming of captured packets."""
        self.event_queue = event_queue

    @classmethod
    def create_mock(
        cls,
        bus: VirtualRadioBus | None = None,
        observer_channel: int = 37,
        observer_hop: bool = False,
        single_dongle: bool = False,
        event_queue: Any | None = None,
    ) -> TopologyAOrchestrator:
        """Create a mock-backed Topology A instance for offline simulation."""
        shared_bus = bus or VirtualRadioBus()
        dev1 = None if single_dongle else SniffleDeviceController(port="mock://stimulator", mock=True, bus=shared_bus)
        dev2 = SniffleDeviceController(port="mock://observer", mock=True, bus=shared_bus)
        return cls(
            device1=dev1,
            device2=dev2,
            observer_channel=observer_channel,
            observer_hop=observer_hop,
            event_queue=event_queue,
        )

    @classmethod
    def create_hardware(
        cls,
        port1: str | None = None,
        port2: str | None = None,
        observer_channel: int = 37,
        observer_hop: bool = False,
        allow_single: bool = True,
        single_dongle: bool = False,
        event_queue: Any | None = None,
    ) -> TopologyAOrchestrator:
        """Create a hardware-backed Topology A instance using auto-discovered ports.

        Supports single-dongle passive sniffing mode when single_dongle=True, port1 is None (with port2 specified),
        or when only a single Sniffle dongle is available.
        """
        if port1 is not None and port2 is not None and port1 == port2:
            raise ValueError(f"Conflicting port allocation: Device 1 and Device 2 cannot share port '{port1}'")

        if single_dongle:
            dev1_port: str | None = None
            if port2 is not None:
                dev2_port = port2
            elif port1 is not None:
                dev2_port = port1
            else:
                available = list(dict.fromkeys(discover_sniffle_ports()))
                if not available:
                    raise RuntimeError(
                        "Single-dongle topology requires at least 1 Sniffle dongle, but 0 detected. "
                        "Connect a dongle or run with mock simulation mode."
                    )
                dev2_port = available[0]
        elif port1 is None and port2 is not None:
            dev1_port = None
            dev2_port = port2
        else:
            dev1_port, dev2_port = allocate_dual_ports(port1, port2, allow_single=allow_single)

        dev1 = SniffleDeviceController(port=dev1_port, mock=False) if dev1_port is not None else None
        dev2 = SniffleDeviceController(port=dev2_port, mock=False)
        return cls(
            device1=dev1,
            device2=dev2,
            observer_channel=observer_channel,
            observer_hop=observer_hop,
            event_queue=event_queue,
        )

    def start(self) -> None:
        """Open observer (and stimulator if configured), configure observer, and prepare stimulator."""
        if self.is_running:
            return

        # 1. Open observer first so no injected packets are missed
        self.observer.open()
        self.observer.start_sniffing(
            chan=self.observer_channel,
            hop=self.observer_hop,
            validate_crc=True,
            rssi_min=-128,
        )

        # 2. Open stimulator if present
        if self.stimulator is not None:
            self.stimulator.open()

        # 3. In single-dongle passive mode, connect to shared EventQueue if not already attached
        if self.stimulator is None and self.event_queue is None:
            try:
                from app.queue_bridge import get_event_queue

                self.event_queue = get_event_queue()
            except Exception:
                pass

        self.is_running = True
        if self.stimulator is not None:
            logger.info(
                "Topology A started: Stimulator (%s), Observer (%s, Ch %d, Hop=%s)",
                self.stimulator.port,
                self.observer.port,
                self.observer_channel,
                self.observer_hop,
            )
        else:
            logger.info(
                "Topology A started in single-dongle passive mode: Observer (%s, Ch %d, Hop=%s), Stimulator (inactive)",
                self.observer.port,
                self.observer_channel,
                self.observer_hop,
            )

    def stop(self) -> None:
        """Stop stimulus injection and close both serial devices."""
        if not self.is_running:
            return

        # 1. Close stimulator if present
        if self.stimulator is not None:
            try:
                self.stimulator.close()
            except Exception as exc:
                logger.warning("Error closing stimulator: %s", exc)

        # 2. Close observer
        try:
            self.observer.close()
        except Exception as exc:
            logger.warning("Error closing observer: %s", exc)

        self.is_running = False
        logger.info("Topology A stopped cleanly.")

    def set_stimulus_mac(self, mac: bytes | str, is_random: bool = True) -> None:
        """Set the transmitter MAC address on the stimulator device."""
        if self.stimulator is None:
            logger.warning("set_stimulus_mac called but stimulator is inactive in single-dongle mode")
            return
        self.stimulator.set_mac_address(mac, is_random=is_random)

    def inject_beacon(
        self,
        adv_data: bytes,
        scan_rsp_data: bytes = b"",
        interval_ms: int = 100,
        mode: int = 2,
        duration_sec: float | None = None,
    ) -> None:
        """Broadcast an advertisement payload from the stimulator.

        Args:
            adv_data: Primary AD structure payload (max 31 bytes).
            scan_rsp_data: Optional scan response data (max 31 bytes).
            interval_ms: Advertising interval in milliseconds.
            mode: 0 = connectable, 2 = non-connectable, 3 = scannable.
            duration_sec: If specified, injects for this duration then stops.
        """
        if not self.is_running:
            raise RuntimeError("Cannot inject beacon: Topology A is not running")

        if self.stimulator is None:
            logger.warning(
                "inject_beacon called in single-dongle passive mode (no stimulator configured); stimulus ignored"
            )
            return

        self.stimulator.configure_advertising(
            adv_data=adv_data,
            scan_rsp_data=scan_rsp_data,
            interval_ms=interval_ms,
            mode=mode,
        )
        self.stimuli_count += 1

        if duration_sec is not None and duration_sec > 0:
            time.sleep(duration_sec)

    def inject_burst_sequence(
        self,
        sequence: Sequence[tuple[bytes, float]],
        interval_ms: int = 100,
        mode: int = 2,
    ) -> None:
        """Broadcast a sequence of (payload, duration_sec) beacon bursts sequentially."""
        if self.stimulator is None:
            logger.warning("inject_burst_sequence called in single-dongle mode; sequence ignored")
            return
        for payload, duration in sequence:
            self.inject_beacon(
                adv_data=payload,
                interval_ms=interval_ms,
                mode=mode,
                duration_sec=duration,
            )

    def _push_to_event_queue(self, pkt: PacketMessage) -> None:
        """Forward captured packet to attached EventQueue if present."""
        if self.event_queue is None:
            return
        try:
            if hasattr(self.event_queue, "push_packet"):
                self.event_queue.push_packet(pkt)
            elif hasattr(self.event_queue, "push"):
                from app.queue_bridge import packet_to_event_dict

                self.event_queue.push(packet_to_event_dict(pkt))
        except Exception as exc:
            logger.debug("Failed to forward packet to EventQueue: %s", exc)

    def read_packet(self, timeout: float = 1.0) -> PacketMessage | None:
        """Read a single captured packet from the observer."""
        pkt = self.observer.read_packet(timeout=timeout)
        if pkt is not None:
            self.captured_packets.append(pkt)
            self._push_to_event_queue(pkt)
        return pkt

    def get_captured_packets(self, timeout: float = 0.5) -> list[PacketMessage]:
        """Read all available packets currently in the observer queue."""
        packets = self.observer.read_packets_batch(max_count=200, timeout=timeout)
        self.captured_packets.extend(packets)
        for pkt in packets:
            self._push_to_event_queue(pkt)
        return packets

    def get_stats(self) -> dict[str, Any]:
        """Return operational statistics for Topology A."""
        is_single = self.stimulator is None
        return {
            "topology": "Topology A (Passive Observer)" if is_single else "Topology A (Stimulator + Observer)",
            "is_running": self.is_running,
            "stimulator_port": self.stimulator.port if self.stimulator is not None else None,
            "observer_port": self.observer.port,
            "observer_channel": self.observer_channel,
            "observer_hop": self.observer_hop,
            "stimuli_count": self.stimuli_count,
            "captured_packets_total": len(self.captured_packets),
            "single_dongle": is_single,
        }
