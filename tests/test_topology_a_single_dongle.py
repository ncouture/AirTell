"""Automated unit and integration test suite for single-dongle passive sniffing mode in Topology A."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airtell.cli import main
from airtell.device.controller import SniffleDeviceController
from airtell.device.mock import VirtualRadioBus
from airtell.device.serial_port import allocate_dual_ports
from airtell.protocol.beacons import build_ibeacon
from airtell.protocol.wire import PacketMessage
from airtell.sniff.pcap import PcapBleReader, PcapBleWriter
from airtell.topology.topology_a import TopologyAOrchestrator
from app.queue_bridge import EventQueue, packet_to_event_dict


class TestAllocateDualPortsSingleDongleFallback:
    """Test suite for allocate_dual_ports(allow_single=True) fallback behavior (Issue #31)."""

    def test_allocate_zero_ports_raises_runtime_error(self) -> None:
        """When 0 ports are available, allocate_dual_ports must raise RuntimeError even if allow_single=True."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=[]):
            with pytest.raises(RuntimeError, match="requires at least 1 Sniffle dongle"):
                allocate_dual_ports(allow_single=True)

    def test_allocate_one_port_auto_discovery(self) -> None:
        """When 1 port is available and allow_single=True, return (None, port)."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=["/dev/ttyUSB0"]):
            p1, p2 = allocate_dual_ports(allow_single=True)
            assert p1 is None
            assert p2 == "/dev/ttyUSB0"

    def test_allocate_one_port_without_allow_single_raises(self) -> None:
        """When 1 port is available and allow_single=False (default), raise RuntimeError."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=["/dev/ttyUSB0"]):
            with pytest.raises(RuntimeError, match="requires 2 Sniffle dongles"):
                allocate_dual_ports(allow_single=False)

    def test_allocate_two_ports_auto_discovery(self) -> None:
        """When 2 ports are available and allow_single=True, allocate both ports."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"]):
            p1, p2 = allocate_dual_ports(allow_single=True)
            assert p1 == "/dev/ttyUSB0"
            assert p2 == "/dev/ttyUSB1"

    def test_allocate_explicit_dev2_only(self) -> None:
        """When dev2 is passed without dev1 and allow_single=True, return (None, dev2)."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=[]):
            p1, p2 = allocate_dual_ports(dev2="/dev/ttyUSB1", allow_single=True)
            assert p1 is None
            assert p2 == "/dev/ttyUSB1"

    def test_allocate_explicit_dev1_only(self) -> None:
        """When dev1 is passed without dev2 and allow_single=True, return (None, dev1)."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=[]):
            p1, p2 = allocate_dual_ports(dev1="/dev/ttyUSB0", allow_single=True)
            assert p1 is None
            assert p2 == "/dev/ttyUSB0"

    def test_allocate_dev1_with_two_ports_available_allocates_dual_ports(self) -> None:
        """When dev1 is passed and a second port is available, allocate both ports even if allow_single=True."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"]):
            p1, p2 = allocate_dual_ports(dev1="/dev/ttyUSB0", allow_single=True)
            assert p1 == "/dev/ttyUSB0"
            assert p2 == "/dev/ttyUSB1"

    def test_allocate_dev2_with_two_ports_available_allocates_dual_ports(self) -> None:
        """When dev2 is passed and a second port is available, allocate both ports even if allow_single=True."""
        with patch("airtell.device.serial_port.discover_sniffle_ports", return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"]):
            p1, p2 = allocate_dual_ports(dev2="/dev/ttyUSB1", allow_single=True)
            assert p1 == "/dev/ttyUSB0"
            assert p2 == "/dev/ttyUSB1"

    def test_allocate_explicit_identical_raises_value_error(self) -> None:
        """Conflicting identical ports must raise ValueError even with allow_single=True."""
        with pytest.raises(ValueError, match="Conflicting port allocation"):
            allocate_dual_ports(dev1="/dev/ttyUSB0", dev2="/dev/ttyUSB0", allow_single=True)


class TestTopologyAOrchestratorSingleDongleLifecycle:
    """Test suite for TopologyAOrchestrator single-dongle mode lifecycle and stimulator guards (Issues #15, #29, #30)."""

    def test_create_mock_single_dongle_initialization(self) -> None:
        """Verify create_mock with single_dongle=True sets stimulator to None."""
        topo = TopologyAOrchestrator.create_mock(observer_channel=38, single_dongle=True)
        assert topo.stimulator is None
        assert topo.is_single_dongle is True
        assert topo.observer is not None
        assert topo.observer_channel == 38
        assert not topo.is_running

    def test_single_dongle_start_and_stop_cleanly(self) -> None:
        """Verify start() and stop() work cleanly without stimulator hardware."""
        bus = VirtualRadioBus()
        topo = TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37, single_dongle=True)
        assert not topo.is_running

        topo.start()
        assert topo.is_running
        assert topo.observer.is_sniffing
        assert topo.observer.channel == 37

        stats = topo.get_stats()
        assert stats["single_dongle"] is True
        assert stats["stimulator_port"] is None
        assert stats["topology"] == "Topology A (Passive Observer)"
        assert stats["captured_packets_total"] == 0

        topo.stop()
        assert not topo.is_running
        assert not topo.observer.is_sniffing

    def test_context_manager_single_dongle(self) -> None:
        """Verify context manager interface starts and stops single-dongle topology cleanly."""
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, single_dongle=True) as topo:
            assert topo.is_running
            assert topo.is_single_dongle is True
        assert not topo.is_running

    def test_stimulator_methods_safe_noop_when_stimulator_is_none(self) -> None:
        """Stimulator injection calls must safely no-op when stimulator is None."""
        bus = VirtualRadioBus()
        with TopologyAOrchestrator.create_mock(bus=bus, single_dongle=True) as topo:
            topo.set_stimulus_mac("11:22:33:44:55:66")
            topo.inject_beacon(adv_data=b"\x02\x01\x06")
            topo.inject_burst_sequence([(b"\x02\x01\x06", 0.01)])
            assert topo.stimuli_count == 0

    def test_create_hardware_single_dongle_port1_none(self) -> None:
        """create_hardware with port1=None must configure single-dongle passive mode."""
        with patch(
            "airtell.topology.topology_a.allocate_dual_ports",
            return_value=(None, "/dev/ttyUSB1"),
        ):
            topo = TopologyAOrchestrator.create_hardware(
                port1=None,
                port2="/dev/ttyUSB1",
                observer_channel=37,
                allow_single=True,
            )
            assert topo.stimulator is None
            assert topo.is_single_dongle is True
            assert topo.observer.port == "/dev/ttyUSB1"

    def test_create_hardware_single_dongle_flag(self) -> None:
        """create_hardware with single_dongle=True enforces single-dongle mode even with 2 ports discovered."""
        with patch("airtell.topology.topology_a.discover_sniffle_ports", return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"]):
            topo = TopologyAOrchestrator.create_hardware(
                observer_channel=37,
                single_dongle=True,
            )
            assert topo.stimulator is None
            assert topo.is_single_dongle is True
            assert topo.observer.port == "/dev/ttyUSB0"

    def test_create_hardware_conflicting_identical_ports_raises(self) -> None:
        """create_hardware with identical port1 and port2 raises ValueError."""
        with pytest.raises(ValueError, match="Conflicting port allocation"):
            TopologyAOrchestrator.create_hardware(
                port1="/dev/ttyUSB0",
                port2="/dev/ttyUSB0",
            )


class TestSingleDongleCaptureAndPcap:
    """Test passive packet observation and PCAP recording in single-dongle mode (Issue #32)."""

    def test_single_dongle_packet_capture_and_pcap_output(self, tmp_path: Path) -> None:
        """Validate observer captures packets and writes to PCAP in single-dongle mode."""
        bus = VirtualRadioBus()
        pcap_file = tmp_path / "single_dongle_capture.pcap"

        sender = SniffleDeviceController(port="mock://beacon_sender", mock=True, bus=bus)
        sender.open()
        ibeacon_payload = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=2,
            tx_power=-59,
        )
        sender.set_mac_address("C0:11:22:33:44:55")

        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37, single_dongle=True) as topo:
            sender.configure_advertising(adv_data=ibeacon_payload, interval_ms=25)
            writer = PcapBleWriter(pcap_file)
            pkt = topo.read_packet(timeout=1.0)
            assert pkt is not None
            assert isinstance(pkt, PacketMessage)
            assert pkt.chan == 37
            assert pkt.rssi == -60
            assert ibeacon_payload in pkt.body
            writer.write_packet_message(pkt)
            writer.close()

            stats = topo.get_stats()
            assert stats["captured_packets_total"] >= 1

        sender.close()

        # Verify PCAP file integrity
        assert pcap_file.exists()
        with PcapBleReader(pcap_file) as reader:
            records = list(reader)
            assert len(records) >= 1
            assert ibeacon_payload in records[0].body

    def test_get_captured_packets_batch(self) -> None:
        """Validate get_captured_packets batch reading in single-dongle mode."""
        bus = VirtualRadioBus()
        sender = SniffleDeviceController(port="mock://sender", mock=True, bus=bus)
        sender.open()
        sender.set_mac_address("C0:22:33:44:55:66")

        with TopologyAOrchestrator.create_mock(bus=bus, observer_channel=37, single_dongle=True) as topo:
            sender.configure_advertising(adv_data=b"\x02\x01\x06\x03\x03\xaa\xfe", interval_ms=20)
            batch = topo.get_captured_packets(timeout=0.3)
            assert len(batch) >= 1
            assert len(topo.captured_packets) >= 1

        sender.close()


class TestSingleDongleEventQueueStreaming:
    """Test packet streaming from single-dongle observer into EventQueue (Issue #32)."""

    def test_forward_packet_to_event_queue(self) -> None:
        """Captured packets must be forwarded into the EventQueue for Streamlit visualization."""
        queue = EventQueue(maxsize=100)
        bus = VirtualRadioBus()

        sender = SniffleDeviceController(port="mock://sender", mock=True, bus=bus)
        sender.open()
        ibeacon_payload = build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=5,
            minor=10,
        )
        sender.set_mac_address("C0:11:22:33:44:55")

        topo = TopologyAOrchestrator.create_mock(
            bus=bus,
            observer_channel=37,
            single_dongle=True,
            event_queue=queue,
        )

        with topo:
            sender.configure_advertising(adv_data=ibeacon_payload, interval_ms=20)
            pkt = topo.read_packet(timeout=0.5)
            assert pkt is not None
            assert queue.size() >= 1

            items = queue.drain()
            assert len(items) >= 1
            event = items[0]
            assert event["channel"] == 37
            assert event["rssi"] == -60
            assert "mac_address" in event
            assert event["network_type"] == "Apple Find My"

        sender.close()

    def test_packet_to_event_dict_helper(self) -> None:
        """packet_to_event_dict converts packet into complete telemetry dictionary."""
        body = bytes([0x00, 0x1A]) + bytes.fromhex("112233445566") + bytes.fromhex("0201061216fe9f00112233")
        pkt = PacketMessage.pack(body=body, chan=38, rssi=-55, ts=123456)
        msg = PacketMessage(pkt)

        event = packet_to_event_dict(msg)
        assert event["channel"] == 38
        assert event["rssi"] == -55
        assert "datetime_str" in event
        assert event["network_type"] == "Google Find Hub"
        assert len(event["raw_payload"]) > 0

    def test_event_queue_push_packet_method(self) -> None:
        """EventQueue.push_packet pushes packet-like objects into internal queue."""
        queue = EventQueue(maxsize=10)
        body = bytes([0x00, 0x08]) + bytes.fromhex("112233445566")
        pkt = PacketMessage(PacketMessage.pack(body=body, chan=39, rssi=-70))

        assert queue.push_packet(pkt) is True
        assert queue.size() == 1
        drained = queue.drain()
        assert drained[0]["channel"] == 39
        assert drained[0]["rssi"] == -70


class TestCliTopologyASingleDongle:
    """Test CLI airtell topology-a in single-dongle mode (Issue #43)."""

    def test_cli_topology_a_single_dongle_mock(self, tmp_path: Path) -> None:
        """CLI with --mock and --single-dongle executes cleanly and generates telemetry/PCAP."""
        pcap_file = tmp_path / "cli_single.pcap"
        json_file = tmp_path / "cli_single.json"
        csv_file = tmp_path / "cli_single.csv"

        rc = main([
            "topology-a",
            "--mock",
            "--single-dongle",
            "--duration-sec",
            "0.5",
            "--pcap",
            str(pcap_file),
            "--json",
            str(json_file),
            "--csv",
            str(csv_file),
        ])
        assert rc == 0
        assert pcap_file.exists()
        assert json_file.exists()
        assert csv_file.exists()

        data = json.loads(json_file.read_text(encoding="utf-8"))
        assert data["metadata"]["topology"] == "Topology A"

    def test_cli_topology_a_dev2_without_dev1_mock(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --dev2 provided without --dev1 triggers single-dongle passive mode."""
        rc = main([
            "topology-a",
            "--mock",
            "--dev2",
            "/dev/ttyUSB1",
            "--duration-sec",
            "0.3",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Single-dongle passive capture mode active" in captured.out or "Single-dongle passive capture mode active" in captured.err

    def test_cli_topology_a_single_dongle_hardware_autodiscovery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CLI with auto-discovery finding 1 port operates in single-dongle passive mode."""
        mock_controller = MagicMock(spec=SniffleDeviceController)
        mock_controller.port = "/dev/ttyUSB0"
        mock_controller.is_open = True
        mock_controller.is_sniffing = True
        mock_controller.read_packet.return_value = None

        monkeypatch.setattr(
            "airtell.topology.topology_a.allocate_dual_ports",
            lambda *args, **kwargs: (None, "/dev/ttyUSB0"),
        )
        monkeypatch.setattr(
            "airtell.topology.topology_a.SniffleDeviceController",
            lambda port, mock: mock_controller,
        )

        rc = main([
            "topology-a",
            "--duration-sec",
            "0.2",
        ])
        assert rc == 0

    def test_cli_single_dongle_flag_with_two_ports_available(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """CLI with --single-dongle enforces single-dongle passive mode even if 2 ports are available."""
        mock_controller = MagicMock(spec=SniffleDeviceController)
        mock_controller.port = "/dev/ttyUSB0"
        mock_controller.is_open = True
        mock_controller.is_sniffing = True
        mock_controller.read_packet.return_value = None

        monkeypatch.setattr(
            "airtell.topology.topology_a.discover_sniffle_ports",
            lambda: ["/dev/ttyUSB0", "/dev/ttyUSB1"],
        )
        created_controllers: list[str] = []

        def mock_init(port: str, mock: bool = False) -> MagicMock:
            created_controllers.append(port)
            return mock_controller

        monkeypatch.setattr("airtell.topology.topology_a.SniffleDeviceController", mock_init)

        rc = main([
            "topology-a",
            "--single-dongle",
            "--duration-sec",
            "0.1",
        ])
        assert rc == 0
        assert len(created_controllers) == 1
        assert created_controllers[0] == "/dev/ttyUSB0"
        captured = capsys.readouterr()
        assert "Single-dongle passive capture mode active" in captured.out or "Single-dongle passive capture mode active" in captured.err

    def test_cli_dev1_with_two_ports_available_operates_dual_device(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """CLI with --dev1 when 2 ports are available operates in dual-device mode without falling back."""
        mock_controller = MagicMock(spec=SniffleDeviceController)
        mock_controller.port = "/dev/ttyUSB0"
        mock_controller.is_open = True
        mock_controller.is_sniffing = True
        mock_controller.read_packet.return_value = None

        monkeypatch.setattr(
            "airtell.device.serial_port.discover_sniffle_ports",
            lambda: ["/dev/ttyUSB0", "/dev/ttyUSB1"],
        )
        created_controllers: list[str] = []

        def mock_init(port: str, mock: bool = False) -> MagicMock:
            created_controllers.append(port)
            return mock_controller

        monkeypatch.setattr("airtell.topology.topology_a.SniffleDeviceController", mock_init)

        rc = main([
            "topology-a",
            "--dev1",
            "/dev/ttyUSB0",
            "--duration-sec",
            "0.1",
        ])
        assert rc == 0
        assert len(created_controllers) == 2
        assert created_controllers == ["/dev/ttyUSB0", "/dev/ttyUSB1"]
        captured = capsys.readouterr()
        assert "Single-dongle passive capture mode active" not in captured.out

    def test_cli_identical_dev1_and_dev2_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with identical --dev1 and --dev2 returns error code 1 and error message."""
        rc = main([
            "topology-a",
            "--dev1",
            "/dev/ttyUSB0",
            "--dev2",
            "/dev/ttyUSB0",
        ])
        assert rc == 1
        captured = capsys.readouterr()
        assert "Conflicting port allocation" in captured.err or "Conflicting port allocation" in captured.out

    def test_cli_single_dongle_with_correlate_prints_notice(self, capsys: pytest.CaptureFixture[str]) -> None:
        """CLI with --single-dongle and --correlate logs that correlation is disabled."""
        rc = main([
            "topology-a",
            "--mock",
            "--single-dongle",
            "--correlate",
            "--duration-sec",
            "0.1",
        ])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Correlation disabled in single-dongle passive mode" in captured.out or "Correlation disabled in single-dongle passive mode" in captured.err
