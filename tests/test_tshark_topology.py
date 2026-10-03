"""Unit tests for Tshark multi-dongle topology orchestration and contention guard."""

from __future__ import annotations

import errno
import json
from unittest.mock import MagicMock, patch

import pytest

from app.queue_bridge import EventQueue
from bluetooth_sniffle.extcap.topology import (
    TsharkTopologyManager,
    check_port_availability,
    get_process_holding_port,
)


class TestPortAvailabilityGuard:
    """Tests checking serial port availability and avoiding interference with existing tools."""

    @patch("os.path.exists", return_value=True)
    @patch("os.open")
    @patch("os.close")
    def test_port_available_when_free(
        self, mock_close: MagicMock, mock_open: MagicMock, mock_exists: MagicMock
    ) -> None:
        """Port should report available when open succeeds with no conflicting processes."""
        mock_open.return_value = 42
        with patch("bluetooth_sniffle.extcap.topology.get_process_holding_port", return_value=None):
            avail, reason = check_port_availability("/dev/ttyUSB0")
            assert avail is True
            assert "Available" in reason
            mock_close.assert_called_with(42)

    @patch("os.path.exists", return_value=True)
    def test_port_busy_when_process_holding(self, mock_exists: MagicMock) -> None:
        """Port should report busy if an active Sniffle or tracker process holds it."""
        with patch(
            "bluetooth_sniffle.extcap.topology.get_process_holding_port",
            return_value="python3 scripts/ble_antistalking_tracker.py (PID 1001)",
        ):
            avail, reason = check_port_availability("/dev/ttyUSB0")
            assert avail is False
            assert "ble_antistalking_tracker.py" in reason
            assert "1001" in reason

    @patch("os.path.exists", return_value=True)
    @patch("os.open")
    def test_port_busy_when_ebusy_raised(
        self, mock_open: MagicMock, mock_exists: MagicMock
    ) -> None:
        """Port should report busy if OS returns EBUSY on open."""
        mock_open.side_effect = OSError(errno.EBUSY, "Device or resource busy")
        with patch("bluetooth_sniffle.extcap.topology.get_process_holding_port", return_value=None):
            avail, reason = check_port_availability("/dev/ttyUSB1")
            assert avail is False
            assert "busy" in reason.lower() or "locked" in reason.lower()

    @patch("os.path.exists", return_value=False)
    def test_port_unavailable_when_path_does_not_exist(self, mock_exists: MagicMock) -> None:
        """Non-existent device node should report unavailable."""
        avail, reason = check_port_availability("/dev/ttyUSB99")
        assert avail is False
        assert "not found" in reason.lower() or "does not exist" in reason.lower()

    def test_get_process_holding_port_open_fd(self) -> None:
        """Process holding open fd to port should be identified."""
        from unittest.mock import mock_open

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.listdir", side_effect=lambda p: ["9999"] if p == "/proc" else (["3"] if "fd" in p else [])),
            patch("os.readlink", return_value="/dev/ttyUSB0"),
            patch("builtins.open", mock_open(read_data=b"python3\x00scripts/ble_antistalking_tracker.py\x00")),
        ):
            result = get_process_holding_port("/dev/ttyUSB0")
            assert result is not None
            assert "9999" in result
            assert "holds open descriptor to /dev/ttyUSB0" in result

    def test_get_process_holding_port_cmdline_match(self) -> None:
        """Process commandline with sniffer script and port should be identified."""
        from unittest.mock import mock_open

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.listdir", side_effect=lambda p: ["9999"] if p == "/proc" else []),
            patch("builtins.open", mock_open(read_data=b"python3\x00scripts/sniff_receiver.py\x00--port\x00/dev/ttyUSB1\x00")),
        ):
            result = get_process_holding_port("/dev/ttyUSB1")
            assert result is not None
            assert "sniff_receiver.py" in result
            assert "9999" in result

    def test_get_process_holding_port_ignores_current_and_parent_pid(self) -> None:
        """Current process and parent process PIDs should be skipped to prevent self-contention."""
        with (
            patch("os.getpid", return_value=1234),
            patch("os.getppid", return_value=5678),
            patch("os.path.isdir", return_value=True),
            patch("os.listdir", return_value=["1234", "5678"]),
        ):
            result = get_process_holding_port("/dev/ttyUSB0")
            assert result is None

    def test_get_process_holding_port_ignores_non_sniffer_cmdlines(self) -> None:
        """Unrelated processes with port in arguments should be ignored if not matching sniffer tools."""
        from unittest.mock import mock_open

        with (
            patch("os.path.isdir", return_value=True),
            patch("os.listdir", side_effect=lambda p: ["9999"] if p == "/proc" else []),
            patch("builtins.open", mock_open(read_data=b"python3\x00unrelated_tool.py\x00/dev/ttyUSB0\x00")),
        ):
            result = get_process_holding_port("/dev/ttyUSB0")
            assert result is None



class TestTsharkTopologyManager:
    """Tests covering Topology A (dual-channel) and Topology B (single-channel) orchestration."""

    def test_topology_a_requires_distinct_ports(self) -> None:
        """Attempting to start Topology A with identical ports should raise ValueError."""
        manager = TsharkTopologyManager()
        with pytest.raises(ValueError, match="cannot share the same serial port"):
            manager.start_topology_a(port1="/dev/ttyUSB0", port2="/dev/ttyUSB0")

    @patch("bluetooth_sniffle.extcap.topology.check_port_availability")
    def test_topology_a_aborts_on_busy_port(self, mock_check: MagicMock) -> None:
        """Topology A should refuse to start if either port is busy."""
        mock_check.side_effect = [
            (True, "Available"),
            (False, "Held by ble_antistalking_tracker.py"),
        ]
        manager = TsharkTopologyManager()
        started = manager.start_topology_a(port1="/dev/ttyUSB0", port2="/dev/ttyUSB1")
        assert started is False
        status = manager.get_status()
        assert status["running"] is False
        assert "Held by ble_antistalking_tracker.py" in status.get("error", "")

    @patch("bluetooth_sniffle.extcap.topology.check_port_availability", return_value=(True, "Available"))
    @patch("bluetooth_sniffle.extcap.runner.TsharkExtcapRunner.is_running", return_value=True)
    @patch("bluetooth_sniffle.extcap.runner.TsharkExtcapRunner.start", return_value=True)
    def test_topology_a_dual_channel_aggregation(
        self, mock_runner_start: MagicMock, mock_is_running: MagicMock, mock_check: MagicMock
    ) -> None:
        """Topology A should aggregate packets from both dongles into single EventQueue."""
        queue = EventQueue(maxsize=100)
        manager = TsharkTopologyManager(event_queue=queue)

        started = manager.start_topology_a(
            port1="/dev/ttyUSB0",
            port2="/dev/ttyUSB1",
            chan1=37,
            chan2=38,
        )
        assert started is True
        status = manager.get_status()
        assert status["running"] is True
        assert status["topology"] == "Topology A"
        assert len(manager.runners) == 2

        # Simulate packet lines on runner 1 (Ch 37) and runner 2 (Ch 38)
        pkt1 = json.dumps({
            "timestamp": "1790000010.000",
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000010.000"},
                "btle": {"btle_btle_advertising_address": "11:11:11:11:11:11"},
                "btle_rf": {"btle_rf_btle_rf_channel": "37", "btle_rf_btle_rf_signal_dbm": "-60"},
            },
        })
        pkt2 = json.dumps({
            "timestamp": "1790000011.000",
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000011.000"},
                "btle": {"btle_btle_advertising_address": "22:22:22:22:22:22"},
                "btle_rf": {"btle_rf_btle_rf_channel": "38", "btle_rf_btle_rf_signal_dbm": "-65"},
            },
        })

        manager.dispatch_line(port="/dev/ttyUSB0", line=pkt1)
        manager.dispatch_line(port="/dev/ttyUSB1", line=pkt2)

        assert queue.size() == 2
        drained = queue.drain_all()
        macs = [p["mac_address"] for p in drained]
        channels = [p["channel"] for p in drained]
        assert "11:11:11:11:11:11" in macs
        assert "22:22:22:22:22:22" in macs
        assert 37 in channels
        assert 38 in channels

        manager.stop()
        assert manager.get_status()["running"] is False

    @patch("bluetooth_sniffle.extcap.topology.check_port_availability", return_value=(True, "Available"))
    @patch("bluetooth_sniffle.extcap.runner.TsharkExtcapRunner.is_running", return_value=True)
    @patch("bluetooth_sniffle.extcap.runner.TsharkExtcapRunner.start", return_value=True)
    def test_topology_b_single_channel_orchestration(
        self, mock_runner_start: MagicMock, mock_is_running: MagicMock, mock_check: MagicMock
    ) -> None:
        """Topology B should orchestrate a single radio, leaving secondary free."""
        queue = EventQueue(maxsize=100)
        manager = TsharkTopologyManager(event_queue=queue)

        started = manager.start_topology_b(port="/dev/ttyUSB0", chan=39)
        assert started is True
        status = manager.get_status()
        assert status["running"] is True
        assert status["topology"] == "Topology B"
        assert len(manager.runners) == 1

        pkt = json.dumps({
            "timestamp": "1790000020.000",
            "layers": {
                "frame": {"frame_frame_time_epoch": "1790000020.000"},
                "btle": {"btle_btle_advertising_address": "33:33:33:33:33:33"},
                "btle_rf": {"btle_rf_btle_rf_channel": "39", "btle_rf_btle_rf_signal_dbm": "-50"},
            },
        })
        manager.dispatch_line(port="/dev/ttyUSB0", line=pkt)

        assert queue.size() == 1
        obs = queue.drain_all()[0]
        assert obs["mac_address"] == "33:33:33:33:33:33"
        assert obs["channel"] == 39

        manager.stop()
        assert manager.get_status()["running"] is False
