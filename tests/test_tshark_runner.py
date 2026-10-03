"""Unit tests for Tshark Extcap Runner and configuration command construction."""

from __future__ import annotations

import signal
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from bluetooth_sniffle.extcap.runner import (
    TsharkConfig,
    TsharkExtcapRunner,
)


class TestTsharkConfig:
    """Tests covering TsharkConfig command generation and extcap option formatting."""

    def test_default_config_args(self) -> None:
        """Default configuration should output minimal expected arguments."""
        config = TsharkConfig(serport="/dev/ttyUSB0")
        args = config.to_command_args(tshark_bin="tshark")

        assert args[0] == "tshark"
        assert "-i" in args
        idx_i = args.index("-i")
        assert args[idx_i + 1] == "sniffle"

        # Check default extcap overrides
        assert "-o" in args
        assert "extcap.sniffle.serport:/dev/ttyUSB0" in args
        assert "extcap.sniffle.mode:passive_scan" in args
        assert "extcap.sniffle.advchan:37" in args

        # Default output format and buffering
        assert "-T" in args
        idx_t = args.index("-T")
        assert args[idx_t + 1] == "ek"
        assert "-l" in args
        assert "-Y" in args
        idx_y = args.index("-Y")
        assert args[idx_y + 1] == "btle.advertising_address"

    def test_comprehensive_extcap_parameters(self) -> None:
        """All extcap options should be formatted according to Sniffle parameter specification."""
        config = TsharkConfig(
            serport="/dev/ttyUSB1",
            mode="active_scan",
            advchan=38,
            rssi=-75,
            mac="AA:BB:CC:DD:EE:FF",
            irk="00112233445566778899aabbccddeeff",
            string="FindMy",
            extadv=True,
            longrange=True,
            crcerr=True,
            display_filter="btle",
            output_format="json",
            line_buffered=True,
        )
        args = config.to_command_args()

        assert "extcap.sniffle.serport:/dev/ttyUSB1" in args
        assert "extcap.sniffle.mode:active_scan" in args
        assert "extcap.sniffle.advchan:38" in args
        assert "extcap.sniffle.rssi:-75" in args
        assert "extcap.sniffle.mac:AA:BB:CC:DD:EE:FF" in args
        assert "extcap.sniffle.irk:00112233445566778899aabbccddeeff" in args
        assert "extcap.sniffle.string:FindMy" in args
        assert "extcap.sniffle.extadv:true" in args
        assert "extcap.sniffle.longrange:true" in args
        assert "extcap.sniffle.crcerr:true" in args

        idx_t = args.index("-T")
        assert args[idx_t + 1] == "json"
        idx_y = args.index("-Y")
        assert args[idx_y + 1] == "btle"

    def test_boolean_flags_false_omitted(self) -> None:
        """When boolean flags are false, they should not be asserted as true."""
        config = TsharkConfig(
            serport="/dev/ttyUSB0",
            extadv=False,
            longrange=False,
            crcerr=False,
        )
        args = config.to_command_args()
        assert "extcap.sniffle.extadv:true" not in args
        assert "extcap.sniffle.longrange:true" not in args
        assert "extcap.sniffle.crcerr:true" not in args

    def test_custom_extra_arguments(self) -> None:
        """Additional command arguments should append cleanly."""
        config = TsharkConfig(
            serport="/dev/ttyUSB0",
            extra_args=["-N", "m", "-c", "100"],
        )
        args = config.to_command_args()
        assert "-N" in args
        assert "m" in args
        assert "-c" in args
        assert "100" in args

    def test_to_shell_command_string(self) -> None:
        """String representation of command should properly quote options for debugging."""
        config = TsharkConfig(serport="/dev/ttyUSB0", rssi=-80)
        cmd_str = config.to_shell_command()
        assert "tshark -i sniffle" in cmd_str
        assert '-o "extcap.sniffle.serport:/dev/ttyUSB0"' in cmd_str
        assert '-o "extcap.sniffle.rssi:-80"' in cmd_str


class TestTsharkExtcapRunner:
    """Tests covering TsharkExtcapRunner process lifecycle, streams, and ring buffer."""

    def test_ring_buffer_overflow_protection(self) -> None:
        """Ring buffer should enforce maxlen and discard oldest items without error."""
        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config, ring_buffer_size=5)

        # Emulate receiving 8 lines
        for i in range(8):
            runner._ingest_line(f"line_{i}\n")

        assert len(runner.ring_buffer) == 5
        # The oldest items (line_0, line_1, line_2) should have rolled off
        assert list(runner.ring_buffer) == ["line_3", "line_4", "line_5", "line_6", "line_7"]

    def test_drain_lines(self) -> None:
        """Draining lines should retrieve and clear lines up to max_count."""
        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config, ring_buffer_size=10)

        for i in range(5):
            runner._ingest_line(f"msg_{i}")

        batch = runner.drain_lines(max_count=3)
        assert batch == ["msg_0", "msg_1", "msg_2"]
        assert list(runner.ring_buffer) == ["msg_3", "msg_4"]

        remaining = runner.drain_lines()
        assert remaining == ["msg_3", "msg_4"]
        assert len(runner.ring_buffer) == 0

    @patch("subprocess.Popen")
    def test_process_start_and_stdout_worker(self, mock_popen: MagicMock) -> None:
        """Runner start should launch process and stream stdout lines into ring buffer."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345
        mock_proc.stdout = iter(["line1\n", "line2\n", "line3\n"])
        mock_proc.stderr = iter([])
        mock_popen.return_value = mock_proc

        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config, ring_buffer_size=100)

        started = runner.start()
        assert started is True
        assert runner.is_running() is True
        assert runner.pid == 12345

        # Give background thread brief moment to consume lines
        time.sleep(0.05)

        lines = runner.drain_lines()
        assert "line1" in lines
        assert "line2" in lines
        assert "line3" in lines

        metrics = runner.get_metrics()
        assert metrics["lines_read"] >= 3
        assert metrics["pid"] == 12345

        runner.stop()

    @patch("subprocess.Popen")
    def test_graceful_shutdown_sigterm(self, mock_popen: MagicMock) -> None:
        """Stopping runner should first attempt SIGTERM and wait for exit."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process is running
        mock_proc.pid = 23456
        mock_proc.stdout = iter([])
        mock_proc.stderr = iter([])
        def fake_wait(timeout: float | None = None) -> int:
            mock_proc.poll.return_value = 0
            return 0
        mock_proc.wait.side_effect = fake_wait
        mock_popen.return_value = mock_proc

        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config)
        runner.start()
        assert runner.is_running() is True

        stopped = runner.stop(timeout=0.5)
        assert stopped is True
        assert runner.is_running() is False
        mock_proc.send_signal.assert_called_with(signal.SIGTERM)
        mock_proc.kill.assert_not_called()

    @patch("subprocess.Popen")
    def test_escalated_shutdown_sigkill_on_timeout(self, mock_popen: MagicMock) -> None:
        """If SIGTERM fails within timeout, runner should escalate to SIGKILL."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process refuses to terminate
        mock_proc.pid = 34567
        mock_proc.stdout = iter([])
        mock_proc.stderr = iter([])
        call_count = 0
        def fake_wait(timeout: float | None = None) -> int:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise subprocess.TimeoutExpired(cmd="tshark", timeout=0.1)
            mock_proc.poll.return_value = 0
            return 0
        mock_proc.wait.side_effect = fake_wait
        mock_popen.return_value = mock_proc

        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config)
        runner.start()

        stopped = runner.stop(timeout=0.05)
        assert stopped is True
        assert runner.is_running() is False
        mock_proc.send_signal.assert_called_with(signal.SIGTERM)
        mock_proc.kill.assert_called_once()

    @patch("subprocess.Popen")
    def test_context_manager_lifecycle(self, mock_popen: MagicMock) -> None:
        """Runner used as a context manager should start on enter and stop on exit."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 45678
        mock_proc.stdout = iter([])
        mock_proc.stderr = iter([])
        def fake_wait(timeout: float | None = None) -> int:
            mock_proc.poll.return_value = 0
            return 0
        mock_proc.wait.side_effect = fake_wait
        mock_popen.return_value = mock_proc

        config = TsharkConfig(serport="/dev/ttyUSB0")
        with TsharkExtcapRunner(config=config) as runner:
            assert runner.is_running() is True
        assert runner.is_running() is False

    @patch("subprocess.Popen")
    def test_start_already_running_returns_false(self, mock_popen: MagicMock) -> None:
        """Calling start() on an already-running runner should safely return False."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 56789
        mock_proc.stdout = iter([])
        mock_proc.stderr = iter([])
        mock_popen.return_value = mock_proc

        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config)
        assert runner.start() is True
        assert runner.start() is False
        runner.stop()

    def test_start_missing_binary_raises_or_returns_false(self) -> None:
        """Starting with a non-existent binary should raise FileNotFoundError or handle gracefully."""
        config = TsharkConfig(serport="/dev/ttyUSB0")
        runner = TsharkExtcapRunner(config=config, tshark_bin="/usr/bin/nonexistent_tshark_binary_xyz")
        with pytest.raises(FileNotFoundError):
            runner.start()
        assert runner.is_running() is False
