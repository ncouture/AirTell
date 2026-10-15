"""Unit and integration tests for Sniffle device usage validation via lsof."""

from __future__ import annotations

import subprocess
import tempfile
from unittest.mock import MagicMock, patch

from airtell.device.serial_port import (
    check_device_usage,
    get_device_status,
    get_sniffle_devices_status,
)
from app.components.navigation import get_top_app_bar_html


def test_check_device_usage_in_use() -> None:
    """Validate that return code 0 indicates device is open and being used."""
    mock_res = MagicMock()
    mock_res.returncode = 0

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        assert check_device_usage("/dev/ttyUSB0") is True
        mock_run.assert_called_once_with(
            ["lsof", "/dev/ttyUSB0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )


def test_check_device_usage_not_in_use() -> None:
    """Validate that non-zero return code indicates device is not open / not in use."""
    for code in [1, 2, 127, 255]:
        mock_res = MagicMock()
        mock_res.returncode = code

        with patch("subprocess.run", return_value=mock_res):
            assert check_device_usage("/dev/ttyUSB1") is False


def test_check_device_usage_exception_handling() -> None:
    """Validate graceful error handling when lsof encounters exceptions."""
    for exc in [
        FileNotFoundError("lsof not found"),
        PermissionError("Permission denied"),
        subprocess.TimeoutExpired(cmd=["lsof"], timeout=2.0),
        OSError("OS error"),
    ]:
        with patch("subprocess.run", side_effect=exc):
            assert check_device_usage("/dev/ttyUSB0") is False


def test_check_device_usage_real_lsof_invocation() -> None:
    """Test actual lsof system execution against open and closed filesystem descriptors."""
    with tempfile.NamedTemporaryFile() as temp_f:
        # File is currently open by this process
        assert check_device_usage(temp_f.name) is True

    # File is now closed and deleted
    assert check_device_usage(temp_f.name) is False


def test_get_device_status_formatting() -> None:
    """Validate get_device_status returns proper dictionary schema."""
    with patch("airtell.device.serial_port.check_device_usage", return_value=True):
        status = get_device_status("/dev/ttyUSB0")
        assert status["device"] == "/dev/ttyUSB0"
        assert status["in_use"] is True
        assert status["status"] == "IN USE"
        assert "/dev/ttyUSB0: IN USE" in status["label"]

    with patch("airtell.device.serial_port.check_device_usage", return_value=False):
        status = get_device_status("/dev/ttyUSB1")
        assert status["device"] == "/dev/ttyUSB1"
        assert status["in_use"] is False
        assert status["status"] == "IDLE"
        assert "/dev/ttyUSB1: IDLE" in status["label"]


def test_get_sniffle_devices_status() -> None:
    """Validate get_sniffle_devices_status across default and custom port lists."""
    with patch(
        "airtell.device.serial_port.check_device_usage",
        side_effect=lambda dev: dev == "/dev/ttyUSB0",
    ):
        statuses = get_sniffle_devices_status()
        assert len(statuses) == 2
        assert statuses[0]["device"] == "/dev/ttyUSB0"
        assert statuses[0]["in_use"] is True
        assert statuses[1]["device"] == "/dev/ttyUSB1"
        assert statuses[1]["in_use"] is False

        # Custom ports
        custom = get_sniffle_devices_status(["/dev/ttyACM0"])
        assert len(custom) == 1
        assert custom[0]["device"] == "/dev/ttyACM0"
        assert custom[0]["in_use"] is False


def test_top_app_bar_device_status_styling() -> None:
    """Validate top app bar dot classes reflect in-use and idle states."""
    # Active state
    html_active = get_top_app_bar_html(
        dongle1_status="/dev/ttyUSB0: IN USE",
        dongle2_status="/dev/ttyUSB1: IN USE",
        dongle1_active=True,
        dongle2_active=True,
    )
    assert "m3-status-dot" in html_active
    assert "m3-status-dot-idle" not in html_active

    # Idle state
    html_idle = get_top_app_bar_html(
        dongle1_status="/dev/ttyUSB0: IDLE",
        dongle2_status="/dev/ttyUSB1: IDLE",
    )
    assert "m3-status-dot-idle" in html_idle
    assert "/dev/ttyUSB0: IDLE" in html_idle
    assert "/dev/ttyUSB1: IDLE" in html_idle


def test_check_device_usage_none_and_empty() -> None:
    """Validate that None, empty string, or whitespace string safely return False without error."""
    assert check_device_usage(None) is False
    assert check_device_usage("") is False
    assert check_device_usage("   ") is False


def test_check_device_usage_whitespace_stripping() -> None:
    """Validate that whitespace around device paths is stripped before invoking lsof."""
    mock_res = MagicMock()
    mock_res.returncode = 0

    with patch("subprocess.run", return_value=mock_res) as mock_run:
        assert check_device_usage("  /dev/ttyUSB0  ") is True
        mock_run.assert_called_once_with(
            ["lsof", "/dev/ttyUSB0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )


def test_get_device_status_none_input() -> None:
    """Validate get_device_status with None defaults safely to /dev/ttyUSB0."""
    with patch("airtell.device.serial_port.check_device_usage", return_value=False):
        status = get_device_status(None)
        assert status["device"] == "/dev/ttyUSB0"
        assert status["in_use"] is False
        assert status["status"] == "IDLE"

