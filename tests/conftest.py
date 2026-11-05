"""Pytest configuration, CLI options, and shared fixtures for AirTell tests."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
import serial

# Ensure src/ and in-tree sniffle are on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
SNIFFLE_SRC_DIR = SRC_DIR / "sniffle" / "src"
if str(SNIFFLE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SNIFFLE_SRC_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from airtell.device.controller import SniffleDeviceController  # noqa: E402
from airtell.topology.topology_a import TopologyAOrchestrator  # noqa: E402
from airtell.topology.topology_b import TopologyBOrchestrator  # noqa: E402


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options for hardware-in-the-loop testing."""
    parser.addoption(
        "--hardware",
        "--live-hardware",
        action="store_true",
        default=False,
        help="Run tests requiring physical Sniffle USB dongles (/dev/ttyUSB0 and /dev/ttyUSB1).",
    )
    parser.addoption(
        "--dev1",
        action="store",
        default=os.getenv("SNIFFLE_DEV1", "/dev/ttyUSB0"),
        help="Serial device path for Device 1 (default: $SNIFFLE_DEV1 or /dev/ttyUSB0).",
    )
    parser.addoption(
        "--dev2",
        action="store",
        default=os.getenv("SNIFFLE_DEV2", "/dev/ttyUSB1"),
        help="Serial device path for Device 2 (default: $SNIFFLE_DEV2 or /dev/ttyUSB1).",
    )
    parser.addoption(
        "--sniffle-baud",
        "--baudrate",
        action="store",
        type=int,
        default=int(os.getenv("SNIFFLE_BAUDRATE", "921600")),
        help="Baud rate for physical Sniffle devices (default: $SNIFFLE_BAUDRATE or 921600).",
    )


def is_hardware_enabled(config: pytest.Config) -> bool:
    """Return True if hardware testing is enabled via CLI flag or environment variable."""
    if config.getoption("--hardware", default=False):
        return True
    env_val = os.getenv("SNIFFLE_HARDWARE", "").strip()
    return env_val in ("1", "true", "TRUE", "yes")


def pytest_configure(config: pytest.Config) -> None:
    """Register custom pytest markers."""
    config.addinivalue_line(
        "markers",
        "hardware: marks tests requiring physical Sniffle USB dongles (deselect with '-m \"not hardware\"')",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Automatically skip hardware tests when hardware testing is not enabled or devices are missing."""
    if not is_hardware_enabled(config):
        skip_marker = pytest.mark.skip(
            reason="Hardware tests require --hardware / --live-hardware or SNIFFLE_HARDWARE=1"
        )
        for item in items:
            if "hardware" in item.keywords:
                item.add_marker(skip_marker)
    else:
        dev1 = config.getoption("--dev1")
        dev2 = config.getoption("--dev2")
        if not (os.path.exists(dev1) and os.path.exists(dev2)):
            skip_marker = pytest.mark.skip(
                reason=f"Hardware devices missing: {dev1} or {dev2} not found"
            )
            for item in items:
                if "hardware" in item.keywords:
                    item.add_marker(skip_marker)


@pytest.fixture
def ground_truth_vectors() -> dict[str, str]:
    """Verified ground-truth packet vectors from explorer_survey_2/handoff.md."""
    return {
        "iBeacon": "0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5",
        "AltBeacon": "0201061bff1801beace2c56db5dffb48d2b060d0f5a71096e000010002c500",
        "Eddystone-UID": "0201060303aafe1716aafe00ec0102030405060708090a0102030405060000",
        "Eddystone-URL": "0201060303aafe1216aafe10ee036578616d706c650074657374",
        "Eddystone-TLM": "0201060303aafe1116aafe20000bb81480000003e800002710",
        "GAEN": "02011a03036ffd17166ffd0102030405060708090a0b0c0d0e0f1011223344",
        "Palindromic_MAC": "c011222211c0",
        "SCAN_REQ": "c30cc011222211c0c033444433c0",
        "SCAN_RSP": "4423c033444433c00a09506f504554732d30311107000102030405060708090a0b0c0d0e0f",
    }


@pytest.fixture(scope="session")
def sniffle_hardware_config(request: pytest.FixtureRequest) -> dict[str, Any]:
    """Resolved hardware configuration dictionary for physical Sniffle testing."""
    return {
        "dev1": request.config.getoption("--dev1"),
        "dev2": request.config.getoption("--dev2"),
        "baudrate": request.config.getoption("--sniffle-baud"),
    }


@pytest.fixture
def hardware_ports(sniffle_hardware_config: dict[str, Any]) -> tuple[str, str]:
    """Validated pair of serial ports for physical Sniffle devices."""
    dev1 = sniffle_hardware_config["dev1"]
    dev2 = sniffle_hardware_config["dev2"]
    if not (os.path.exists(dev1) and os.path.exists(dev2)):
        pytest.skip(f"Hardware ports not found: {dev1} or {dev2}")
    if dev1 == dev2:
        pytest.skip(f"Conflicting hardware ports: dev1 and dev2 both specify '{dev1}'")
    return dev1, dev2


@pytest.fixture(autouse=True)
def hardware_test_isolation(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Ensure settling delay and clean state before and after each hardware test."""
    if "hardware" in request.keywords and is_hardware_enabled(request.config):
        time.sleep(0.20)
        yield
        time.sleep(0.20)
    else:
        yield


@pytest.fixture
def live_sniffle_controllers(
    hardware_ports: tuple[str, str],
    sniffle_hardware_config: dict[str, Any],
) -> Generator[tuple[SniffleDeviceController, SniffleDeviceController], None, None]:
    """Yields connected and mark_and_flush synchronized controllers for dev1 and dev2."""
    dev1, dev2 = hardware_ports
    baudrate = sniffle_hardware_config["baudrate"]
    c1 = SniffleDeviceController(port=dev1, baudrate=baudrate, mock=False)
    c2 = SniffleDeviceController(port=dev2, baudrate=baudrate, mock=False)
    try:
        c1.open()
        c2.open()
        assert c1.mark_and_flush(timeout=1.5), f"Failed to sync controller on {dev1}"
        assert c2.mark_and_flush(timeout=1.5), f"Failed to sync controller on {dev2}"
        yield c1, c2
    finally:
        for c in (c1, c2):
            try:
                c.close(reset=True)
            except (OSError, serial.SerialException, RuntimeError):
                pass
        time.sleep(0.20)


@pytest.fixture
def live_sniffle_devices(
    live_sniffle_controllers: tuple[SniffleDeviceController, SniffleDeviceController],
) -> tuple[SniffleDeviceController, SniffleDeviceController]:
    """Convenience alias for live_sniffle_controllers."""
    return live_sniffle_controllers


@pytest.fixture
def hardware_topology_a(
    hardware_ports: tuple[str, str],
) -> Generator[TopologyAOrchestrator, None, None]:
    """Yields an active hardware-backed Topology A (Stimulator + Observer) orchestrator."""
    dev1, dev2 = hardware_ports
    orchestrator = TopologyAOrchestrator.create_hardware(port1=dev1, port2=dev2)
    orchestrator.start()
    try:
        if orchestrator.stimulator:
            assert orchestrator.stimulator.mark_and_flush(timeout=1.5), f"Failed to sync stimulator on {dev1}"
        assert orchestrator.observer.mark_and_flush(timeout=1.5), f"Failed to sync observer on {dev2}"
        yield orchestrator
    finally:
        try:
            orchestrator.stop(reset=True)
        except (OSError, serial.SerialException, RuntimeError):
            pass
        for c in (orchestrator.stimulator, orchestrator.observer):
            if c is not None and getattr(c, "is_open", False):
                try:
                    c.close(reset=True)
                except (OSError, serial.SerialException, RuntimeError):
                    pass
        time.sleep(0.20)


@pytest.fixture
def hardware_topology_b(
    hardware_ports: tuple[str, str],
) -> Generator[TopologyBOrchestrator, None, None]:
    """Yields an active hardware-backed Topology B (Dual-channel passive observer) orchestrator."""
    dev1, dev2 = hardware_ports
    orchestrator = TopologyBOrchestrator.create_hardware(port1=dev1, port2=dev2, chan1=37, chan2=38)
    orchestrator.start()
    try:
        assert orchestrator.device1.mark_and_flush(timeout=1.5), f"Failed to sync device1 on {dev1}"
        assert orchestrator.device2.mark_and_flush(timeout=1.5), f"Failed to sync device2 on {dev2}"
        yield orchestrator
    finally:
        try:
            orchestrator.stop(reset=True)
        except (OSError, serial.SerialException, RuntimeError):
            pass
        for c in (orchestrator.device1, orchestrator.device2):
            if c is not None and getattr(c, "is_open", False):
                try:
                    c.close(reset=True)
                except (OSError, serial.SerialException, RuntimeError):
                    pass
        time.sleep(0.20)


@pytest.fixture
def dual_sniffer_manager(
    hardware_ports: tuple[str, str],
    sniffle_hardware_config: dict[str, Any],
) -> Generator[Any, None, None]:
    """Yields a live hardware-backed DualSnifferManager instance."""
    from sniffle.radar.capture import DualSnifferManager

    dev1, dev2 = hardware_ports
    baudrate = sniffle_hardware_config["baudrate"]
    mgr = DualSnifferManager(
        port1=dev1,
        port2=dev2,
        baudrate=baudrate,
        simulate=False,
        fallback_to_mock=False,
        channel1=37,
        channel2=38,
    )
    mgr.start()
    try:
        yield mgr
    finally:
        for src in (getattr(mgr, "source1", None), getattr(mgr, "source2", None)):
            if src is not None and getattr(src, "hw", None) is not None:
                try:
                    src.hw.cmd_reset()
                except (OSError, serial.SerialException, RuntimeError):
                    pass
        try:
            mgr.stop()
        except (OSError, serial.SerialException, RuntimeError):
            pass
        time.sleep(0.20)
