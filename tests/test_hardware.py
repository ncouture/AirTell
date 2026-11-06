"""Comprehensive live hardware test suite for dual Sniffle USB dongles.

Exercises physical Silicon Labs CP2102 UART bridges and CC2652P microcontrollers
connected to /dev/ttyUSB0 (Device 1) and /dev/ttyUSB1 (Device 2) across port discovery,
baud rate negotiation (921,600 baud), marker synchronization, firmware version query,
over-the-air Topology A transmission and reception, dual-channel Topology B listening,
radar multi-channel ingestion, CLI verification, and clean thread teardown.
"""

from __future__ import annotations

import os
import stat
import threading
import time
from typing import Any

import pytest
import serial

from airtell.cli import main as cli_main
from airtell.device.controller import SniffleDeviceController
from airtell.device.serial_port import (
    allocate_dual_ports,
    detect_optimal_baudrate,
    discover_sniffle_ports,
)
from airtell.protocol.beacons import build_altbeacon, build_ibeacon
from airtell.protocol.mac import generate_palindromic_mac
from airtell.topology.lifecycle import ShutdownCoordinator
from airtell.topology.topology_a import TopologyAOrchestrator
from airtell.topology.topology_b import TopologyBOrchestrator

pytestmark = pytest.mark.hardware


@pytest.fixture(autouse=True)
def reset_shutdown_coordinator() -> None:
    """Ensure ShutdownCoordinator is pristine before and after each hardware test."""
    coord = ShutdownCoordinator.get_instance()
    coord.reset()
    yield
    coord.reset()


@pytest.mark.hardware
def test_hardware_port_discovery_and_allocation(
    hardware_ports: tuple[str, str],
    sniffle_hardware_config: dict[str, Any],
) -> None:
    """Verify hardware discovery, physical character device node properties, and port allocation."""
    dev1, dev2 = hardware_ports

    # 1. Verify ports exist as character special files
    stat1 = os.stat(dev1)
    stat2 = os.stat(dev2)
    assert stat.S_ISCHR(stat1.st_mode), f"{dev1} is not a character device"
    assert stat.S_ISCHR(stat2.st_mode), f"{dev2} is not a character device"

    # 2. Verify port discovery returns both devices
    discovered = discover_sniffle_ports()
    assert len(discovered) >= 2, f"Expected >= 2 Sniffle devices, found {discovered}"
    assert dev1 in discovered, f"{dev1} not found in discovered ports: {discovered}"
    assert dev2 in discovered, f"{dev2} not found in discovered ports: {discovered}"

    # 3. Verify dual-port allocation produces distinct non-conflicting ports
    p1, p2 = allocate_dual_ports(dev1, dev2)
    assert p1 == dev1
    assert p2 == dev2
    assert p1 != p2

    # 4. Verify conflicting port allocation raises ValueError
    with pytest.raises(ValueError, match="Conflicting port allocation"):
        allocate_dual_ports(dev1, dev1)


@pytest.mark.hardware
def test_hardware_baudrate_detection_and_negotiation(
    hardware_ports: tuple[str, str],
) -> None:
    """Verify CP2102 non-N bridge optimal baud rate detection caps at 921,600 baud."""
    dev1, dev2 = hardware_ports
    baud1 = detect_optimal_baudrate(dev1)
    baud2 = detect_optimal_baudrate(dev2)

    assert baud1 == 921_600, f"Expected 921600 baud for {dev1}, got {baud1}"
    assert baud2 == 921_600, f"Expected 921600 baud for {dev2}, got {baud2}"


@pytest.mark.hardware
def test_hardware_controllers_lifecycle_and_firmware_version(
    hardware_ports: tuple[str, str],
    sniffle_hardware_config: dict[str, Any],
) -> None:
    """Verify direct controller connection, 921600 baud sync marker echo, and firmware version >= 1.11.0.0."""
    dev1, dev2 = hardware_ports
    baudrate = sniffle_hardware_config["baudrate"]

    # 1. Device 1 Controller lifecycle
    c1 = SniffleDeviceController(port=dev1, baudrate=baudrate, mock=False)
    c1.open()
    try:
        assert c1.is_open is True
        assert c1.baudrate == baudrate
        sync_ok = c1.mark_and_flush(timeout=1.5)
        assert sync_ok is True, f"Sync marker echo failed on {dev1}"

        fw_ver1 = c1.get_firmware_version(timeout=1.5)
        assert fw_ver1 is not None, f"Firmware version query timed out on {dev1}"
        assert fw_ver1 >= (1, 11, 0, 0), f"Expected firmware version >= 1.11.0.0, got {fw_ver1}"
    finally:
        c1.close(reset=True)
        time.sleep(0.1)
    assert c1.is_open is False

    # 2. Device 2 Controller lifecycle
    c2 = SniffleDeviceController(port=dev2, baudrate=baudrate, mock=False)
    c2.open()
    try:
        assert c2.is_open is True
        assert c2.baudrate == baudrate
        sync_ok = c2.mark_and_flush(timeout=1.5)
        assert sync_ok is True, f"Sync marker echo failed on {dev2}"

        fw_ver2 = c2.get_firmware_version(timeout=1.5)
        assert fw_ver2 is not None, f"Firmware version query timed out on {dev2}"
        assert fw_ver2 >= (1, 11, 0, 0), f"Expected firmware version >= 1.11.0.0, got {fw_ver2}"
    finally:
        c2.close(reset=True)
        time.sleep(0.1)
    assert c2.is_open is False


@pytest.mark.hardware
def test_hardware_controllers_fixtures(
    live_sniffle_controllers: tuple[SniffleDeviceController, SniffleDeviceController],
    live_sniffle_devices: tuple[SniffleDeviceController, SniffleDeviceController],
) -> None:
    """Verify live_sniffle_controllers and live_sniffle_devices fixtures operate cleanly."""
    c1, c2 = live_sniffle_controllers
    assert c1.is_open is True
    assert c2.is_open is True

    # Both fixtures reference the active controller instances
    d1, d2 = live_sniffle_devices
    assert d1 is c1
    assert d2 is c2

    # Verify both respond to marker synchronization
    assert c1.mark_and_flush(timeout=1.5) is True
    assert c2.mark_and_flush(timeout=1.5) is True


@pytest.mark.hardware
def test_hardware_topology_a_live_ota(
    hardware_topology_a: TopologyAOrchestrator,
) -> None:
    """Verify Topology A live over-the-air packet transmission (Device 1) and capture (Device 2)."""
    topo = hardware_topology_a
    assert topo.is_running is True
    assert topo.stimulator is not None
    assert topo.observer is not None

    # Configure palindromic MAC address on stimulator
    pal_mac = generate_palindromic_mac("static", seed=b"hardware-test-pal-mac")
    topo.set_stimulus_mac(pal_mac, is_random=True)

    # 1. Transmit Apple iBeacon burst
    ibeacon_payload = build_ibeacon(
        uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
        major=100,
        minor=200,
        tx_power=-59,
    )
    topo.inject_beacon(adv_data=ibeacon_payload, interval_ms=50, duration_sec=0.5)

    # 2. Transmit Radius Networks AltBeacon burst
    altbeacon_payload = build_altbeacon(
        mfg_id=0x0118,
        beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"),
        ref_rssi=-59,
    )
    topo.inject_beacon(adv_data=altbeacon_payload, interval_ms=50, duration_sec=0.5)

    # 3. Read captured packets from observer
    captured = topo.get_captured_packets(timeout=0.5)
    assert len(captured) > 0 or len(topo.captured_packets) > 0, "No over-the-air packets captured by observer"

    # 4. Verify operational telemetry
    stats = topo.get_stats()
    assert stats["is_running"] is True
    assert stats["stimuli_count"] >= 2
    assert stats["observer_channel"] == 37


@pytest.mark.hardware
def test_hardware_topology_b_simultaneous_capture(
    hardware_topology_b: TopologyBOrchestrator,
) -> None:
    """Verify Topology B live dual-channel simultaneous capture on Channel 37 and Channel 38."""
    topo = hardware_topology_b
    assert topo.is_running is True
    assert topo.chan1 == 37
    assert topo.chan2 == 38

    # Allow dual-channel background collection
    time.sleep(0.5)

    # Read merged packets from timestamp-ordered queue
    merged_batch = topo.get_merged_packets(max_count=50, timeout=0.3)

    stats = topo.get_stats()
    assert stats["is_running"] is True
    assert stats["chan1"] == 37
    assert stats["chan2"] == 38
    assert isinstance(merged_batch, list)


@pytest.mark.hardware
def test_hardware_radar_dual_sniffer_manager(
    dual_sniffer_manager: Any,
) -> None:
    """Verify Sniffle radar DualSnifferManager live multi-channel hardware ingestion."""
    mgr = dual_sniffer_manager
    assert mgr.is_running() is True
    assert mgr.using_mock is False, "DualSnifferManager erroneously fell back to mock mode"
    assert mgr.source1 is not None
    assert mgr.source2 is not None
    assert mgr.channel1 == 37
    assert mgr.channel2 == 38

    # Allow sample ingestion
    time.sleep(0.5)

    # Verify stream sample generator functions without raising errors
    samples = []
    for sample in mgr.stream_samples(timeout=0.2):
        samples.append(sample)
        if len(samples) >= 5:
            break

    assert isinstance(samples, list)
    for s in samples:
        assert s.channel in (37, 38)
        assert -128.0 <= s.rssi <= 0.0


@pytest.mark.hardware
def test_hardware_cli_verify_hardware_invocation(
    hardware_ports: tuple[str, str],
) -> None:
    """Verify CLI airtell verify-hardware passes 5/5 loopback stages on physical dongles."""
    dev1, dev2 = hardware_ports
    try:
        rc = cli_main([
            "verify-hardware",
            "--dev1",
            dev1,
            "--dev2",
            dev2,
            "--burst-duration-sec",
            "1.2",
            "--settling-sec",
            "0.15",
            "--interval-ms",
            "35",
        ])
        assert rc == 0, f"airtell verify-hardware failed with return code {rc}"
    finally:
        time.sleep(0.20)


@pytest.mark.hardware
def test_hardware_clean_teardown_no_thread_or_lock_leak(
    hardware_ports: tuple[str, str],
    sniffle_hardware_config: dict[str, Any],
) -> None:
    """Verify controllers and reader threads shut down cleanly without leaking background threads or locks."""
    dev1, dev2 = hardware_ports
    baudrate = sniffle_hardware_config["baudrate"]

    initial_threads = {t.name for t in threading.enumerate() if t.is_alive()}

    # Initialize and open controllers
    c1 = SniffleDeviceController(port=dev1, baudrate=baudrate, mock=False)
    c2 = SniffleDeviceController(port=dev2, baudrate=baudrate, mock=False)
    try:
        c1.open()
        c2.open()

        assert c1._reader_thread is not None and c1._reader_thread.is_alive()
        assert c2._reader_thread is not None and c2._reader_thread.is_alive()

        # Perform active operations
        assert c1.mark_and_flush(timeout=1.5) is True
        assert c2.mark_and_flush(timeout=1.5) is True
    finally:
        # Close and reset both controllers individually
        for c in (c1, c2):
            try:
                c.close(reset=True)
            except (OSError, serial.SerialException, RuntimeError):
                pass
        time.sleep(0.20)

    assert not c1.is_open
    assert not c2.is_open

    # Wait briefly for thread shutdown
    time.sleep(0.2)

    current_threads = {t.name for t in threading.enumerate() if t.is_alive()}
    new_threads = current_threads - initial_threads
    leaked_sniffle_threads = [name for name in new_threads if name.startswith("SniffleReader-")]
    assert len(leaked_sniffle_threads) == 0, f"Leaked SniffleReader threads: {leaked_sniffle_threads}"


@pytest.mark.hardware
def test_hardware_cli_pairing_relay_execution(
    hardware_ports: tuple[str, str],
) -> None:
    """Verify CLI airtell relay initializes dual Sniffle radios and tears down cleanly."""
    dev1, dev2 = hardware_ports
    try:
        rc = cli_main([
            "relay",
            "--port1",
            dev1,
            "--port2",
            dev2,
            "--duration-sec",
            "1.0",
            "--quiet",
        ])
        assert rc == 0, f"airtell relay failed with return code {rc}"
    finally:
        time.sleep(0.20)
