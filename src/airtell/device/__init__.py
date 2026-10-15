"""Device management, serial communication, and mock hardware emulation package."""

from airtell.device.controller import SniffleDeviceController
from airtell.device.mock import (
    DeviceRadioState,
    MockSerialInterface,
    VirtualRadioBus,
)
from airtell.device.serial_port import (
    DEFAULT_BAUDRATE,
    allocate_dual_ports,
    check_device_usage,
    detect_optimal_baudrate,
    discover_sniffle_ports,
    get_device_status,
    get_sniffle_devices_status,
    mark_and_flush,
    open_sniffle_serial,
)

__all__ = [
    "DEFAULT_BAUDRATE",
    "DeviceRadioState",
    "MockSerialInterface",
    "SniffleDeviceController",
    "VirtualRadioBus",
    "allocate_dual_ports",
    "check_device_usage",
    "detect_optimal_baudrate",
    "discover_sniffle_ports",
    "get_device_status",
    "get_sniffle_devices_status",
    "mark_and_flush",
    "open_sniffle_serial",
]

