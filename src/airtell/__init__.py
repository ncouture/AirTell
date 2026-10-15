"""AirTell Testbed Framework

Dual-device Sniffle orchestration, active beacon synthesis, passive sniffing,
and protocol analysis for Bluetooth Low Energy tracking research (PoPETs 2025-0103).
"""

import sys

try:
    from airtell import scripts as _scripts

    sys.modules.setdefault("scripts", _scripts)
except ImportError:
    pass

from airtell.device import (
    MockSerialInterface,
    SniffleDeviceController,
    VirtualRadioBus,
)
from airtell.topology import (
    ShutdownCoordinator,
    TopologyAOrchestrator,
    TopologyBOrchestrator,
)

__version__ = "0.1.0"

__all__ = [
    "MockSerialInterface",
    "ShutdownCoordinator",
    "SniffleDeviceController",
    "TopologyAOrchestrator",
    "TopologyBOrchestrator",
    "VirtualRadioBus",
    "__version__",
]
