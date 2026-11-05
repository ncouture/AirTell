"""
Unified Test Harness & Reference Oracle for BLE RSSI Radar E2E Suite.
Provides standard reference models, physics simulation, protocol mocks,
and bridges to the core radar package.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Ensure python_cli is on sys.path
_SNIFFLE_CLI = Path(__file__).resolve().parents[1]
if str(_SNIFFLE_CLI) not in sys.path:
    sys.path.insert(0, str(_SNIFFLE_CLI))

from sniffle.radar.capture import (
    DualSnifferManager,
    HardwareSniffleSource,
    LinkSample,
    MockSniffleSource,
    SnifflePacketSource,
    point_to_segment_distance,
)

try:
    from sniffle.errors import SniffleHWPacketError, UsageError
    from sniffle.packet_decoder import (
        AdvDirectIndMessage,
        AdvExtIndMessage,
        AdvIndMessage,
        AdvNonconnIndMessage,
        AdvScanIndMessage,
        PacketMessage,
        ScanRspMessage,
        str_mac,
    )
    from sniffle.sniffle_hw import SnifferMode, SniffleHW, make_sniffle_hw
except ImportError:
    make_sniffle_hw = None  # type: ignore
    SnifferMode = None  # type: ignore
    SniffleHW = None  # type: ignore
    PacketMessage = Any  # type: ignore
    AdvIndMessage = Any  # type: ignore
    AdvNonconnIndMessage = Any  # type: ignore
    ScanRspMessage = Any  # type: ignore
    AdvScanIndMessage = Any  # type: ignore
    AdvDirectIndMessage = Any  # type: ignore
    AdvExtIndMessage = Any  # type: ignore
    UsageError = Exception  # type: ignore
    SniffleHWPacketError = Exception  # type: ignore

    def str_mac(mac: bytes) -> str:
        return ":".join(["%02X" % b for b in reversed(mac)])


from radar_tomography import (
    RadarTomographyPipeline,
    build_cli_parser,
    parse_radar_args,
)
from sniffle.radar.anomaly import (
    LinkAnomalyVector,
    RobustAnomalyEngine,
    compute_wilson_hilferty,
)
from sniffle.radar.matrix import (
    AddressType,
    LinkRecord,
    LinkState,
    MxNLinkMatrixManager,
    NodeType,
    PublicDeviceManager,
    classify_ble_mac,
)
from sniffle.radar.tomography import (
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
)
from sniffle.radar.visualizer import (
    RadarFrameProcessor,
    RadarVisualizer,
    run_radar_pipeline,
    run_single_frame,
)


def create_synthetic_adv_packet(pdu_type: str, mac_bytes: bytes, data: bytes = b"\x02\x01\x06") -> Any:
    """
    Constructs a synthetic BLE advertising packet for testing MAC decoders.
    mac_bytes: 6 raw little-endian bytes.
    """
    pdu_map = {
        "ADV_IND": (0, AdvIndMessage),
        "ADV_DIRECT_IND": (1, AdvDirectIndMessage),
        "ADV_NONCONN_IND": (2, AdvNonconnIndMessage),
        "SCAN_RSP": (4, ScanRspMessage),
        "ADV_SCAN_IND": (6, AdvScanIndMessage),
        "ADV_EXT_IND": (7, AdvExtIndMessage),
    }

    pdu_id, cls_type = pdu_map.get(pdu_type, (0, AdvIndMessage))

    if pdu_type == "ADV_EXT_IND":
        body = bytes([7, 1]) + mac_bytes + data
    else:
        body = mac_bytes + data
    header = bytes([pdu_id, len(body)])
    raw_payload = header + body

    class MockPacketMessage:
        def __init__(self, payload: bytes):
            self.payload = payload
            self.body = payload
            self.rssi = -60
            self.channel = 37
            self.chan = 37
            self.ts = 0.0
            self.ts_epoch = 0.0
            self.aa = 0x8E89BED6
            self.phy = 0
            self.data_dir = 0
            self.crc_err = False
            self.event = 0
            self.crc_rev = 0

    pkt = MockPacketMessage(raw_payload)
    if cls_type is not Any:
        return cls_type(pkt)

    class MockDecodedMsg:
        def __init__(self, adva_bytes: bytes):
            self.AdvA = adva_bytes
            self.body = b"\x00\x00" + adva_bytes + data
            self.rssi = -60
            self.channel = 37

    return MockDecodedMsg(mac_bytes)


__all__ = [
    # Capture (M1)
    "LinkSample",
    "SnifflePacketSource",
    "HardwareSniffleSource",
    "MockSniffleSource",
    "DualSnifferManager",
    "point_to_segment_distance",
    "str_mac",
    # Matrix (M2)
    "NodeType",
    "AddressType",
    "classify_ble_mac",
    "LinkState",
    "LinkRecord",
    "MxNLinkMatrixManager",
    "PublicDeviceManager",
    # Anomaly (M3)
    "compute_wilson_hilferty",
    "RobustAnomalyEngine",
    "LinkAnomalyVector",
    # Tomography & Tracking (M4)
    "SpatialTomography2D",
    "TargetTracker",
    "TomographyResult",
    # Visualizer & Pipeline (M4)
    "RadarVisualizer",
    "RadarFrameProcessor",
    "run_single_frame",
    "run_radar_pipeline",
    "RadarTomographyPipeline",
    "build_cli_parser",
    "parse_radar_args",
    # Test Fixtures
    "create_synthetic_adv_packet",
]
