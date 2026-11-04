"""
Sniffle Radar Package - Passive BLE Human Sensing & Radio Tomographic Imaging Engine
"""

from .anomaly import (
    LinkAnomalyVector,
    RobustAnomalyEngine,
    compute_wilson_hilferty,
)
from .baseline import BaselineTracker
from .capture import (
    DualSnifferManager,
    HardwareSniffleSource,
    LinkSample,
    MockSniffleSource,
    SnifflePacketSource,
    point_to_segment_distance,
)
from .demuxer import StreamDemuxer
from .features import FeatureExtractor
from .localization import estimate_position
from .matrix import (
    AddressType,
    LinkRecord,
    LinkState,
    MxNLinkMatrixManager,
    PublicDeviceManager,
    classify_ble_mac,
)
from .models import LinkFeatures, Node, NodeType, RFLink
from .tomography import (
    LinkTomographyGrid,
    SpatialTomography2D,
    TargetTracker,
    TomographyResult,
)
from .tracker import AlphaBetaTracker
from .visualizer import (
    RadarFrameProcessor,
    RadarVisualizer,
    run_radar_pipeline,
    run_single_frame,
)

__all__ = [
    # Ingestion & Capture
    "LinkSample",
    "SnifflePacketSource",
    "HardwareSniffleSource",
    "MockSniffleSource",
    "DualSnifferManager",
    "point_to_segment_distance",

    # Matrix & Lifecycle
    "NodeType",
    "AddressType",
    "classify_ble_mac",
    "LinkState",
    "LinkRecord",
    "MxNLinkMatrixManager",
    "PublicDeviceManager",

    # Anomaly Engine
    "compute_wilson_hilferty",
    "LinkAnomalyVector",
    "RobustAnomalyEngine",

    # Tomography & Tracking
    "TomographyResult",
    "SpatialTomography2D",
    "TargetTracker",
    "LinkTomographyGrid",

    # Visualization & Runner
    "RadarVisualizer",
    "RadarFrameProcessor",
    "run_single_frame",

    # Legacy models & helpers
    "Node",
    "RFLink",
    "LinkFeatures",
    "BaselineTracker",
    "FeatureExtractor",
    "estimate_position",
    "AlphaBetaTracker",
    "StreamDemuxer",
    "run_radar_pipeline",
]
