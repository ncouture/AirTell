"""Adversarial evaluation, identity deanonymization, and pairing relay testbeds."""

from __future__ import annotations

from airtell.adversarial.deanonymizer import (
    LinkabilityObservation,
    RotationDesyncAnalyzer,
    RotationDesyncEvent,
    StaticLeakageDetector,
    StaticLeakageResult,
    Trajectory,
    TrajectoryReconstructor,
)
from airtell.adversarial.relay import (
    DualDongleRelayEngine,
    PairingFailureCode,
    PairingHandshakeEvent,
    PairingRelayBridge,
    PairingSignature,
    RelayConfig,
    RelayedLinkLayerPacket,
    RelayMasterRunner,
    RelaySlaveRunner,
    SMPPairingState,
)
from airtell.adversarial.rogue_beacon import (
    AntiStalkingEvasionEvaluator,
    EvasionBenchmarkResult,
    RogueBeaconGenerator,
    SyntheticBeaconSpec,
    SyntheticPacket,
)

__all__ = [
    "AntiStalkingEvasionEvaluator",
    "DualDongleRelayEngine",
    "EvasionBenchmarkResult",
    "LinkabilityObservation",
    "PairingFailureCode",
    "PairingHandshakeEvent",
    "PairingRelayBridge",
    "PairingSignature",
    "RelayConfig",
    "RelayMasterRunner",
    "RelaySlaveRunner",
    "RelayedLinkLayerPacket",
    "RogueBeaconGenerator",
    "RotationDesyncAnalyzer",
    "RotationDesyncEvent",
    "SMPPairingState",
    "StaticLeakageDetector",
    "StaticLeakageResult",
    "SyntheticBeaconSpec",
    "SyntheticPacket",
    "Trajectory",
    "TrajectoryReconstructor",
]
