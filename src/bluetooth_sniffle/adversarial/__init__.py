"""Adversarial evaluation, identity deanonymization, and pairing relay testbeds."""

from __future__ import annotations

from bluetooth_sniffle.adversarial.deanonymizer import (
    LinkabilityObservation,
    RotationDesyncAnalyzer,
    RotationDesyncEvent,
    StaticLeakageDetector,
    StaticLeakageResult,
    Trajectory,
    TrajectoryReconstructor,
)
from bluetooth_sniffle.adversarial.relay import (
    PairingFailureCode,
    PairingHandshakeEvent,
    PairingRelayBridge,
    PairingSignature,
    RelayedLinkLayerPacket,
    SMPPairingState,
)
from bluetooth_sniffle.adversarial.rogue_beacon import (
    AntiStalkingEvasionEvaluator,
    EvasionBenchmarkResult,
    RogueBeaconGenerator,
    SyntheticBeaconSpec,
    SyntheticPacket,
)

__all__ = [
    "AntiStalkingEvasionEvaluator",
    "EvasionBenchmarkResult",
    "LinkabilityObservation",
    "PairingFailureCode",
    "PairingHandshakeEvent",
    "PairingRelayBridge",
    "PairingSignature",
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
