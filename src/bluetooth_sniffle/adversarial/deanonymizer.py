"""Rotating identifier deanonymization, static leakage detection, and rotation desynchronization analysis."""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LinkabilityObservation:
    """Individual advertising observation for linkability and identity correlation.

    Attributes:
        mac_address: Colon-separated Bluetooth MAC address (e.g., 'AA:BB:CC:DD:EE:FF').
        mac_type: Address type ('Public', 'Static', 'NRPA', 'RPA').
        ephemeral_key: Hex string of isolated ephemeral public key or payload fragment.
        timestamp: Monotonic epoch timestamp in seconds.
        rssi: Received signal strength indicator in dBm.
        network_type: Identified tracking network ('Apple Find My', 'Google Find Hub', etc.).
    """

    mac_address: str
    mac_type: str = "RPA"
    ephemeral_key: str = ""
    timestamp: float = 0.0
    rssi: int = -70
    network_type: str = "Unknown"


@dataclass
class StaticLeakageResult:
    """Result of static identifier leakage analysis.

    Attributes:
        has_static_leakage: True if a non-rotating or persistent identifier is detected.
        leakage_category: Category ('STATIC_MAC', 'CONSTANT_OUI', 'NONE').
        reason: Explanation of the leakage finding.
        has_constant_oui: True if multiple randomized addresses share a static OUI prefix.
        oui_prefix: Extracted 24-bit OUI vendor prefix (e.g. 'F0:F5:BD').
    """

    has_static_leakage: bool = False
    leakage_category: str = "NONE"
    reason: str = ""
    has_constant_oui: bool = False
    oui_prefix: str = ""


class StaticLeakageDetector:
    """Detects static MAC leakage and constant OUI vendor prefixes across rotating tags."""

    def __init__(self) -> None:
        self._oui_history: dict[str, set[str]] = collections.defaultdict(set)
        self._key_to_macs: dict[str, set[str]] = collections.defaultdict(set)

    def analyze(self, obs: LinkabilityObservation) -> StaticLeakageResult:
        """Analyze an observation for static MAC or constant prefix leakage.

        Args:
            obs: LinkabilityObservation record.

        Returns:
            StaticLeakageResult with leakage classifications.
        """
        mac = obs.mac_address.upper()
        mac_type = obs.mac_type.capitalize()
        oui = ":".join(mac.split(":")[:3]) if len(mac.split(":")) >= 3 else ""

        # Check 1: Non-randomized MAC address used with tracking network payloads
        if mac_type in ("Public", "Static") and obs.ephemeral_key:
            return StaticLeakageResult(
                has_static_leakage=True,
                leakage_category="STATIC_MAC",
                reason=f"Public/Static MAC address ({mac}) in use with rotating tracking key.",
            )

        # Track OUI vendor prefixes across distinct RPAs
        if oui:
            self._oui_history[oui].add(mac)
            if len(self._oui_history[oui]) >= 3:
                return StaticLeakageResult(
                    has_static_leakage=True,
                    leakage_category="CONSTANT_OUI",
                    reason=f"Constant 24-bit OUI prefix ({oui}) observed across {len(self._oui_history[oui])} addresses.",
                    has_constant_oui=True,
                    oui_prefix=oui,
                )

        return StaticLeakageResult(has_static_leakage=False)


@dataclass
class RotationDesyncEvent:
    """Event representing desynchronized rotation between Link Layer MAC and payload.

    Attributes:
        desync_type: 'MAC_ROTATED_KEY_PERSISTED' or 'KEY_ROTATED_MAC_PERSISTED'.
        delta_seconds: Elapsed duration in seconds during desynchronization.
        is_linkable: True if the desynchronization creates an explicit identity link.
        previous_mac: Prior observed MAC address.
        current_mac: Current observed MAC address.
        previous_key: Prior observed payload key.
        current_key: Current observed payload key.
        timestamp: Timestamp of the transition event.
    """

    desync_type: str
    delta_seconds: float
    is_linkable: bool
    previous_mac: str
    current_mac: str
    previous_key: str
    current_key: str
    timestamp: float


class RotationDesyncAnalyzer:
    """Analyzes timing divergence between Link Layer AdvA rotation and payload key rotation."""

    def __init__(self) -> None:
        self._last_obs_by_key: dict[str, LinkabilityObservation] = {}
        self._last_obs_by_mac: dict[str, LinkabilityObservation] = {}

    def feed(self, obs: LinkabilityObservation) -> Optional[RotationDesyncEvent]:
        """Feed a new observation and check for rotation desynchronization.

        Args:
            obs: LinkabilityObservation record.

        Returns:
            RotationDesyncEvent if a desynchronization condition is met, else None.
        """
        mac = obs.mac_address.upper()
        key = obs.ephemeral_key

        event: Optional[RotationDesyncEvent] = None

        # Case 1: Key was previously seen with a DIFFERENT MAC address (MAC rotated, key persisted)
        if key and key in self._last_obs_by_key:
            prev_obs = self._last_obs_by_key[key]
            if prev_obs.mac_address != mac:
                delta = abs(obs.timestamp - prev_obs.timestamp)
                event = RotationDesyncEvent(
                    desync_type="MAC_ROTATED_KEY_PERSISTED",
                    delta_seconds=delta,
                    is_linkable=True,
                    previous_mac=prev_obs.mac_address,
                    current_mac=mac,
                    previous_key=key,
                    current_key=key,
                    timestamp=obs.timestamp,
                )

        # Case 2: MAC was previously seen with a DIFFERENT Key (Key rotated, MAC persisted)
        if not event and mac in self._last_obs_by_mac:
            prev_obs = self._last_obs_by_mac[mac]
            if key and prev_obs.ephemeral_key and prev_obs.ephemeral_key != key:
                delta = abs(obs.timestamp - prev_obs.timestamp)
                event = RotationDesyncEvent(
                    desync_type="KEY_ROTATED_MAC_PERSISTED",
                    delta_seconds=delta,
                    is_linkable=True,
                    previous_mac=mac,
                    current_mac=mac,
                    previous_key=prev_obs.ephemeral_key,
                    current_key=key,
                    timestamp=obs.timestamp,
                )

        # Update cache
        if key:
            self._last_obs_by_key[key] = obs
        self._last_obs_by_mac[mac] = obs

        return event


@dataclass
class Trajectory:
    """Reconstructed physical/temporal trajectory across rotating addresses.

    Attributes:
        mac_addresses: Set of MAC addresses correlated to this trajectory.
        observations: Ordered list of observations forming the trajectory.
        confidence: Linkability confidence score (0.0 to 1.0).
    """

    mac_addresses: set[str] = field(default_factory=set)
    observations: list[LinkabilityObservation] = field(default_factory=list)
    confidence: float = 0.0


class TrajectoryReconstructor:
    """Reconstructs continuous device trajectories across MAC address rotations."""

    def __init__(self, max_time_gap: float = 30.0, max_rssi_delta: float = 15.0) -> None:
        self.max_time_gap = max_time_gap
        self.max_rssi_delta = max_rssi_delta
        self._observations: list[LinkabilityObservation] = []

    def add_observation(self, obs: LinkabilityObservation) -> None:
        """Add an observation to the trajectory pool."""
        self._observations.append(obs)

    def reconstruct_trajectories(self) -> list[Trajectory]:
        """Correlate observations across MAC address rotations into cohesive trajectories.

        Returns:
            List of Trajectory records linking correlated MAC addresses.
        """
        if not self._observations:
            return []

        sorted_obs = sorted(self._observations, key=lambda x: x.timestamp)
        trajectories: list[Trajectory] = []

        for obs in sorted_obs:
            matched = False
            for traj in trajectories:
                last_obs = traj.observations[-1]
                time_diff = abs(obs.timestamp - last_obs.timestamp)
                rssi_diff = abs(obs.rssi - last_obs.rssi)

                # Link if within temporal threshold, RSSI continuity, and matching network type
                if (
                    time_diff <= self.max_time_gap
                    and rssi_diff <= self.max_rssi_delta
                    and (obs.network_type == last_obs.network_type or obs.network_type == "Unknown")
                ):
                    traj.observations.append(obs)
                    traj.mac_addresses.add(obs.mac_address)
                    # Confidence heuristic based on proximity and tight time correlation
                    time_factor = max(0.0, 1.0 - (time_diff / self.max_time_gap) * 0.3)
                    rssi_factor = max(0.0, 1.0 - (rssi_diff / self.max_rssi_delta) * 0.3)
                    traj.confidence = round(min(1.0, 0.70 + 0.15 * time_factor + 0.15 * rssi_factor), 2)
                    matched = True
                    break

            if not matched:
                traj = Trajectory(
                    mac_addresses={obs.mac_address},
                    observations=[obs],
                    confidence=0.50,
                )
                trajectories.append(traj)

        return trajectories
