"""Synthetic rogue beacon generator and anti-stalking evasion benchmark engine."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Optional

try:
    from airtell.scripts.ble_antistalking_tracker import BLETrackerDB, classify_payload
except ImportError:
    from scripts.ble_antistalking_tracker import BLETrackerDB, classify_payload


@dataclass
class SyntheticBeaconSpec:
    """Specification for synthesizing connectionless BLE beacon payloads.

    Attributes:
        network_type: 'Apple Find My', 'Google Find Hub', 'Samsung SmartThings Find', 'Tile'.
        ephemeral_key: Hex string representing isolated key material or payload data.
        mac_address: Transmitter Bluetooth MAC address.
        rssi: Signal strength in dBm.
        channel: Physical BLE advertising channel (37, 38, or 39).
    """

    network_type: str = "Apple Find My"
    ephemeral_key: str = "0102030405060708090a0b0c0d0e0f10"
    mac_address: str = "40:11:22:33:44:55"
    rssi: int = -65
    channel: int = 37


@dataclass
class SyntheticPacket:
    """Instantiated synthetic advertising packet record.

    Attributes:
        mac_address: Bluetooth MAC address.
        rssi: Simulated signal strength in dBm.
        channel: Radio channel.
        payload_bytes: Raw 31-byte binary advertising payload.
        timestamp: Unix epoch timestamp in seconds.
        network_type: Tracking network classification.
        ephemeral_key: Extracted key hex string.
    """

    mac_address: str
    rssi: int
    channel: int
    payload_bytes: bytes
    timestamp: float
    network_type: str
    ephemeral_key: str


class RogueBeaconGenerator:
    """Generates valid 31-byte advertising payloads across crowdsourced tracking networks."""

    def build_payload(self, spec: SyntheticBeaconSpec) -> bytes:
        """Construct binary Link Layer payload adhering to specified network format.

        Args:
            spec: SyntheticBeaconSpec parameters.

        Returns:
            bytes object up to 31 bytes length.
        """
        flags_ad = bytes([0x02, 0x01, 0x06])  # Length 2, AD Flags (LE General Discoverable + BR/EDR Not Supported)
        key_raw = bytes.fromhex(spec.ephemeral_key) if spec.ephemeral_key else b"\x00" * 16

        net_lower = spec.network_type.lower()
        if "apple" in net_lower:
            # Apple Find My: Manufacturer Specific Data (0xFF), Apple ID 0x004C (4c00), Type 0x12, Length 0x19
            # Followed by 22 bytes of public key / status
            apple_header = bytes([0x4C, 0x00, 0x12, 0x19])
            avail_len = 31 - len(flags_ad) - 2 - len(apple_header)
            payload_data = key_raw[:avail_len].ljust(avail_len, b"\x00")
            msd_len = 1 + len(apple_header) + len(payload_data)
            return flags_ad + bytes([msd_len, 0xFF]) + apple_header + payload_data

        elif "google" in net_lower:
            # Google Find Hub: 16-bit Service Data (0x16), Service UUID 0xFE9F
            avail_len = 31 - len(flags_ad) - 2 - 2
            payload_data = key_raw[:avail_len].ljust(avail_len, b"\x00")
            sd_len = 1 + 2 + len(payload_data)
            return flags_ad + bytes([sd_len, 0x16, 0xFE, 0x9F]) + payload_data

        elif "samsung" in net_lower:
            # Samsung SmartThings Find: Manufacturer Specific Data (0xFF), Samsung ID 0x0075 (7500)
            avail_len = 31 - len(flags_ad) - 2 - 2
            payload_data = key_raw[:avail_len].ljust(avail_len, b"\x00")
            msd_len = 1 + 2 + len(payload_data)
            return flags_ad + bytes([msd_len, 0xFF, 0x75, 0x00]) + payload_data

        elif "tile" in net_lower:
            # Tile: 16-bit Service Data (0x16), Service UUID 0xFEED
            avail_len = 31 - len(flags_ad) - 2 - 2
            payload_data = key_raw[:avail_len].ljust(avail_len, b"\x00")
            sd_len = 1 + 2 + len(payload_data)
            return flags_ad + bytes([sd_len, 0x16, 0xFE, 0xED]) + payload_data

        # Fallback generic manufacturer payload
        return flags_ad + bytes([0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x00])

    def generate_burst(
        self,
        spec: SyntheticBeaconSpec,
        count: int = 5,
        interval_seconds: float = 1.0,
        jitter_seconds: float = 0.05,
        start_time: Optional[float] = None,
    ) -> list[SyntheticPacket]:
        """Generate a sequential burst of synthetic packets with timing jitter.

        Args:
            spec: SyntheticBeaconSpec parameters.
            count: Number of packets in the burst.
            interval_seconds: Nominal interval between packets.
            jitter_seconds: Random timing jitter bound.
            start_time: Initial burst timestamp in seconds.

        Returns:
            List of SyntheticPacket objects.
        """
        payload = self.build_payload(spec)
        net, key = classify_payload(payload.hex())

        current_time = start_time if start_time is not None else time.time()
        packets: list[SyntheticPacket] = []

        for i in range(count):
            if i > 0:
                jitter = random.uniform(-jitter_seconds, jitter_seconds)
                step = max(0.01, interval_seconds + jitter)
                current_time += step

            packets.append(
                SyntheticPacket(
                    mac_address=spec.mac_address,
                    rssi=spec.rssi,
                    channel=spec.channel,
                    payload_bytes=payload,
                    timestamp=current_time,
                    network_type=net,
                    ephemeral_key=key,
                )
            )

        return packets


@dataclass
class EvasionBenchmarkResult:
    """Benchmark outcome for anti-stalking detection threshold testing.

    Attributes:
        scenario_name: Name of evaluated evasion tactic.
        is_detected: True if heuristics triggered one or more alerts.
        alert_count: Number of threat alerts logged.
        packets_injected: Total packets simulated.
        duration_minutes: Total duration span of the scenario.
        alerts: Detailed alert dictionaries returned by tracker DB.
    """

    scenario_name: str
    is_detected: bool
    alert_count: int
    packets_injected: int
    duration_minutes: float
    alerts: list[dict[str, Any]]


class AntiStalkingEvasionEvaluator:
    """Systematically evaluates anti-stalking heuristic resilience against evasion strategies."""

    def __init__(self, tracker_db: BLETrackerDB) -> None:
        self.db = tracker_db
        self.generator = RogueBeaconGenerator()

    def evaluate_scenario(
        self,
        scenario_name: str,
        packets_count: int = 10,
        duration_minutes: float = 8.0,
        rotation_interval_minutes: float = 30.0,
        network_type: str = "Apple Find My",
    ) -> EvasionBenchmarkResult:
        """Execute a simulated trajectory and evaluate anti-stalking alert thresholds.

        Args:
            scenario_name: Label for test scenario.
            packets_count: Total packets to inject.
            duration_minutes: Span of time covered by injections.
            rotation_interval_minutes: How frequently MAC and key rotate during scenario.
            network_type: Target tracking network.

        Returns:
            EvasionBenchmarkResult evaluating detection vs. evasion.
        """
        now = time.time()
        start_time = now - (duration_minutes * 60.0)
        time_step = (duration_minutes * 60.0) / max(1, packets_count - 1)

        scenario_hash = abs(hash(scenario_name)) % 0xFFFF
        key_id = 1
        current_key = f"{scenario_hash:04x}02030405060708090a0b0c0d0e0f{key_id:02x}"
        current_mac = f"40:{(scenario_hash >> 8) & 0xFF:02x}:{scenario_hash & 0xFF:02x}:33:44:{key_id:02x}"
        last_rotation = start_time

        injected_count = 0
        for i in range(packets_count):
            pkt_time = start_time + (i * time_step)

            # Check if rotation threshold reached
            if (pkt_time - last_rotation) >= (rotation_interval_minutes * 60.0):
                key_id += 1
                current_key = f"0102030405060708090a0b0c0d0e0f{key_id:02x}"
                current_mac = f"40:11:22:33:44:{key_id:02x}"
                last_rotation = pkt_time

            spec = SyntheticBeaconSpec(
                network_type=network_type,
                ephemeral_key=current_key,
                mac_address=current_mac,
                rssi=-62,
            )
            payload = self.generator.build_payload(spec)
            net, eph_key = classify_payload(payload.hex())

            self.db.insert_observation(
                mac_address=current_mac,
                rssi=-62,
                network_type=net,
                ephemeral_key=eph_key,
                channel=37,
                raw_payload=payload.hex(),
                timestamp=pkt_time,
            )
            injected_count += 1

        # Evaluate heuristics over default 15m window
        all_alerts = self.db.check_stalking_heuristics(
            window_minutes=15,
            min_observations=5,
            min_duration_minutes=5,
        )
        scenario_key_prefix = f"{scenario_hash:04x}"
        alerts = [a for a in all_alerts if scenario_key_prefix in a.get("identifier", "")]

        return EvasionBenchmarkResult(
            scenario_name=scenario_name,
            is_detected=len(alerts) > 0,
            alert_count=len(alerts),
            packets_injected=injected_count,
            duration_minutes=duration_minutes,
            alerts=alerts,
        )
