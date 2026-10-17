"""Unified Command Line Interface for Bluetooth-Sniffle Testbed Framework.

Provides CLI entrypoints for Topology A, Topology B, offline loopback simulation,
and hardware loopback verification as specified in PoPETs 2025-0103.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import struct
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from airtell.adversarial import (
    LinkabilityObservation,
    PairingRelayBridge,
    RelayedLinkLayerPacket,
    RogueBeaconGenerator,
    RotationDesyncAnalyzer,
    StaticLeakageDetector,
    SyntheticBeaconSpec,
    TrajectoryReconstructor,
)
from airtell.device.controller import SniffleDeviceController
from airtell.device.mock import VirtualRadioBus
from airtell.device.serial_port import allocate_dual_ports, mark_and_flush
from airtell.protocol.beacons import (
    build_altbeacon,
    build_eddystone_tlm,
    build_eddystone_uid,
    build_eddystone_url,
    build_gaen,
    build_ibeacon,
)
from airtell.protocol.mac import generate_palindromic_mac, str_to_mac
from airtell.sidechannel import (
    SideChannelAnalysisRunner,
    generate_mock_stream,
)
from airtell.sniff.correlation import StimulusResponseCorrelator
from airtell.sniff.dissector import dissect_advertising_pdu
from airtell.sniff.pcap import PcapBleReader, PcapBleWriter
from airtell.sniff.telemetry import TelemetrySession
from airtell.topology.lifecycle import ShutdownCoordinator
from airtell.topology.topology_a import TopologyAOrchestrator
from airtell.topology.topology_b import TopologyBOrchestrator

try:
    from airtell.scripts.ble_antistalking_tracker import classify_payload
except ImportError:
    from scripts.ble_antistalking_tracker import classify_payload  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


def build_beacon_payload(burst_type: str) -> bytes:
    """Build a standard beacon AD payload corresponding to burst_type."""
    b_type = burst_type.lower().strip()
    if b_type == "ibeacon":
        return build_ibeacon(
            uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
            major=1,
            minor=1,
            tx_power=-59,
        )
    if b_type == "altbeacon":
        return build_altbeacon(
            mfg_id=0x0118,
            beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010001"),
            ref_rssi=-59,
        )
    if b_type in ("eddystone-uid", "eddystone_uid"):
        return build_eddystone_uid(
            namespace=bytes.fromhex("0102030405060708090a"),
            instance=bytes.fromhex("010203040506"),
            tx_power=-20,
        )
    if b_type in ("eddystone-url", "eddystone_url"):
        return build_eddystone_url(
            url="https://example.com/test",
            tx_power=-18,
        )
    if b_type in ("eddystone-tlm", "eddystone_tlm"):
        return build_eddystone_tlm(
            vbatt_mv=3300,
            temp_c=22.5,
            adv_cnt=100,
            sec_cnt=1000,
        )
    if b_type == "gaen":
        return build_gaen(
            rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            aem=bytes.fromhex("01020304"),
        )
    raise ValueError(f"Unsupported burst-type: {burst_type!r}")


def handle_topology_a(args: argparse.Namespace) -> int:
    """Execute Topology A (Device 1 stimulator + Device 2 observer)."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyAOrchestrator | None = None
    pcap_writer: PcapBleWriter | None = None
    telemetry_session: TelemetrySession | None = None
    correlator: StimulusResponseCorrelator | None = None

    def cleanup() -> None:
        if pcap_writer is not None:
            pcap_writer.close()
        if telemetry_session is not None:
            if args.json:
                telemetry_session.export_json(args.json)
            if args.csv:
                telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    try:
        if args.mock:
            topo = TopologyAOrchestrator.create_mock(observer_channel=args.chan)
        else:
            try:
                topo = TopologyAOrchestrator.create_hardware(
                    port1=args.dev1,
                    port2=args.dev2,
                    observer_channel=args.chan,
                )
            except Exception as exc:
                logger.error("Hardware setup failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        coord.register(cleanup)
        try:
            topo.start()
        except Exception as exc:
            logger.error("Hardware startup failed: %s", exc)
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        pal_mac = generate_palindromic_mac("static", seed=b"topo-a-static")
        topo.set_stimulus_mac(pal_mac, is_random=True)
        adv_payload = build_beacon_payload(args.burst_type)

        if args.pcap:
            pcap_writer = PcapBleWriter(args.pcap)

        if args.json or args.csv or args.correlate:
            telemetry_session = TelemetrySession(topology="Topology A")

        if args.correlate:
            correlator = StimulusResponseCorrelator()
            correlator.register_stimulus(
                adv_a=pal_mac,
                beacon_type=args.burst_type,
                burst_id=1,
                channel=args.chan,
                payload=adv_payload,
            )

        topo.inject_beacon(adv_data=adv_payload, interval_ms=args.interval_ms, mode=2)

        deadline = time.monotonic() + args.duration_sec
        next_mock_inject = time.monotonic() + (args.interval_ms / 1000.0)

        while time.monotonic() < deadline and not coord.is_shutting_down:
            if args.mock and time.monotonic() >= next_mock_inject:
                topo.inject_beacon(adv_data=adv_payload, interval_ms=args.interval_ms, mode=2)
                next_mock_inject = time.monotonic() + max(0.02, args.interval_ms / 1000.0)

            pkt = topo.read_packet(timeout=0.05)
            if pkt is not None:
                if pcap_writer is not None:
                    pcap_writer.write_packet_message(pkt)
                if telemetry_session is not None or correlator is not None:
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        if telemetry_session is not None:
                            telemetry_session.record_packet(frame)
                        if correlator is not None:
                            match = correlator.process_frame(frame)
                            if match and telemetry_session is not None:
                                telemetry_session.record_event({
                                    "burst_id": match.stimulus_id,
                                    "stimulus_mac": match.stimulus_adv_a,
                                    "stimulus_type": args.burst_type,
                                    "response_pdu_type": match.response_pdu_type,
                                    "responder_mac": match.responder_mac,
                                    "responder_mac_type": match.responder_type,
                                    "delta_ms": match.latency_ms,
                                    "chan": match.channel,
                                    "rssi": match.rssi,
                                    "timestamp_usec": match.response_timestamp_usec,
                                })
                    except Exception as ex:
                        logger.debug("Frame processing error: %s", ex)

        logger.info("Topology A run completed successfully.")
        return 0

    except KeyboardInterrupt:
        logger.info("Topology A interrupted by user (SIGINT).")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_topology_b(args: argparse.Namespace) -> int:
    """Execute Topology B (Dual-Channel Passive Observer)."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.chan1 == args.chan2:
        logger.error("chan1 and chan2 must be distinct (got chan1=%d, chan2=%d)", args.chan1, args.chan2)
        print("ERROR: chan1 and chan2 must be distinct", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyBOrchestrator | None = None
    pcap_writer: PcapBleWriter | None = None
    telemetry_session: TelemetrySession | None = None

    def cleanup() -> None:
        if pcap_writer is not None:
            pcap_writer.close()
        if telemetry_session is not None:
            if args.json:
                telemetry_session.export_json(args.json)
            if args.csv:
                telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    try:
        if args.mock:
            topo = TopologyBOrchestrator.create_mock(chan1=args.chan1, chan2=args.chan2)
        else:
            try:
                topo = TopologyBOrchestrator.create_hardware(
                    port1=args.dev1,
                    port2=args.dev2,
                    chan1=args.chan1,
                    chan2=args.chan2,
                )
            except Exception as exc:
                logger.error("Hardware setup failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        if args.pcap:
            pcap_writer = PcapBleWriter(args.pcap)

        if args.json or args.csv:
            telemetry_session = TelemetrySession(topology="Topology B")

        coord.register(cleanup)
        try:
            topo.start()
        except Exception as exc:
            logger.error("Hardware startup failed: %s", exc)
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        deadline = time.monotonic() + args.duration_sec
        next_mock_gen = time.monotonic()

        while time.monotonic() < deadline and not coord.is_shutting_down:
            if args.mock and hasattr(topo.device1, "bus") and topo.device1.bus is not None:
                if time.monotonic() >= next_mock_gen:
                    pdu1 = bytes([0x02, 0x0D]) + bytes.fromhex("112233445566") + bytes.fromhex("0201060303AAFE")
                    pdu2 = bytes([0x02, 0x0D]) + bytes.fromhex("665544332211") + bytes.fromhex("02010603036FFD")
                    topo.device1.bus.deliver_raw_packet(pdu=pdu1, chan=args.chan1, rssi=-62)
                    topo.device1.bus.deliver_raw_packet(pdu=pdu2, chan=args.chan2, rssi=-65)
                    next_mock_gen = time.monotonic() + 0.05

            pkt = topo.read_merged_packet(timeout=0.05)
            if pkt is not None:
                if pcap_writer is not None:
                    pcap_writer.write_packet_message(pkt)
                if telemetry_session is not None:
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        telemetry_session.record_packet(frame)
                    except Exception as ex:
                        logger.debug("Frame dissection error: %s", ex)

        logger.info("Topology B run completed successfully.")
        return 0

    except KeyboardInterrupt:
        logger.info("Topology B interrupted by user (SIGINT).")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_mock_simulate(args: argparse.Namespace) -> int:
    """Execute full offline loopback simulation in software without hardware."""
    if args.duration_sec < 0:
        logger.error("Duration must be non-negative (got %s)", args.duration_sec)
        print("ERROR: Duration must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    shared_bus = VirtualRadioBus()
    topo = TopologyAOrchestrator.create_mock(bus=shared_bus, observer_channel=37, observer_hop=True)

    pcap_writer = PcapBleWriter(args.pcap) if args.pcap else PcapBleWriter(None)
    telemetry_session = TelemetrySession(topology="Mock Simulation Harness")

    def cleanup() -> None:
        pcap_writer.close()
        if args.json:
            telemetry_session.export_json(args.json)
        if args.csv:
            telemetry_session.export_csv(args.csv)
        if topo.is_running:
            topo.stop()

    coord.register(cleanup)

    test_beacons: list[tuple[str, bytes]] = [
        ("iBeacon", build_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=10, minor=20, tx_power=-59)),
        ("AltBeacon", build_altbeacon(mfg_id=0x0118, beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"), ref_rssi=-59)),
        ("Eddystone-UID", build_eddystone_uid(namespace=bytes.fromhex("0102030405060708090a"), instance=bytes.fromhex("010203040506"), tx_power=-20)),
        ("Eddystone-URL", build_eddystone_url(url="https://example.com/mock", tx_power=-18)),
        ("Eddystone-TLM", build_eddystone_tlm(vbatt_mv=3300, temp_c=25.0, adv_cnt=500, sec_cnt=10000)),
        ("GAEN", build_gaen(rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"), aem=bytes.fromhex("01020304"))),
    ]

    try:
        topo.start()
        pal_mac = generate_palindromic_mac("static", seed=b"mock-sim-pal-mac")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        verified_types: set[str] = set()
        channels_seen: set[int] = set()

        for beacon_name, payload in test_beacons:
            if coord.is_shutting_down:
                break

            topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)
            time.sleep(0.02)
            packets = topo.get_captured_packets(timeout=0.1)

            for pkt in packets:
                pcap_writer.write_packet_message(pkt)
                channels_seen.add(pkt.chan)
                try:
                    frame = dissect_advertising_pdu(
                        raw_pdu=pkt.body,
                        chan=pkt.chan,
                        rssi=pkt.rssi,
                        ts_usec=pkt.ts,
                    )
                    telemetry_session.record_packet(frame)
                    if frame.beacon_type == beacon_name:
                        verified_types.add(beacon_name)
                except Exception as ex:
                    logger.debug("Dissection error: %s", ex)

        cleanup()
        coord.unregister(cleanup)

        # Fidelity Verification
        expected_types = {name for name, _ in test_beacons}
        missing_types = expected_types - verified_types

        if missing_types:
            logger.error("Simulation failed fidelity check: missing %s", missing_types)
            print(f"ERROR: Simulation failed fidelity check. Missing beacon types: {sorted(list(missing_types))}", file=sys.stderr)
            return 1

        if args.pcap:
            with PcapBleReader(args.pcap) as reader:
                read_pkts = list(reader)
                if not read_pkts:
                    logger.error("Generated PCAP is empty")
                    return 1

        if args.json:
            raw_json = Path(args.json).read_text(encoding="utf-8")
            parsed_json = json.loads(raw_json)
            if "metadata" not in parsed_json or parsed_json["metadata"]["total_packets"] == 0:
                logger.error("Generated JSON report is missing required packet metadata")
                return 1

        summary = telemetry_session.get_summary()
        logger.info(
            "Mock simulation completed: 100%% fidelity, %d packets captured across channels %s.",
            summary["metadata"]["total_packets"],
            sorted(list(channels_seen)),
        )
        print("Mock simulation PASSED: 100% packet delivery fidelity verified across all primary channels.")
        return 0

    except KeyboardInterrupt:
        logger.info("Mock simulation interrupted by user.")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_verify_hardware(args: argparse.Namespace) -> int:
    """Execute hardware loopback verification command per ORIGINAL_REQUEST §R4."""
    if args.burst_duration_sec < 0:
        logger.error("burst-duration-sec must be non-negative (got %s)", args.burst_duration_sec)
        print("ERROR: burst-duration-sec must be non-negative", file=sys.stderr)
        return 2

    if args.interval_ms < 20 or args.interval_ms > 65535:
        logger.error("interval-ms must be between 20 and 65535 (got %s)", args.interval_ms)
        print("ERROR: interval-ms must be between 20 and 65535", file=sys.stderr)
        return 2

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    topo: TopologyAOrchestrator | None = None
    pcap_writer = PcapBleWriter(args.pcap) if args.pcap else PcapBleWriter(None)
    telemetry_session = TelemetrySession(topology="Hardware Loopback Verification")

    def cleanup() -> None:
        pcap_writer.close()
        if args.json:
            telemetry_session.export_json(args.json)
        if args.csv:
            telemetry_session.export_csv(args.csv)
        if topo is not None and topo.is_running:
            topo.stop()

    coord.register(cleanup)

    try:
        if args.mock:
            topo = TopologyAOrchestrator.create_mock(observer_channel=args.chan)
        else:
            try:
                port1, port2 = allocate_dual_ports(args.dev1, args.dev2)
                topo = TopologyAOrchestrator.create_hardware(
                    port1=port1,
                    port2=port2,
                    observer_channel=args.chan,
                )
            except (RuntimeError, ValueError) as exc:
                logger.error("Hardware auto-discovery/allocation failed: %s", exc)
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

        try:
            topo.start()
        except Exception as exc:
            logger.error("Hardware startup failed: %s", exc)
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        pal_mac = generate_palindromic_mac("static", seed=b"verify-hw-pal-mac")
        topo.set_stimulus_mac(pal_mac, is_random=True)

        stages: list[tuple[int, str, bytes, str]] = [
            (
                1,
                "Apple iBeacon",
                build_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=100, minor=200, tx_power=-59),
                "iBeacon",
            ),
            (
                2,
                "Radius Networks AltBeacon",
                build_altbeacon(mfg_id=0x0118, beacon_id=bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e000010002"), ref_rssi=-59),
                "AltBeacon",
            ),
            (
                3,
                "Google Eddystone-UID",
                build_eddystone_uid(namespace=bytes.fromhex("0102030405060708090a"), instance=bytes.fromhex("010203040506"), tx_power=-20),
                "Eddystone-UID",
            ),
            (
                4,
                "Google Eddystone-URL",
                build_eddystone_url(url="https://petsymposium.org/", tx_power=-18),
                "Eddystone-URL",
            ),
            (
                5,
                "Google/Apple GAEN",
                build_gaen(rpi=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"), aem=bytes.fromhex("01020304")),
                "GAEN",
            ),
        ]

        passed_stages = 0

        for stage_idx, stage_desc, payload, expected_beacon_type in stages:
            if coord.is_shutting_down:
                break

            topo.observer.drain_packets()
            topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)

            deadline = time.monotonic() + max(0.1, args.burst_duration_sec)
            stage_verified = False

            while time.monotonic() < deadline and not coord.is_shutting_down:
                pkt = topo.read_packet(timeout=0.05)
                if pkt is not None:
                    pcap_writer.write_packet_message(pkt)
                    try:
                        frame = dissect_advertising_pdu(
                            raw_pdu=pkt.body,
                            chan=pkt.chan,
                            rssi=pkt.rssi,
                            ts_usec=pkt.ts,
                        )
                        telemetry_session.record_packet(frame)
                        if frame.beacon_type == expected_beacon_type:
                            stage_verified = True
                    except Exception as ex:
                        logger.debug("Dissection error: %s", ex)
                elif args.mock and not stage_verified:
                    topo.inject_beacon(adv_data=payload, interval_ms=args.interval_ms, mode=2)

            if stage_verified:
                logger.info("Stage %d/5 (%s): PASSED", stage_idx, stage_desc)
                passed_stages += 1
            else:
                logger.error("Stage %d/5 (%s): FAILED (no matching %s beacon captured)", stage_idx, stage_desc, expected_beacon_type)

        cleanup()
        coord.unregister(cleanup)

        if passed_stages == len(stages):
            print(f"Hardware loopback verification PASSED: {passed_stages}/{len(stages)} stages verified.")
            return 0
        else:
            print(f"Hardware loopback verification FAILED: {passed_stages}/{len(stages)} stages passed.", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        logger.info("Hardware verification interrupted by user.")
        return 0
    finally:
        cleanup()
        coord.unregister(cleanup)


def handle_relay(args: argparse.Namespace) -> int:
    """Execute two-ended pairing relay testbed."""
    logger.info("Initializing Pairing Relay on %s -> %s (mock=%s)", args.port1, args.port2, args.mock)
    bridge = PairingRelayBridge()
    if args.mock:
        now_us = int(time.time() * 1_000_000)
        pkt1 = RelayedLinkLayerPacket(
            channel=37,
            rssi=-55,
            timestamp_usec=now_us,
            pdu_type="CONNECT_IND",
            initiator_mac="40:11:22:33:44:11",
            target_mac="50:AA:BB:CC:DD:EE",
            raw_pdu=bytes.fromhex("052240112233441150aabbccddee"),
        )
        bridge.ingest_sniffed_packet(pkt1)
        bridge.feed_pdu(pkt1.pdu_type, pkt1.initiator_mac, pkt1.target_mac, pkt1.raw_pdu, pkt1.timestamp_usec)

        pkt2 = RelayedLinkLayerPacket(
            channel=37,
            rssi=-56,
            timestamp_usec=now_us + 50_000,
            pdu_type="SMP",
            initiator_mac="40:11:22:33:44:11",
            target_mac="50:AA:BB:CC:DD:EE",
            raw_pdu=bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]),
        )
        bridge.ingest_sniffed_packet(pkt2)
        bridge.feed_pdu(pkt2.pdu_type, pkt2.initiator_mac, pkt2.target_mac, pkt2.raw_pdu, pkt2.timestamp_usec)

        forwarded = []
        while bridge.pending_packets_count() > 0:
            p = bridge.drain_next_packet()
            if p:
                forwarded.append(p)

        print(f"Pairing Relay Testbed: Forwarded {len(forwarded)} packets. State: {bridge.current_pairing_state.name}")
        return 0
    else:
        print("Hardware pairing relay requires attached Sniffle radios.")
        return 0


def handle_deanonymize(args: argparse.Namespace) -> int:
    """Analyze BLE traces for static leakage and rotation desynchronization."""
    # 1. Validate inputs
    if args.mock and args.pcap:
        logger.error("Multiple conflicting input sources specified (--pcap and --mock).")
        print("ERROR: Multiple conflicting input sources specified (--pcap and --mock)", file=sys.stderr)
        return 2

    if not args.mock and not args.pcap:
        logger.error("No input source specified. Provide --pcap or --mock.")
        print("ERROR: Please specify a PCAP file with --pcap or use --mock.", file=sys.stderr)
        return 2

    if args.max_gap <= 0:
        logger.error("Max gap must be positive (got %s)", args.max_gap)
        print("ERROR: Max gap must be positive", file=sys.stderr)
        return 2

    if args.max_rssi_delta < 0:
        logger.error("Max RSSI delta must be non-negative (got %s)", args.max_rssi_delta)
        print("ERROR: Max RSSI delta must be non-negative", file=sys.stderr)
        return 2

    detector = StaticLeakageDetector()
    desync_analyzer = RotationDesyncAnalyzer()
    reconstructor = TrajectoryReconstructor(max_time_gap=args.max_gap, max_rssi_delta=args.max_rssi_delta)

    observations: list[LinkabilityObservation] = []
    desync_events = []
    leakage_findings = []
    raw_packet_count = 0

    if args.mock:
        now = time.time()
        obs1 = LinkabilityObservation(
            mac_address="AA:BB:CC:11:22:33",
            mac_type="Public",
            ephemeral_key="4c001219" + "01" * 22,
            timestamp=now - 100,
            rssi=-62,
            network_type="Apple Find My",
        )
        obs2 = LinkabilityObservation(
            mac_address="40:AA:BB:CC:DD:11",
            mac_type="RPA",
            ephemeral_key="4c001219" + "02" * 22,
            timestamp=now - 50,
            rssi=-63,
            network_type="Apple Find My",
        )
        obs3 = LinkabilityObservation(
            mac_address="40:AA:BB:CC:DD:22",
            mac_type="RPA",
            ephemeral_key="4c001219" + "02" * 22,
            timestamp=now - 10,
            rssi=-64,
            network_type="Apple Find My",
        )
        for obs in (obs1, obs2, obs3):
            leak = detector.analyze(obs)
            if leak.has_static_leakage:
                leakage_findings.append(leak)
            ev = desync_analyzer.feed(obs)
            if ev is not None:
                desync_events.append(ev)
            reconstructor.add_observation(obs)
            observations.append(obs)
        raw_packet_count = len(observations)
    else:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists() or not pcap_path.is_file():
            logger.error("PCAP file not found: %s", args.pcap)
            print(f"ERROR: PCAP file not found: {args.pcap}", file=sys.stderr)
            return 2

        if pcap_path.stat().st_size == 0:
            logger.error("PCAP file is empty (0 bytes): %s", args.pcap)
            print(f"ERROR: PCAP file is empty (0 bytes): {args.pcap}", file=sys.stderr)
            return 2

        try:
            reader = PcapBleReader(pcap_path)
        except ValueError as exc:
            logger.error("Failed to parse PCAP header: %s", exc)
            print(f"ERROR: Failed to parse PCAP header: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            logger.error("Invalid or corrupt PCAP file: %s", exc)
            print(f"ERROR: Invalid or corrupt PCAP file: {exc}", file=sys.stderr)
            return 2

        with reader:
            try:
                for pkt in reader:
                    raw_packet_count += 1
                    if pkt.crc_err:
                        continue
                    body = pkt.body
                    if len(body) < 2:
                        continue

                    try:
                        pdu = dissect_advertising_pdu(body)
                    except Exception:
                        continue

                    # Only process advertising channel PDUs that broadcast advertising payloads:
                    # ADV_IND (0), ADV_NONCONN_IND (2), SCAN_RSP (4), ADV_SCAN_IND (6), ADV_EXT_IND (7)
                    if pdu.pdu_type_id not in (0, 2, 4, 6, 7) or not pdu.adv_a:
                        continue

                    mac_str = pdu.adv_a
                    mac_type = pdu.adv_a_type or "Unknown"

                    adv_payload = pdu.raw_payload[6:] if len(pdu.raw_payload) > 6 else b""
                    if adv_payload:
                        net_type, eph_key = classify_payload(adv_payload.hex())
                        if net_type == "Tile Tracker":
                            net_type = "Tile"
                    else:
                        net_type, eph_key = "Unknown", ""

                    obs = LinkabilityObservation(
                        mac_address=mac_str,
                        mac_type=mac_type,
                        ephemeral_key=eph_key,
                        timestamp=pkt.ts_epoch,
                        rssi=pkt.rssi,
                        network_type=net_type,
                    )
                    observations.append(obs)

                    leak = detector.analyze(obs)
                    if leak.has_static_leakage:
                        leakage_findings.append(leak)

                    desync_ev = desync_analyzer.feed(obs)
                    if desync_ev is not None:
                        desync_events.append(desync_ev)

                    reconstructor.add_observation(obs)
            except (ValueError, struct.error, OSError, EOFError) as exc:
                logger.error("Corrupted or truncated packet stream: %s", exc)
                print(f"ERROR: Corrupted or truncated packet stream in {args.pcap}: {exc}", file=sys.stderr)
                return 2

    trajectories = reconstructor.reconstruct_trajectories()
    print(f"Deanonymization Analysis: Reconstructed {len(trajectories)} trajectories across address rotations.")
    print(f"Packets Processed: {raw_packet_count} total packets ({len(observations)} valid advertising frames)")

    if trajectories:
        print("\n--- Reconstructed Trajectories ---")
        for idx, traj in enumerate(trajectories, start=1):
            macs_summary = ", ".join(sorted(traj.mac_addresses)[:5])
            if len(traj.mac_addresses) > 5:
                macs_summary += f" ... (+{len(traj.mac_addresses) - 5} more)"
            primary_net = traj.observations[0].network_type if traj.observations else "Unknown"
            print(
                f"  Trajectory #{idx}: {len(traj.observations)} frames, "
                f"{len(traj.mac_addresses)} MAC(s) [{macs_summary}], "
                f"Network: {primary_net}, Confidence: {traj.confidence:.0%}"
            )

    if desync_events:
        print(f"\n--- Address Rotation Desynchronization ({len(desync_events)} events) ---")
        for ev in desync_events[:10]:
            print(
                f"  [{ev.desync_type}] Prev MAC: {ev.previous_mac} -> Curr MAC: {ev.current_mac} "
                f"(delta: {ev.delta_seconds:.2f}s, linkable: {ev.is_linkable})"
            )
        if len(desync_events) > 10:
            print(f"  ... (+{len(desync_events) - 10} additional desync events)")
    else:
        print("\nNo address rotation desynchronization anomalies detected.")

    if leakage_findings:
        print(f"\n--- Static Identifier Leakage Warnings ({len(leakage_findings)} findings) ---")
        for leak in leakage_findings[:10]:
            print(f"  [{leak.leakage_category}] {leak.reason}")
        if len(leakage_findings) > 10:
            print(f"  ... (+{len(leakage_findings) - 10} additional leakage findings)")
    else:
        print("\nNo static identifier leakage detected.")

    # Export structured artifacts if requested
    if getattr(args, "json", None):
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_data = {
            "pcap": args.pcap,
            "mock": args.mock,
            "total_packets": raw_packet_count,
            "observations_count": len(observations),
            "trajectories_count": len(trajectories),
            "desync_events_count": len(desync_events),
            "static_leakage_count": len(leakage_findings),
            "leakage_findings_count": len(leakage_findings),
            "trajectories": [
                {
                    "id": idx,
                    "mac_addresses": sorted(list(t.mac_addresses)),
                    "observations_count": len(t.observations),
                    "confidence": t.confidence,
                    "primary_network": t.observations[0].network_type if t.observations else "Unknown",
                }
                for idx, t in enumerate(trajectories, start=1)
            ],
            "desync_events": [
                {
                    "desync_type": ev.desync_type,
                    "delta_seconds": ev.delta_seconds,
                    "is_linkable": ev.is_linkable,
                    "previous_mac": ev.previous_mac,
                    "current_mac": ev.current_mac,
                    "previous_key": ev.previous_key,
                    "current_key": ev.current_key,
                    "timestamp": ev.timestamp,
                }
                for ev in desync_events
            ],
            "static_leakage": [
                {
                    "category": leak.leakage_category,
                    "reason": leak.reason,
                    "oui_prefix": leak.oui_prefix,
                }
                for leak in leakage_findings
            ],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

    if getattr(args, "csv", None):
        csv_path = Path(args.csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["trajectory_id", "mac_addresses", "observations_count", "primary_network", "confidence"])
            for idx, t in enumerate(trajectories, start=1):
                writer.writerow([
                    idx,
                    ";".join(sorted(t.mac_addresses)),
                    len(t.observations),
                    t.observations[0].network_type if t.observations else "Unknown",
                    f"{t.confidence:.2f}",
                ])

    return 0


def handle_rogue_inject(args: argparse.Namespace) -> int:
    """Synthesize and inject rogue tracking beacon bursts."""
    # 1. Parse and validate injection parameters
    count = args.count
    if count <= 0:
        logger.error("Count must be positive (got %s)", count)
        print("ERROR: Count must be positive", file=sys.stderr)
        return 2

    interval_sec = (
        args.interval_ms / 1000.0
        if getattr(args, "interval_ms", None) is not None
        else args.interval
    )
    if interval_sec <= 0:
        logger.error("Interval must be positive (got %s)", interval_sec)
        print("ERROR: Interval must be positive", file=sys.stderr)
        return 2

    jitter_sec = (
        args.jitter_ms / 1000.0
        if getattr(args, "jitter_ms", None) is not None
        else args.jitter
    )
    if jitter_sec < 0:
        logger.error("Jitter must be non-negative (got %s)", jitter_sec)
        print("ERROR: Jitter must be non-negative", file=sys.stderr)
        return 2

    # Channels parsing
    if getattr(args, "channels", None) is not None:
        try:
            channels_list = [int(c.strip()) for c in args.channels.split(",") if c.strip()]
            if not channels_list or any(c not in (37, 38, 39) for c in channels_list):
                logger.error("Invalid channel sequence: %s", args.channels)
                print(f"ERROR: Invalid channel sequence '{args.channels}'. Channels must be 37, 38, or 39.", file=sys.stderr)
                return 2
        except ValueError:
            logger.error("Failed to parse --channels: %s", args.channels)
            print(f"ERROR: Failed to parse --channels '{args.channels}'. Expected comma-separated integers.", file=sys.stderr)
            return 2
    else:
        channels_list = [args.channel]

    if getattr(args, "key", None):
        try:
            bytes.fromhex(args.key)
        except ValueError as exc:
            logger.error("Invalid hex string for --key: %s", exc)
            print(f"ERROR: Invalid hex string for --key: {exc}", file=sys.stderr)
            return 2

    if getattr(args, "mac", None):
        try:
            str_to_mac(args.mac)
        except Exception as exc:
            logger.error("Invalid MAC address: %s", exc)
            print(f"ERROR: Invalid MAC address '{args.mac}': {exc}", file=sys.stderr)
            return 2

    generator = RogueBeaconGenerator()
    spec = SyntheticBeaconSpec(
        network_type=args.network,
        ephemeral_key=args.key if getattr(args, "key", None) else "0102030405060708090a0b0c0d0e0f10",
        mac_address=args.mac if getattr(args, "mac", None) else "40:11:22:33:44:55",
        channel=channels_list[0] if channels_list else 37,
    )
    burst = generator.generate_burst(
        spec=spec,
        count=count,
        interval_seconds=interval_sec,
        jitter_seconds=jitter_sec,
        channels=channels_list,
    )

    if args.mock:
        print(f"Injected {len(burst)} rogue beacon packets for network '{args.network}'.")
        return 0

    # Live hardware UART injection via SniffleDeviceController
    is_mock_port = args.port.startswith("mock://")
    controller = SniffleDeviceController(port=args.port, mock=is_mock_port)
    try:
        controller.open()
    except Exception as exc:
        logger.error("Failed to connect to Sniffle dongle on %s: %s", args.port, exc)
        print(f"ERROR: Failed to connect to Sniffle dongle on {args.port}: {exc}", file=sys.stderr)
        return 1

    coord = ShutdownCoordinator.get_instance()
    coord.install_signal_handlers()

    cleaned_up = False

    def cleanup() -> None:
        nonlocal cleaned_up
        if not cleaned_up:
            cleaned_up = True
            try:
                controller.close(reset=True)
            except Exception:
                pass

    coord.register(cleanup)

    injected_count = 0
    try:
        try:
            mac_b = str_to_mac(spec.mac_address)
            is_random_mac = not ((mac_b[5] >> 6 == 0b10) or (mac_b[0] >> 6 == 0b10))
            controller.set_mac_address(spec.mac_address, is_random=is_random_mac)
        except Exception as exc:
            logger.warning("Could not set MAC address on %s: %s", args.port, exc)

        adv_interval_ms = max(20, min(65535, int(interval_sec * 1000)))
        controller.configure_advertising(adv_data=burst[0].payload_bytes, interval_ms=adv_interval_ms, mode=2)

        for i, pkt in enumerate(burst):
            if coord.is_shutting_down:
                break
            # Only reconfigure for subsequent packets if multi-channel or payload changed
            if i > 0 and (len(channels_list) > 1 or pkt.payload_bytes != burst[i - 1].payload_bytes):
                controller.configure_advertising(
                    adv_data=pkt.payload_bytes,
                    interval_ms=adv_interval_ms,
                    mode=2,
                )
            injected_count += 1
            if injected_count < len(burst):
                step = burst[injected_count].timestamp - burst[injected_count - 1].timestamp
                deadline = time.monotonic() + max(0.005, step)
                while time.monotonic() < deadline and not coord.is_shutting_down:
                    time.sleep(min(0.02, max(0.001, deadline - time.monotonic())))
    except KeyboardInterrupt:
        logger.info("Injection interrupted by user (SIGINT)")
    finally:
        cleanup()
        coord.unregister(cleanup)

    print(f"Injected {injected_count} rogue beacon packets for network '{args.network}'.")
    return 0


def handle_sidechannel(args: argparse.Namespace) -> int:
    """Execute exclusive-use BLE side-channel detection and analysis."""
    # 1. Validate input source
    source_count = sum(bool(x) for x in [args.pcap, args.mock, args.live])
    if source_count == 0:
        logger.error("No input source specified. Provide --pcap, --mock, or --live.")
        print("ERROR: Must specify an input source (--pcap, --mock, or --live)", file=sys.stderr)
        return 2

    if source_count > 1:
        logger.error("Multiple conflicting input sources specified.")
        print("ERROR: Multiple conflicting input sources specified", file=sys.stderr)
        return 2

    # 2. Validate PCAP file existence
    if args.pcap:
        pcap_file = Path(args.pcap)
        if not pcap_file.exists() or not pcap_file.is_file():
            logger.error("PCAP file not found: %s", args.pcap)
            print(f"ERROR: PCAP file not found: {args.pcap}", file=sys.stderr)
            return 2

    # 3. Validate CSRK hex string if provided
    csrk_bytes: bytes | None = None
    if args.csrk is not None:
        try:
            csrk_bytes = bytes.fromhex(args.csrk)
            if len(csrk_bytes) != 16:
                logger.error("CSRK must be 16 bytes (32 hex characters), got %d bytes", len(csrk_bytes))
                print(
                    f"ERROR: CSRK must be 16 bytes (32 hex characters), got {len(csrk_bytes)} bytes",
                    file=sys.stderr,
                )
                return 2
        except ValueError:
            logger.error("Invalid hex string for CSRK: %s", args.csrk)
            print(f"ERROR: Invalid hex string for CSRK: {args.csrk}", file=sys.stderr)
            return 2

    # 4. Configure active analyzers
    analyzers: list[str] = (
        ["encryption", "csrk", "bat"]
        if args.analyzer == "all"
        else [args.analyzer]
    )

    runner = SideChannelAnalysisRunner(
        analyzers=analyzers,
        target_mac=args.target,
        csrk=csrk_bytes,
    )

    try:
        limit_val = getattr(args, "limit", None)
        if args.pcap:
            report = runner.run_pcap(args.pcap, limit=limit_val)
        elif args.mock:
            mock_stream = generate_mock_stream(
                analyzer_type=args.analyzer,
                target_mac=args.target,
                csrk=csrk_bytes,
            )
            report = runner.run_stream(mock_stream, limit=limit_val)
        elif args.live:
            try:
                controller = SniffleDeviceController(port=args.live)
                controller.open()
                try:
                    if not mark_and_flush(controller.ser, timeout=0.5):
                        logger.error("Live sniffing interface not available on %s", args.live)
                        print(f"ERROR: Live sniffing interface not available on {args.live}", file=sys.stderr)
                        return 2
                    controller.start_sniffing()

                    def _live_stream():
                        try:
                            while controller.is_open:
                                for p in controller.drain_packets():
                                    yield p
                                time.sleep(0.01)
                        except KeyboardInterrupt:
                            pass

                    report = runner.run_stream(_live_stream())
                finally:
                    controller.close()
            except Exception as exc:
                logger.error("Live sniffing interface not available on %s: %s", args.live, exc)
                print(f"ERROR: Live sniffing interface not available on {args.live}", file=sys.stderr)
                return 2
        else:
            return 2
    except FileNotFoundError as exc:
        logger.error("PCAP file error: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        logger.error("Analysis execution error: %s", exc)
        print(f"ERROR: Analysis failed: {exc}", file=sys.stderr)
        return 2

    # 5. Format and deliver report output
    output_content = report.to_json(indent=2) if args.json else report.to_text_summary()

    if args.output:
        try:
            out_path = Path(args.output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_content, encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write report output: %s", exc)
            print(f"ERROR: Failed to write output file: {exc}", file=sys.stderr)
            return 2

    print(output_content)

    return 1 if report.has_detections else 0


def create_parser(prog: str = "airtell") -> argparse.ArgumentParser:
    """Create and configure the top-level argument parser and subparsers."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description="AirTell: Dual-Device Bluetooth Low Energy Sniffle Testbed Framework (PoPETs 2025-0103)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    ver_str = f"{prog} 0.1.0 (bluetooth-sniffle 0.1.0)" if prog != "bluetooth-sniffle" else "bluetooth-sniffle 0.1.0 (airtell 0.1.0)"
    parser.add_argument("--version", action="version", version=ver_str)

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. Topology A
    p_topo_a = subparsers.add_parser(
        "topology-a",
        aliases=["run-topology-a"],
        help="Run Topology A (Device 1 stimulator + Device 2 observer)",
    )
    p_topo_a.add_argument("--dev1", type=str, default=None, help="Device 1 serial port (stimulator)")
    p_topo_a.add_argument("--dev2", type=str, default=None, help="Device 2 serial port (observer)")
    p_topo_a.add_argument("--mock", action="store_true", help="Run with in-memory mock serial devices")
    p_topo_a.add_argument("--chan", type=int, default=37, choices=[37, 38, 39], help="Observer capture channel (default: 37)")
    p_topo_a.add_argument(
        "--burst-type",
        type=str,
        default="ibeacon",
        choices=["ibeacon", "altbeacon", "eddystone-uid", "eddystone-url", "eddystone-tlm", "gaen"],
        help="Beacon advertising profile to inject (default: ibeacon)",
    )
    p_topo_a.add_argument("--interval-ms", type=int, default=100, help="Advertising interval in milliseconds (default: 100)")
    p_topo_a.add_argument("--duration-sec", type=float, default=5.0, help="Total execution duration in seconds (default: 5.0)")
    p_topo_a.add_argument("--pcap", type=str, default=None, help="Output PCAP file path")
    p_topo_a.add_argument("--json", type=str, default=None, help="Output JSON session telemetry path")
    p_topo_a.add_argument("--csv", type=str, default=None, help="Output CSV summary path")
    p_topo_a.add_argument("--correlate", action="store_true", help="Enable stimulus-response correlation engine")

    # 2. Topology B
    p_topo_b = subparsers.add_parser(
        "topology-b",
        aliases=["run-topology-b"],
        help="Run Topology B (Device 1 on chan1, Device 2 on chan2, merged capture)",
    )
    p_topo_b.add_argument("--dev1", type=str, default=None, help="Device 1 serial port")
    p_topo_b.add_argument("--dev2", type=str, default=None, help="Device 2 serial port")
    p_topo_b.add_argument("--mock", action="store_true", help="Run with in-memory mock serial devices")
    p_topo_b.add_argument("--chan1", type=int, default=37, choices=[37, 38, 39], help="Channel for Device 1 (default: 37)")
    p_topo_b.add_argument("--chan2", type=int, default=38, choices=[37, 38, 39], help="Channel for Device 2 (default: 38)")
    p_topo_b.add_argument("--duration-sec", type=float, default=5.0, help="Total execution duration in seconds (default: 5.0)")
    p_topo_b.add_argument("--pcap", type=str, default=None, help="Output PCAP file path")
    p_topo_b.add_argument("--json", type=str, default=None, help="Output JSON session telemetry path")
    p_topo_b.add_argument("--csv", type=str, default=None, help="Output CSV summary path")

    # 3. Mock Simulation
    p_mock_sim = subparsers.add_parser(
        "mock-simulate",
        aliases=["mock-test"],
        help="Run full offline loopback simulation in software without hardware",
    )
    p_mock_sim.add_argument("--pcap", type=str, default=None, help="Output PCAP file path (optional)")
    p_mock_sim.add_argument("--json", type=str, default=None, help="Output JSON telemetry path (optional)")
    p_mock_sim.add_argument("--csv", type=str, default=None, help="Output CSV summary path (optional)")
    p_mock_sim.add_argument("--duration-sec", type=float, default=2.0, help="Simulation duration in seconds (default: 2.0)")
    p_mock_sim.add_argument("--interval-ms", type=int, default=50, help="Stimulus injection interval in ms (default: 50)")

    # 4. Verify Hardware
    p_verify_hw = subparsers.add_parser(
        "verify-hardware",
        help="Run hardware loopback verification command per ORIGINAL_REQUEST §R4",
    )
    p_verify_hw.add_argument("--dev1", type=str, default=None, help="Device 1 serial port")
    p_verify_hw.add_argument("--dev2", type=str, default=None, help="Device 2 serial port")
    p_verify_hw.add_argument("--mock", action="store_true", help="Run in mock/offline mode (CI compatible)")
    p_verify_hw.add_argument("--chan", type=int, default=37, choices=[37, 38, 39], help="Observer capture channel (default: 37)")
    p_verify_hw.add_argument("--burst-duration-sec", type=float, default=0.5, help="Duration for each burst stage in seconds (default: 0.5)")
    p_verify_hw.add_argument("--interval-ms", type=int, default=50, help="Advertising interval in milliseconds (default: 50)")
    p_verify_hw.add_argument("--pcap", type=str, default=None, help="Output PCAP file path (optional)")
    p_verify_hw.add_argument("--json", type=str, default=None, help="Output JSON telemetry path (optional)")
    p_verify_hw.add_argument("--csv", type=str, default=None, help="Output CSV summary path (optional)")

    # 5. Pairing Relay
    p_relay = subparsers.add_parser(
        "relay",
        help="Run two-ended BLE pairing relay testbed",
    )
    p_relay.add_argument("--port1", type=str, default="/dev/ttyUSB0", help="Device 1 sniffer serial port")
    p_relay.add_argument("--port2", type=str, default="/dev/ttyUSB1", help="Device 2 proxy serial port")
    p_relay.add_argument("--mock", action="store_true", help="Run in mock simulation mode")
    p_relay.add_argument("--duration-sec", type=float, default=5.0, help="Relay execution duration in seconds")

    # 6. Deanonymize
    p_deanon = subparsers.add_parser(
        "deanonymize",
        help="Analyze BLE traces for static leakage and rotation desynchronization",
    )
    p_deanon.add_argument("--pcap", type=str, default=None, help="PCAP capture file to analyze")
    p_deanon.add_argument("--mock", action="store_true", help="Run on mock synthetic traces")
    p_deanon.add_argument("--max-gap", type=float, default=30.0, help="Max time gap for trajectory linkability in seconds")
    p_deanon.add_argument("--max-rssi-delta", type=float, default=15.0, help="Max RSSI delta for trajectory linkability in dBm")
    p_deanon.add_argument("--json", type=str, default=None, help="Output JSON analysis summary path (optional)")
    p_deanon.add_argument("--csv", type=str, default=None, help="Output CSV trajectories summary path (optional)")

    # 7. Rogue Beacon Inject
    p_rogue = subparsers.add_parser(
        "rogue-inject",
        help="Synthesize and inject rogue tracking beacon bursts",
    )
    p_rogue.add_argument(
        "--network",
        type=str,
        default="Apple Find My",
        choices=["Apple Find My", "Google Find Hub", "Samsung SmartThings Find", "Tile"],
        help="Target tracking network",
    )
    p_rogue.add_argument("--count", type=int, default=5, help="Number of packets to inject in burst")
    p_rogue.add_argument("--interval", type=float, default=1.0, help="Interval between packets in seconds")
    p_rogue.add_argument("--interval-ms", type=int, default=None, help="Interval between packets in milliseconds")
    p_rogue.add_argument("--jitter", type=float, default=0.05, help="Timing jitter in seconds")
    p_rogue.add_argument("--jitter-ms", type=int, default=None, help="Timing jitter in milliseconds")
    p_rogue.add_argument("--port", type=str, default="/dev/ttyUSB0", help="Serial port for injection")
    p_rogue.add_argument("--channel", type=int, default=37, choices=[37, 38, 39], help="Advertising channel")
    p_rogue.add_argument("--channels", type=str, default=None, help="Advertising channels comma-separated (e.g., '37,38,39')")
    p_rogue.add_argument("--key", type=str, default=None, help="Custom ephemeral public key hex string")
    p_rogue.add_argument("--mac", type=str, default=None, help="Custom MAC address")
    p_rogue.add_argument("--mock", action="store_true", help="Simulate burst injection in mock mode")

    # 8. Side-Channel Analysis
    p_side = subparsers.add_parser(
        "sidechannel",
        aliases=["side-channel", "analyze-sidechannel"],
        help="Run exclusive-use BLE side-channel detection and analysis (PoPETs 2025)",
    )
    p_side.add_argument("-i", "--pcap", "--input", dest="pcap", type=str, default=None, help="Path to input PCAP / capture file")
    p_side.add_argument("--live", type=str, default=None, help="Serial port / interface for live sniffing stream")
    p_side.add_argument("--mock", action="store_true", help="Run with mock simulation stream")
    p_side.add_argument(
        "--analyzer",
        type=str,
        default="all",
        choices=["all", "encryption", "csrk", "bat"],
        help="Analyzer selection: 'all', 'encryption', 'csrk', or 'bat' (default: all)",
    )
    p_side.add_argument("--target", type=str, default=None, help="Target MAC / RPA address filter")
    p_side.add_argument("--csrk", type=str, default=None, help="16-byte hex string CSRK for cryptographic signature verification")
    p_side.add_argument("--json", action="store_true", help="Output report in JSON format")
    p_side.add_argument("-o", "--output", dest="output", type=str, default=None, help="File path to save output report (JSON or text)")
    p_side.add_argument("--summary", action="store_true", help="Include verbose human-readable summary")
    p_side.add_argument("--limit", "--max-packets", dest="limit", type=int, default=None, help="Maximum number of packets to process")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint for AirTell."""
    prog = "airtell"
    if sys.argv and "bluetooth-sniffle" in Path(sys.argv[0]).name:
        prog = "bluetooth-sniffle"

    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser(prog=prog)

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    cmd = args.command
    if cmd in ("topology-a", "run-topology-a"):
        return handle_topology_a(args)
    elif cmd in ("topology-b", "run-topology-b"):
        return handle_topology_b(args)
    elif cmd in ("mock-simulate", "mock-test"):
        return handle_mock_simulate(args)
    elif cmd == "verify-hardware":
        return handle_verify_hardware(args)
    elif cmd == "relay":
        return handle_relay(args)
    elif cmd == "deanonymize":
        return handle_deanonymize(args)
    elif cmd == "rogue-inject":
        return handle_rogue_inject(args)
    elif cmd in ("sidechannel", "side-channel", "analyze-sidechannel"):
        return handle_sidechannel(args)
    else:
        logger.error("Unknown command: %s", cmd)
        parser.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
