"""Integration tests for radio orchestration, synthetic beacon burst triggers, and offline replay."""

from __future__ import annotations

import io
import json
import time

from app.queue_bridge import EventQueue
from app.views.offline_replay import parse_session_json, parse_uploaded_pcap
from app.views.radio_controls import RadioOrchestrator
from bluetooth_sniffle.protocol.beacons import build_ibeacon
from bluetooth_sniffle.sniff.pcap import PcapBleWriter


def test_radio_orchestrator_beacon_burst_injection() -> None:
    """Validate generating synthetic beacon bursts and pushing to the EventQueue."""
    q = EventQueue(maxsize=100)
    orchestrator = RadioOrchestrator(event_queue=q)

    # Trigger iBeacon burst
    packets = orchestrator.trigger_beacon_burst(
        beacon_type="iBeacon",
        count=5,
        channel=37,
    )
    assert len(packets) == 5
    assert q.size() == 5

    drained = q.drain_all()
    assert len(drained) == 5
    assert all(p["network_type"] == "Apple Find My" or "iBeacon" in p.get("raw_payload", "") for p in drained)
    assert all(p["channel"] == 37 for p in drained)


def test_radio_orchestrator_supported_beacon_types() -> None:
    """Validate burst generation across iBeacon, AltBeacon, Eddystone-UID, and GAEN."""
    q = EventQueue(maxsize=100)
    orchestrator = RadioOrchestrator(event_queue=q)

    for b_type in ["iBeacon", "AltBeacon", "Eddystone-UID", "GAEN"]:
        pkts = orchestrator.trigger_beacon_burst(beacon_type=b_type, count=2, channel=38)
        assert len(pkts) == 2
        assert all(p["channel"] == 38 for p in pkts)


def test_radio_orchestrator_mock_topology_lifecycle() -> None:
    """Validate starting and stopping mock topology execution."""
    q = EventQueue(maxsize=1000)
    orchestrator = RadioOrchestrator(event_queue=q)

    assert not orchestrator.is_running()
    success = orchestrator.start_topology(topology="topology-a", mock=True, duration_sec=0.2)
    assert success
    assert orchestrator.is_running()
    status = orchestrator.get_status()
    assert status["running"] is True
    assert status["active_topology"] == "topology-a"

    time.sleep(0.3)
    orchestrator.stop_topology()
    assert not orchestrator.is_running()


def test_offline_pcap_parsing() -> None:
    """Validate parsing uploaded PCAP bytes into observation dictionaries."""
    # Synthesize small valid in-memory PCAP with 2 packets
    buf = io.BytesIO()
    writer = PcapBleWriter(buf)

    ibeacon_bytes = build_ibeacon(
        uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0", major=1, minor=2
    )
    # PDU header (ADV_IND, len=36) + AdvA (6B) + AdvData (30B)
    adv_pdu = bytes([0x00, 36]) + bytes.fromhex("C01122334455") + ibeacon_bytes
    writer.write_packet(ts_usec=1000, chan=37, rssi=-62, packet=adv_pdu)
    writer.write_packet(ts_usec=2000, chan=38, rssi=-55, packet=adv_pdu)
    writer.flush()

    pcap_data = buf.getvalue()
    observations = parse_uploaded_pcap(pcap_data)

    assert len(observations) == 2
    assert observations[0]["channel"] == 37
    assert observations[0]["rssi"] == -62
    assert "C0:11:22:33:44:55" in observations[0]["mac_address"].upper()
    assert observations[1]["channel"] == 38
    assert observations[1]["rssi"] == -55


def test_offline_session_json_parsing() -> None:
    """Validate parsing exported session JSON records."""
    records = [
        {
            "id": 1,
            "datetime_str": "2026-10-02 12:00:00",
            "timestamp": 1727870400.0,
            "mac_address": "AA:BB:CC:DD:EE:01",
            "rssi": -65,
            "network_type": "Tile",
            "ephemeral_key": "tile_key_001",
            "channel": 37,
            "raw_payload": "020106",
        }
    ]
    raw_json = json.dumps(records).encode("utf-8")
    parsed = parse_session_json(raw_json)

    assert len(parsed) == 1
    assert parsed[0]["mac_address"] == "AA:BB:CC:DD:EE:01"
    assert parsed[0]["network_type"] == "Tile"
    assert parsed[0]["channel"] == 37


def test_radio_orchestrator_serial_port_discovery() -> None:
    """Validate auto-discovery of USB serial ports for CC2652P dongles."""
    from unittest.mock import MagicMock, patch

    from app.views.radio_controls import discover_available_dongles

    mock_port1 = MagicMock()
    mock_port1.device = "/dev/ttyUSB0"
    mock_port1.description = "Sonoff Zigbee 3.0 USB Dongle Plus"
    mock_port1.vid = 0x10C4
    mock_port1.pid = 0xEA60
    mock_port1.product = "CP2102N USB to UART Bridge Controller"

    mock_port2 = MagicMock()
    mock_port2.device = "/dev/ttyUSB1"
    mock_port2.description = "Sonoff Zigbee 3.0 USB Dongle Plus"
    mock_port2.vid = 0x10C4
    mock_port2.pid = 0xEA60
    mock_port2.product = "CP2102N USB to UART Bridge Controller"

    with patch("serial.tools.list_ports.comports", return_value=[mock_port1, mock_port2]):
        discovered = discover_available_dongles()
        assert len(discovered) == 2
        assert discovered[0]["device"] == "/dev/ttyUSB0"
        assert discovered[0]["is_sniffle"] is True
        assert discovered[1]["device"] == "/dev/ttyUSB1"
        assert discovered[1]["is_sniffle"] is True

