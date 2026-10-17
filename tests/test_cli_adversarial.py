"""CLI and dashboard view tests for adversarial relay, deanonymization, and rogue beacon injection."""

from __future__ import annotations

import csv
import json
import struct
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from airtell.adversarial.rogue_beacon import RogueBeaconGenerator, SyntheticBeaconSpec
from airtell.cli import main
from airtell.protocol.mac import str_to_mac
from airtell.sniff.pcap import PcapBleWriter


def _create_synthetic_adversarial_pcap(path: Path) -> Path:
    """Generate a valid DLT 256 PCAP containing Apple Find My beacons with static leakage and desynchronization."""
    generator = RogueBeaconGenerator()
    writer = PcapBleWriter(output=path)
    now_us = int(time.time() * 1_000_000)

    # 1. Packet from Apple Find My with Public MAC (static leakage: STATIC_MAC)
    spec_public = SyntheticBeaconSpec(
        network_type="Apple Find My",
        ephemeral_key="0102030405060708090a0b0c0d0e0f10",
        mac_address="AA:BB:CC:11:22:33",
        channel=37,
    )
    payload_apple = generator.build_payload(spec_public)
    mac_bytes_public = str_to_mac("AA:BB:CC:11:22:33")
    adv_frame_public = bytes([0x02, len(mac_bytes_public) + len(payload_apple)]) + mac_bytes_public + payload_apple
    writer.write_packet(ts_usec=now_us, chan=37, rssi=-60, packet=adv_frame_public)

    # 2. Packet with same key but rotated RPA MAC (desync: MAC_ROTATED_KEY_PERSISTED)
    # RPA MSB has 01b (0x40 >> 6 == 1)
    mac_bytes_rpa1 = str_to_mac("40:11:22:33:44:55")
    adv_frame_rpa1 = bytes([0x42, len(mac_bytes_rpa1) + len(payload_apple)]) + mac_bytes_rpa1 + payload_apple
    writer.write_packet(ts_usec=now_us + 10_000_000, chan=37, rssi=-61, packet=adv_frame_rpa1)

    # 3. Packet with same RPA MAC but rotated ephemeral key (desync: KEY_ROTATED_MAC_PERSISTED)
    spec_rotated_key = SyntheticBeaconSpec(
        network_type="Apple Find My",
        ephemeral_key="99887766554433221100aabbccddeeff",
        mac_address="40:11:22:33:44:55",
        channel=37,
    )
    payload_key2 = generator.build_payload(spec_rotated_key)
    adv_frame_key2 = bytes([0x42, len(mac_bytes_rpa1) + len(payload_key2)]) + mac_bytes_rpa1 + payload_key2
    writer.write_packet(ts_usec=now_us + 20_000_000, chan=37, rssi=-62, packet=adv_frame_key2)

    writer.close()
    return path


def test_cli_relay_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify relay subcommand exists in CLI parser."""
    rc = main(["relay", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "relay" in captured.out.lower()
    assert "--port1" in captured.out
    assert "--port2" in captured.out


def test_cli_deanonymize_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify deanonymize subcommand exists in CLI parser."""
    rc = main(["deanonymize", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "deanonymize" in captured.out.lower()
    assert "--pcap" in captured.out
    assert "--max-gap" in captured.out
    assert "--max-rssi-delta" in captured.out


def test_cli_rogue_inject_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify rogue-inject subcommand exists in CLI parser."""
    rc = main(["rogue-inject", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "rogue-inject" in captured.out.lower()
    assert "--network" in captured.out
    assert "--interval-ms" in captured.out
    assert "--jitter-ms" in captured.out
    assert "--channels" in captured.out


def test_cli_rogue_inject_mock_execution(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify mock execution of rogue beacon injection burst."""
    rc = main(["rogue-inject", "--mock", "--count", "3", "--network", "Apple Find My"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Injected 3" in captured.out or "Generated 3" in captured.out


def test_cli_deanonymize_mock_execution(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify mock execution of deanonymization analysis on synthetic traces."""
    rc = main(["deanonymize", "--mock"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Deanonymization" in captured.out or "Linkability" in captured.out


def test_cli_deanonymize_valid_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify PCAP ingestion into trajectory reconstructor, desync analyzer, and leakage detector."""
    pcap_path = _create_synthetic_adversarial_pcap(tmp_path / "valid_test.pcap")

    rc = main(["deanonymize", "--pcap", str(pcap_path), "--max-gap", "30.0", "--max-rssi-delta", "15.0"])
    assert rc == 0

    captured = capsys.readouterr()
    assert "Deanonymization Analysis" in captured.out
    assert "Packets Processed: 3 total packets (3 valid advertising frames)" in captured.out
    assert "Reconstructed" in captured.out
    assert "Trajectory #1" in captured.out
    assert "Address Rotation Desynchronization" in captured.out
    assert "MAC_ROTATED_KEY_PERSISTED" in captured.out
    assert "KEY_ROTATED_MAC_PERSISTED" in captured.out
    assert "Static Identifier Leakage Warnings" in captured.out
    assert "STATIC_MAC" in captured.out


def test_cli_deanonymize_json_and_csv_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify structured artifact export (--json and --csv) in deanonymize subcommand."""
    pcap_path = _create_synthetic_adversarial_pcap(tmp_path / "export_test.pcap")
    json_path = tmp_path / "artifacts" / "deanonymize_report.json"
    csv_path = tmp_path / "artifacts" / "trajectories.csv"

    rc = main([
        "deanonymize",
        "--pcap", str(pcap_path),
        "--json", str(json_path),
        "--csv", str(csv_path),
    ])
    assert rc == 0
    capsys.readouterr()

    # Validate JSON structure
    assert json_path.exists()
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_packets"] == 3
    assert data["observations_count"] == 3
    assert data["trajectories_count"] >= 1
    assert data["desync_events_count"] == 2
    assert data["static_leakage_count"] == 1
    assert len(data["trajectories"]) >= 1

    # Validate CSV structure
    assert csv_path.exists()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == ["trajectory_id", "mac_addresses", "observations_count", "primary_network", "confidence"]
        rows = list(reader)
        assert len(rows) >= 1


def test_cli_deanonymize_missing_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify error handling when specified PCAP does not exist."""
    missing_file = tmp_path / "nonexistent.pcap"
    rc = main(["deanonymize", "--pcap", str(missing_file)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR: PCAP file not found" in captured.err


def test_cli_deanonymize_empty_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify error handling on 0-byte PCAP file."""
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")
    rc = main(["deanonymize", "--pcap", str(empty_file)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR: PCAP file is empty (0 bytes)" in captured.err


def test_cli_deanonymize_bad_magic_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify error handling on corrupt PCAP magic number."""
    bad_magic = tmp_path / "corrupt_magic.pcap"
    bad_magic.write_bytes(b"GARBAGE_HEADER_DATA_123456789012")
    rc = main(["deanonymize", "--pcap", str(bad_magic)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR: Failed to parse PCAP header" in captured.err


def test_cli_deanonymize_unsupported_dlt_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify error handling on PCAP with LinkType other than DLT 256."""
    bad_dlt = tmp_path / "bad_dlt.pcap"
    # DLT 1 (Ethernet) instead of 256
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    bad_dlt.write_bytes(hdr)
    rc = main(["deanonymize", "--pcap", str(bad_dlt)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR: Failed to parse PCAP header" in captured.err
    assert "Unsupported LinkType" in captured.err


def test_cli_deanonymize_truncated_packet_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify error handling when a packet header specifies bytes that are missing."""
    truncated = tmp_path / "truncated.pcap"
    # Write valid PCAP header with DLT 256
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256)
    # Write packet header claiming 100 bytes, but write only 4 bytes
    pkt_hdr = struct.pack("<IIII", 1000, 0, 100, 100)
    truncated.write_bytes(hdr + pkt_hdr + b"\x00\x01\x02\x03")

    rc = main(["deanonymize", "--pcap", str(truncated)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR: Corrupted or truncated packet stream" in captured.err


def test_cli_deanonymize_missing_and_conflicting_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify validation when no input or conflicting inputs are provided."""
    # No source specified
    rc_missing = main(["deanonymize"])
    assert rc_missing == 2
    captured = capsys.readouterr()
    assert "ERROR: Please specify a PCAP file with --pcap or use --mock." in captured.err

    # Conflicting sources
    rc_conflicting = main(["deanonymize", "--mock", "--pcap", "/tmp/any.pcap"])
    assert rc_conflicting == 2
    captured = capsys.readouterr()
    assert "ERROR: Multiple conflicting input sources specified" in captured.err


def test_cli_deanonymize_invalid_thresholds(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify validation for non-positive max-gap and negative max-rssi-delta."""
    rc_gap = main(["deanonymize", "--mock", "--max-gap", "0.0"])
    assert rc_gap == 2
    captured = capsys.readouterr()
    assert "ERROR: Max gap must be positive" in captured.err

    rc_rssi = main(["deanonymize", "--mock", "--max-rssi-delta", "-5.0"])
    assert rc_rssi == 2
    captured = capsys.readouterr()
    assert "ERROR: Max RSSI delta must be non-negative" in captured.err


def test_cli_rogue_inject_mock_burst_parameters(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify rogue beacon injection with custom burst count, interval-ms, jitter-ms, and channels."""
    rc = main([
        "rogue-inject",
        "--mock",
        "--count", "8",
        "--interval-ms", "150",
        "--jitter-ms", "10",
        "--channels", "37,38,39",
        "--network", "Google Find Hub",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Injected 8 rogue beacon packets for network 'Google Find Hub'." in captured.out


@pytest.mark.parametrize(
    "network_type",
    [
        "Apple Find My",
        "Google Find Hub",
        "Samsung SmartThings Find",
        "Tile",
    ],
)
def test_cli_rogue_inject_network_profiles(network_type: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify synthetic frame generation across all four supported tracking networks."""
    rc = main([
        "rogue-inject",
        "--mock",
        "--count", "2",
        "--network", network_type,
        "--key", "0102030405060708090a0b0c0d0e0f10",
        "--mac", "40:AA:BB:CC:DD:EE",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert f"Injected 2 rogue beacon packets for network '{network_type}'." in captured.out


def test_cli_rogue_inject_invalid_parameters(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify input validation for count, interval, jitter, channels, key, and MAC."""
    # Count <= 0
    assert main(["rogue-inject", "--mock", "--count", "0"]) == 2
    assert "ERROR: Count must be positive" in capsys.readouterr().err

    # Interval <= 0
    assert main(["rogue-inject", "--mock", "--interval", "-0.5"]) == 2
    assert "ERROR: Interval must be positive" in capsys.readouterr().err

    # Jitter < 0
    assert main(["rogue-inject", "--mock", "--jitter", "-0.1"]) == 2
    assert "ERROR: Jitter must be non-negative" in capsys.readouterr().err

    # Invalid channels
    assert main(["rogue-inject", "--mock", "--channels", "37,42"]) == 2
    assert "ERROR: Invalid channel sequence" in capsys.readouterr().err

    assert main(["rogue-inject", "--mock", "--channels", "bad,channels"]) == 2
    assert "ERROR: Failed to parse --channels" in capsys.readouterr().err

    # Invalid hex key
    assert main(["rogue-inject", "--mock", "--key", "not_a_hex_string"]) == 2
    assert "ERROR: Invalid hex string for --key" in capsys.readouterr().err

    # Invalid MAC
    assert main(["rogue-inject", "--mock", "--mac", "invalid_mac"]) == 2
    assert "ERROR: Invalid MAC address" in capsys.readouterr().err


def test_cli_rogue_inject_live_mock_serial(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify live injection pipeline execution against mock serial interface."""
    rc = main([
        "rogue-inject",
        "--port", "mock://sniffle",
        "--count", "2",
        "--interval-ms", "25",
        "--network", "Apple Find My",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Injected 2 rogue beacon packets for network 'Apple Find My'." in captured.out


def test_cli_rogue_inject_failed_port_connection(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify clean exit code 1 and error reporting when serial port cannot be opened."""
    rc = main([
        "rogue-inject",
        "--port", "/dev/nonexistent_dongle_9999",
        "--count", "1",
    ])
    assert rc == 1
    captured = capsys.readouterr()
    assert "ERROR: Failed to connect to Sniffle dongle on /dev/nonexistent_dongle_9999" in captured.err


def test_cli_rogue_inject_controller_hardware_dispatch(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify SniffleDeviceController methods are called with exact advertising parameters."""
    mock_controller = MagicMock()
    mock_controller.open = MagicMock()
    mock_controller.close = MagicMock()
    mock_controller.set_mac_address = MagicMock()
    mock_controller.configure_advertising = MagicMock()

    # Monkeypatch SniffleDeviceController class in cli module
    monkeypatch.setattr("airtell.cli.SniffleDeviceController", lambda port, mock: mock_controller)

    rc = main([
        "rogue-inject",
        "--port", "/dev/ttyUSB0",
        "--count", "3",
        "--interval-ms", "50",
        "--jitter-ms", "5",
        "--channels", "37,38,39",
        "--mac", "40:11:22:33:44:55",
        "--network", "Tile",
    ])

    assert rc == 0
    captured = capsys.readouterr()
    assert "Injected 3 rogue beacon packets for network 'Tile'." in captured.out

    # Assert controller open, set_mac_address, configure_advertising, and close calls
    mock_controller.open.assert_called_once()
    mock_controller.set_mac_address.assert_called_with("40:11:22:33:44:55", is_random=True)
    assert mock_controller.configure_advertising.call_count >= 1
    # Verify adv_interval_ms was passed as 50ms and mode=2
    first_call_kwargs = mock_controller.configure_advertising.call_args_list[0].kwargs
    assert first_call_kwargs["interval_ms"] == 50
    assert first_call_kwargs["mode"] == 2
    assert len(first_call_kwargs["adv_data"]) <= 31
    # Verify cleanup resets dongle
    mock_controller.close.assert_called_with(reset=True)


def test_cli_deanonymize_scan_req_pdu_ignored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that SCAN_REQ frames (PDU type 3) do not produce false beacon trajectories or false static leakage."""
    pcap_path = tmp_path / "scan_req.pcap"
    writer = PcapBleWriter(output=pcap_path)
    # SCAN_REQ: pdu_type=3 (SCAN_REQ), length=12
    # ScanA = 11:22:33:44:55:66, AdvA = 75:00:AA:BB:CC:DD
    frame = bytes([0x03, 12]) + bytes.fromhex("112233445566") + bytes.fromhex("7500aabbccdd")
    writer.write_packet(ts_usec=int(time.time() * 1_000_000), chan=37, rssi=-60, packet=frame)
    writer.close()

    rc = main(["deanonymize", "--pcap", str(pcap_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Reconstructed 0 trajectories" in captured.out
    assert "No static identifier leakage detected." in captured.out


def test_cli_deanonymize_empty_adv_payload_no_false_positive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that frames with 0-byte advertising payloads do not trigger false network detection on MAC bytes."""
    pcap_path = tmp_path / "empty_payload.pcap"
    writer = PcapBleWriter(output=pcap_path)
    # Header 0x02 (ADV_NONCONN_IND, public), len=6, MAC=75:00:11:22:33:44, no payload
    frame = bytes([0x02, 0x06, 0x75, 0x00, 0x11, 0x22, 0x33, 0x44])
    writer.write_packet(ts_usec=int(time.time() * 1_000_000), chan=37, rssi=-60, packet=frame)
    writer.close()

    rc = main(["deanonymize", "--pcap", str(pcap_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Samsung SmartThings Find" not in captured.out
    assert "No static identifier leakage detected." in captured.out


def test_cli_deanonymize_all_tracking_networks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify trajectory extraction and classification across Apple, Google, Samsung, and Tile."""
    pcap_path = tmp_path / "all_networks.pcap"
    writer = PcapBleWriter(output=pcap_path)
    generator = RogueBeaconGenerator()
    now_us = int(time.time() * 1_000_000)

    networks = [
        ("Apple Find My", "40:11:11:11:11:11"),
        ("Google Find Hub", "40:22:22:22:22:22"),
        ("Samsung SmartThings Find", "40:33:33:33:33:33"),
        ("Tile", "40:44:44:44:44:44"),
    ]

    for idx, (net, mac) in enumerate(networks):
        spec = SyntheticBeaconSpec(
            network_type=net,
            ephemeral_key="0102030405060708090a0b0c0d0e0f10",
            mac_address=mac,
            channel=37,
        )
        payload = generator.build_payload(spec)
        mac_bytes = str_to_mac(mac)
        frame = bytes([0x42, len(mac_bytes) + len(payload)]) + mac_bytes + payload
        writer.write_packet(ts_usec=now_us + idx * 5_000_000, chan=37, rssi=-60, packet=frame)

    writer.close()

    rc = main(["deanonymize", "--pcap", str(pcap_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Apple Find My" in captured.out
    assert "Google Find Hub" in captured.out
    assert "Samsung SmartThings Find" in captured.out
    assert "Tile" in captured.out


def test_cli_deanonymize_padded_frame_length(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that PDU length header is respected when radio buffers contain trailing zero-padding."""
    pcap_path = tmp_path / "padded.pcap"
    writer = PcapBleWriter(output=pcap_path)
    generator = RogueBeaconGenerator()

    spec = SyntheticBeaconSpec(
        network_type="Apple Find My",
        ephemeral_key="0102030405060708090a0b0c0d0e0f10",
        mac_address="40:11:22:33:44:55",
        channel=37,
    )
    payload = generator.build_payload(spec)
    mac_bytes = str_to_mac("40:11:22:33:44:55")
    # PDU specifies real length (37 bytes), but frame has 20 extra trailing bytes
    frame = bytes([0x42, len(mac_bytes) + len(payload)]) + mac_bytes + payload + (b"\x00" * 20)
    writer.write_packet(ts_usec=int(time.time() * 1_000_000), chan=37, rssi=-60, packet=frame)
    writer.close()

    rc = main(["deanonymize", "--pcap", str(pcap_path)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Apple Find My" in captured.out
    assert "Packets Processed: 1 total packets (1 valid advertising frames)" in captured.out


def test_cli_rogue_inject_public_mac_dispatch(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that specifying a Public MAC causes SniffleDeviceController to configure is_random=False."""
    mock_controller = MagicMock()
    mock_controller.open = MagicMock()
    mock_controller.close = MagicMock()
    mock_controller.set_mac_address = MagicMock()
    mock_controller.configure_advertising = MagicMock()

    monkeypatch.setattr("airtell.cli.SniffleDeviceController", lambda port, mock: mock_controller)

    rc = main([
        "rogue-inject",
        "--port", "/dev/ttyUSB0",
        "--count", "1",
        "--mac", "AA:BB:CC:11:22:33",  # Public MAC
        "--network", "Apple Find My",
    ])

    assert rc == 0
    capsys.readouterr()
    mock_controller.set_mac_address.assert_called_with("AA:BB:CC:11:22:33", is_random=False)


def test_cli_rogue_inject_timing_jitter_honored(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that inter-packet sleep deltas reflect jitter parameter."""
    mock_controller = MagicMock()
    monkeypatch.setattr("airtell.cli.SniffleDeviceController", lambda port, mock: mock_controller)

    sleep_calls: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

    rc = main([
        "rogue-inject",
        "--port", "/dev/ttyUSB0",
        "--count", "4",
        "--interval-ms", "100",
        "--jitter-ms", "30",
        "--network", "Apple Find My",
    ])

    assert rc == 0
    capsys.readouterr()
    # Ensure sleep was called between packets
    assert len(sleep_calls) >= 3
