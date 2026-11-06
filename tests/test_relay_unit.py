"""Unit tests for BLE pairing relay configuration, CLI argument parsing, and mock execution."""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sniffle.packet_decoder import LlControlMessage
from sniffle.relay_protocol import MessageType, RelaySocketWrapper

from airtell.adversarial.relay import (
    DualDongleRelayEngine,
    PairingRelayBridge,
    RelayConfig,
    RelayMasterRunner,
    RelaySlaveRunner,
    SMPPairingState,
    has_instant,
    is_param_req,
    parse_preloads,
)
from airtell.cli import create_parser
from airtell.cli import main as cli_main


def test_cli_relay_argument_parsing() -> None:
    """Verify that CLI parser correctly parses all relay sub-command flags and defaults."""
    parser = create_parser()

    # 1. Defaults
    args = parser.parse_args(["relay"])
    assert args.port1 == "/dev/ttyUSB0"
    assert args.port2 == "/dev/ttyUSB1"
    assert args.mac is None
    assert args.irk is None
    assert args.string is None
    assert args.public is False
    assert args.advchan == 37
    assert args.fastslave is False
    assert args.fastmaster is False
    assert args.preload is None
    assert args.pause is False
    assert args.quiet is False
    assert args.pcap is None
    assert args.duration_sec is None
    assert args.mock is False

    # 2. Custom flags and aliases
    args_custom = parser.parse_args([
        "relay",
        "-s", "/dev/ttyUSB2",
        "--port2", "/dev/ttyUSB3",
        "-m", "12:34:56:78:9A:BC",
        "-P",
        "-c", "38",
        "-f",
        "-F",
        "-Q", "6:6,39:6",
        "-p",
        "-q",
        "-o", "/tmp/relay_test.pcap",
        "--duration-sec", "2.5",
        "--mock",
    ])
    assert args_custom.port1 == "/dev/ttyUSB2"
    assert args_custom.port2 == "/dev/ttyUSB3"
    assert args_custom.mac == "12:34:56:78:9A:BC"
    assert args_custom.public is True
    assert args_custom.advchan == 38
    assert args_custom.fastslave is True
    assert args_custom.fastmaster is True
    assert args_custom.preload == "6:6,39:6"
    assert args_custom.pause is True
    assert args_custom.quiet is True
    assert args_custom.pcap == "/tmp/relay_test.pcap"
    assert args_custom.duration_sec == 2.5
    assert args_custom.mock is True


def test_relay_config_validation() -> None:
    """Verify RelayConfig validation constraints across channels, filters, and formats."""
    # 1. Valid default config
    cfg = RelayConfig(mock=True)
    cfg.validate()

    # 2. Invalid advertising channel
    with pytest.raises(ValueError, match="Advertising channel must be 37, 38, or 39"):
        RelayConfig(advchan=40, mock=True).validate()

    # 3. Mutually exclusive target filters
    with pytest.raises(ValueError, match="mutually exclusive"):
        RelayConfig(mac="11:22:33:44:55:66", irk="00112233445566778899aabbccddeeff", mock=True).validate()

    with pytest.raises(ValueError, match="mutually exclusive"):
        RelayConfig(mac="11:22:33:44:55:66", search_string="SmartLock", mock=True).validate()

    # 4. Public flag compatibility
    with pytest.raises(ValueError, match="IRK only works on RPAs"):
        RelayConfig(irk="00112233445566778899aabbccddeeff", is_public=True, mock=True).validate()

    with pytest.raises(ValueError, match="Cannot specify string search target MAC publicness"):
        RelayConfig(search_string="SmartLock", is_public=True, mock=True).validate()

    # 5. Invalid MAC format
    with pytest.raises(ValueError, match="MAC address must be 6 colon-separated hex bytes"):
        RelayConfig(mac="NOT:A:MAC", mock=True).validate()

    # 6. Invalid IRK format
    with pytest.raises(ValueError, match="IRK must be 32 hex characters"):
        RelayConfig(irk="short_irk", mock=True).validate()

    with pytest.raises(ValueError, match="Invalid hex string for IRK"):
        RelayConfig(irk="zz" * 16, mock=True).validate()

    # 7. Non-positive duration
    with pytest.raises(ValueError, match="duration_sec must be positive"):
        RelayConfig(duration_sec=-1.0, mock=True).validate()

    # 8. Port conflict in hardware mode
    with pytest.raises(ValueError, match="Conflicting port allocation"):
        RelayConfig(port1="/dev/ttyUSB0", port2="/dev/ttyUSB0", mock=False).validate()


def test_preload_parser() -> None:
    """Verify parsing of connection update preload strings."""
    assert parse_preloads(None) == []
    assert parse_preloads("") == []
    assert parse_preloads("6:6,39:6") == [(6, 6), (39, 6)]
    assert parse_preloads("  12:4  ,  24:8  ") == [(12, 4), (24, 8)]
    assert parse_preloads("malformed:string,12:4") == [(12, 4)]


def test_packet_type_helpers() -> None:
    """Verify Link Layer control packet type inspection helpers."""
    # LL_CONNECTION_UPDATE_IND (0x00), LL_CHANNEL_MAP_IND (0x01), LL_PHY_UPDATE_IND (0x18)
    pkt_update = MagicMock(spec=LlControlMessage)
    pkt_update.opcode = 0x00
    assert has_instant(pkt_update) is True
    assert is_param_req(pkt_update) is False

    pkt_param_req = MagicMock(spec=LlControlMessage)
    pkt_param_req.opcode = 0x0F
    assert has_instant(pkt_param_req) is False
    assert is_param_req(pkt_param_req) is True

    pkt_other = MagicMock(spec=LlControlMessage)
    pkt_other.opcode = 0x02
    assert has_instant(pkt_other) is False
    assert is_param_req(pkt_other) is False


def test_dual_dongle_relay_engine_mock_execution(tmp_path: Path) -> None:
    """Verify DualDongleRelayEngine runs cleanly in mock mode, forwarding synthetic frames."""
    pcap_file = tmp_path / "mock_relay.pcap"
    bridge = PairingRelayBridge()
    config = RelayConfig(
        mock=True,
        duration_sec=0.1,
        pcap_path=str(pcap_file),
    )
    engine = DualDongleRelayEngine(config=config, bridge=bridge)

    rc = engine.run()
    assert rc == 0
    assert bridge.current_pairing_state in (SMPPairingState.PAIRING_REQUESTED, SMPPairingState.PAIRING_RESPONSE)
    assert pcap_file.exists()
    assert pcap_file.stat().st_size > 0


def test_cli_handle_relay_mock_execution(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI airtell relay --mock executes and outputs status."""
    rc = cli_main(["relay", "--mock", "--duration-sec", "0.1"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Pairing Relay Testbed: Forwarded" in captured.out
    assert "State: PAIRING_RESPONSE" in captured.out


def test_cli_handle_relay_validation_error(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI handle_relay catches validation errors and returns exit code 2."""
    rc = cli_main([
        "relay",
        "--mock",
        "-m", "11:22:33:44:55:66",
        "-i", "00112233445566778899aabbccddeeff",
    ])
    assert rc == 2
    captured = capsys.readouterr()
    assert "ERROR:" in captured.err or "mutually exclusive" in captured.err


def test_relay_runners_socketpair_ipc() -> None:
    """Verify IPC handshake and Ping latency exchange between RelayMasterRunner and RelaySlaveRunner."""
    sock_master, sock_slave = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    conn_master = RelaySocketWrapper(sock_master, ("local", 0))
    conn_slave = RelaySocketWrapper(sock_slave, ("local", 0))

    stop_event = threading.Event()
    bridge = PairingRelayBridge()
    config = RelayConfig(mock=True)

    hw_master = MagicMock()
    hw_slave = MagicMock()

    master = RelayMasterRunner(
        hw=hw_master,
        conn=conn_master,
        config=config,
        bridge=bridge,
        stop_event=stop_event,
    )
    slave = RelaySlaveRunner(
        hw=hw_slave,
        conn=conn_slave,
        config=config,
        bridge=bridge,
        stop_event=stop_event,
    )

    # Master sends latency ping, slave receives and replies
    conn_master.send_msg(MessageType.PING, b"latency_test")
    mtype, body = conn_slave.recv_msg()
    assert mtype == MessageType.PING
    assert body == b"latency_test"

    conn_slave.send_msg(MessageType.PING, b"latency_test")
    mtype2, body2 = conn_master.recv_msg()
    assert mtype2 == MessageType.PING
    assert body2 == b"latency_test"

    # Stop and close sockets
    stop_event.set()
    sock_master.close()
    sock_slave.close()
    assert master.forwarded_packets_count == 0
    assert slave.forwarded_packets_count == 0
