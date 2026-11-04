"""Unit tests verifying CLI Session runner classes and global state encapsulation."""

from unittest.mock import MagicMock, patch

from sniffle.packet_decoder import AdvertMessage

from airtell.scripts.advertiser import AdvertiserSession
from airtell.scripts.advertiser import reset_globals as adv_reset_globals
from airtell.scripts.initiator import InitiatorSession
from airtell.scripts.initiator import reset_globals as init_reset_globals
from airtell.scripts.relay_master import RelayMasterSession
from airtell.scripts.relay_master import reset_globals as master_reset_globals
from airtell.scripts.relay_slave import RelaySlaveSession
from airtell.scripts.relay_slave import reset_globals as slave_reset_globals
from airtell.scripts.scanner import ScannerSession
from airtell.scripts.scanner import reset_globals as scan_reset_globals
from airtell.scripts.sniff_receiver import SniffReceiverSession
from airtell.scripts.sniff_receiver import reset_globals as recv_reset_globals


def test_sniff_receiver_session_reentrancy():
    mock_hw = MagicMock()
    with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=mock_hw):
        session1 = SniffReceiverSession()
        session2 = SniffReceiverSession()
        assert session1 is not session2

        recv_reset_globals()


def test_scanner_session_isolation():
    session1 = ScannerSession()
    session2 = ScannerSession()

    mock_pkt = MagicMock(spec=AdvertMessage)
    mock_pkt.rssi = -60

    session1.advertisers["test_mac"] = MagicMock()
    assert "test_mac" not in session2.advertisers

    session1.reset()
    assert len(session1.advertisers) == 0
    scan_reset_globals()


def test_advertiser_session_lifecycle():
    session = AdvertiserSession()
    session.hw = MagicMock()
    session.reset()
    assert session.hw is None
    adv_reset_globals()


def test_initiator_session_lifecycle():
    session = InitiatorSession()
    session.hw = MagicMock()
    session._aa = 0x12345678
    session.msg_ctr = 42
    session.reset()
    assert session.hw is None
    assert session._aa == 0
    assert session.msg_ctr == 0
    init_reset_globals()


def test_relay_sessions_lifecycle():
    master = RelayMasterSession()
    master.hw = MagicMock()
    master.reset()
    assert master.hw is None
    master_reset_globals()

    slave = RelaySlaveSession()
    slave.hw = MagicMock()
    slave._aa = 0x87654321
    slave.reset()
    assert slave.hw is None
    assert slave._aa == 0
    slave_reset_globals()
