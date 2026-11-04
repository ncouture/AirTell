from unittest.mock import MagicMock, patch

import pytest

from airtell.scripts.sniff_receiver import SourceDone, UsageError, main


def test_sniff_receiver_invalid_mac_length():
    with patch("sys.argv", ["sniff_receiver.py", "-s", "/dev/null", "-m", "11:22:33"]):
        with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=MagicMock()):
            with pytest.raises(UsageError, match="MAC must be 6 colon-separated hex bytes"):
                main()


def test_sniff_receiver_valid_mac():
    mock_hw = MagicMock()
    mock_hw.recv_and_decode.side_effect = SourceDone()
    with patch("sys.argv", ["sniff_receiver.py", "-s", "/dev/null", "-m", "11:22:33:44:55:66"]):
        with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=mock_hw):
            main()
            mock_hw.setup_sniffer.assert_called_once()
            call_args = mock_hw.setup_sniffer.call_args[1]
            assert call_args["targ_mac"] == [0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
