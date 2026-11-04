from unittest.mock import MagicMock, patch

from airtell.scripts.advertiser import main


def test_advertiser_truncates_long_name(capsys):
    long_name = "A" * 50
    mock_hw = MagicMock()
    mock_hw.recv_and_decode.side_effect = KeyboardInterrupt()

    with patch("sys.argv", ["advertiser.py", "-s", "/dev/null", "--name", long_name]):
        with patch("airtell.scripts.advertiser.SniffleHW", return_value=mock_hw):
            try:
                main()
            except KeyboardInterrupt:
                pass

            mock_hw.cmd_advertise.assert_called_once()
            _, scan_rsp = mock_hw.cmd_advertise.call_args[0]
            # 1 byte length + 1 byte type (0x09) + 29 bytes name = 31 bytes
            assert len(scan_rsp) == 31
            assert scan_rsp[2:] == b"A" * 29

            captured = capsys.readouterr()
            assert "Truncating to 29 bytes" in captured.err
