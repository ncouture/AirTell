import sys
from unittest.mock import MagicMock, patch

from airtell.scripts.ble_parser import run_sniffle_sniffer


def test_run_sniffle_sniffer_uses_sys_executable_and_cleans_up():
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_proc.poll.return_value = None

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
        run_sniffle_sniffer("/dev/ttyUSB9", 38)
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == sys.executable
        assert cmd[1].endswith("sniff_receiver.py")
        assert "-s" in cmd and "/dev/ttyUSB9" in cmd
        assert "-c" in cmd and "38" in cmd
        mock_proc.terminate.assert_called_once()
