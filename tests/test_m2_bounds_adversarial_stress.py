"""Milestone M2 Bounds, Error Handling, and Reliability Adversarial Stress Tests.

Author: Challenger M2-2 (Adversarial Critic)
Target Scope:
  - Issue #103: MAC address validation in sniff_receiver and parser (0B, 5B, 7B, invalid hex)
  - Issue #104: devName buffer clamping in advertiser (0B, 29B, 30B, 1000B, multibyte UTF-8)
  - Issue #106: PCAP global header bounds check (<24B, corrupt magic, bad DLT, pcap_decoder)
  - Issue #102: Process cleanup and sys.executable in ble_parser and script runners
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from sniffle.pcap import PcapBleReader as SnifflePcapReader

from airtell.scripts import advertiser, ble_parser, pcap_decoder, sniff_receiver
from airtell.scripts.ble_antistalking_tracker import SniffleLineParser
from airtell.sniff.pcap import (
    GLOBAL_HEADER_FORMAT,
    PCAP_MAGIC_USEC,
)
from airtell.sniff.pcap import (
    PcapBleReader as AirtellPcapReader,
)


# ===========================================================================
# 1. MAC Address Validation Adversarial Stress Tests (#103)
# ===========================================================================
class TestMacValidationAdversarialStress:
    """Empirical verification of MAC address bounds and format validation."""

    @pytest.mark.parametrize(
        "mac_str,desc",
        [
            ("11:22:33:44:55", "5 bytes (under length)"),
            ("11:22:33:44:55:66:77", "7 bytes (over length)"),
            ("11:22:33:44:55:GG", "invalid hex character 'GG'"),
            ("11:22:33:44:55:ZZ", "invalid hex character 'ZZ'"),
            ("11:22:33:44:55:--", "invalid hex character '--'"),
            ("11:22:33:44:55:", "trailing colon / empty final byte"),
            (":11:22:33:44:55:66", "leading colon / empty initial byte"),
            ("11::33:44:55:66", "middle empty byte"),
            ("11-22-33-44-55-66", "dash delimited instead of colon"),
            ("11.22.33.44.55.66", "dot delimited instead of colon"),
            ("112233445566", "raw 12-char hex without colons"),
            ("garbage_mac_string", "arbitrary alphanumeric text"),
            ("11:22:33:44:55:  ", "whitespace in hex byte"),
        ],
    )
    def test_sniff_receiver_rejects_malformed_mac(self, mac_str: str, desc: str) -> None:
        """Verify sniff_receiver rejects malformed MACs with UsageError instead of crashing."""
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = sniff_receiver.SourceDone()

        with patch("sys.argv", ["sniff_receiver.py", "-s", "/dev/null", "-m", mac_str]):
            with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=mock_hw):
                with pytest.raises(sniff_receiver.UsageError, match="MAC must be 6 colon-separated hex bytes"):
                    sniff_receiver.main()

    def test_sniff_receiver_empty_mac_string_behavior(self) -> None:
        """Adversarial check: test empty string '' passed to --mac.

        Documenting behavior: 'elif args.mac:' treats '' as falsy,
        causing it to bypass the MAC filter entirely rather than raising UsageError.
        """
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = sniff_receiver.SourceDone()

        with patch("sys.argv", ["sniff_receiver.py", "-s", "/dev/null", "-m", ""]):
            with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=mock_hw):
                sniff_receiver.main()
                mock_hw.setup_sniffer.assert_called_once()
                # Document finding: targ_mac was bypassed and left None
                assert mock_hw.setup_sniffer.call_args[1]["targ_mac"] is None

    def test_sniff_receiver_valid_mac_reversal(self) -> None:
        """Verify valid 6-byte MAC strings are parsed into reversed integer byte arrays."""
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = sniff_receiver.SourceDone()

        with patch("sys.argv", ["sniff_receiver.py", "-s", "/dev/null", "-m", "01:23:45:67:89:AB"]):
            with patch("airtell.scripts.sniff_receiver.make_sniffle_hw", return_value=mock_hw):
                sniff_receiver.main()
                mock_hw.setup_sniffer.assert_called_once()
                targ_mac = mock_hw.setup_sniffer.call_args[1]["targ_mac"]
                # Hardware expects little-endian reversed byte list
                assert targ_mac == [0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]

    def test_sniffle_line_parser_mac_regex_bounds(self) -> None:
        """Verify SniffleLineParser AdvA regex bounds: only matches exact 17-char colon hex."""
        parser = SniffleLineParser()

        # Valid AdvA line
        parser.feed("AdvA: AA:BB:CC:DD:EE:FF (Random)")
        assert parser._mac == "AA:BB:CC:DD:EE:FF"

        # Under-length AdvA line (5 bytes)
        parser = SniffleLineParser()
        parser.feed("AdvA: AA:BB:CC:DD:EE (Random)")
        assert parser._mac is None

        # Over-length AdvA line (7 bytes)
        parser = SniffleLineParser()
        parser.feed("AdvA: AA:BB:CC:DD:EE:FF:00 (Random)")
        # AdvA regex matches the first 17 chars
        assert parser._mac == "AA:BB:CC:DD:EE:FF"

        # Invalid hex characters
        parser = SniffleLineParser()
        parser.feed("AdvA: GG:HH:II:JJ:KK:LL (Random)")
        assert parser._mac is None


# ===========================================================================
# 2. devName Buffer Clamping Adversarial Stress Tests (#104)
# ===========================================================================
class TestDevNameClampingAdversarialStress:
    """Empirical verification of devName clamping to 29 bytes in advertiser."""

    @pytest.mark.parametrize(
        "name_str,expected_name_len,expect_warning",
        [
            ("", 0, False),  # 0-byte
            ("A" * 15, 15, False),  # 15-byte
            ("B" * 29, 29, False),  # Exactly 29 bytes (boundary)
            ("C" * 30, 29, True),  # 30 bytes (boundary + 1, triggers clamp)
            ("D" * 50, 29, True),  # 50 bytes
            ("E" * 1000, 29, True),  # 1000 bytes (stress payload)
        ],
    )
    def test_advertiser_devname_clamping(self, name_str: str, expected_name_len: int, expect_warning: bool) -> None:
        """Verify devName clamping and warning emissions across boundary lengths."""
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["advertiser.py", "-s", "/dev/null", "-n", name_str]):
            with patch("airtell.scripts.advertiser.SniffleHW", return_value=mock_hw):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    try:
                        advertiser.main()
                    except KeyboardInterrupt:
                        pass

                    mock_hw.cmd_advertise.assert_called_once()
                    _, scan_rsp = mock_hw.cmd_advertise.call_args[0]
                    stderr_content = mock_stderr.getvalue()

                    # Total scan_rsp length must never exceed 31 bytes
                    assert len(scan_rsp) <= 31, f"scan_rsp length {len(scan_rsp)} exceeds 31"
                    # Structure: [length, 0x09, ...name_bytes...]
                    assert scan_rsp[0] == expected_name_len + 1
                    assert scan_rsp[1] == 0x09
                    assert scan_rsp[2:] == name_str[:expected_name_len].encode("utf-8")

                    if expect_warning:
                        assert "Warning: Device name exceeds 29 bytes" in stderr_content
                        assert "Truncating to 29 bytes" in stderr_content
                    else:
                        assert "Warning: Device name exceeds 29 bytes" not in stderr_content

    def test_advertiser_devname_multibyte_utf8_clamping(self) -> None:
        """Verify advertiser clamps multi-byte UTF-8 string to <= 29 bytes without crashing."""
        # 10 crab emojis: each is 4 bytes -> 40 bytes in UTF-8
        crab_name = "🦀" * 10
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["advertiser.py", "-s", "/dev/null", "-n", crab_name]):
            with patch("airtell.scripts.advertiser.SniffleHW", return_value=mock_hw):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    try:
                        advertiser.main()
                    except KeyboardInterrupt:
                        pass

                    _, scan_rsp = mock_hw.cmd_advertise.call_args[0]
                    assert len(scan_rsp) <= 31
                    assert len(scan_rsp[2:]) == 29
                    assert "Truncating to 29 bytes" in mock_stderr.getvalue()

    def test_advertiser_default_devname(self) -> None:
        """Verify advertiser defaults to 'NCC Goat' (8 bytes) when no name argument is given."""
        mock_hw = MagicMock()
        mock_hw.recv_and_decode.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["advertiser.py", "-s", "/dev/null"]):
            with patch("airtell.scripts.advertiser.SniffleHW", return_value=mock_hw):
                try:
                    advertiser.main()
                except KeyboardInterrupt:
                    pass

                _, scan_rsp = mock_hw.cmd_advertise.call_args[0]
                assert scan_rsp[2:] == b"NCC Goat"
                assert len(scan_rsp) == 1 + 1 + 8  # 10 bytes


# ===========================================================================
# 3. PCAP Global Header Bounds Adversarial Stress Tests (#106)
# ===========================================================================
class TestPcapGlobalHeaderBoundsAdversarialStress:
    """Empirical verification of PCAP global header 24-byte boundary validation."""

    @pytest.mark.parametrize(
        "header_bytes,desc",
        [
            (b"", "0 bytes (empty file)"),
            (b"A" * 1, "1 byte"),
            (b"A" * 10, "10 bytes (half header)"),
            (b"A" * 23, "23 bytes (off-by-one boundary)"),
        ],
    )
    def test_airtell_reader_rejects_truncated_global_headers(self, header_bytes: bytes, desc: str) -> None:
        """Verify Airtell PcapBleReader raises ValueError on global headers < 24 bytes."""
        stream = io.BytesIO(header_bytes)
        with pytest.raises(ValueError, match="File too short for PCAP global header"):
            AirtellPcapReader(stream)

    @pytest.mark.parametrize(
        "header_bytes,desc",
        [
            (b"", "0 bytes"),
            (b"X" * 10, "10 bytes"),
            (b"Y" * 23, "23 bytes"),
        ],
    )
    def test_sniffle_reader_rejects_truncated_global_headers(self, header_bytes: bytes, desc: str) -> None:
        """Verify Sniffle PcapBleReader raises ValueError on global headers < 24 bytes."""
        stream = io.BytesIO(header_bytes)
        with pytest.raises(ValueError, match="Unexpected PCAP header"):
            SnifflePcapReader(stream)

    @pytest.mark.parametrize(
        "bad_magic_bytes,desc",
        [
            (b"\x00\x00\x00\x00" + b"\x00" * 20, "null magic 0x00000000"),
            (b"\xde\xad\xbe\xef" + b"\x00" * 20, "corrupted magic 0xEFBEADDE"),
            (b"\x12\x34\x56\x78" + b"\x00" * 20, "arbitrary magic 0x78563412"),
        ],
    )
    def test_airtell_reader_rejects_corrupted_magic(self, bad_magic_bytes: bytes, desc: str) -> None:
        """Verify Airtell PcapBleReader raises ValueError on invalid PCAP magic numbers."""
        stream = io.BytesIO(bad_magic_bytes)
        with pytest.raises(ValueError, match="Invalid PCAP magic"):
            AirtellPcapReader(stream)

    def test_airtell_reader_rejects_invalid_dlt(self) -> None:
        """Verify Airtell PcapBleReader raises ValueError if DLT is not 256."""
        import struct

        bad_dlt_hdr = struct.pack(
            GLOBAL_HEADER_FORMAT,
            PCAP_MAGIC_USEC,
            2,
            4,
            0,
            0,
            65535,
            1,  # DLT 1 = Ethernet, not 256 (Bluetooth LE)
        )
        stream = io.BytesIO(bad_dlt_hdr)
        with pytest.raises(ValueError, match="Unsupported LinkType: 1, expected 256"):
            AirtellPcapReader(stream)

    @pytest.mark.parametrize(
        "bad_header,desc",
        [
            (b"", "0-byte file"),
            (b"A" * 10, "10-byte file"),
            (b"B" * 23, "23-byte file"),
            (b"\x00" * 24, "24-byte zeroed header"),
            (b"\xde\xad\xbe\xef" + b"\x00" * 20, "24-byte corrupt magic"),
        ],
    )
    def test_pcap_decoder_cli_on_corrupt_files(self, bad_header: bytes, desc: str) -> None:
        """Verify pcap_decoder.py safely raises ValueError and does not crash on struct.error."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(bad_header)
            temp_path = f.name

        try:
            with patch("sys.argv", ["pcap_decoder.py", temp_path]):
                with pytest.raises(ValueError):
                    pcap_decoder.main()
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


# ===========================================================================
# 4. Process Cleanup and sys.executable Adversarial Stress Tests (#102)
# ===========================================================================
class TestProcessCleanupAndSysExecutableStress:
    """Empirical verification of subprocess execution and orphan cleanup."""

    def test_ble_parser_uses_sys_executable_and_absolute_path(self) -> None:
        """Verify ble_parser.py invokes child script with sys.executable and absolute path."""
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.poll.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            ble_parser.run_sniffle_sniffer("/dev/ttyUSB1", 38)
            cmd = mock_popen.call_args[0][0]

            assert cmd[0] == sys.executable, f"First arg is not sys.executable: {cmd[0]}"
            assert os.path.isabs(cmd[1]), f"Script path is not absolute: {cmd[1]}"
            assert cmd[1].endswith("sniff_receiver.py")
            assert "-s" in cmd and "/dev/ttyUSB1" in cmd
            assert "-c" in cmd and "38" in cmd

    def test_ble_parser_cleans_up_process_on_keyboard_interrupt(self) -> None:
        """Verify ble_parser terminates running child process upon KeyboardInterrupt."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process is still running

        def raise_ki():
            yield "Line 1\n"
            raise KeyboardInterrupt()

        mock_proc.stdout = raise_ki()

        with patch("subprocess.Popen", return_value=mock_proc):
            ble_parser.run_sniffle_sniffer("/dev/ttyUSB0", 37)

            mock_proc.terminate.assert_called_once()
            mock_proc.wait.assert_called_once_with(timeout=2)
            mock_proc.kill.assert_not_called()

    def test_ble_parser_kills_stubborn_child_on_timeout(self) -> None:
        """Verify ble_parser escalates to SIGKILL if child ignores SIGTERM (TimeoutExpired)."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process still running

        def raise_ki():
            yield "Line 1\n"
            raise KeyboardInterrupt()

        mock_proc.stdout = raise_ki()
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=["mock"], timeout=2),
            None,
        ]

        with patch("subprocess.Popen", return_value=mock_proc):
            ble_parser.run_sniffle_sniffer("/dev/ttyUSB0", 37)

            mock_proc.terminate.assert_called_once()
            mock_proc.kill.assert_called_once()
            assert mock_proc.wait.call_count == 2

    def test_ble_parser_no_cleanup_if_process_already_exited(self) -> None:
        """Verify ble_parser does not attempt terminate/kill if child process already finished."""
        mock_proc = MagicMock()
        mock_proc.stdout = iter(["Header: RSSI: -50\n", "AdvA: 11:22:33:44:55:66\n"])
        mock_proc.poll.return_value = 0  # Exited cleanly with returncode 0

        with patch("subprocess.Popen", return_value=mock_proc):
            ble_parser.run_sniffle_sniffer("/dev/ttyUSB0", 37)

            mock_proc.terminate.assert_not_called()
            mock_proc.kill.assert_not_called()
