"""Unit and integration test suite for Synthetic Trace Generator & PCAP Fixtures (Milestone 1).

Tests:
- Bit-accurate Link-Layer Control PDU generation (LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ,
  LL_START_ENC_RSP, LL_REJECT_IND, LL_REJECT_EXT_IND, LL_TERMINATE_IND, LL_CONNECTION_UPDATE_IND).
- Cryptographic CSRK AES-CMAC message authentication and ATT Signed Write (0xD2) construction.
- BAT / Allowlist advertising behaviors (ADV_DIRECT_IND, selective probe responses, timing).
- Valid DLT 256 PCAP generation readable by PcapBleReader.
- Subprocess Wireshark / tshark validation asserting zero malformed frame errors.
- In-memory PacketMessage and CapturedBlePacket conversion.
- Boundary conditions and edge cases (empty payloads, 32-bit counter rollover, invalid inputs).
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from airtell.protocol.mac import str_to_mac
from airtell.protocol.wire import PacketMessage
from airtell.sidechannel import (
    ATT_OPCODE_SIGNED_WRITE_CMD,
    ERROR_AUTHENTICATION_FAILURE,
    ERROR_PIN_OR_KEY_MISSING,
    ERROR_REMOTE_USER_TERMINATED,
    OPCODE_LL_ENC_REQ,
    OPCODE_LL_ENC_RSP,
    OPCODE_LL_REJECT_EXT_IND,
    OPCODE_LL_REJECT_IND,
    OPCODE_LL_START_ENC_REQ,
    OPCODE_LL_START_ENC_RSP,
    OPCODE_LL_TERMINATE_IND,
    ConnectionParameters,
    SyntheticEvent,
    SyntheticTraceGenerator,
    build_adv_direct_ind,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_connection_update_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_header,
    build_ll_reject_ext_ind,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_ll_terminate_ind,
    build_scan_req,
    build_scan_rsp,
    compute_csrk_mac,
    events_to_captured_packets,
    events_to_packet_messages,
    generate_bat_allowlist_trace,
    generate_csrk_trace,
    generate_encryption_trace,
    generate_synthetic_captured_stream,
    generate_synthetic_pcap,
    generate_synthetic_stream,
)
from airtell.sniff.pcap import BLE_ADV_AA, CapturedBlePacket, PcapBleReader

TEST_CSRK: bytes = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"


# =============================================================================
# 1. Link-Layer Control PDU Builder Tests
# =============================================================================
class TestLinkLayerControlPduBuilders:
    """Verifies bit-exact construction and layout of Link-Layer Control PDUs."""

    def test_ll_header_bits(self) -> None:
        """Data channel PDU header encodes LLID, NESN, SN, MD, and Length correctly."""
        # LLID = 3 (Control), NESN = 1, SN = 0, MD = 0, Length = 23
        hdr = build_ll_header(llid=3, length=23, nesn=1, sn=0)
        assert len(hdr) == 2
        # b0: 3 | (1 << 2) = 7 (0x07)
        assert hdr[0] == 0x07
        assert hdr[1] == 23

        # LLID = 2 (L2CAP Start), NESN = 1, SN = 1, MD = 1, Length = 50
        hdr2 = build_ll_header(llid=2, length=50, nesn=1, sn=1, md=1)
        # b0: 2 | (1 << 2) | (1 << 3) | (1 << 4) = 2 | 4 | 8 | 16 = 30 (0x1E)
        assert hdr2[0] == 0x1E
        assert hdr2[1] == 50

    def test_build_ll_enc_req_fields(self) -> None:
        """LL_ENC_REQ PDU contains 22B payload: Rand 8B, EDIV 2B, SKDm 8B, IVm 4B."""
        rand = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        ediv = 0xABCD
        skdm = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ivm = b"\xAA\xBB\xCC\xDD"

        pdu = build_ll_enc_req(rand=rand, ediv=ediv, skdm=skdm, ivm=ivm, nesn=0, sn=0)
        assert len(pdu) == 25  # 2B header + 1B opcode + 22B payload

        # Header: LLID 3, Length 23
        assert pdu[0] == 0x03
        assert pdu[1] == 23

        # Opcode
        assert pdu[2] == OPCODE_LL_ENC_REQ  # 0x03
        # Rand
        assert pdu[3:11] == rand
        # EDIV (2B little-endian)
        assert struct.unpack("<H", pdu[11:13])[0] == ediv
        # SKDm
        assert pdu[13:21] == skdm
        # IVm
        assert pdu[21:25] == ivm

    def test_build_ll_enc_req_validation_errors(self) -> None:
        """LL_ENC_REQ raises ValueError on invalid parameter lengths or ranges."""
        with pytest.raises(ValueError, match="Rand must be exactly 8 bytes"):
            build_ll_enc_req(rand=b"\x00" * 7)

        with pytest.raises(ValueError, match="EDIV must be a 16-bit unsigned integer"):
            build_ll_enc_req(ediv=0x10000)

        with pytest.raises(ValueError, match="SKDm must be exactly 8 bytes"):
            build_ll_enc_req(skdm=b"\x00" * 9)

        with pytest.raises(ValueError, match="IVm must be exactly 4 bytes"):
            build_ll_enc_req(ivm=b"\x00" * 3)

    def test_build_ll_enc_rsp_fields(self) -> None:
        """LL_ENC_RSP PDU contains 12B payload: SKDs 8B, IVs 4B."""
        skds = b"\x99\x88\x77\x66\x55\x44\x33\x22"
        ivs = b"\xDE\xAD\xBE\xEF"

        pdu = build_ll_enc_rsp(skds=skds, ivs=ivs, nesn=1, sn=0)
        assert len(pdu) == 15  # 2B header + 1B opcode + 12B payload

        # Header: LLID 3, NESN 1 -> 0x07, Length 13
        assert pdu[0] == 0x07
        assert pdu[1] == 13
        assert pdu[2] == OPCODE_LL_ENC_RSP  # 0x04
        assert pdu[3:11] == skds
        assert pdu[11:15] == ivs

    def test_build_ll_enc_rsp_validation_errors(self) -> None:
        """LL_ENC_RSP raises ValueError on invalid SKDs or IVs lengths."""
        with pytest.raises(ValueError, match="SKDs must be exactly 8 bytes"):
            build_ll_enc_rsp(skds=b"\x01")
        with pytest.raises(ValueError, match="IVs must be exactly 4 bytes"):
            build_ll_enc_rsp(ivs=b"\x01")

    def test_build_ll_start_enc_req_fields(self) -> None:
        """LL_START_ENC_REQ PDU contains 0B payload."""
        pdu = build_ll_start_enc_req(nesn=1, sn=1)
        assert len(pdu) == 3
        # Header: LLID 3, NESN 1, SN 1 -> 3 | 4 | 8 = 15 (0x0F), Length 1
        assert pdu[0] == 0x0F
        assert pdu[1] == 1
        assert pdu[2] == OPCODE_LL_START_ENC_REQ  # 0x05

    def test_build_ll_start_enc_rsp_fields(self) -> None:
        """LL_START_ENC_RSP PDU contains 0B payload (or 4B MIC if specified)."""
        # Unencrypted
        pdu_unenc = build_ll_start_enc_rsp(nesn=0, sn=1)
        assert len(pdu_unenc) == 3
        assert pdu_unenc[0] == (0x03 | 0x08)  # LLID 3, SN 1 -> 0x0B
        assert pdu_unenc[1] == 1
        assert pdu_unenc[2] == OPCODE_LL_START_ENC_RSP  # 0x06

        # Encrypted with 4-byte MIC
        mic = b"\x12\x34\x56\x78"
        pdu_enc = build_ll_start_enc_rsp(nesn=0, sn=0, mic=mic)
        assert len(pdu_enc) == 7
        assert pdu_enc[0] == 0x03
        assert pdu_enc[1] == 5
        assert pdu_enc[2] == OPCODE_LL_START_ENC_RSP
        assert pdu_enc[3:7] == mic

        with pytest.raises(ValueError, match="MIC must be exactly 4 bytes"):
            build_ll_start_enc_rsp(mic=b"\x01\x02")

    def test_build_ll_reject_ind_fields(self) -> None:
        """LL_REJECT_IND PDU contains 1B ErrorCode."""
        pdu = build_ll_reject_ind(error_code=ERROR_PIN_OR_KEY_MISSING, nesn=1, sn=0)
        assert len(pdu) == 4
        assert pdu[0] == 0x07
        assert pdu[1] == 2
        assert pdu[2] == OPCODE_LL_REJECT_IND  # 0x0D
        assert pdu[3] == ERROR_PIN_OR_KEY_MISSING  # 0x06

    def test_build_ll_reject_ext_ind_fields(self) -> None:
        """LL_REJECT_EXT_IND PDU contains 1B RejectOpcode and 1B ErrorCode."""
        pdu = build_ll_reject_ext_ind(
            reject_opcode=OPCODE_LL_ENC_REQ,
            error_code=ERROR_PIN_OR_KEY_MISSING,
            nesn=1,
            sn=0,
        )
        assert len(pdu) == 5
        assert pdu[0] == 0x07
        assert pdu[1] == 3
        assert pdu[2] == OPCODE_LL_REJECT_EXT_IND  # 0x11
        assert pdu[3] == OPCODE_LL_ENC_REQ  # 0x03
        assert pdu[4] == ERROR_PIN_OR_KEY_MISSING  # 0x06

    def test_build_ll_terminate_ind_fields(self) -> None:
        """LL_TERMINATE_IND PDU contains 1B ErrorCode."""
        pdu = build_ll_terminate_ind(error_code=ERROR_REMOTE_USER_TERMINATED)
        assert len(pdu) == 4
        assert pdu[0] == 0x03
        assert pdu[1] == 2
        assert pdu[2] == OPCODE_LL_TERMINATE_IND  # 0x02
        assert pdu[3] == ERROR_REMOTE_USER_TERMINATED  # 0x13

    def test_build_ll_connection_update_ind_fields(self) -> None:
        """LL_CONNECTION_UPDATE_IND PDU encodes 11B payload accurately."""
        pdu = build_ll_connection_update_ind(
            win_size=2,
            win_offset=4,
            interval=32,
            latency=1,
            timeout=200,
            instant=50,
        )
        assert len(pdu) == 14
        assert pdu[0] == 0x03
        assert pdu[1] == 12
        assert pdu[2] == 0x00  # Opcode 0x00
        assert pdu[3] == 2     # WinSize
        win_offset, interval, latency, timeout, instant = struct.unpack("<HHHHH", pdu[4:14])
        assert win_offset == 4
        assert interval == 32
        assert latency == 1
        assert timeout == 200
        assert instant == 50


# =============================================================================
# 2. CSRK Signed Write & Cryptographic MAC Tests
# =============================================================================
class TestCsrkSignedWriteBuilders:
    """Verifies AES-CMAC signature calculation and ATT_SIGNED_WRITE_CMD encapsulation."""

    def test_compute_csrk_mac_deterministic(self) -> None:
        """compute_csrk_mac returns exact 8-byte truncated AES-CMAC and is deterministic."""
        mac1 = compute_csrk_mac(
            csrk=TEST_CSRK,
            opcode=ATT_OPCODE_SIGNED_WRITE_CMD,
            handle=0x0012,
            value=b"\x01\x02\x03",
            counter=42,
        )
        mac2 = compute_csrk_mac(
            csrk=TEST_CSRK,
            opcode=ATT_OPCODE_SIGNED_WRITE_CMD,
            handle=0x0012,
            value=b"\x01\x02\x03",
            counter=42,
        )
        assert len(mac1) == 8
        assert mac1 == mac2

    def test_compute_csrk_mac_sensitivity(self) -> None:
        """Altering any component (key, handle, value, counter) modifies the MAC output."""
        base = compute_csrk_mac(TEST_CSRK, 0xD2, 0x0010, b"abc", 10)

        # Alter counter
        diff_counter = compute_csrk_mac(TEST_CSRK, 0xD2, 0x0010, b"abc", 11)
        assert base != diff_counter

        # Alter value
        diff_value = compute_csrk_mac(TEST_CSRK, 0xD2, 0x0010, b"abd", 10)
        assert base != diff_value

        # Alter handle
        diff_handle = compute_csrk_mac(TEST_CSRK, 0xD2, 0x0011, b"abc", 10)
        assert base != diff_handle

        # Alter CSRK
        alt_csrk = bytes([TEST_CSRK[0] ^ 0xFF]) + TEST_CSRK[1:]
        diff_key = compute_csrk_mac(alt_csrk, 0xD2, 0x0010, b"abc", 10)
        assert base != diff_key

    def test_build_att_signed_write_framing(self) -> None:
        """build_att_signed_write produces valid L2CAP B-frame and Data Channel framing."""
        val = b"SecretToken123"
        counter = 1000
        pdu = build_att_signed_write(
            csrk=TEST_CSRK,
            handle=0x002A,
            value=val,
            counter=counter,
            corrupt_mac=False,
            nesn=1,
            sn=0,
        )

        # 1. LL Data Channel header (2B)
        assert len(pdu) == 2 + 4 + (1 + 2 + len(val) + 12)
        llid = pdu[0] & 0x03
        assert llid == 2  # L2CAP Start
        ll_len = pdu[1]
        assert ll_len == 4 + 1 + 2 + len(val) + 12

        # 2. L2CAP header (4B)
        l2cap_len, l2cap_cid = struct.unpack("<HH", pdu[2:6])
        assert l2cap_cid == 0x0004  # Attribute Protocol
        assert l2cap_len == 1 + 2 + len(val) + 12

        # 3. ATT Signed Write Command
        att_opcode = pdu[6]
        assert att_opcode == 0xD2
        handle = struct.unpack("<H", pdu[7:9])[0]
        assert handle == 0x002A
        extracted_val = pdu[9 : 9 + len(val)]
        assert extracted_val == val

        # 4. AuthSignature (12B: 4B SC + 8B MAC)
        sig_offset = 9 + len(val)
        extracted_counter = struct.unpack("<I", pdu[sig_offset : sig_offset + 4])[0]
        assert extracted_counter == counter
        extracted_mac = pdu[sig_offset + 4 : sig_offset + 12]

        expected_mac = compute_csrk_mac(
            TEST_CSRK, 0xD2, 0x002A, val, counter
        )
        assert extracted_mac == expected_mac

    def test_build_att_signed_write_corrupted_mac(self) -> None:
        """build_att_signed_write with corrupt_mac=True produces inverted first byte."""
        pdu_valid = build_att_signed_write(TEST_CSRK, 0x0001, b"a", 5, corrupt_mac=False)
        pdu_corrupt = build_att_signed_write(TEST_CSRK, 0x0001, b"a", 5, corrupt_mac=True)

        mac_valid = pdu_valid[-8:]
        mac_corrupt = pdu_corrupt[-8:]
        assert mac_corrupt[0] == (mac_valid[0] ^ 0xFF)
        assert mac_corrupt[1:] == mac_valid[1:]

    def test_build_att_signed_write_edge_cases(self) -> None:
        """Handles empty values, max 32-bit counter rollover, and override MAC."""
        # Empty value
        pdu_empty = build_att_signed_write(TEST_CSRK, 0x0005, b"", counter=0)
        assert len(pdu_empty) == 2 + 4 + 15  # 21 bytes

        # Boundary counter 0xFFFFFFFF
        pdu_max_sc = build_att_signed_write(TEST_CSRK, 0x0005, b"", counter=0xFFFFFFFF)
        sc = struct.unpack("<I", pdu_max_sc[2 + 4 + 3 : 2 + 4 + 7])[0]
        assert sc == 0xFFFFFFFF

        # Override MAC
        override = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11"
        pdu_override = build_att_signed_write(
            TEST_CSRK, 0x0001, b"", counter=1, override_mac=override
        )
        assert pdu_override[-8:] == override

        # Invalid CSRK length
        with pytest.raises(ValueError, match="CSRK must be exactly 16 bytes"):
            build_att_signed_write(b"\x00" * 15)

        # Counter out of 32-bit range
        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            build_att_signed_write(TEST_CSRK, counter=0x100000000)


# =============================================================================
# 3. Advertising Channel PDU Builder Tests
# =============================================================================
class TestAdvertisingPduBuilders:
    """Verifies construction of advertising PDUs (ADV_DIRECT_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND)."""

    def test_build_adv_direct_ind(self) -> None:
        """ADV_DIRECT_IND contains AdvA (6B) and TargetA (6B)."""
        adv_a = "AA:BB:CC:DD:EE:01"
        target_a = "5A:11:22:33:44:55"
        pdu = build_adv_direct_ind(adv_a, target_a, tx_random=True, rx_random=True)
        assert len(pdu) == 14
        # Header: PDU Type 1 | TxAdd (0x40) | RxAdd (0x80) = 0xC1, Length 12
        assert pdu[0] == 0xC1
        assert pdu[1] == 12
        assert pdu[2:8] == str_to_mac(adv_a)
        assert pdu[8:14] == str_to_mac(target_a)

    def test_build_scan_req(self) -> None:
        """SCAN_REQ contains ScanA (6B) and AdvA (6B)."""
        scan_a = "11:22:33:44:55:66"
        adv_a = "AA:BB:CC:DD:EE:01"
        pdu = build_scan_req(scan_a, adv_a, tx_random=True, rx_random=True)
        assert len(pdu) == 14
        # PDU Type 3 | TxAdd | RxAdd = 0xC3
        assert pdu[0] == 0xC3
        assert pdu[1] == 12
        assert pdu[2:8] == str_to_mac(scan_a)
        assert pdu[8:14] == str_to_mac(adv_a)

    def test_build_scan_rsp(self) -> None:
        """SCAN_RSP contains AdvA (6B) and Scan Response data."""
        adv_a = "AA:BB:CC:DD:EE:01"
        data = bytes([0x05, 0x09]) + b"Test"
        pdu = build_scan_rsp(adv_a, scan_rsp_data=data, tx_random=True)
        assert len(pdu) == 2 + 6 + len(data)
        assert pdu[0] == 0x44  # PDU Type 4 | TxAdd (0x40)
        assert pdu[1] == 6 + len(data)
        assert pdu[2:8] == str_to_mac(adv_a)
        assert pdu[8:] == data

    def test_build_connect_ind(self) -> None:
        """CONNECT_IND contains InitA, AdvA, and 22B LLData."""
        init_a = "5A:11:22:33:44:55"
        adv_a = "AA:BB:CC:DD:EE:01"
        conn_aa = 0x87654321
        pdu = build_connect_ind(
            init_a=init_a,
            adv_a=adv_a,
            conn_aa=conn_aa,
            interval=36,
            latency=2,
            timeout=150,
            hop=7,
        )
        assert len(pdu) == 2 + 34  # 36 bytes
        assert pdu[0] == 0xC5      # PDU Type 5 | TxAdd | RxAdd
        assert pdu[1] == 34
        assert pdu[2:8] == str_to_mac(init_a)
        assert pdu[8:14] == str_to_mac(adv_a)

        # Unpack LLData
        lldata = pdu[14:36]
        unpacked_aa = struct.unpack("<I", lldata[0:4])[0]
        assert unpacked_aa == conn_aa
        win_size = lldata[7]
        assert win_size == 1
        win_offset, interval, latency, timeout = struct.unpack("<HHHH", lldata[8:16])
        assert interval == 36
        assert latency == 2
        assert timeout == 150
        hop = lldata[21] & 0x1F
        assert hop == 7

    def test_mac_address_coercion_and_errors(self) -> None:
        """Accepts various MAC formats and raises TypeError/ValueError on invalid ones."""
        # Clean hex string
        b1 = str_to_mac("AA:BB:CC:DD:EE:01")
        b2 = str_to_mac("aabbccddeeff")
        assert len(b1) == 6
        assert len(b2) == 6

        with pytest.raises(ValueError):
            str_to_mac("invalid_mac")

        with pytest.raises(TypeError):
            build_adv_ind(adv_a=12345)  # type: ignore[arg-type]


# =============================================================================
# 4. High-Level PCAP Fixture Generation Tests
# =============================================================================
class TestHighLevelPcapGenerators:
    """Verifies PCAP fixture generation for all three exclusive-use side-channels."""

    def test_generate_encryption_trace_shared_ltk_positive(self) -> None:
        """Generates positive handshake trace (LL_START_ENC_RSP) readable by PcapBleReader."""
        pcap_data = generate_encryption_trace(
            shared_ltk=True,
            central_addr="AA:BB:CC:DD:EE:01",
            periph_addr="AA:BB:CC:DD:EE:02",
        )
        assert len(pcap_data) > 24
        assert pcap_data[:4] == b"\xd4\xc3\xb2\xa1"  # 0xA1B2C3D4 LE

        reader = PcapBleReader(io.BytesIO(pcap_data))
        packets = list(reader)
        reader.close()

        # Expected packets:
        # 1. CONNECT_IND (chan 37, pdu_type 0)
        # 2. LL_ENC_REQ (data chan 1, pdu_type 2)
        # 3. LL_ENC_RSP (data chan 1, pdu_type 3)
        # 4. LL_START_ENC_REQ (data chan 1, pdu_type 3)
        # 5. LL_START_ENC_RSP (data chan 1, pdu_type 2)
        # 6. LL_START_ENC_RSP (data chan 1, pdu_type 3)
        assert len(packets) == 6

        # Check packet 1: CONNECT_IND
        assert packets[0].ble_chan == 37
        assert packets[0].pdu_type == 0
        assert packets[0].body[0] & 0x0F == 5  # PDU Type 5 CONNECT_IND

        # Check packet 2: LL_ENC_REQ
        assert packets[1].ble_chan == 1
        assert packets[1].pdu_type == 2  # Central -> Peripheral
        assert packets[1].body[2] == OPCODE_LL_ENC_REQ

        # Check packet 3: LL_ENC_RSP
        assert packets[2].ble_chan == 1
        assert packets[2].pdu_type == 3  # Peripheral -> Central
        assert packets[2].body[2] == OPCODE_LL_ENC_RSP

        # Check packet 4: LL_START_ENC_REQ
        assert packets[3].ble_chan == 1
        assert packets[3].pdu_type == 3
        assert packets[3].body[2] == OPCODE_LL_START_ENC_REQ

        # Check packets 5 & 6: LL_START_ENC_RSP
        assert packets[4].pdu_type == 2
        assert packets[4].body[2] == OPCODE_LL_START_ENC_RSP
        assert packets[5].pdu_type == 3
        assert packets[5].body[2] == OPCODE_LL_START_ENC_RSP

    def test_generate_encryption_trace_rejected_negative(self) -> None:
        """Generates negative handshake trace (LL_REJECT_IND 0x06 + LL_TERMINATE_IND)."""
        pcap_data = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            error_code=ERROR_PIN_OR_KEY_MISSING,
        )
        reader = PcapBleReader(io.BytesIO(pcap_data))
        packets = list(reader)
        reader.close()

        assert len(packets) == 4
        # 1. CONNECT_IND
        assert packets[0].ble_chan == 37
        # 2. LL_ENC_REQ
        assert packets[1].body[2] == OPCODE_LL_ENC_REQ
        # 3. LL_REJECT_IND with error code 0x06
        assert packets[2].body[2] == OPCODE_LL_REJECT_IND
        assert packets[2].body[3] == ERROR_PIN_OR_KEY_MISSING
        assert packets[2].pdu_type == 3
        # 4. LL_TERMINATE_IND with error code 0x13
        assert packets[3].body[2] == OPCODE_LL_TERMINATE_IND
        assert packets[3].body[3] == ERROR_REMOTE_USER_TERMINATED

    def test_generate_encryption_trace_extended_reject(self) -> None:
        """Generates negative handshake trace with LL_REJECT_EXT_IND."""
        pcap_data = generate_encryption_trace(
            shared_ltk=False,
            extended_reject=True,
            error_code=ERROR_AUTHENTICATION_FAILURE,
        )
        reader = PcapBleReader(io.BytesIO(pcap_data))
        packets = list(reader)
        reader.close()

        assert len(packets) == 4
        assert packets[2].body[2] == OPCODE_LL_REJECT_EXT_IND
        assert packets[2].body[3] == OPCODE_LL_ENC_REQ
        assert packets[2].body[4] == ERROR_AUTHENTICATION_FAILURE

    def test_generate_csrk_trace_sequential_and_anomalies(self) -> None:
        """Generates CSRK signed write stream with valid and corrupted MAC signatures."""
        counters = [100, 101, 102, 103, 104]
        # Corrupt packet at index 2 (counter 102)
        pcap_data = generate_csrk_trace(
            counter_sequence=counters,
            csrk=TEST_CSRK,
            corrupt_mac_indices=[2],
            handle=0x0015,
            value=b"\xCA\xFE",
        )
        reader = PcapBleReader(io.BytesIO(pcap_data))
        packets = list(reader)
        reader.close()

        # 1 CONNECT_IND + 5 ATT writes = 6 packets
        assert len(packets) == 6
        assert packets[0].ble_chan == 37

        for idx, expected_sc in enumerate(counters):
            pkt = packets[idx + 1]
            assert pkt.ble_chan == 1
            assert pkt.pdu_type == 2  # Master -> Slave
            # L2CAP CID at body[4:6]
            cid = struct.unpack("<H", pkt.body[4:6])[0]
            assert cid == 0x0004
            # ATT Opcode at body[6]
            assert pkt.body[6] == 0xD2
            # Handle at body[7:9]
            handle = struct.unpack("<H", pkt.body[7:9])[0]
            assert handle == 0x0015
            # SignCounter
            val_len = 2
            sc_offset = 9 + val_len
            sc = struct.unpack("<I", pkt.body[sc_offset : sc_offset + 4])[0]
            assert sc == expected_sc

            mac = pkt.body[sc_offset + 4 : sc_offset + 12]
            expected_valid_mac = compute_csrk_mac(
                TEST_CSRK, 0xD2, 0x0015, b"\xCA\xFE", expected_sc
            )
            if idx == 2:
                # Corrupted MAC
                assert mac != expected_valid_mac
                assert mac[0] == (expected_valid_mac[0] ^ 0xFF)
            else:
                assert mac == expected_valid_mac

    def test_generate_csrk_trace_rpa_rotation(self) -> None:
        """Simulates central RPA rotation mid-stream linking same counter trajectory."""
        counters = [1, 2, 3, 4]
        rotated_rpas = ["5A:11:11:11:11:01", "5A:22:22:22:22:02"]
        pcap_data = generate_csrk_trace(
            counter_sequence=counters,
            csrk=TEST_CSRK,
            rotate_rpa_indices=[2],
            rpa_sequence=rotated_rpas,
        )
        reader = PcapBleReader(io.BytesIO(pcap_data))
        packets = list(reader)
        reader.close()

        # 1 initial CONNECT_IND + 2 writes + 1 rotated CONNECT_IND + 2 writes = 6 packets
        assert len(packets) == 6
        assert packets[0].ble_chan == 37
        assert packets[3].ble_chan == 37  # Reconnect on advertising channel
        # Assert new InitA is the rotated RPA
        assert packets[3].body[2:8] == str_to_mac(rotated_rpas[0])

    def test_generate_bat_allowlist_selective_probe(self) -> None:
        """Differential probe response: silent drop for unauthorized vs response for authorized."""
        # 1. Allowlist ENABLED (Exclusive-use peripheral)
        pcap_allowed = generate_bat_allowlist_trace(
            allowlist_enabled=True,
            target_rpa="5A:99:88:77:66:01",
            foreign_rpa="4A:00:11:22:33:44",
            mode="selective_probe",
        )
        reader = PcapBleReader(io.BytesIO(pcap_allowed))
        pkts_allowed = list(reader)
        reader.close()

        # Packets:
        # 0: ADV_IND
        # 1: SCAN_REQ from foreign_rpa
        # (NO SCAN_RSP! Silent drop)
        # 2: ADV_IND
        # 3: SCAN_REQ from target_rpa
        # 4: SCAN_RSP to target_rpa
        assert len(pkts_allowed) == 5
        assert pkts_allowed[0].body[0] & 0x0F == 0  # ADV_IND
        assert pkts_allowed[1].body[0] & 0x0F == 3  # SCAN_REQ
        assert pkts_allowed[1].body[2:8] == str_to_mac("4A:00:11:22:33:44")
        assert pkts_allowed[2].body[0] & 0x0F == 0  # ADV_IND
        assert pkts_allowed[3].body[0] & 0x0F == 3  # SCAN_REQ from target
        assert pkts_allowed[3].body[2:8] == str_to_mac("5A:99:88:77:66:01")
        assert pkts_allowed[4].body[0] & 0x0F == 4  # SCAN_RSP

        # 2. Allowlist DISABLED (Open advertiser)
        pcap_open = generate_bat_allowlist_trace(
            allowlist_enabled=False,
            target_rpa="5A:99:88:77:66:01",
            foreign_rpa="4A:00:11:22:33:44",
            mode="selective_probe",
        )
        reader_open = PcapBleReader(io.BytesIO(pcap_open))
        pkts_open = list(reader_open)
        reader_open.close()

        # Both foreign and target elicit SCAN_RSP -> 6 packets total
        assert len(pkts_open) == 6
        assert pkts_open[1].body[0] & 0x0F == 3  # SCAN_REQ from foreign
        assert pkts_open[2].body[0] & 0x0F == 4  # SCAN_RSP sent!

    def test_generate_bat_allowlist_directed_and_timing(self) -> None:
        """Generates directed advertising and differential timing modes."""
        # Directed mode
        pcap_directed = generate_bat_allowlist_trace(
            mode="directed",
            target_rpa="5A:99:88:77:66:01",
        )
        reader = PcapBleReader(io.BytesIO(pcap_directed))
        pkts_dir = list(reader)
        reader.close()
        # 5 ADV_DIRECT_IND + 1 CONNECT_IND = 6
        assert len(pkts_dir) == 6
        for i in range(5):
            assert pkts_dir[i].body[0] & 0x0F == 1  # ADV_DIRECT_IND

        # Reconnection timing mode
        params = ConnectionParameters(interval=24, latency=0, timeout=100, hop_increment=5)
        pcap_timing = generate_bat_allowlist_trace(
            mode="reconnection_timing",
            conn_params=params,
        )
        reader_timing = PcapBleReader(io.BytesIO(pcap_timing))
        pkts_timing = list(reader_timing)
        reader_timing.close()
        # 4 fast ADV + 3 slow ADV + 1 CONNECT_IND = 8 packets
        assert len(pkts_timing) == 8
        assert pkts_timing[-1].body[0] & 0x0F == 5  # CONNECT_IND

    def test_file_output_export(self, tmp_path: Path) -> None:
        """File output paths write valid PCAP files directly to disk."""
        out_file = tmp_path / "subdir" / "test_trace.pcap"
        raw_data = generate_encryption_trace(shared_ltk=True, output_path=out_file)
        assert out_file.exists()
        assert out_file.read_bytes() == raw_data

    def test_generate_synthetic_pcap_custom_events(self) -> None:
        """generate_synthetic_pcap directly serializes an arbitrary list of SyntheticEvents."""
        evs = [
            SyntheticEvent(ts_usec=1000, chan=37, aa=BLE_ADV_AA, body=b"\x00\x00"),
            SyntheticEvent(ts_usec=2000, chan=1, aa=0x12345678, body=b"\x03\x01\x05", direction=1),
        ]
        pcap_bytes = generate_synthetic_pcap(evs)
        assert len(pcap_bytes) > 24
        reader = PcapBleReader(io.BytesIO(pcap_bytes))
        pkts = list(reader)
        reader.close()
        assert len(pkts) == 2
        assert pkts[0].ble_chan == 37
        assert pkts[0].aa == BLE_ADV_AA
        assert pkts[1].ble_chan == 1
        assert pkts[1].pdu_type == 3  # Peripheral -> Central



# =============================================================================
# 5. In-Memory Streaming & Generator Class Tests
# =============================================================================
class TestInMemoryStreamingAndGeneratorClass:
    """Verifies PacketMessage and CapturedBlePacket conversion and fluent builder API."""

    def test_events_to_packet_messages(self) -> None:
        """Converts SyntheticEvent sequence into valid Sniffle PacketMessage objects."""
        ev1 = SyntheticEvent(
            ts_usec=100_000,
            chan=37,
            body=bytes([0x00, 0x00]),
            direction=0,
            rssi=-65,
        )
        ev2 = SyntheticEvent(
            ts_usec=120_000,
            chan=15,
            body=bytes([0x01, 0x01, 0xAA]),
            direction=1,
            rssi=-50,
        )

        messages = events_to_packet_messages([ev1, ev2])
        assert len(messages) == 2

        assert isinstance(messages[0], PacketMessage)
        assert messages[0].ts == 100_000
        assert messages[0].chan == 37
        assert messages[0].rssi == -65
        assert messages[0].pkt_dir == 0
        assert messages[0].body == ev1.body

        assert isinstance(messages[1], PacketMessage)
        assert messages[1].ts == 120_000
        assert messages[1].chan == 15
        assert messages[1].pkt_dir == 1
        assert messages[1].body == ev2.body

    def test_events_to_captured_packets(self) -> None:
        """Round-trip parses SyntheticEvents to CapturedBlePacket records."""
        ev = SyntheticEvent(
            ts_usec=50_000,
            chan=38,
            body=bytes([0x00, 0x02, 0x11, 0x22]),
            direction=0,
        )
        pkts = events_to_captured_packets([ev])
        assert len(pkts) == 1
        assert isinstance(pkts[0], CapturedBlePacket)
        assert pkts[0].ble_chan == 38
        assert pkts[0].body == ev.body

    def test_stream_generators(self) -> None:
        """generate_synthetic_stream and generate_synthetic_captured_stream yield iterators."""
        evs = [
            SyntheticEvent(ts_usec=1000, chan=37, body=b"\x00\x00"),
            SyntheticEvent(ts_usec=2000, chan=37, body=b"\x00\x00"),
        ]
        msg_list = list(generate_synthetic_stream(evs))
        assert len(msg_list) == 2
        assert all(isinstance(m, PacketMessage) for m in msg_list)

        cap_list = list(generate_synthetic_captured_stream(evs))
        assert len(cap_list) == 2
        assert all(isinstance(c, CapturedBlePacket) for c in cap_list)

    def test_synthetic_trace_generator_fluent_builder(self, tmp_path: Path) -> None:
        """SyntheticTraceGenerator fluent builder creates complete trace fluently."""
        gen = SyntheticTraceGenerator(conn_aa=0xAABBCCDD)
        (
            gen.add_adv_ind("AA:BB:CC:DD:EE:01", ad_data=b"\x02\x01\x06")
            .add_scan_req("5A:11:22:33:44:55", "AA:BB:CC:DD:EE:01")
            .add_scan_rsp("AA:BB:CC:DD:EE:01", scan_rsp_data=b"\x05\x09Test")
            .add_connect_ind("5A:11:22:33:44:55", "AA:BB:CC:DD:EE:01")
            .add_att_signed_write(TEST_CSRK, handle=0x0010, value=b"data", counter=1)
        )

        assert len(gen) == 5
        pcap_bytes = gen.build_pcap_bytes()
        assert len(pcap_bytes) > 24

        out_path = gen.save_pcap(tmp_path / "builder_test.pcap")
        assert out_path.exists()
        assert out_path.stat().st_size == len(pcap_bytes)

        # Check conversion to PacketMessage
        pkt_msgs = gen.to_packet_messages()
        assert len(pkt_msgs) == 5


# =============================================================================
# 6. Wireshark / tshark Clean Dissection Validation Tests
# =============================================================================
class TestTsharkCleanDissection:
    """Runs tshark subprocess assertions confirming zero malformed packets across all scenarios."""

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed on system")
    def test_tshark_encryption_positive_dissection(self, tmp_path: Path) -> None:
        """Wireshark dissects successful encryption trace with zero malformed frame errors."""
        pcap_file = tmp_path / "tshark_enc_success.pcap"
        generate_encryption_trace(shared_ltk=True, output_path=pcap_file)

        res = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "[Malformed Packet" not in res.stdout
        assert "LL_ENC_REQ" in res.stdout
        assert "LL_ENC_RSP" in res.stdout
        assert "LL_START_ENC_REQ" in res.stdout
        assert "LL_START_ENC_RSP" in res.stdout

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed on system")
    def test_tshark_encryption_rejected_dissection(self, tmp_path: Path) -> None:
        """Wireshark dissects encryption rejection trace (LL_REJECT_IND and LL_TERMINATE_IND)."""
        pcap_file = tmp_path / "tshark_enc_reject.pcap"
        generate_encryption_trace(
            shared_ltk=False,
            extended_reject=False,
            error_code=ERROR_PIN_OR_KEY_MISSING,
            output_path=pcap_file,
        )

        res = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "[Malformed Packet" not in res.stdout
        assert "LL_REJECT_IND" in res.stdout
        assert "PIN or Key Missing" in res.stdout

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed on system")
    def test_tshark_csrk_signed_write_dissection(self, tmp_path: Path) -> None:
        """Wireshark dissects ATT Signed Write command down to Sign Counter and Signature."""
        pcap_file = tmp_path / "tshark_csrk.pcap"
        generate_csrk_trace(
            counter_sequence=[50, 51, 52],
            csrk=TEST_CSRK,
            handle=0x0033,
            value=b"Telemetry",
            output_path=pcap_file,
        )

        res = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "[Malformed Packet" not in res.stdout
        assert "Signed Write Command" in res.stdout
        assert "Sign Counter: 50" in res.stdout
        assert "Sign Counter: 51" in res.stdout
        assert "Sign Counter: 52" in res.stdout

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed on system")
    def test_tshark_bat_allowlist_dissection(self, tmp_path: Path) -> None:
        """Wireshark dissects BAT allowlist probing trace with zero malformed frame errors."""
        pcap_file = tmp_path / "tshark_bat.pcap"
        generate_bat_allowlist_trace(
            allowlist_enabled=True,
            mode="selective_probe",
            output_path=pcap_file,
        )

        res = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-V"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "[Malformed Packet" not in res.stdout
        assert "ADV_IND" in res.stdout
        assert "SCAN_REQ" in res.stdout
        assert "SCAN_RSP" in res.stdout
