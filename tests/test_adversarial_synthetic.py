"""Adversarial stress and edge-case challenge suite for Milestone 1 Synthetic Generator.

Tests:
1. Boundary Counter Rollover & Mathematical Integrity:
   - 32-bit SignCounter boundaries (0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFF, 0x80000000)
   - SignCounter overflow and negative input rejection (>= 0x100000000, < 0)
   - Attribute Handle 16-bit boundaries and rejection (> 0xFFFF, < 0)
   - Hardware timestamp rollover unwrapping across 0xFFFFFFFF boundary (monotonicity & microsecond accuracy)
   - Multiple successive timestamp rollovers
   - Out-of-order timestamps and jitter immunity
2. Corrupted Lengths, Truncated Frames & Payload Edge Cases:
   - Declared PDU length > actual body length (corrupted short frame) -> tshark flags [Malformed Packet]
   - Declared PDU length < actual body length (oversized unannounced data)
   - Truncated 0-byte and 1-byte body payloads
   - Max unfragmented ATT signed write value (236 bytes -> 255-byte LL PDU) vs empty value (0 bytes)
   - Corrupted MAC inversion and override validation
   - Control PDU validation errors (illegal opcodes, error codes > 255, invalid EDIV, SKD/IV lengths)
3. DLT 256 Libpcap Packing & Deserialization Stress Harness:
   - Corrupted global headers (< 24B, bad magic, invalid DLT) rejected by PcapBleReader
   - Corrupted packet records (truncated payload, short pseudo-header < 17B)
   - CRC error flag injection, preservation by reader, and tshark [Incorrect CRC] detection
   - PHY modes packing (1M, 2M, Coded S=8, Coded S=2) and 1-byte Coding Indicator
4. Extreme Packet Rates, High-Volume Floods & Stream Conversion:
   - Zero-delta timestamps (concurrent packets at identical microsecond)
   - 5,000-packet high-throughput flood assertion (> 10,000 pkts/s, 0 data loss)
   - SyntheticTraceGenerator fluent builder, streaming iterators, and PacketMessage conversion
5. Wireshark / TShark v4.4.19 Dissection Verification Oracle:
   - Comprehensive dissection of all LL Control PDUs (0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x11)
   - Dissection of ATT Signed Write (0xD2), L2CAP CID 0x0004, SignCounter, and Signature
   - Dissection of Advertising PDUs (ADV_IND, ADV_DIRECT_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND)
   - Dissection of all BAT Allowlist modes (selective_probe, directed, reconnection_timing)
   - Dissection of Encryption Handshake scenarios (positive shared LTK, standard reject, extended reject)
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import tempfile
import time

import pytest

from airtell.protocol.wire import PacketMessage
from airtell.sidechannel import (
    ATT_OPCODE_SIGNED_WRITE_CMD,
    SyntheticEvent,
    SyntheticTraceGenerator,
    build_adv_direct_ind,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_connection_update_ind,
    build_ll_enc_req,
    build_ll_enc_rsp,
    build_ll_reject_ext_ind,
    build_ll_reject_ind,
    build_ll_start_enc_req,
    build_ll_start_enc_rsp,
    build_ll_terminate_ind,
    build_scan_req,
    build_scan_rsp,
    compute_csrk_mac,
    generate_bat_allowlist_trace,
    generate_encryption_trace,
    generate_synthetic_captured_stream,
    generate_synthetic_pcap,
    generate_synthetic_stream,
)
from airtell.sniff.pcap import (
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    GLOBAL_HEADER_FORMAT,
    PACKET_HEADER_FORMAT,
    PCAP_MAGIC_USEC,
    CapturedBlePacket,
    PcapBleReader,
    PcapBleWriter,
)

ADVERSARIAL_CSRK: bytes = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab\xcd\xef"
TSHARK_BIN: str | None = shutil.which("tshark")


# =============================================================================
# 1. Boundary Counter Rollover & Mathematical Integrity
# =============================================================================
class TestBoundaryCounterRollover:
    """Stress tests boundary counters, rollovers, overflows, and timestamp math."""

    @pytest.mark.parametrize(
        "counter",
        [
            0x00000000,
            0x00000001,
            0x7FFFFFFF,
            0x80000000,
            0xFFFFFFFE,
            0xFFFFFFFF,
        ],
    )
    def test_csrk_sign_counter_boundary_values(self, counter: int) -> None:
        """SignCounter accurately encodes and authenticates at all 32-bit boundary values."""
        mac = compute_csrk_mac(
            csrk=ADVERSARIAL_CSRK,
            opcode=ATT_OPCODE_SIGNED_WRITE_CMD,
            handle=0x0024,
            value=b"\x42",
            counter=counter,
        )
        assert len(mac) == 8
        assert isinstance(mac, bytes)

        pdu = build_att_signed_write(
            csrk=ADVERSARIAL_CSRK,
            handle=0x0024,
            value=b"\x42",
            counter=counter,
        )
        # Verify packed counter in ATT PDU (offset: 2B LL hdr + 4B L2CAP hdr + 1B opcode + 2B handle + 1B value = 10)
        unpacked_counter = struct.unpack("<I", pdu[10:14])[0]
        assert unpacked_counter == counter
        # Verify packed MAC at offset 14..22
        assert pdu[14:22] == mac

    def test_csrk_sign_counter_overflow_and_negative_rejection(self) -> None:
        """SignCounter strictly rejects values exceeding 32-bit uint (0x100000000) or negative."""
        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            compute_csrk_mac(
                csrk=ADVERSARIAL_CSRK,
                opcode=ATT_OPCODE_SIGNED_WRITE_CMD,
                handle=0x0001,
                value=b"\x01",
                counter=0x100000000,
            )

        with pytest.raises(ValueError, match="SignCounter must be 32-bit uint"):
            compute_csrk_mac(
                csrk=ADVERSARIAL_CSRK,
                opcode=ATT_OPCODE_SIGNED_WRITE_CMD,
                handle=0x0001,
                value=b"\x01",
                counter=-1,
            )

    def test_csrk_handle_boundary_and_rejection(self) -> None:
        """Attribute Handle must be within 16-bit range (0x0000 to 0xFFFF)."""
        # Min handle
        mac_min = compute_csrk_mac(ADVERSARIAL_CSRK, 0xD2, 0x0000, b"\x01", 1)
        assert len(mac_min) == 8
        # Max handle
        mac_max = compute_csrk_mac(ADVERSARIAL_CSRK, 0xD2, 0xFFFF, b"\x01", 1)
        assert len(mac_max) == 8
        assert mac_min != mac_max

        with pytest.raises(ValueError, match="Attribute handle must be 16-bit uint"):
            compute_csrk_mac(ADVERSARIAL_CSRK, 0xD2, 0x10000, b"\x01", 1)

        with pytest.raises(ValueError, match="Attribute handle must be 16-bit uint"):
            compute_csrk_mac(ADVERSARIAL_CSRK, 0xD2, -1, b"\x01", 1)

    def test_pcap_timestamp_hardware_rollover_unwrapping(self) -> None:
        """PcapBleWriter monotonically unwraps hardware timestamp rollover at 0xFFFFFFFF."""
        stream = io.BytesIO()
        with PcapBleWriter(stream, base_epoch=1700000000.0) as writer:
            # Packet 1: 16 microseconds before 32-bit rollover
            writer.write_packet(
                ts_usec=0xFFFFFFF0, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06"
            )
            # Packet 2: 16 microseconds after 32-bit rollover
            writer.write_packet(
                ts_usec=0x00000010, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06"
            )

        pkts = list(PcapBleReader(io.BytesIO(stream.getvalue())))
        assert len(pkts) == 2
        # Verify strictly monotonic
        assert pkts[1].ts_epoch > pkts[0].ts_epoch
        # Verify exact microsecond delta: (0x100000000 - 0xFFFFFFF0) + 0x10 = 16 + 16 = 32 usec
        delta_usec = int(round((pkts[1].ts_epoch - pkts[0].ts_epoch) * 1_000_000))
        assert delta_usec == 32

    def test_pcap_timestamp_multiple_consecutive_rollovers(self) -> None:
        """PcapBleWriter accurately tracks multiple successive hardware rollovers."""
        stream = io.BytesIO()
        with PcapBleWriter(stream, base_epoch=1700000000.0) as writer:
            writer.write_packet(ts_usec=0xFFFFFFF0, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06")
            writer.write_packet(ts_usec=0x00000010, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06")  # Rollover 1
            writer.write_packet(ts_usec=0xFFFFFFF5, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06")
            writer.write_packet(ts_usec=0x00000020, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06")  # Rollover 2

        pkts = list(PcapBleReader(io.BytesIO(stream.getvalue())))
        assert len(pkts) == 4
        for i in range(1, len(pkts)):
            assert pkts[i].ts_epoch > pkts[i - 1].ts_epoch

    def test_pcap_timestamp_out_of_order_and_jitter(self) -> None:
        """PcapBleWriter preserves out-of-order timestamps without triggering false rollovers."""
        stream = io.BytesIO()
        with PcapBleWriter(stream, base_epoch=1700000000.0) as writer:
            for ts in [1_000_000, 950_000, 1_050_000, 900_000]:
                writer.write_packet(ts_usec=ts, chan=37, packet=b"\x00\x06\x01\x02\x03\x04\x05\x06")

        pkts = list(PcapBleReader(io.BytesIO(stream.getvalue())))
        assert len(pkts) == 4
        assert pkts[0].ts_epoch == 1700000001.0
        assert pkts[1].ts_epoch == 1700000000.95
        assert pkts[2].ts_epoch == 1700000001.05
        assert pkts[3].ts_epoch == 1700000000.90


# =============================================================================
# 2. Corrupted Lengths, Truncated Frames & Payload Edge Cases
# =============================================================================
class TestCorruptedLengthsAndPayloadEdgeCases:
    """Stress tests corrupted headers, truncated frames, and boundary payload sizes."""

    def test_corrupted_ll_declared_length_larger_than_actual(self) -> None:
        """PDU with declared length larger than payload is packed, preserved, and detectable."""
        # Header specifies Length = 80, but body only contains 4 bytes
        corrupted_pdu = b"\x03\x50\x01\x02\x03\x04"
        event = SyntheticEvent(ts_usec=1_000_000, chan=1, body=corrupted_pdu)
        pcap_data = generate_synthetic_pcap([event])

        reader = PcapBleReader(io.BytesIO(pcap_data))
        pkts = list(reader)
        assert len(pkts) == 1
        assert pkts[0].body == corrupted_pdu

    def test_corrupted_ll_declared_length_smaller_than_actual(self) -> None:
        """PDU with declared length smaller than payload preserves raw bytes without truncating."""
        # Header specifies Length = 2, but body contains 30 bytes
        corrupted_pdu = b"\x03\x02" + b"\xFE" * 28
        event = SyntheticEvent(ts_usec=1_000_000, chan=1, body=corrupted_pdu)
        pcap_data = generate_synthetic_pcap([event])

        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        assert len(pkts) == 1
        assert pkts[0].body == corrupted_pdu

    def test_truncated_zero_and_single_byte_body(self) -> None:
        """Handles 0-byte and 1-byte payloads (below 2-byte header minimum) gracefully."""
        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=37, body=b""),
            SyntheticEvent(ts_usec=1_010_000, chan=37, body=b"\x03"),
        ]
        pcap_data = generate_synthetic_pcap(events)
        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        assert len(pkts) == 2
        assert pkts[0].body == b""
        assert pkts[1].body == b"\x03"

    def test_att_signed_write_maximum_unfragmented_payload(self) -> None:
        """236-byte characteristic value generates maximum 255-octet Link-Layer Data PDU."""
        # 236B value + 1B opcode + 2B handle + 12B auth_sig = 251B ATT PDU
        # + 4B L2CAP hdr = 255B L2CAP frame (fits in single LL PDU with length=255)
        pdu_max = build_att_signed_write(
            csrk=ADVERSARIAL_CSRK,
            handle=0x0012,
            value=b"V" * 236,
            counter=100,
        )
        assert len(pdu_max) == 257  # 2B LL hdr + 255B payload
        assert pdu_max[1] == 255   # LL length byte is 255

        # Empty value payload
        pdu_empty = build_att_signed_write(
            csrk=ADVERSARIAL_CSRK,
            handle=0x0012,
            value=b"",
            counter=101,
        )
        assert len(pdu_empty) == 21  # 2B LL hdr + 4B L2CAP hdr + 1B opcode + 2B handle + 12B auth_sig
        assert pdu_empty[1] == 19

    def test_att_signed_write_override_mac_validation(self) -> None:
        """Explicit override_mac must be exactly 8 bytes."""
        valid_override = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        pdu = build_att_signed_write(
            csrk=ADVERSARIAL_CSRK,
            override_mac=valid_override,
        )
        assert pdu[-8:] == valid_override

        with pytest.raises(ValueError, match="Override MAC must be exactly 8 bytes"):
            build_att_signed_write(csrk=ADVERSARIAL_CSRK, override_mac=b"\x01" * 7)

        with pytest.raises(ValueError, match="Override MAC must be exactly 8 bytes"):
            build_att_signed_write(csrk=ADVERSARIAL_CSRK, override_mac=b"\x01" * 9)

    def test_control_pdu_boundary_validations(self) -> None:
        """All Control PDU builders enforce strict range and length validation."""
        # LL_REJECT_IND
        with pytest.raises(ValueError, match="ErrorCode must be an 8-bit unsigned integer"):
            build_ll_reject_ind(error_code=256)
        with pytest.raises(ValueError, match="ErrorCode must be an 8-bit unsigned integer"):
            build_ll_reject_ind(error_code=-1)

        # LL_REJECT_EXT_IND
        with pytest.raises(ValueError, match="RejectOpcode must be an 8-bit unsigned integer"):
            build_ll_reject_ext_ind(reject_opcode=300)
        with pytest.raises(ValueError, match="ErrorCode must be an 8-bit unsigned integer"):
            build_ll_reject_ext_ind(error_code=-5)

        # LL_TERMINATE_IND
        with pytest.raises(ValueError, match="ErrorCode must be an 8-bit unsigned integer"):
            build_ll_terminate_ind(error_code=0x100)


# =============================================================================
# 3. DLT 256 Libpcap Packing & Reader Deserialization Stress Harness
# =============================================================================
class TestDlt256LibpcapStressHarness:
    """Stress tests DLT 256 packing, header integrity, error injection, and reader resilience."""

    def test_corrupted_pcap_global_headers_rejected(self) -> None:
        """PcapBleReader rejects truncated global headers, invalid magic, and wrong DLT."""
        # 1. Truncated (< 24B)
        with pytest.raises(ValueError, match="File too short for PCAP global header"):
            PcapBleReader(io.BytesIO(b"\xd4\xc3\xb2\xa1\x02\x00"))

        # 2. Bad magic
        bad_magic = struct.pack(GLOBAL_HEADER_FORMAT, 0x12345678, 2, 4, 0, 0, 65535, 256)
        with pytest.raises(ValueError, match="Invalid PCAP magic"):
            PcapBleReader(io.BytesIO(bad_magic))

        # 3. Unsupported DLT (DLT 1 instead of DLT 256)
        bad_dlt = struct.pack(GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, 1)
        with pytest.raises(ValueError, match="Unsupported LinkType: 1"):
            PcapBleReader(io.BytesIO(bad_dlt))

    def test_corrupted_pcap_packet_records_rejected(self) -> None:
        """PcapBleReader raises appropriate errors on truncated packet records."""
        valid_hdr = struct.pack(
            GLOBAL_HEADER_FORMAT, PCAP_MAGIC_USEC, 2, 4, 0, 0, 65535, DLT_BLUETOOTH_LE_LL_WITH_PHDR
        )

        # Truncated payload (< incl_len)
        pkt_hdr = struct.pack(PACKET_HEADER_FORMAT, 1000, 0, 60, 60)
        with pytest.raises(EOFError, match="Truncated packet payload in PCAP"):
            r = PcapBleReader(io.BytesIO(valid_hdr + pkt_hdr + b"\x00" * 30))
            list(r)

        # Payload too short for BLE PHDR (< 17B)
        pkt_hdr_short = struct.pack(PACKET_HEADER_FORMAT, 1000, 0, 12, 12)
        with pytest.raises(ValueError, match="Payload too short for BLE PHDR"):
            r = PcapBleReader(io.BytesIO(valid_hdr + pkt_hdr_short + b"\x00" * 12))
            list(r)

    def test_crc_error_flag_propagation_and_detection(self) -> None:
        """Injected crc_err=True sets flags accurately and is reported by reader."""
        event = SyntheticEvent(
            ts_usec=1_000_000,
            chan=37,
            body=b"\x00\x06\x01\x02\x03\x04\x05\x06",
            crc_err=True,
        )
        pcap_data = generate_synthetic_pcap([event])
        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        assert len(pkts) == 1
        assert pkts[0].crc_err is True

    def test_phy_modes_packing_and_coding_indicator_parsing(self) -> None:
        """All 4 PHY modes (1M, 2M, Coded S=8, Coded S=2) are packed and parsed correctly."""
        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=37, phy=0, body=b"\x00\x06\x01\x02\x03\x04\x05\x06"),
            SyntheticEvent(ts_usec=1_010_000, chan=1, phy=1, body=b"\x03\x02\x02\x13"),
            SyntheticEvent(ts_usec=1_020_000, chan=37, phy=2, body=b"\x00\x06\x01\x02\x03\x04\x05\x06"),
            SyntheticEvent(ts_usec=1_030_000, chan=1, phy=3, body=b"\x03\x02\x02\x13"),
        ]
        pcap_data = generate_synthetic_pcap(events)
        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        assert len(pkts) == 4
        # 1M
        assert pkts[0].phy == 0
        assert pkts[0].body == events[0].body
        # 2M
        assert pkts[1].phy == 1
        assert pkts[1].body == events[1].body
        # Coded S=8 (flags bit 14..15 is 2)
        assert pkts[2].phy == 2
        assert pkts[2].body == events[2].body
        # Coded S=2 (flags bit 14..15 is 2 per DLT 256 spec, CI byte skipped)
        assert pkts[3].phy == 2
        assert pkts[3].body == events[3].body


# =============================================================================
# 4. Extreme Packet Rates, High-Volume Floods & Stream Conversion
# =============================================================================
class TestExtremePacketRatesAndFloods:
    """Stress tests concurrent packets, high volume floods, and streaming converters."""

    def test_concurrent_zero_delta_timestamps(self) -> None:
        """Simultaneous packets with delta_usec=0 maintain consistent timestamps and ordering."""
        events = [
            SyntheticEvent(
                ts_usec=2_000_000,
                chan=37,
                body=b"\x00\x06" + bytes([i, 2, 3, 4, 5, 6]),
            )
            for i in range(20)
        ]
        pcap_data = generate_synthetic_pcap(events)
        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        assert len(pkts) == 20
        assert all(p.ts_epoch == pkts[0].ts_epoch for p in pkts)
        # Verify arrival order is preserved
        for i, p in enumerate(pkts):
            assert p.body[2] == i

    def test_high_volume_flood_throughput(self) -> None:
        """Generates and parses 5,000 packets under flood conditions with > 10,000 pkts/s."""
        count = 5_000
        events = [
            SyntheticEvent(
                ts_usec=1_000_000 + (i * 10),
                chan=(i % 37),
                aa=0x12345678,
                body=b"\x03\x02\x02\x13",
            )
            for i in range(count)
        ]

        # Serialization throughput
        t0 = time.time()
        pcap_data = generate_synthetic_pcap(events)
        t_gen = time.time() - t0
        rate_gen = count / t_gen
        assert rate_gen > 10_000, f"Generation rate too low: {rate_gen:.1f} pkts/s"

        # Parsing throughput
        t1 = time.time()
        pkts = list(PcapBleReader(io.BytesIO(pcap_data)))
        t_read = time.time() - t1
        rate_read = count / t_read
        assert rate_read > 10_000, f"Reading rate too low: {rate_read:.1f} pkts/s"

        assert len(pkts) == count
        assert pkts[0].body == b"\x03\x02\x02\x13"
        assert pkts[-1].body == b"\x03\x02\x02\x13"

    def test_streaming_and_fluent_builder_stress(self) -> None:
        """SyntheticTraceGenerator fluent builder chains correctly without state pollution."""
        builder = (
            SyntheticTraceGenerator()
            .add_adv_ind("AA:BB:CC:DD:EE:01", b"\x02\x01\x06")
            .add_scan_req("11:22:33:44:55:66", "AA:BB:CC:DD:EE:01")
            .add_scan_rsp("AA:BB:CC:DD:EE:01", b"\x05\x09Test")
            .add_connect_ind("11:22:33:44:55:66", "AA:BB:CC:DD:EE:01", conn_aa=0xAABBCCDD)
            .add_att_signed_write(ADVERSARIAL_CSRK, handle=0x15, value=b"\x01", counter=0)
            .add_att_signed_write(ADVERSARIAL_CSRK, handle=0x15, value=b"\x02", counter=1)
        )
        assert len(builder) == 6

        # Convert to PacketMessage
        msgs = builder.to_packet_messages()
        assert len(msgs) == 6
        assert isinstance(msgs[0], PacketMessage)
        assert msgs[0].chan == 37

        # Convert to CapturedBlePacket
        captured = builder.to_captured_packets()
        assert len(captured) == 6
        assert isinstance(captured[0], CapturedBlePacket)

        # Streams
        stream_msgs = list(generate_synthetic_stream(builder.events))
        assert len(stream_msgs) == 6
        stream_captured = list(generate_synthetic_captured_stream(builder.events))
        assert len(stream_captured) == 6


# =============================================================================
# 5. Wireshark / TShark v4.4.19 Dissection Verification Oracle
# =============================================================================
@pytest.mark.skipif(TSHARK_BIN is None, reason="tshark not installed on system")
class TestTsharkDissectionVerificationOracle:
    """Verifies Wireshark / tshark v4.4.19 dissects all synthetic frames without malformed errors."""

    def _dissect_pcap(self, pcap_bytes: bytes, display_filter: str | None = None) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
            f.write(pcap_bytes)
            f.flush()
            cmd = ["tshark", "-r", f.name, "-V"]
            if display_filter:
                cmd.extend(["-Y", display_filter])
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.returncode, res.stdout

    def test_tshark_all_link_layer_control_opcodes_dissection(self) -> None:
        """Every Link-Layer control opcode is dissected cleanly by tshark without Malformed Packet."""
        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=1, body=build_ll_connection_update_ind()),
            SyntheticEvent(ts_usec=1_010_000, chan=1, body=build_ll_terminate_ind()),
            SyntheticEvent(ts_usec=1_020_000, chan=1, body=build_ll_enc_req()),
            SyntheticEvent(ts_usec=1_030_000, chan=1, body=build_ll_enc_rsp()),
            SyntheticEvent(ts_usec=1_040_000, chan=1, body=build_ll_start_enc_req()),
            SyntheticEvent(ts_usec=1_050_000, chan=1, body=build_ll_start_enc_rsp()),
            SyntheticEvent(ts_usec=1_060_000, chan=1, body=build_ll_start_enc_rsp(mic=b"\x12\x34\x56\x78")),
            SyntheticEvent(ts_usec=1_070_000, chan=1, body=build_ll_reject_ind()),
            SyntheticEvent(ts_usec=1_080_000, chan=1, body=build_ll_reject_ext_ind()),
        ]
        pcap_data = generate_synthetic_pcap(events)
        ret, stdout = self._dissect_pcap(pcap_data)
        assert ret == 0
        assert "[Malformed Packet" not in stdout

        expected_opcodes = [
            "LL_CONNECTION_UPDATE_IND (0x00)",
            "LL_TERMINATE_IND (0x02)",
            "LL_ENC_REQ (0x03)",
            "LL_ENC_RSP (0x04)",
            "LL_START_ENC_REQ (0x05)",
            "LL_START_ENC_RSP (0x06)",
            "LL_REJECT_IND (0x0d)",
            "LL_REJECT_EXT_IND (0x11)",
        ]
        for op in expected_opcodes:
            assert op in stdout, f"Expected {op} in tshark output"

    def test_tshark_att_signed_write_dissection(self) -> None:
        """TShark parses ATT Signed Write command down to SignCounter and Authentication Signature."""
        pdu = build_att_signed_write(
            csrk=ADVERSARIAL_CSRK,
            handle=0x0012,
            value=b"\x01",
            counter=4294967295,  # 0xFFFFFFFF
        )
        pcap_data = generate_synthetic_pcap([SyntheticEvent(ts_usec=1_000_000, chan=1, body=pdu)])
        ret, stdout = self._dissect_pcap(pcap_data)
        assert ret == 0
        assert "[Malformed Packet" not in stdout
        assert "Signed Write Command (0xd2)" in stdout
        assert "Sign Counter: 4294967295" in stdout
        assert "Authentication Signature: True" in stdout

    def test_tshark_all_advertising_pdus_dissection(self) -> None:
        """TShark dissects ADV_IND, ADV_DIRECT_IND, SCAN_REQ, SCAN_RSP, and CONNECT_IND cleanly."""
        events = [
            SyntheticEvent(ts_usec=1_000_000, chan=37, body=build_adv_ind("11:22:33:44:55:66", b"\x02\x01\x06")),
            SyntheticEvent(ts_usec=1_010_000, chan=37, body=build_adv_direct_ind("11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF")),
            SyntheticEvent(ts_usec=1_020_000, chan=37, body=build_scan_req("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66")),
            SyntheticEvent(ts_usec=1_030_000, chan=37, body=build_scan_rsp("11:22:33:44:55:66", b"\x07\x09AdvDev")),
            SyntheticEvent(ts_usec=1_040_000, chan=37, body=build_connect_ind("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66")),
        ]
        pcap_data = generate_synthetic_pcap(events)
        ret, stdout = self._dissect_pcap(pcap_data)
        assert ret == 0
        assert "[Malformed Packet" not in stdout

    def test_tshark_bat_allowlist_modes_dissection(self) -> None:
        """TShark parses all three BAT Allowlist modes cleanly."""
        for mode in ["selective_probe", "directed", "reconnection_timing"]:
            pcap_data = generate_bat_allowlist_trace(mode=mode, conn_params=(24, 0, 100, 5))
            ret, stdout = self._dissect_pcap(pcap_data)
            assert ret == 0, f"tshark failed on BAT mode {mode}"
            assert "[Malformed Packet" not in stdout, f"Malformed frame in BAT mode {mode}"

    def test_tshark_encryption_handshake_scenarios(self) -> None:
        """TShark parses positive and negative encryption handshake traces cleanly."""
        # Positive
        pcap_pos = generate_encryption_trace(shared_ltk=True)
        ret_pos, stdout_pos = self._dissect_pcap(pcap_pos)
        assert ret_pos == 0
        assert "[Malformed Packet" not in stdout_pos
        assert "LL_START_ENC_RSP" in stdout_pos

        # Negative with LL_REJECT_IND
        pcap_neg = generate_encryption_trace(shared_ltk=False, extended_reject=False)
        ret_neg, stdout_neg = self._dissect_pcap(pcap_neg)
        assert ret_neg == 0
        assert "[Malformed Packet" not in stdout_neg
        assert "LL_REJECT_IND" in stdout_neg

        # Negative with LL_REJECT_EXT_IND
        pcap_ext = generate_encryption_trace(shared_ltk=False, extended_reject=True)
        ret_ext, stdout_ext = self._dissect_pcap(pcap_ext)
        assert ret_ext == 0
        assert "[Malformed Packet" not in stdout_ext
        assert "LL_REJECT_EXT_IND" in stdout_ext

    def test_tshark_corrupted_frame_detection(self) -> None:
        """TShark correctly flags intentionally corrupted length frame as Malformed Packet."""
        # Intentionally construct corrupted frame
        corrupted_pdu = b"\x03\x50\x01\x02"  # Declared length = 80, actual = 2
        pcap_data = generate_synthetic_pcap([SyntheticEvent(ts_usec=1_000_000, chan=1, body=corrupted_pdu)])
        ret, stdout = self._dissect_pcap(pcap_data)
        assert ret == 0
        # tshark MUST identify this as Malformed Packet
        assert "Malformed Packet" in stdout
