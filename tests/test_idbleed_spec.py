"""Comprehensive unit and edge-case test suite for the IDBLEED verification specification.

Audits protocol state evaluators, bounds-checked Link-Layer/ATT PDU parsers,
AES-CMAC CSRK verification, multi-window RPA correlation, and AirTell BlePacketRecord adapters.
"""

from __future__ import annotations

import io
import struct
import unittest

import pytest

import idbleed_spec as root_idbleed_spec
from airtell.sidechannel.idbleed_spec import (
    ActiveRelayProbeOrchestrator,
    AppAuthOracleEvaluator,
    ATTOpcode,
    ATTSignedWritePayload,
    BLEFrame,
    CSRKSigningOracleEvaluator,
    IdbleedVerificationAnalyzer,
    IdentityRecord,
    LLEncryptionOracleEvaluator,
    LLEncryptionReqPayload,
    LLOpcode,
    OracleResult,
    TestIDBLEEDSpecification,
    ble_packet_record_to_frame,
    compute_csrk_cmac,
)
from airtell.sidechannel.models import BlePacketRecord, SideChannelAnalyzer, Verdict
from airtell.sidechannel.synthetic import (
    build_adv_direct_ind,
    build_adv_ind,
    build_att_signed_write,
    build_connect_ind,
    build_ll_enc_req,
    build_ll_header,
    build_ll_reject_ind,
    build_ll_terminate_ind,
    build_scan_req,
    compute_csrk_mac,
    generate_csrk_trace,
    generate_encryption_trace,
)
from airtell.sniff.pcap import BLE_ADV_AA, PcapBleReader


class TestCoreTypesAndPayloads(unittest.TestCase):
    """Tests exact enum definitions and bounds-checked PDU serialization."""

    def test_canonical_suite_has_all_five_methods(self) -> None:
        """Verify TestIDBLEEDSpecification exposes all 5 canonical verification methods."""
        for method_name in (
            "test_ll_encryption_oracle_paired",
            "test_ll_encryption_oracle_unpaired",
            "test_csrk_signing_oracle_success",
            "test_app_auth_oracle_workflow",
            "test_active_relay_correlation",
        ):
            self.assertTrue(hasattr(TestIDBLEEDSpecification, method_name))

    def test_identity_record_defaults_and_isolation(self) -> None:
        """Verify IdentityRecord fields and independent mutable default list instances."""
        rec1 = IdentityRecord("dev-a")
        rec2 = IdentityRecord("dev-b")
        rec1.observed_rpas.append("5A:00:00:00:00:01")
        self.assertEqual(rec2.observed_rpas, [])
        self.assertEqual(rec1.last_seen, 0.0)

        explicit = IdentityRecord("dev-c", ["6B:00:00:00:00:02"], 42.5)
        self.assertEqual(explicit.canonical_id, "dev-c")
        self.assertEqual(explicit.observed_rpas, ["6B:00:00:00:00:02"])
        self.assertEqual(explicit.last_seen, 42.5)

    def test_oracle_result_enum_values(self) -> None:
        """Verify exact OracleResult enum names and integer values."""
        self.assertEqual(OracleResult.UNPAIRED.value, 0)
        self.assertEqual(OracleResult.PAIRED.value, 1)
        self.assertEqual(OracleResult.INDETERMINATE.value, 2)
        self.assertFalse(issubclass(OracleResult, int))

    def test_ll_opcode_enum_values(self) -> None:
        """Verify all 20 Bluetooth Link-Layer Control opcode constants."""
        expected = {
            "LL_CONNECTION_UPDATE_IND": 0x00,
            "LL_CHANNEL_MAP_IND": 0x01,
            "LL_TERMINATE_IND": 0x02,
            "LL_ENC_REQ": 0x03,
            "LL_ENC_RSP": 0x04,
            "LL_START_ENC_REQ": 0x05,
            "LL_START_ENC_RSP": 0x06,
            "LL_REJECT_IND": 0x0D,
            "LL_SLAVE_FEATURE_REQ": 0x0E,
            "LL_CONNECTION_PARAM_REQ": 0x0F,
            "LL_CONNECTION_PARAM_RSP": 0x10,
            "LL_REJECT_EXT_IND": 0x11,
            "LL_PING_REQ": 0x12,
            "LL_PING_RSP": 0x13,
            "LL_LENGTH_REQ": 0x14,
            "LL_LENGTH_RSP": 0x15,
            "LL_PHY_REQ": 0x16,
            "LL_PHY_RSP": 0x17,
            "LL_PHY_UPDATE_IND": 0x18,
            "LL_MIN_USED_CHANNELS_IND": 0x19,
        }
        for name, val in expected.items():
            self.assertEqual(int(LLOpcode[name]), val)

    def test_att_opcode_enum_values(self) -> None:
        """Verify all 14 Attribute Protocol opcode constants."""
        expected = {
            "ATT_ERROR_RSP": 0x01,
            "ATT_EXCHANGE_MTU_REQ": 0x02,
            "ATT_EXCHANGE_MTU_RSP": 0x03,
            "ATT_FIND_INFO_REQ": 0x04,
            "ATT_FIND_INFO_RSP": 0x05,
            "ATT_READ_BY_TYPE_REQ": 0x08,
            "ATT_READ_BY_TYPE_RSP": 0x09,
            "ATT_READ_REQ": 0x0A,
            "ATT_READ_RSP": 0x0B,
            "ATT_WRITE_REQ": 0x12,
            "ATT_WRITE_RSP": 0x13,
            "ATT_WRITE_CMD": 0x52,
            "ATT_SIGNED_WRITE_CMD": 0xD2,
            "ATT_HANDLE_VALUE_NOTI": 0x1B,
        }
        for name, val in expected.items():
            self.assertEqual(int(ATTOpcode[name]), val)

    def test_ll_encryption_req_payload_roundtrip_and_bounds(self) -> None:
        """Verify LLEncryptionReqPayload serialize/deserialize and strict bounds checks."""
        req = LLEncryptionReqPayload(
            rand=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            ediv=0xABCD,
            skd_c=b"\x11\x12\x13\x14\x15\x16\x17\x18",
            iv_c=b"\x21\x22\x23\x24",
        )
        raw = req.serialize()
        self.assertEqual(len(raw), 23)
        self.assertEqual(raw[0], LLOpcode.LL_ENC_REQ)

        parsed = LLEncryptionReqPayload.deserialize(raw)
        self.assertEqual(parsed, req)

        # Extra trailing bytes (e.g. MIC) should still deserialize first 23 bytes cleanly
        parsed_with_mic = LLEncryptionReqPayload.deserialize(raw + b"\xde\xad\xbe\xef")
        self.assertEqual(parsed_with_mic, req)

        # Truncated buffers (< 23 bytes) must raise ValueError
        for length in (0, 1, 10, 22):
            with self.assertRaises(ValueError):
                LLEncryptionReqPayload.deserialize(raw[:length])

        # Wrong opcode must raise ValueError
        bad_opcode = bytes([LLOpcode.LL_ENC_RSP]) + raw[1:]
        with self.assertRaises(ValueError):
            LLEncryptionReqPayload.deserialize(bad_opcode)

        # Invalid field sizes on serialize must raise ValueError
        with self.assertRaises(ValueError):
            LLEncryptionReqPayload(rand=b"\x00" * 7, ediv=1, skd_c=b"\x00" * 8, iv_c=b"\x00" * 4).serialize()
        with self.assertRaises(ValueError):
            LLEncryptionReqPayload(rand=b"\x00" * 8, ediv=0x10000, skd_c=b"\x00" * 8, iv_c=b"\x00" * 4).serialize()
        with self.assertRaises(ValueError):
            LLEncryptionReqPayload(rand=b"\x00" * 8, ediv=1, skd_c=b"\x00" * 9, iv_c=b"\x00" * 4).serialize()
        with self.assertRaises(ValueError):
            LLEncryptionReqPayload(rand=b"\x00" * 8, ediv=1, skd_c=b"\x00" * 8, iv_c=b"\x00" * 3).serialize()

    def test_att_signed_write_payload_cmac_and_bounds(self) -> None:
        """Verify ATTSignedWritePayload serialization, bounds checks, and AES-CMAC verification."""
        csrk = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        other_csrk = bytes.fromhex("ff0102030405060708090a0b0c0d0e0f")
        handle = 0x002A
        value = b"audit-probe-payload"
        counter = 42

        tag = compute_csrk_cmac(csrk, handle, value, counter)
        self.assertEqual(len(tag), 8)
        self.assertEqual(tag, ATTSignedWritePayload.compute_csrk_cmac(csrk, handle, value, counter))
        # Must match AirTell's Core Spec Vol 3 Part H §2.4.5 reference implementation
        self.assertEqual(
            tag,
            compute_csrk_mac(
                csrk=csrk,
                opcode=ATTOpcode.ATT_SIGNED_WRITE_CMD,
                handle=handle,
                value=value,
                counter=counter,
            ),
        )

        pkt = ATTSignedWritePayload(handle=handle, value=value, signature_counter=counter, cmac=tag)
        self.assertTrue(pkt.verify_cmac(csrk))
        self.assertFalse(pkt.verify_cmac(other_csrk))

        wire = pkt.serialize()
        self.assertEqual(len(wire), 15 + len(value))
        self.assertEqual(wire[0], ATTOpcode.ATT_SIGNED_WRITE_CMD)

        decoded = ATTSignedWritePayload.deserialize(wire)
        self.assertEqual(decoded, pkt)
        self.assertTrue(decoded.verify_cmac(csrk))

        # Empty value (exact 15-byte minimum boundary)
        empty_tag = compute_csrk_cmac(csrk, 0x0010, b"", 0)
        empty_pkt = ATTSignedWritePayload(handle=0x0010, value=b"", signature_counter=0, cmac=empty_tag)
        empty_wire = empty_pkt.serialize()
        self.assertEqual(len(empty_wire), 15)
        self.assertEqual(ATTSignedWritePayload.deserialize(empty_wire), empty_pkt)
        self.assertTrue(empty_pkt.verify_cmac(csrk))

        # Tampered CMAC / value fails verification
        tampered = ATTSignedWritePayload(
            handle=handle,
            value=value + b"!",
            signature_counter=counter,
            cmac=tag,
        )
        self.assertFalse(tampered.verify_cmac(csrk))

        # Truncated buffers (< 15 bytes) and wrong opcode raise ValueError
        for length in (0, 1, 3, 14):
            with self.assertRaises(ValueError):
                ATTSignedWritePayload.deserialize(empty_wire[:length])
        with self.assertRaises(ValueError):
            ATTSignedWritePayload.deserialize(bytes([ATTOpcode.ATT_WRITE_CMD]) + empty_wire[1:])

        # Invalid CSRK key size / field ranges raise ValueError
        with self.assertRaises(ValueError):
            compute_csrk_cmac(b"short-key", handle, value, counter)
        with self.assertRaises(ValueError):
            pkt.verify_cmac(b"short-key")
        with self.assertRaises(ValueError):
            ATTSignedWritePayload(handle=0x1FFFF, value=b"", signature_counter=0, cmac=b"\x00" * 8).serialize()
        with self.assertRaises(ValueError):
            ATTSignedWritePayload(handle=1, value=b"", signature_counter=-1, cmac=b"\x00" * 8).serialize()
        with self.assertRaises(ValueError):
            ATTSignedWritePayload(handle=1, value=b"", signature_counter=0, cmac=b"\x00" * 7).serialize()


class TestEvaluatorEdgeCases(unittest.TestCase):
    """Tests malformed frames, CRC errors, timeouts, replay rejection, and 2-byte GATT bounds."""

    def test_ll_encryption_evaluator_crc_mac_empty_timeout_and_rejections(self) -> None:
        """Audit LLEncryptionOracleEvaluator against corrupt, mismatched, timed-out, and rejected PDUs."""
        target = "AA:BB:CC:11:22:33"
        peer = "44:55:66:77:88:99"
        evaluator = LLEncryptionOracleEvaluator(target_mac=target, timeout_seconds=2.0)

        enc_req_bytes = LLEncryptionReqPayload(
            rand=b"\x11" * 8,
            ediv=0x0042,
            skd_c=b"\x22" * 8,
            iv_c=b"\x33" * 4,
        ).serialize()

        # Invalid CRC ignored
        res, _ = evaluator.process_frame(
            BLEFrame(1.0, 10, -55, peer, target, "LL_CONTROL", enc_req_bytes, crc_valid=False)
        )
        self.assertEqual(res, OracleResult.INDETERMINATE)

        # Unrelated MAC ignored
        res, _ = evaluator.process_frame(
            BLEFrame(1.0, 10, -55, "DE:AD:BE:EF:00:01", "DE:AD:BE:EF:00:02", "LL_CONTROL", enc_req_bytes)
        )
        self.assertEqual(res, OracleResult.INDETERMINATE)

        # Empty PDU ignored
        res, _ = evaluator.process_frame(BLEFrame(1.0, 10, -55, peer, target, "LL_CONTROL", b""))
        self.assertEqual(res, OracleResult.INDETERMINATE)

        # Truncated LL_ENC_REQ handled without panic
        res, _ = evaluator.process_frame(
            BLEFrame(1.0, 10, -55, peer, target, "LL_CONTROL", bytes([LLOpcode.LL_ENC_REQ, 0x01, 0x02]))
        )
        self.assertEqual(res, OracleResult.INDETERMINATE)
        evaluator.reset()

        # Handshake timeout enforcement when elapsed > timeout_seconds
        res, _ = evaluator.process_frame(BLEFrame(10.0, 10, -55, peer, target, "LL_CONTROL", enc_req_bytes))
        self.assertEqual(res, OracleResult.INDETERMINATE)
        res, reason = evaluator.process_frame(
            BLEFrame(12.5, 10, -55, target, peer, "LL_CONTROL", bytes([LLOpcode.LL_START_ENC_RSP]))
        )
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertIn("timeout", reason.lower())

        # LL_REJECT_EXT_IND (0x11) produces UNPAIRED with 0x11 formatted
        evaluator.reset()
        evaluator.process_frame(BLEFrame(20.0, 10, -55, peer, target, "LL_CONTROL", enc_req_bytes))
        res, reason = evaluator.process_frame(
            BLEFrame(
                20.1,
                10,
                -55,
                target.lower(),
                peer,
                "LL_CONTROL",
                bytes([LLOpcode.LL_REJECT_EXT_IND, LLOpcode.LL_ENC_REQ, 0x06]),
            )
        )
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertIn("0x11", reason)

        # LL_TERMINATE_IND during encryption handshake produces UNPAIRED
        evaluator.reset()
        evaluator.process_frame(BLEFrame(30.0, 10, -55, peer, target, "LL_CONTROL", enc_req_bytes))
        res, reason = evaluator.process_frame(
            BLEFrame(30.2, 10, -55, target, peer, "LL_CONTROL", bytes([LLOpcode.LL_TERMINATE_IND, 0x05]))
        )
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertEqual(reason, "Connection terminated during encryption handshake")

    def test_csrk_signing_oracle_replay_truncated_and_failures(self) -> None:
        """Audit CSRKSigningOracleEvaluator against counter replay, empty drops, and truncated writes."""
        target = "AA:BB:CC:DD:EE:FF"
        central = "11:22:33:44:55:66"
        csrk = b"\x42" * 16
        evaluator = CSRKSigningOracleEvaluator(target_mac=target, csrk=csrk)

        def make_signed_req(counter: int, key: bytes = csrk) -> BLEFrame:
            mac = compute_csrk_cmac(key, 0x0012, b"\x01", counter)
            pdu = ATTSignedWritePayload(0x0012, b"\x01", counter, mac).serialize()
            return BLEFrame(1.0 + counter, 5, -60, central, target, "ATT", pdu)

        ack_rsp = BLEFrame(2.1, 5, -60, target, central, "LL_DATA", b"\x01\x00")
        empty_rsp = BLEFrame(2.1, 5, -60, target, central, "LL_EMPTY", b"")
        term_rsp = BLEFrame(2.1, 5, -60, target, central, "LL_CONTROL", bytes([LLOpcode.LL_TERMINATE_IND, 0x3D]))

        # Empty response -> UNPAIRED and does NOT advance last_counter
        res, _ = evaluator.evaluate_signature_response(make_signed_req(100), empty_rsp)
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertIsNone(evaluator.last_counter)

        # LL_TERMINATE_IND response -> UNPAIRED and does NOT advance last_counter
        res, _ = evaluator.evaluate_signature_response(make_signed_req(100), term_rsp)
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertIsNone(evaluator.last_counter)

        # Valid signed write + ACK -> PAIRED and sets last_counter = 10
        res, reason = evaluator.evaluate_signature_response(make_signed_req(10), ack_rsp)
        self.assertEqual(res, OracleResult.PAIRED)
        self.assertEqual(reason, "Data signature verified via CSRK ACK")
        self.assertEqual(evaluator.last_counter, 10)

        # Replay of counter 10 -> rejected (UNPAIRED)
        res, _ = evaluator.evaluate_signature_response(make_signed_req(10), ack_rsp)
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertEqual(evaluator.last_counter, 10)

        # Rollback to counter 9 -> rejected (UNPAIRED)
        res, _ = evaluator.evaluate_signature_response(make_signed_req(9), ack_rsp)
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertEqual(evaluator.last_counter, 10)

        # Monotonic advance to counter 11 -> PAIRED
        res, _ = evaluator.evaluate_signature_response(make_signed_req(11), ack_rsp)
        self.assertEqual(res, OracleResult.PAIRED)
        self.assertEqual(evaluator.last_counter, 11)

        # Wrong CSRK fails cryptographic check -> UNPAIRED
        res, _ = evaluator.evaluate_signature_response(make_signed_req(12, key=b"\x99" * 16), ack_rsp)
        self.assertEqual(res, OracleResult.UNPAIRED)
        self.assertEqual(evaluator.last_counter, 11)

        # Truncated ATT_SIGNED_WRITE_CMD (< 15 bytes) -> INDETERMINATE without struct.error
        trunc_req = BLEFrame(5.0, 5, -60, central, target, "ATT", bytes([ATTOpcode.ATT_SIGNED_WRITE_CMD, 0x12]))
        res, _ = evaluator.evaluate_signature_response(trunc_req, ack_rsp)
        self.assertEqual(res, OracleResult.INDETERMINATE)

        # Bad CRC -> INDETERMINATE
        bad_crc_rsp = BLEFrame(5.1, 5, -60, target, central, "LL_DATA", b"\x01\x00", crc_valid=False)
        res, _ = evaluator.evaluate_signature_response(make_signed_req(12), bad_crc_rsp)
        self.assertEqual(res, OracleResult.INDETERMINATE)

    def test_app_auth_oracle_two_byte_bounds_and_state_machine(self) -> None:
        """Verify 1-2 byte ATT_READ_RSP / LL_TERMINATE_IND bounds and empty PDU state transitions."""
        target = "CA:FE:BA:BE:00:01"
        central = "10:20:30:40:50:60"
        evaluator = AppAuthOracleEvaluator(target_mac=target, auth_handle=0xFFF1)
        self.assertEqual(evaluator.state, "AWAITING_SERVICE_DISCOVERY")

        # Empty PDU initially -> (INDETERMINATE, "Empty PDU")
        res, reason = evaluator.process_att_frame(BLEFrame(1.0, 12, -50, central, target, "ATT", b""))
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertEqual(reason, "Empty PDU")

        # 2-byte ATT_READ_RSP transitions AWAITING_SERVICE_DISCOVERY -> AWAITING_AUTH_WRITE cleanly
        read_rsp_2b = BLEFrame(1.1, 12, -50, target, central, "ATT", bytes([ATTOpcode.ATT_READ_RSP, 0x01]))
        res, _ = evaluator.process_att_frame(read_rsp_2b)
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AWAITING_AUTH_WRITE")

        # Empty PDU AFTER discovery -> UNPAIRED
        res, _ = evaluator.process_att_frame(BLEFrame(1.2, 12, -50, target, central, "ATT", b""))
        self.assertEqual(res, OracleResult.UNPAIRED)

        # Truncated 2-byte ATT_WRITE_CMD (< 3 bytes) -> INDETERMINATE without struct.error
        evaluator.reset()
        evaluator.process_att_frame(read_rsp_2b)
        trunc_write = BLEFrame(1.3, 12, -50, central, target, "ATT", bytes([ATTOpcode.ATT_WRITE_CMD, 0xF1]))
        res, _ = evaluator.process_att_frame(trunc_write)
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AWAITING_AUTH_WRITE")

        # Write to non-auth handle (0x2902 CCCD) stays AWAITING_AUTH_WRITE
        cccd_write = BLEFrame(
            1.35,
            12,
            -50,
            central,
            target,
            "ATT",
            bytes([ATTOpcode.ATT_WRITE_REQ]) + struct.pack("<H", 0x2902) + b"\x01\x00",
        )
        res, _ = evaluator.process_att_frame(cccd_write)
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AWAITING_AUTH_WRITE")

        # Valid write to 0xFFF1 transitions to AUTH_SUBMITTED
        auth_write = BLEFrame(
            1.4,
            12,
            -50,
            central,
            target,
            "ATT",
            bytes([ATTOpcode.ATT_WRITE_CMD]) + struct.pack("<H", 0xFFF1) + b"TOKEN123",
        )
        res, _ = evaluator.process_att_frame(auth_write)
        self.assertEqual(res, OracleResult.INDETERMINATE)
        self.assertEqual(evaluator.state, "AUTH_SUBMITTED")

        # Truncated 2-byte ATT_HANDLE_VALUE_NOTI (< 3 bytes) -> INDETERMINATE without struct.error
        trunc_noti = BLEFrame(1.45, 12, -50, target, central, "ATT", bytes([ATTOpcode.ATT_HANDLE_VALUE_NOTI, 0xF1]))
        res, _ = evaluator.process_att_frame(trunc_noti)
        self.assertEqual(res, OracleResult.INDETERMINATE)

        # Valid ATT_HANDLE_VALUE_NOTI (>= 3 bytes) in AUTH_SUBMITTED -> PAIRED
        ok_noti = BLEFrame(
            1.5,
            12,
            -50,
            target,
            central,
            "ATT",
            bytes([ATTOpcode.ATT_HANDLE_VALUE_NOTI]) + struct.pack("<H", 0xFFF1) + b"OK",
        )
        res, reason = evaluator.process_att_frame(ok_noti)
        self.assertEqual(res, OracleResult.PAIRED)
        self.assertEqual(reason, "GATT Auth succeeded: NOTIFY(OK) received")

        # 1-byte and 2-byte LL_TERMINATE_IND return exact UNPAIRED termination reason
        for term_bytes in (bytes([LLOpcode.LL_TERMINATE_IND]), bytes([LLOpcode.LL_TERMINATE_IND, 0x13])):
            evaluator.reset()
            evaluator.process_att_frame(read_rsp_2b)
            res, reason = evaluator.process_att_frame(BLEFrame(2.0, 12, -50, target, central, "LL_CONTROL", term_bytes))
            self.assertEqual(res, OracleResult.UNPAIRED)
            self.assertEqual(reason, "Connection terminated prior to GATT auth completion")


class TestEcosystemAdapterAndOrchestrator(unittest.TestCase):
    """Tests ActiveRelayProbeOrchestrator multi-window tracking and AirTell ecosystem integration."""

    def test_multi_window_rpa_correlation_across_15_min_boundaries(self) -> None:
        """Verify RPA correlation across three 15-minute (900s) rotation boundaries."""
        with pytest.raises(ValueError):
            ActiveRelayProbeOrchestrator("target-01", rpa_rotation_window_sec=0.0)

        orch = ActiveRelayProbeOrchestrator("canonical-watch-01", rpa_rotation_window_sec=900.0)
        base_frame = BLEFrame(
            timestamp=1000.0,
            channel=14,
            rssi=-58,
            source_mac="AA:00:00:00:00:01",
            dest_mac="5A:00:00:00:00:01",
            pdu_type="LL_CONTROL",
            payload=bytes([LLOpcode.LL_PING_REQ]),
        )

        rpa_1 = "5A:11:22:33:44:01"
        rpa_2 = "6B:11:22:33:44:02"
        rpa_3 = "7C:11:22:33:44:03"
        bystander_rpa = "5E:99:99:99:99:99"

        probed = orch.relay_probe_frame(base_frame, rpa_1)
        self.assertEqual(probed.dest_mac, rpa_1)
        self.assertEqual(probed.payload, base_frame.payload)

        self.assertTrue(orch.evaluate_and_correlate(rpa_1, OracleResult.PAIRED, timestamp=1000.0))
        # Duplicate observation in same window does not add duplicate RPA or interval
        self.assertTrue(orch.evaluate_and_correlate(rpa_1, OracleResult.PAIRED, timestamp=1100.0))
        # Bystander UNPAIRED and hardened INDETERMINATE are not correlated
        self.assertFalse(orch.evaluate_and_correlate(bystander_rpa, OracleResult.UNPAIRED, timestamp=1200.0))
        self.assertFalse(orch.evaluate_and_correlate("6F:00:00:00:00:00", OracleResult.INDETERMINATE, timestamp=1300.0))

        # Window 2 (+900s) and Window 3 (+900s)
        self.assertTrue(orch.evaluate_and_correlate(rpa_2, OracleResult.PAIRED, timestamp=2000.0))
        self.assertTrue(orch.evaluate_and_correlate(rpa_3, OracleResult.PAIRED, timestamp=2900.0))

        self.assertEqual(orch.identity_record.observed_rpas, [rpa_1, rpa_2, rpa_3])
        self.assertEqual(len(orch.rotation_intervals), 2)
        self.assertAlmostEqual(orch.rotation_intervals[0], 900.0)
        self.assertAlmostEqual(orch.rotation_intervals[1], 900.0)

        summary = orch.correlation_summary()
        self.assertEqual(summary["canonical_id"], "canonical-watch-01")
        self.assertEqual(summary["correlated_rpa_count"], 3)
        self.assertTrue(summary["privacy_leak_detected"])

    def test_ble_packet_record_to_frame_conversions(self) -> None:
        """Verify BlePacketRecord conversion across advertising, LL control, ATT, and malformed PDUs."""
        conn_aa = 0x5065719A

        # Advertising PDUs
        conn_ind = BlePacketRecord(
            body=build_connect_ind("11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", conn_aa=conn_aa),
            channel=37,
            rssi=-48,
            timestamp_usec=1_500_000,
            access_address=BLE_ADV_AA,
        )
        conn_frame = ble_packet_record_to_frame(conn_ind)
        self.assertEqual(conn_frame.pdu_type, "CONNECT_IND")
        self.assertAlmostEqual(conn_frame.timestamp, 1.5)
        self.assertEqual(conn_frame.source_mac, "11:22:33:44:55:66")
        self.assertEqual(conn_frame.dest_mac, "AA:BB:CC:DD:EE:FF")

        adv_ind_frame = ble_packet_record_to_frame(
            BlePacketRecord(build_adv_ind("AA:BB:CC:DD:EE:FF", b"\x02\x01\x06"), 37, -60, 2_000_000)
        )
        self.assertEqual(adv_ind_frame.pdu_type, "ADV_IND")

        scan_req_frame = ble_packet_record_to_frame(
            BlePacketRecord(build_scan_req("11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"), 38, -55, 2_100_000)
        )
        self.assertEqual(scan_req_frame.pdu_type, "SCAN_REQ")

        direct_frame = ble_packet_record_to_frame(
            BlePacketRecord(build_adv_direct_ind("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"), 39, -52, 2_200_000)
        )
        self.assertEqual(direct_frame.pdu_type, "ADV_DIRECT_IND")

        # Data Channel LL_ENC_REQ -> LLEncryptionReqPayload compatible
        enc_rec = BlePacketRecord(
            body=build_ll_enc_req(ediv=0x1234),
            channel=11,
            rssi=-50,
            timestamp_usec=3_000_000,
            access_address=conn_aa,
            direction=0,
        )
        enc_frame = ble_packet_record_to_frame(
            enc_rec,
            source_mac="11:22:33:44:55:66",
            dest_mac="AA:BB:CC:DD:EE:FF",
        )
        self.assertEqual(enc_frame.pdu_type, "LL_CONTROL")
        parsed_enc = LLEncryptionReqPayload.deserialize(enc_frame.payload)
        self.assertEqual(parsed_enc.ediv, 0x1234)

        # Data Channel ATT_SIGNED_WRITE_CMD -> ATTSignedWritePayload compatible
        csrk = b"\x55" * 16
        sw_rec = BlePacketRecord(
            body=build_att_signed_write(csrk=csrk, handle=0x0025, value=b"ping", counter=7),
            channel=12,
            rssi=-52,
            timestamp_usec=4_000_000,
            access_address=conn_aa,
            direction=0,
            crc_err=True,
        )
        sw_frame = ble_packet_record_to_frame(sw_rec)
        self.assertEqual(sw_frame.pdu_type, "ATT")
        self.assertFalse(sw_frame.crc_valid)
        parsed_sw = ATTSignedWritePayload.deserialize(sw_frame.payload)
        self.assertEqual(parsed_sw.handle, 0x0025)
        self.assertEqual(parsed_sw.signature_counter, 7)
        self.assertTrue(parsed_sw.verify_cmac(csrk))

        # Empty Data PDU and Malformed 1-byte PDU
        empty_frame = ble_packet_record_to_frame(
            BlePacketRecord(build_ll_header(llid=1, length=0), 5, -60, 5_000_000, access_address=conn_aa)
        )
        self.assertEqual(empty_frame.pdu_type, "LL_EMPTY")
        self.assertEqual(empty_frame.payload, b"")

        malformed_frame = ble_packet_record_to_frame(
            BlePacketRecord(b"\x01", 5, -60, 5_100_000, access_address=conn_aa)
        )
        self.assertEqual(malformed_frame.pdu_type, "MALFORMED")
        self.assertEqual(malformed_frame.payload, b"")

    def test_idbleed_verification_analyzer_on_synthetic_streams(self) -> None:
        """Audit BlePacketRecord streams via IdbleedVerificationAnalyzer (SideChannelAnalyzer)."""
        analyzer = IdbleedVerificationAnalyzer()
        self.assertIsInstance(analyzer, SideChannelAnalyzer)
        self.assertEqual(analyzer.finalize().verdict, Verdict.INCONCLUSIVE.value)

        # 1. Paired encryption PCAP trace + Unpaired encryption PCAP trace
        paired_pcap = generate_encryption_trace(
            shared_ltk=True,
            central_addr="11:22:33:44:55:66",
            periph_addr="AA:BB:CC:DD:EE:01",
            conn_aa=0x11112222,
        )
        unpaired_pcap = generate_encryption_trace(
            shared_ltk=False,
            central_addr="77:88:99:AA:BB:CC",
            periph_addr="AA:BB:CC:DD:EE:01",
            base_time_usec=5_000_000,
            conn_aa=0x12345678,
        )
        with PcapBleReader(io.BytesIO(paired_pcap)) as reader:
            for pkt in reader:
                analyzer.process_packet(pkt)
        with PcapBleReader(io.BytesIO(unpaired_pcap)) as reader:
            for pkt in reader:
                analyzer.process_packet(pkt)

        report = analyzer.finalize()
        self.assertEqual(report.verdict, Verdict.CONFIRMED_EXCLUSIVE.value)
        self.assertGreaterEqual(report.metrics["paired_verdicts"], 1)
        self.assertGreaterEqual(report.metrics["unpaired_verdicts"], 1)

        # 2. CSRK PCAP trace with explicit CSRK verification and Empty LL ACK
        csrk = b"\x33" * 16
        conn_aa = 0x55667788
        analyzer = IdbleedVerificationAnalyzer(csrk=csrk)
        csrk_pcap = generate_csrk_trace(
            counter_sequence=[1, 2],
            csrk=csrk,
            central_addr="11:22:33:44:55:66",
            periph_addr="AA:BB:CC:DD:EE:02",
            aa=conn_aa,
        )
        with PcapBleReader(io.BytesIO(csrk_pcap)) as reader:
            for pkt in reader:
                rec = BlePacketRecord.from_captured_ble_packet(pkt)
                analyzer.process_packet(rec)
                if rec.access_address == conn_aa and rec.channel < 37:
                    # Peripheral responds with Link-Layer empty data ACK on data channel
                    ack_rec = BlePacketRecord(
                        body=build_ll_header(llid=1, length=0, nesn=1, sn=0),
                        channel=rec.channel,
                        rssi=-55,
                        timestamp_usec=rec.timestamp_usec + 1500,
                        access_address=conn_aa,
                        direction=1,
                    )
                    analyzer.process_packet(ack_rec)

        csrk_report = analyzer.finalize()
        self.assertEqual(csrk_report.verdict, Verdict.PAIRED_SHARED_LTK.value)
        self.assertEqual(csrk_report.metrics["paired_verdicts"], 2)

        # 3. Verify GATT AppAuth and rejection-only verdicts via raw BlePacketRecords
        analyzer.reset()
        gatt_aa = 0x99887766
        analyzer.process_packet(
            BlePacketRecord(
                build_connect_ind("11:22:33:44:55:66", "AA:BB:CC:DD:EE:09", conn_aa=gatt_aa),
                37,
                -50,
                900_000,
            )
        )

        def wrap_att(att_pdu: bytes) -> bytes:
            l2cap = struct.pack("<HH", len(att_pdu), 0x0004) + att_pdu
            return build_ll_header(llid=2, length=len(l2cap)) + l2cap

        analyzer.process_packet(
            BlePacketRecord(
                wrap_att(bytes([ATTOpcode.ATT_READ_RSP, 0x01])),
                6,
                -50,
                910_000,
                access_address=gatt_aa,
                direction=1,
            )
        )
        analyzer.process_packet(
            BlePacketRecord(
                wrap_att(bytes([ATTOpcode.ATT_WRITE_CMD]) + struct.pack("<H", 0xFFF1) + b"AUTH"),
                6,
                -50,
                920_000,
                access_address=gatt_aa,
                direction=0,
            )
        )
        analyzer.process_packet(
            BlePacketRecord(
                wrap_att(bytes([ATTOpcode.ATT_HANDLE_VALUE_NOTI]) + struct.pack("<H", 0xFFF1) + b"OK"),
                6,
                -50,
                930_000,
                access_address=gatt_aa,
                direction=1,
            )
        )
        self.assertEqual(analyzer.finalize().verdict, Verdict.PAIRED_SHARED_LTK.value)

        # Rejection-only session report
        analyzer.reset()
        analyzer.process_packet(
            BlePacketRecord(build_ll_reject_ind(), 4, -50, 1_020_000, access_address=0xABCDEF02, direction=1)
        )
        analyzer.process_packet(
            BlePacketRecord(build_ll_terminate_ind(), 4, -50, 1_030_000, access_address=0xABCDEF03, direction=1)
        )
        rej_report = analyzer.finalize()
        self.assertEqual(rej_report.verdict, Verdict.REJECTED_UNTRUSTED.value)
        self.assertIn("packets_processed", rej_report.to_dict()["metrics"])

    def test_root_wrapper_exports_all_public_symbols(self) -> None:
        """Verify repository-root idbleed_spec.py cleanly re-exports the specification API."""
        expected_exports = (
            "OracleResult",
            "LLOpcode",
            "ATTOpcode",
            "BLEFrame",
            "LLEncryptionReqPayload",
            "ATTSignedWritePayload",
            "compute_csrk_cmac",
            "LLEncryptionOracleEvaluator",
            "CSRKSigningOracleEvaluator",
            "AppAuthOracleEvaluator",
            "IdentityRecord",
            "ActiveRelayProbeOrchestrator",
            "ble_packet_record_to_frame",
            "IdbleedVerificationAnalyzer",
            "TestIDBLEEDSpecification",
        )
        for symbol in expected_exports:
            self.assertTrue(hasattr(root_idbleed_spec, symbol), f"Missing export {symbol}")
