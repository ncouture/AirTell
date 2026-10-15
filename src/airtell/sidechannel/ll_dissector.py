"""Link-Layer Control PDU and ATT Signed Write packet dissector.

Provides bit-level dissection for:
1. Data Channel PDUs (LLID = 0b11 Control, LLID = 0b10 L2CAP Start, LLID = 0b01 L2CAP Cont/Empty).
2. Link Layer Control Opcodes:
   - LL_ENC_REQ (0x03), LL_ENC_RSP (0x04), LL_START_ENC_REQ (0x05), LL_START_ENC_RSP (0x06)
   - LL_REJECT_IND (0x0D), LL_REJECT_EXT_IND (0x11), LL_TERMINATE_IND (0x02)
   - LL_CONNECTION_UPDATE_IND (0x00), LL_CONNECTION_PARAM_REQ (0x0F), LL_CONNECTION_PARAM_RSP (0x10)
3. L2CAP B-frames (CID = 0x0004 ATT) and ATT_SIGNED_WRITE_CMD (Opcode 0xD2) with 64-bit truncated AES-CMAC.
4. Advertising Channel PDUs (ADV_IND, ADV_DIRECT_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from airtell.protocol.mac import mac_to_str
from airtell.sidechannel.synthetic import (
    ATT_OPCODE_SIGNED_WRITE_CMD,
    L2CAP_CID_ATT,
    LL_CONTROL_OPCODE_NAMES,
    OPCODE_LL_CONNECTION_PARAM_REQ,
    OPCODE_LL_CONNECTION_PARAM_RSP,
    OPCODE_LL_CONNECTION_UPDATE_IND,
    OPCODE_LL_ENC_REQ,
    OPCODE_LL_ENC_RSP,
    OPCODE_LL_PAUSE_ENC_REQ,
    OPCODE_LL_PAUSE_ENC_RSP,
    OPCODE_LL_REJECT_EXT_IND,
    OPCODE_LL_REJECT_IND,
    OPCODE_LL_START_ENC_REQ,
    OPCODE_LL_START_ENC_RSP,
    OPCODE_LL_TERMINATE_IND,
    compute_csrk_mac,
)
from airtell.sniff.pcap import BLE_ADV_AA

ATT_OPCODE_ERROR_RSP: int = 0x01
ATT_OPCODE_WRITE_CMD: int = 0x52
ATT_OPCODE_WRITE_REQ: int = 0x12
ATT_OPCODE_HANDLE_VALUE_NTF: int = 0x1B
ATT_OPCODE_HANDLE_VALUE_IND: int = 0x1D


@dataclass
class LlControlFrame:
    """Dissected Link-Layer Control PDU (LLID = 0b11).

    Attributes:
        opcode: 1-byte LL Control opcode.
        name: Human-readable specification name (e.g. 'LL_ENC_REQ').
        payload: Decoded dictionary of opcode parameters.
        raw_bytes: Raw control frame bytes (opcode + payload).
    """

    opcode: int
    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    raw_bytes: bytes = b""


@dataclass
class AttSignedWriteFrame:
    """Dissected ATT Signed Write Command (Opcode 0xD2).

    Attributes:
        handle: 16-bit attribute handle.
        value: Characteristic value payload bytes.
        sign_counter: 32-bit unsigned SignCounter (SC).
        auth_signature: 12-byte authentication signature (4B SC + 8B MAC).
        mac: 8-byte authentication MAC.
        mac_valid: True/False if CSRK was provided and checked, None if no CSRK provided.
    """

    handle: int
    value: bytes
    sign_counter: int
    auth_signature: bytes
    mac: bytes
    mac_valid: bool | None = None


@dataclass
class AttErrorFrame:
    """Dissected ATT Error Response (Opcode 0x01)."""

    req_opcode: int
    handle: int
    error_code: int


@dataclass
class DissectedDataPdu:
    """Dissected Link-Layer Data Channel PDU.

    Attributes:
        llid: 2-bit Logical Link Identifier (0b01, 0b10, 0b11).
        sn: 1-bit Sequence Number.
        nesn: 1-bit Next Expected Sequence Number.
        length: 8-bit PDU length from header.
        control_frame: Present if LLID == 0b11 (Control).
        att_frame: Present if LLID == 0b10, CID == 0x0004 and ATT Opcode == 0xD2.
        att_error: Present if LLID == 0b10, CID == 0x0004 and ATT Opcode == 0x01.
        raw_payload: Payload bytes excluding 2-byte LL header.
        raw_bytes: Complete raw PDU bytes.
    """

    llid: int
    sn: int
    nesn: int
    length: int
    control_frame: LlControlFrame | None = None
    att_frame: AttSignedWriteFrame | None = None
    att_error: AttErrorFrame | None = None
    raw_payload: bytes = b""
    raw_bytes: bytes = b""


@dataclass
class DissectedAdvertisingPdu:
    """Dissected Link-Layer Advertising Channel PDU.

    Attributes:
        pdu_type: 4-bit PDU type (0x00-0x07).
        pdu_name: Specification name (ADV_IND, ADV_DIRECT_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND).
        tx_add: TxAdd address type bit (0=Public, 1=Random).
        rx_add: RxAdd address type bit (0=Public, 1=Random).
        adv_a: Advertiser address (MAC string).
        target_a: Target address (for ADV_DIRECT_IND).
        scan_a: Scanner address (for SCAN_REQ).
        init_a: Initiator address (for CONNECT_IND).
        conn_aa: Connection Access Address (for CONNECT_IND).
        interval: Connection interval (for CONNECT_IND).
        latency: Peripheral latency (for CONNECT_IND).
        timeout: Supervision timeout (for CONNECT_IND).
        hop: Hop increment (for CONNECT_IND).
        data: Advertising or scan response payload bytes.
        raw_bytes: Complete raw PDU bytes.
    """

    pdu_type: int
    pdu_name: str
    tx_add: int
    rx_add: int
    adv_a: str | None = None
    target_a: str | None = None
    scan_a: str | None = None
    init_a: str | None = None
    conn_aa: int | None = None
    interval: int | None = None
    latency: int | None = None
    timeout: int | None = None
    hop: int | None = None
    data: bytes = b""
    raw_bytes: bytes = b""


ADV_PDU_NAMES: dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND",
}


def dissect_ll_control_pdu(ctr_data: bytes) -> LlControlFrame | None:
    """Dissect Link-Layer Control PDU payload (Opcode + CtrData).

    Args:
        ctr_data: Bytes starting with the 1-byte opcode.

    Returns:
        LlControlFrame or None if malformed.
    """
    if not ctr_data:
        return None

    opcode = ctr_data[0]
    name = LL_CONTROL_OPCODE_NAMES.get(opcode, f"UNKNOWN_LL_CONTROL_0x{opcode:02X}")
    payload_bytes = ctr_data[1:]
    payload: dict[str, Any] = {}

    try:
        if opcode == OPCODE_LL_ENC_REQ:
            if len(payload_bytes) < 22:
                payload["error"] = "truncated_enc_req"
            else:
                rand = payload_bytes[0:8]
                ediv = struct.unpack("<H", payload_bytes[8:10])[0]
                skdm = payload_bytes[10:18]
                ivm = payload_bytes[18:22]
                payload = {
                    "rand": rand,
                    "rand_hex": rand.hex(),
                    "ediv": ediv,
                    "skdm": skdm,
                    "skdm_hex": skdm.hex(),
                    "ivm": ivm,
                    "ivm_hex": ivm.hex(),
                }

        elif opcode == OPCODE_LL_ENC_RSP:
            if len(payload_bytes) < 12:
                payload["error"] = "truncated_enc_rsp"
            else:
                skds = payload_bytes[0:8]
                ivs = payload_bytes[8:12]
                payload = {
                    "skds": skds,
                    "skds_hex": skds.hex(),
                    "ivs": ivs,
                    "ivs_hex": ivs.hex(),
                }

        elif opcode == OPCODE_LL_START_ENC_REQ:
            # 0 bytes payload
            payload = {}

        elif opcode == OPCODE_LL_START_ENC_RSP:
            # 0 bytes unencrypted payload, or 4-byte MIC if encrypted
            if len(payload_bytes) >= 4:
                payload = {"mic": payload_bytes[:4], "mic_hex": payload_bytes[:4].hex()}
            else:
                payload = {}

        elif opcode == OPCODE_LL_REJECT_IND:
            if len(payload_bytes) >= 1:
                payload = {"error_code": payload_bytes[0]}
            else:
                payload["error"] = "truncated_reject_ind"

        elif opcode == OPCODE_LL_REJECT_EXT_IND:
            if len(payload_bytes) >= 2:
                payload = {
                    "reject_opcode": payload_bytes[0],
                    "reject_opcode_name": LL_CONTROL_OPCODE_NAMES.get(
                        payload_bytes[0], f"0x{payload_bytes[0]:02X}"
                    ),
                    "error_code": payload_bytes[1],
                }
            elif len(payload_bytes) == 1:
                payload = {
                    "reject_opcode": payload_bytes[0],
                    "reject_opcode_name": LL_CONTROL_OPCODE_NAMES.get(
                        payload_bytes[0], f"0x{payload_bytes[0]:02X}"
                    ),
                    "error": "truncated_reject_ext_ind",
                }
            else:
                payload["error"] = "truncated_reject_ext_ind"

        elif opcode == OPCODE_LL_TERMINATE_IND:
            if len(payload_bytes) >= 1:
                payload = {"error_code": payload_bytes[0]}
            else:
                payload["error"] = "truncated_terminate_ind"

        elif opcode == OPCODE_LL_CONNECTION_UPDATE_IND:
            if len(payload_bytes) >= 11:
                win_size = payload_bytes[0]
                win_offset, interval, latency, timeout, instant = struct.unpack(
                    "<HHHHH", payload_bytes[1:11]
                )
                payload = {
                    "win_size": win_size,
                    "win_offset": win_offset,
                    "interval": interval,
                    "latency": latency,
                    "timeout": timeout,
                    "instant": instant,
                    "interval_ms": interval * 1.25,
                    "timeout_ms": timeout * 10,
                }
            else:
                payload["error"] = "truncated_conn_update_ind"

        elif opcode in (OPCODE_LL_CONNECTION_PARAM_REQ, OPCODE_LL_CONNECTION_PARAM_RSP):
            if len(payload_bytes) >= 8:
                int_min, int_max, latency, timeout = struct.unpack("<HHHH", payload_bytes[0:8])
                payload = {
                    "interval_min": int_min,
                    "interval_max": int_max,
                    "latency": latency,
                    "timeout": timeout,
                    "interval_min_ms": int_min * 1.25,
                    "interval_max_ms": int_max * 1.25,
                    "timeout_ms": timeout * 10,
                }
            else:
                payload["error"] = "truncated_conn_param"

        elif opcode in (OPCODE_LL_PAUSE_ENC_REQ, OPCODE_LL_PAUSE_ENC_RSP):
            payload = {}

        else:
            payload = {"raw_payload": payload_bytes}

    except Exception as exc:
        payload["parse_exception"] = str(exc)

    return LlControlFrame(opcode=opcode, name=name, payload=payload, raw_bytes=ctr_data)


def dissect_att_pdu(
    l2cap_payload: bytes, csrk: bytes | None = None
) -> tuple[AttSignedWriteFrame | None, AttErrorFrame | None]:
    """Dissect ATT PDU from L2CAP payload (CID 0x0004).

    Args:
        l2cap_payload: Bytes of the ATT PDU (starting with 1-byte opcode).
        csrk: Optional 16-byte CSRK for AES-CMAC signature verification.

    Returns:
        Tuple of (AttSignedWriteFrame | None, AttErrorFrame | None).
    """
    if not l2cap_payload:
        return None, None

    opcode = l2cap_payload[0]

    if opcode == ATT_OPCODE_SIGNED_WRITE_CMD:
        # Minimum length: Opcode (1B) + Handle (2B) + Value (0B) + AuthSignature (12B: 4B SC + 8B MAC) = 15B
        if len(l2cap_payload) < 15:
            return None, None

        handle = struct.unpack("<H", l2cap_payload[1:3])[0]
        val_len = len(l2cap_payload) - 15
        value = l2cap_payload[3 : 3 + val_len]
        sig_bytes = l2cap_payload[3 + val_len :]
        sign_counter = struct.unpack("<I", sig_bytes[0:4])[0]
        mac = sig_bytes[4:12]

        mac_valid: bool | None = None
        if csrk is not None and len(csrk) == 16:
            try:
                expected_mac = compute_csrk_mac(
                    csrk=csrk,
                    opcode=opcode,
                    handle=handle,
                    value=value,
                    counter=sign_counter,
                )
                mac_valid = mac == expected_mac
            except Exception:
                mac_valid = False

        frame = AttSignedWriteFrame(
            handle=handle,
            value=value,
            sign_counter=sign_counter,
            auth_signature=sig_bytes,
            mac=mac,
            mac_valid=mac_valid,
        )
        return frame, None

    if opcode == ATT_OPCODE_ERROR_RSP:
        # Opcode (1B) + ReqOpcode (1B) + Handle (2B) + ErrorCode (1B) = 5B
        if len(l2cap_payload) >= 5:
            req_op = l2cap_payload[1]
            handle = struct.unpack("<H", l2cap_payload[2:4])[0]
            err = l2cap_payload[4]
            return None, AttErrorFrame(req_opcode=req_op, handle=handle, error_code=err)

    return None, None


def dissect_data_channel_pdu(
    raw_bytes: bytes, csrk: bytes | None = None
) -> DissectedDataPdu | None:
    """Dissect Link-Layer Data Channel PDU (Bluetooth Core Spec Vol 6 Part B §2.4).

    Args:
        raw_bytes: Raw Link-Layer PDU bytes (2-byte header + payload).
        csrk: Optional 16-byte CSRK for ATT Signed Write authentication verification.

    Returns:
        DissectedDataPdu or None if malformed.
    """
    if len(raw_bytes) < 2:
        return None

    hdr0 = raw_bytes[0]
    hdr1 = raw_bytes[1]

    llid = hdr0 & 0x03
    nesn = (hdr0 >> 2) & 0x01
    sn = (hdr0 >> 3) & 0x01
    length = hdr1

    payload = raw_bytes[2 : 2 + length]
    # If payload is truncated relative to header length, take what is available
    if len(payload) < length and len(raw_bytes) > 2:
        payload = raw_bytes[2:]

    control_frame: LlControlFrame | None = None
    att_frame: AttSignedWriteFrame | None = None
    att_error: AttErrorFrame | None = None

    if llid == 3:  # LLID = 0b11: Link Layer Control PDU
        control_frame = dissect_ll_control_pdu(payload)

    elif llid == 2:  # LLID = 0b10: L2CAP Start fragment
        if len(payload) >= 4:
            l2cap_len, cid = struct.unpack("<HH", payload[0:4])
            l2cap_body = payload[4 : 4 + l2cap_len]
            if cid == L2CAP_CID_ATT:
                att_frame, att_error = dissect_att_pdu(l2cap_body, csrk=csrk)

    return DissectedDataPdu(
        llid=llid,
        sn=sn,
        nesn=nesn,
        length=length,
        control_frame=control_frame,
        att_frame=att_frame,
        att_error=att_error,
        raw_payload=payload,
        raw_bytes=raw_bytes,
    )


def dissect_advertising_pdu(raw_bytes: bytes) -> DissectedAdvertisingPdu | None:
    """Dissect Link-Layer Advertising Channel PDU (Bluetooth Core Spec Vol 6 Part B §2.3).

    Args:
        raw_bytes: Raw Link-Layer advertising PDU bytes (2-byte header + payload).

    Returns:
        DissectedAdvertisingPdu or None if malformed.
    """
    if len(raw_bytes) < 2:
        return None

    hdr0 = raw_bytes[0]
    hdr1 = raw_bytes[1]

    pdu_type = hdr0 & 0x0F
    tx_add = (hdr0 >> 6) & 0x01
    rx_add = (hdr0 >> 7) & 0x01
    length = hdr1 & 0x3F

    payload = raw_bytes[2 : 2 + length]
    if len(payload) < length and len(raw_bytes) > 2:
        payload = raw_bytes[2:]

    name = ADV_PDU_NAMES.get(pdu_type, f"UNKNOWN_ADV_0x{pdu_type:02X}")

    adv_a: str | None = None
    target_a: str | None = None
    scan_a: str | None = None
    init_a: str | None = None
    conn_aa: int | None = None
    interval: int | None = None
    latency: int | None = None
    timeout: int | None = None
    hop: int | None = None
    data: bytes = b""

    try:
        if pdu_type in (0x00, 0x02, 0x06):  # ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND
            if len(payload) >= 6:
                adv_a = mac_to_str(payload[0:6])
                data = payload[6:]
        elif pdu_type == 0x01:  # ADV_DIRECT_IND
            if len(payload) >= 12:
                adv_a = mac_to_str(payload[0:6])
                target_a = mac_to_str(payload[6:12])
        elif pdu_type == 0x03:  # SCAN_REQ
            if len(payload) >= 12:
                scan_a = mac_to_str(payload[0:6])
                adv_a = mac_to_str(payload[6:12])
        elif pdu_type == 0x04:  # SCAN_RSP
            if len(payload) >= 6:
                adv_a = mac_to_str(payload[0:6])
                data = payload[6:]
        elif pdu_type == 0x05:  # CONNECT_IND
            if len(payload) >= 34:
                init_a = mac_to_str(payload[0:6])
                adv_a = mac_to_str(payload[6:12])
                ll_data = payload[12:34]
                conn_aa = struct.unpack("<I", ll_data[0:4])[0]
                interval = struct.unpack("<H", ll_data[10:12])[0]
                latency = struct.unpack("<H", ll_data[12:14])[0]
                timeout = struct.unpack("<H", ll_data[14:16])[0]
                hop = ll_data[21] & 0x1F
    except Exception:
        pass

    return DissectedAdvertisingPdu(
        pdu_type=pdu_type,
        pdu_name=name,
        tx_add=tx_add,
        rx_add=rx_add,
        adv_a=adv_a,
        target_a=target_a,
        scan_a=scan_a,
        init_a=init_a,
        conn_aa=conn_aa,
        interval=interval,
        latency=latency,
        timeout=timeout,
        hop=hop,
        data=data,
        raw_bytes=raw_bytes,
    )


def dissect_ble_pdu(
    raw_bytes: bytes,
    is_data_channel: bool | None = None,
    access_address: int = BLE_ADV_AA,
    csrk: bytes | None = None,
) -> DissectedDataPdu | DissectedAdvertisingPdu | None:
    """Convenience demuxer for dissecting either Data Channel or Advertising Channel PDUs.

    Args:
        raw_bytes: Raw Link-Layer PDU bytes.
        is_data_channel: Explicit flag indicating whether this is a Data Channel PDU.
        access_address: 32-bit Access Address (defaults to 0x8E89BED6 for advertising).
        csrk: Optional 16-byte CSRK for ATT Signed Write authentication verification.

    Returns:
        DissectedDataPdu, DissectedAdvertisingPdu, or None if malformed.
    """
    if len(raw_bytes) < 2:
        return None

    if is_data_channel is None:
        is_data_channel = access_address != BLE_ADV_AA

    if is_data_channel:
        return dissect_data_channel_pdu(raw_bytes, csrk=csrk)
    return dissect_advertising_pdu(raw_bytes)
