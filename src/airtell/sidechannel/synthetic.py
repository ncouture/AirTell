"""Synthetic packet trace generator and PCAP fixture builder for BLE Link-Layer side-channels.

Provides bit-accurate synthesis for:
1. Link-Layer Control PDUs (LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ, LL_START_ENC_RSP,
   LL_REJECT_IND, LL_REJECT_EXT_IND, LL_TERMINATE_IND, LL_CONNECTION_UPDATE_IND).
2. ATT Signed Write commands (Opcode 0xD2) with L2CAP framing and 64-bit truncated AES-CMAC
   using 128-bit CSRK and 32-bit SignCounter.
3. BAT / Allowlist advertising behaviors (ADV_DIRECT_IND, selective SCAN_RSP vs silent drop,
   fast/slow reconnection timing intervals, and connection parameter tuples).
4. PCAP fixture generation with standard DLT 256 (DLT_BLUETOOTH_LE_LL_WITH_PHDR) via PcapBleWriter.
5. In-memory packet stream generation producing PacketMessage and CapturedBlePacket sequences.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

from airtell.protocol.mac import str_to_mac
from airtell.protocol.wire import PHY_1M, PacketMessage
from airtell.sniff.pcap import (
    BLE_ADV_AA,
    CapturedBlePacket,
    PcapBleReader,
    PcapBleWriter,
)

# -----------------------------------------------------------------------------
# Link Layer Control Opcodes (Bluetooth Core Spec Vol 6, Part B, §2.4.2)
# -----------------------------------------------------------------------------
OPCODE_LL_CONNECTION_UPDATE_IND: int = 0x00
OPCODE_LL_TERMINATE_IND: int = 0x02
OPCODE_LL_ENC_REQ: int = 0x03
OPCODE_LL_ENC_RSP: int = 0x04
OPCODE_LL_START_ENC_REQ: int = 0x05
OPCODE_LL_START_ENC_RSP: int = 0x06
OPCODE_LL_PAUSE_ENC_REQ: int = 0x0A
OPCODE_LL_PAUSE_ENC_RSP: int = 0x0B
OPCODE_LL_REJECT_IND: int = 0x0D
OPCODE_LL_CONNECTION_PARAM_REQ: int = 0x0F
OPCODE_LL_CONNECTION_PARAM_RSP: int = 0x10
OPCODE_LL_REJECT_EXT_IND: int = 0x11

LL_CONTROL_OPCODE_NAMES: dict[int, str] = {
    OPCODE_LL_CONNECTION_UPDATE_IND: "LL_CONNECTION_UPDATE_IND",
    OPCODE_LL_TERMINATE_IND: "LL_TERMINATE_IND",
    OPCODE_LL_ENC_REQ: "LL_ENC_REQ",
    OPCODE_LL_ENC_RSP: "LL_ENC_RSP",
    OPCODE_LL_START_ENC_REQ: "LL_START_ENC_REQ",
    OPCODE_LL_START_ENC_RSP: "LL_START_ENC_RSP",
    OPCODE_LL_PAUSE_ENC_REQ: "LL_PAUSE_ENC_REQ",
    OPCODE_LL_PAUSE_ENC_RSP: "LL_PAUSE_ENC_RSP",
    OPCODE_LL_REJECT_IND: "LL_REJECT_IND",
    OPCODE_LL_CONNECTION_PARAM_REQ: "LL_CONNECTION_PARAM_REQ",
    OPCODE_LL_CONNECTION_PARAM_RSP: "LL_CONNECTION_PARAM_RSP",
    OPCODE_LL_REJECT_EXT_IND: "LL_REJECT_EXT_IND",
}

# -----------------------------------------------------------------------------
# Bluetooth Core Specification Error Codes (Vol 1, Part F, §2)
# -----------------------------------------------------------------------------
ERROR_SUCCESS: int = 0x00
ERROR_AUTHENTICATION_FAILURE: int = 0x05
ERROR_PIN_OR_KEY_MISSING: int = 0x06
ERROR_REMOTE_USER_TERMINATED: int = 0x13
ERROR_UNSUPPORTED_REMOTE_FEATURE: int = 0x1A
ERROR_MIC_FAILURE: int = 0x3D

# -----------------------------------------------------------------------------
# Attribute Protocol (ATT) Constants
# -----------------------------------------------------------------------------
ATT_OPCODE_SIGNED_WRITE_CMD: int = 0xD2
L2CAP_CID_ATT: int = 0x0004

# -----------------------------------------------------------------------------
# Advertising Channel PDU Types (Bluetooth Core Spec Vol 6, Part B, §2.3)
# -----------------------------------------------------------------------------
ADV_PDU_ADV_IND: int = 0x00
ADV_PDU_ADV_DIRECT_IND: int = 0x01
ADV_PDU_ADV_NONCONN_IND: int = 0x02
ADV_PDU_SCAN_REQ: int = 0x03
ADV_PDU_SCAN_RSP: int = 0x04
ADV_PDU_CONNECT_IND: int = 0x05
ADV_PDU_ADV_SCAN_IND: int = 0x06


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
@dataclass
class SyntheticEvent:
    """Represents an individual synthesized BLE Link-Layer packet event.

    Attributes:
        ts_usec: Microsecond timestamp (relative or absolute).
        chan: BLE logical channel index (0-36 for data, 37-39 for advertising).
        aa: 32-bit Access Address.
        body: Raw Link-Layer PDU bytes (2-byte header + payload, without 3-byte CRC).
        rssi: Signal strength in dBm (-128 to 127).
        phy: PHY mode (0 = 1M, 1 = 2M, 2 = Coded S=8, 3 = Coded S=2).
        direction: Packet direction (0: Central->Peripheral, 1: Peripheral->Central).
        crc_err: Whether to flag CRC error in pseudo-header.
        pdu_type: Optional explicit pseudo-header pdu_type override (0-3).
    """

    ts_usec: int
    chan: int = 37
    aa: int = BLE_ADV_AA
    body: bytes = b""
    rssi: int = -60
    phy: int = PHY_1M
    direction: int = 0
    crc_err: bool = False
    pdu_type: int | None = None


@dataclass
class ConnectionParameters:
    """Link-Layer connection timing and hopping parameters tuple <Interval, Latency, Timeout, Hop>.

    Attributes:
        interval: Connection interval in 1.25 ms units (6 to 3200, i.e. 7.5ms to 4.0s).
        latency: Peripheral latency in connection events (0 to 499).
        timeout: Supervision timeout in 10 ms units (10 to 3200, i.e. 100ms to 32.0s).
        hop_increment: Frequency hopping increment (5 to 16).
    """

    interval: int = 24  # 30.0 ms
    latency: int = 0
    timeout: int = 100  # 1000 ms
    hop_increment: int = 5

    @property
    def interval_ms(self) -> float:
        """Connection interval in milliseconds."""
        return self.interval * 1.25

    @property
    def timeout_ms(self) -> int:
        """Supervision timeout in milliseconds."""
        return self.timeout * 10

    def to_tuple(self) -> tuple[int, int, int, int]:
        """Returns raw tuple representation <Interval, Latency, Timeout, Hop>."""
        return (self.interval, self.latency, self.timeout, self.hop_increment)


# -----------------------------------------------------------------------------
# Low-Level PDU Header & Framing Helpers
# -----------------------------------------------------------------------------
def build_ll_header(
    llid: int,
    length: int,
    nesn: int = 0,
    sn: int = 0,
    md: int = 0,
    cp: int = 0,
) -> bytes:
    """Build 2-byte Link-Layer Data Channel PDU Header (Bluetooth Core Vol 6 Part B §2.4).

    Args:
        llid: Logical Link Identifier (0b01: Continuation/Empty, 0b10: L2CAP Start, 0b11: Control).
        length: Payload length in octets (0-255).
        nesn: Next Expected Sequence Number (0 or 1).
        sn: Sequence Number (0 or 1).
        md: More Data bit (0 or 1).
        cp: CTE Info Present (0 or 1).

    Returns:
        2-byte encoded header.
    """
    b0 = (
        (llid & 0x03)
        | ((nesn & 0x01) << 2)
        | ((sn & 0x01) << 3)
        | ((md & 0x01) << 4)
        | ((cp & 0x01) << 5)
    )
    return bytes([b0, length & 0xFF])


def _coerce_mac_bytes(addr: str | bytes) -> bytes:
    """Convert string or bytes representation of 6-byte MAC into bytes."""
    if isinstance(addr, str):
        return str_to_mac(addr)
    if isinstance(addr, (bytes, bytearray)):
        if len(addr) != 6:
            raise ValueError(f"MAC address must be exactly 6 bytes, got {len(addr)}")
        return bytes(addr)
    raise TypeError(f"Expected str or bytes for MAC address, got {type(addr)}")


# -----------------------------------------------------------------------------
# Link-Layer Control PDU Builders
# -----------------------------------------------------------------------------
def build_ll_enc_req(
    rand: bytes = b"\x00" * 8,
    ediv: int = 0,
    skdm: bytes = b"\x00" * 8,
    ivm: bytes = b"\x00" * 4,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_ENC_REQ Control PDU (Opcode 0x03).

    Payload (22 octets): Rand (8B), EDIV (2B LE), SKDm (8B), IVm (4B).
    Total PDU: 25 octets (2B header + 1B opcode + 22B payload).
    """
    if len(rand) != 8:
        raise ValueError(f"Rand must be exactly 8 bytes, got {len(rand)}")
    if not (0 <= ediv <= 0xFFFF):
        raise ValueError(f"EDIV must be a 16-bit unsigned integer (0-0xFFFF), got {ediv}")
    if len(skdm) != 8:
        raise ValueError(f"SKDm must be exactly 8 bytes, got {len(skdm)}")
    if len(ivm) != 4:
        raise ValueError(f"IVm must be exactly 4 bytes, got {len(ivm)}")

    payload = bytes([OPCODE_LL_ENC_REQ]) + rand + struct.pack("<H", ediv) + skdm + ivm
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_enc_rsp(
    skds: bytes = b"\x00" * 8,
    ivs: bytes = b"\x00" * 4,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_ENC_RSP Control PDU (Opcode 0x04).

    Payload (12 octets): SKDs (8B), IVs (4B).
    Total PDU: 15 octets (2B header + 1B opcode + 12B payload).
    """
    if len(skds) != 8:
        raise ValueError(f"SKDs must be exactly 8 bytes, got {len(skds)}")
    if len(ivs) != 4:
        raise ValueError(f"IVs must be exactly 4 bytes, got {len(ivs)}")

    payload = bytes([OPCODE_LL_ENC_RSP]) + skds + ivs
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_start_enc_req(nesn: int = 0, sn: int = 0) -> bytes:
    """Build LL_START_ENC_REQ Control PDU (Opcode 0x05).

    Payload (0 octets). Total PDU: 3 octets (2B header + 1B opcode).
    """
    payload = bytes([OPCODE_LL_START_ENC_REQ])
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_start_enc_rsp(
    nesn: int = 0,
    sn: int = 0,
    mic: bytes | None = None,
) -> bytes:
    """Build LL_START_ENC_RSP Control PDU (Opcode 0x06).

    Args:
        nesn: Next Expected Sequence Number.
        sn: Sequence Number.
        mic: Optional 4-byte Message Integrity Check if simulating encrypted air capture.
             If None, builds standard 1-byte control payload.

    Total PDU: 3 octets (unencrypted) or 7 octets (with 4B MIC).
    """
    if mic is not None:
        if len(mic) != 4:
            raise ValueError(f"MIC must be exactly 4 bytes, got {len(mic)}")
        payload = bytes([OPCODE_LL_START_ENC_RSP]) + mic
    else:
        payload = bytes([OPCODE_LL_START_ENC_RSP])

    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_reject_ind(
    error_code: int = ERROR_PIN_OR_KEY_MISSING,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_REJECT_IND Control PDU (Opcode 0x0D).

    Payload (1 octet): ErrorCode.
    Total PDU: 4 octets (2B header + 1B opcode + 1B error_code).
    """
    if not (0 <= error_code <= 0xFF):
        raise ValueError(f"ErrorCode must be an 8-bit unsigned integer, got {error_code}")
    payload = bytes([OPCODE_LL_REJECT_IND, error_code & 0xFF])
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_reject_ext_ind(
    reject_opcode: int = OPCODE_LL_ENC_REQ,
    error_code: int = ERROR_PIN_OR_KEY_MISSING,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_REJECT_EXT_IND Control PDU (Opcode 0x11).

    Payload (2 octets): RejectOpcode (1B), ErrorCode (1B).
    Total PDU: 5 octets (2B header + 1B opcode + 1B reject_opcode + 1B error_code).
    """
    if not (0 <= reject_opcode <= 0xFF):
        raise ValueError(f"RejectOpcode must be an 8-bit unsigned integer, got {reject_opcode}")
    if not (0 <= error_code <= 0xFF):
        raise ValueError(f"ErrorCode must be an 8-bit unsigned integer, got {error_code}")

    payload = bytes([OPCODE_LL_REJECT_EXT_IND, reject_opcode & 0xFF, error_code & 0xFF])
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_terminate_ind(
    error_code: int = ERROR_REMOTE_USER_TERMINATED,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_TERMINATE_IND Control PDU (Opcode 0x02).

    Payload (1 octet): ErrorCode. Total PDU: 4 octets.
    """
    if not (0 <= error_code <= 0xFF):
        raise ValueError(f"ErrorCode must be an 8-bit unsigned integer, got {error_code}")
    payload = bytes([OPCODE_LL_TERMINATE_IND, error_code & 0xFF])
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


def build_ll_connection_update_ind(
    win_size: int = 1,
    win_offset: int = 0,
    interval: int = 24,
    latency: int = 0,
    timeout: int = 100,
    instant: int = 10,
    nesn: int = 0,
    sn: int = 0,
) -> bytes:
    """Build LL_CONNECTION_UPDATE_IND Control PDU (Opcode 0x00).

    Payload (11 octets): WinSize (1B), WinOffset (2B LE), Interval (2B LE),
    Latency (2B LE), Timeout (2B LE), Instant (2B LE).
    Total PDU: 14 octets (2B header + 1B opcode + 11B payload).
    """
    payload = bytes([OPCODE_LL_CONNECTION_UPDATE_IND, win_size & 0xFF]) + struct.pack(
        "<HHHHH", win_offset, interval, latency, timeout, instant
    )
    hdr = build_ll_header(llid=3, length=len(payload), nesn=nesn, sn=sn)
    return hdr + payload


# -----------------------------------------------------------------------------
# Data Integrity & Signing Verification (CSRK) Builders
# -----------------------------------------------------------------------------
def compute_csrk_mac(
    csrk: bytes,
    opcode: int,
    handle: int,
    value: bytes,
    counter: int,
) -> bytes:
    """Compute 64-bit truncated AES-CMAC authentication signature for ATT Signed Write.

    Specification: Bluetooth Core Spec Vol 3, Part H, §2.4.5.
    Input message: Opcode (1B) || Handle (2B LE) || Value (NB) || SignCounter (4B LE).

    Args:
        csrk: 16-byte (128-bit) Connection Signature Resolving Key.
        opcode: ATT opcode (0xD2 for ATT_SIGNED_WRITE_CMD).
        handle: 16-bit attribute handle.
        value: Characteristic value payload bytes.
        counter: 32-bit SignCounter.

    Returns:
        8-byte (64-bit) truncated MAC.
    """
    if len(csrk) != 16:
        raise ValueError(f"CSRK must be exactly 16 bytes (128 bits), got {len(csrk)}")
    if not (0 <= handle <= 0xFFFF):
        raise ValueError(f"Attribute handle must be 16-bit uint (0-0xFFFF), got {handle}")
    if not (0 <= counter <= 0xFFFFFFFF):
        raise ValueError(f"SignCounter must be 32-bit uint (0-0xFFFFFFFF), got {counter}")

    msg = (
        bytes([opcode & 0xFF])
        + struct.pack("<H", handle)
        + value
        + struct.pack("<I", counter)
    )
    c = cmac.CMAC(algorithms.AES(csrk))
    c.update(msg)
    full_mac = c.finalize()
    return full_mac[:8]


def build_att_signed_write(
    csrk: bytes,
    handle: int = 0x0012,
    value: bytes = b"\x01",
    counter: int = 0,
    corrupt_mac: bool = False,
    nesn: int = 0,
    sn: int = 0,
    override_mac: bytes | None = None,
) -> bytes:
    """Build Link-Layer Data Channel PDU carrying ATT Signed Write Command (Opcode 0xD2).

    Encapsulates:
    1. ATT_SIGNED_WRITE_CMD: Opcode (0xD2) + Handle (2B LE) + Value + AuthSignature (12B: 4B SC + 8B MAC).
    2. L2CAP B-frame: Length (2B LE) + CID (0x0004 ATT).
    3. LL Data Channel PDU: Header (LLID 0b10 L2CAP Start) + L2CAP Frame.

    Args:
        csrk: 16-byte Connection Signature Resolving Key.
        handle: 16-bit Attribute Handle.
        value: Characteristic value payload.
        counter: 32-bit SignCounter.
        corrupt_mac: If True, intentionally inverts first byte of MAC to simulate verification failure.
        nesn: Link-Layer NESN bit.
        sn: Link-Layer SN bit.
        override_mac: Optional explicit 8-byte MAC to insert.

    Returns:
        Full Link-Layer PDU bytes ready for transmission.
    """
    opcode = ATT_OPCODE_SIGNED_WRITE_CMD

    if override_mac is not None:
        if len(override_mac) != 8:
            raise ValueError(f"Override MAC must be exactly 8 bytes, got {len(override_mac)}")
        mac_64 = override_mac
    else:
        valid_mac = compute_csrk_mac(
            csrk=csrk, opcode=opcode, handle=handle, value=value, counter=counter
        )
        if corrupt_mac:
            # Invert first byte to invalidate CMAC
            mac_64 = bytes([valid_mac[0] ^ 0xFF]) + valid_mac[1:]
        else:
            mac_64 = valid_mac

    auth_sig = struct.pack("<I", counter & 0xFFFFFFFF) + mac_64
    att_pdu = bytes([opcode]) + struct.pack("<H", handle) + value + auth_sig
    l2cap_hdr = struct.pack("<HH", len(att_pdu), L2CAP_CID_ATT)
    l2cap_frame = l2cap_hdr + att_pdu

    ll_hdr = build_ll_header(llid=2, length=len(l2cap_frame), nesn=nesn, sn=sn)
    return ll_hdr + l2cap_frame


# -----------------------------------------------------------------------------
# Advertising Channel PDU Builders
# -----------------------------------------------------------------------------
def build_adv_direct_ind(
    adv_a: str | bytes,
    target_a: str | bytes,
    tx_random: bool = True,
    rx_random: bool = True,
) -> bytes:
    """Build ADV_DIRECT_IND Advertising PDU (PDU Type 0x01).

    Payload (12 octets): AdvA (6B), TargetA (6B).
    Header: PDU Type 1, TxAdd (bit 6), RxAdd (bit 7), Length 12.
    """
    adv_b = _coerce_mac_bytes(adv_a)
    target_b = _coerce_mac_bytes(target_a)

    b0 = (
        (ADV_PDU_ADV_DIRECT_IND & 0x0F)
        | ((1 if tx_random else 0) << 6)
        | ((1 if rx_random else 0) << 7)
    )
    hdr = bytes([b0, 12])
    return hdr + adv_b + target_b


def build_adv_ind(
    adv_a: str | bytes,
    ad_data: bytes = b"",
    tx_random: bool = True,
) -> bytes:
    """Build ADV_IND Undirected Advertising PDU (PDU Type 0x00).

    Payload: AdvA (6B) + Advertising Data.
    """
    adv_b = _coerce_mac_bytes(adv_a)
    payload = adv_b + ad_data
    b0 = (ADV_PDU_ADV_IND & 0x0F) | ((1 if tx_random else 0) << 6)
    hdr = bytes([b0, len(payload) & 0x3F])
    return hdr + payload


def build_scan_req(
    scan_a: str | bytes,
    adv_a: str | bytes,
    tx_random: bool = True,
    rx_random: bool = True,
) -> bytes:
    """Build SCAN_REQ Probe PDU (PDU Type 0x03).

    Payload (12 octets): ScanA (6B), AdvA (6B).
    """
    scan_b = _coerce_mac_bytes(scan_a)
    adv_b = _coerce_mac_bytes(adv_a)

    b0 = (
        (ADV_PDU_SCAN_REQ & 0x0F)
        | ((1 if tx_random else 0) << 6)
        | ((1 if rx_random else 0) << 7)
    )
    hdr = bytes([b0, 12])
    return hdr + scan_b + adv_b


def build_scan_rsp(
    adv_a: str | bytes,
    scan_rsp_data: bytes = b"",
    tx_random: bool = True,
) -> bytes:
    """Build SCAN_RSP Probe Response PDU (PDU Type 0x04).

    Payload: AdvA (6B) + Scan Response Data.
    """
    adv_b = _coerce_mac_bytes(adv_a)
    payload = adv_b + scan_rsp_data
    b0 = (ADV_PDU_SCAN_RSP & 0x0F) | ((1 if tx_random else 0) << 6)
    hdr = bytes([b0, len(payload) & 0x3F])
    return hdr + payload


def build_connect_ind(
    init_a: str | bytes,
    adv_a: str | bytes,
    conn_aa: int = 0x12345678,
    crc_init: int = 0x555555,
    win_size: int = 1,
    win_offset: int = 0,
    interval: int = 24,
    latency: int = 0,
    timeout: int = 100,
    chm: bytes = b"\x1f\x00\x00\x00\x00",
    hop: int = 5,
    sca: int = 0,
    tx_random: bool = True,
    rx_random: bool = True,
) -> bytes:
    """Build CONNECT_IND Connection Request PDU (PDU Type 0x05).

    Payload (34 octets): InitA (6B), AdvA (6B), LLData (22B).
    LLData: AA (4B LE), CRCInit (3B LE), WinSize (1B), WinOffset (2B LE),
            Interval (2B LE), Latency (2B LE), Timeout (2B LE), ChM (5B), Hop+SCA (1B).
    """
    init_b = _coerce_mac_bytes(init_a)
    adv_b = _coerce_mac_bytes(adv_a)
    if len(chm) != 5:
        raise ValueError(f"Channel Map must be exactly 5 bytes, got {len(chm)}")

    crc_bytes = bytes([crc_init & 0xFF, (crc_init >> 8) & 0xFF, (crc_init >> 16) & 0xFF])
    hop_sca = (hop & 0x1F) | ((sca & 0x07) << 5)
    lldata = (
        struct.pack("<I", conn_aa)
        + crc_bytes
        + bytes([win_size & 0xFF])
        + struct.pack("<HHHH", win_offset, interval, latency, timeout)
        + chm
        + bytes([hop_sca])
    )

    payload = init_b + adv_b + lldata
    b0 = (
        (ADV_PDU_CONNECT_IND & 0x0F)
        | ((1 if tx_random else 0) << 6)
        | ((1 if rx_random else 0) << 7)
    )
    hdr = bytes([b0, len(payload) & 0x3F])
    return hdr + payload


# -----------------------------------------------------------------------------
# High-Level PCAP & Stream Generation
# -----------------------------------------------------------------------------
def generate_synthetic_pcap(
    events: list[SyntheticEvent],
    output_path: str | Path | None = None,
    base_epoch: float | None = 1700000000.0,
) -> bytes:
    """Generate a standard DLT 256 PCAP byte stream from a sequence of SyntheticEvents.

    Args:
        events: List of SyntheticEvent instances.
        output_path: Optional file path to write PCAP file to.
        base_epoch: Base Unix timestamp for relative microsecond offsets.

    Returns:
        Complete PCAP binary data as bytes.
    """
    stream = io.BytesIO()
    with PcapBleWriter(output=stream, base_epoch=base_epoch, auto_flush=True) as writer:
        for ev in events:
            # Resolve pseudo-header pdu_type if not explicitly set
            if ev.pdu_type is not None:
                pdu_t = ev.pdu_type
            elif ev.chan < 37:
                pdu_t = 3 if ev.direction == 1 else 2
            else:
                pdu_t = 0

            writer.write_packet(
                ts_usec=ev.ts_usec,
                aa=ev.aa,
                chan=ev.chan,
                rssi=ev.rssi,
                packet=ev.body,
                crc_err=ev.crc_err,
                phy=ev.phy,
                pdu_type=pdu_t,
            )

    pcap_data = stream.getvalue()

    if output_path is not None:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(pcap_data)

    return pcap_data


def generate_encryption_trace(
    shared_ltk: bool = True,
    aa: int = BLE_ADV_AA,
    central_addr: str = "AA:BB:CC:DD:EE:01",
    periph_addr: str = "AA:BB:CC:DD:EE:02",
    output_path: str | Path | None = None,
    extended_reject: bool = False,
    error_code: int = ERROR_PIN_OR_KEY_MISSING,
    base_time_usec: int = 1_000_000,
    conn_aa: int = 0x12345678,
    chan: int = 1,
) -> bytes:
    """Generate Link-Layer Encryption Handshake PCAP trace fixture.

    Simulates:
    1. CONNECT_IND on primary advertising channel (chan 37).
    2. Central transmits LL_ENC_REQ on data channel.
    3. Branching behavior:
       - If shared_ltk is True:
         Peripheral -> LL_ENC_RSP
         Peripheral -> LL_START_ENC_REQ
         Central    -> LL_START_ENC_RSP
         Peripheral -> LL_START_ENC_RSP (Encrypted Handshake Complete)
       - If shared_ltk is False:
         Peripheral -> LL_REJECT_IND (or LL_REJECT_EXT_IND) with error_code (default 0x06).
         Followed by LL_TERMINATE_IND (0x13).

    Args:
        shared_ltk: True for successful encryption, False for rejected encryption.
        aa: Advertising Access Address (default 0x8E89BED6).
        central_addr: Central MAC address string.
        periph_addr: Peripheral MAC address string.
        output_path: Optional file path to write PCAP file to.
        extended_reject: If True and shared_ltk is False, emits LL_REJECT_EXT_IND instead of LL_REJECT_IND.
        error_code: Rejection error code (default 0x06 PIN_OR_KEY_MISSING).
        base_time_usec: Starting timestamp in microseconds.
        conn_aa: Connection Access Address for data channel packets.
        chan: Data channel index (0-36).

    Returns:
        PCAP file bytes.
    """
    events: list[SyntheticEvent] = []
    t = base_time_usec

    # 1. Connection initiation on advertising channel 37
    conn_pdu = build_connect_ind(
        init_a=central_addr,
        adv_a=periph_addr,
        conn_aa=conn_aa,
        interval=24,
        latency=0,
        timeout=100,
    )
    events.append(
        SyntheticEvent(
            ts_usec=t,
            chan=37,
            aa=aa,
            body=conn_pdu,
            direction=0,
        )
    )

    # 2. Transition to data channel: Central sends LL_ENC_REQ
    t += 10_000
    rand_bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    ediv = 0x1234
    skdm = b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11"
    ivm = b"\x01\x02\x03\x04"
    enc_req_pdu = build_ll_enc_req(
        rand=rand_bytes, ediv=ediv, skdm=skdm, ivm=ivm, nesn=0, sn=0
    )
    events.append(
        SyntheticEvent(
            ts_usec=t,
            chan=chan,
            aa=conn_aa,
            body=enc_req_pdu,
            direction=0,
        )
    )

    # 3. Handshake response
    t += 2_500
    if shared_ltk:
        # Peripheral recognizes key -> LL_ENC_RSP
        skds = b"\x22\x33\x44\x55\x66\x77\x88\x99"
        ivs = b"\x05\x06\x07\x08"
        enc_rsp_pdu = build_ll_enc_rsp(skds=skds, ivs=ivs, nesn=1, sn=0)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=enc_rsp_pdu,
                direction=1,
            )
        )

        # Peripheral -> LL_START_ENC_REQ
        t += 2_500
        start_req_pdu = build_ll_start_enc_req(nesn=1, sn=1)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=start_req_pdu,
                direction=1,
            )
        )

        # Central -> LL_START_ENC_RSP (Encrypted)
        t += 2_500
        start_rsp_central = build_ll_start_enc_rsp(nesn=0, sn=1)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=start_rsp_central,
                direction=0,
            )
        )

        # Peripheral -> LL_START_ENC_RSP (Encrypted)
        t += 2_500
        start_rsp_periph = build_ll_start_enc_rsp(nesn=0, sn=0)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=start_rsp_periph,
                direction=1,
            )
        )
    else:
        # Key missing or untrusted -> LL_REJECT_IND or LL_REJECT_EXT_IND
        if extended_reject:
            reject_pdu = build_ll_reject_ext_ind(
                reject_opcode=OPCODE_LL_ENC_REQ,
                error_code=error_code,
                nesn=1,
                sn=0,
            )
        else:
            reject_pdu = build_ll_reject_ind(
                error_code=error_code,
                nesn=1,
                sn=0,
            )
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=reject_pdu,
                direction=1,
            )
        )

        # Immediate link termination
        t += 5_000
        term_pdu = build_ll_terminate_ind(
            error_code=ERROR_REMOTE_USER_TERMINATED, nesn=1, sn=1
        )
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=conn_aa,
                body=term_pdu,
                direction=1,
            )
        )

    return generate_synthetic_pcap(events, output_path=output_path)


def generate_csrk_trace(
    counter_sequence: list[int],
    csrk: bytes,
    corrupt_mac_indices: list[int] | None = None,
    output_path: str | Path | None = None,
    handle: int = 0x0012,
    value: bytes = b"\x01",
    aa: int = 0x12345678,
    central_addr: str = "AA:BB:CC:DD:EE:01",
    periph_addr: str = "AA:BB:CC:DD:EE:02",
    rotate_rpa_indices: list[int] | None = None,
    rpa_sequence: list[str] | None = None,
    base_time_usec: int = 1_000_000,
    interval_usec: int = 50_000,
    chan: int = 1,
) -> bytes:
    """Generate CSRK SignCounter & Integrity Verification PCAP trace fixture.

    Simulates:
    1. CONNECT_IND establishing connection between Central and Peripheral.
    2. Sequential or anomalous stream of ATT_SIGNED_WRITE_CMD packets.
    3. Monotonic SignCounter values with valid or corrupted AES-CMAC signatures.
    4. Optional RPA address rotations mid-stream to model cross-RPA linkability tracking.

    Args:
        counter_sequence: List of integer SignCounters to transmit.
        csrk: 16-byte Connection Signature Resolving Key.
        corrupt_mac_indices: List of 0-based indices in counter_sequence where MAC should be corrupted.
        output_path: Optional file path to write PCAP file to.
        handle: Attribute Handle.
        value: Characteristic Value bytes.
        aa: Connection Access Address.
        central_addr: Starting Central MAC address.
        periph_addr: Peripheral MAC address.
        rotate_rpa_indices: Indices where Central address rotates to next address in rpa_sequence.
        rpa_sequence: List of rotated Central RPA addresses.
        base_time_usec: Starting timestamp in microseconds.
        interval_usec: Interval between consecutive writes.
        chan: Data channel index.

    Returns:
        PCAP file bytes.
    """
    events: list[SyntheticEvent] = []
    t = base_time_usec
    corrupt_set = set(corrupt_mac_indices or [])
    rotate_set = set(rotate_rpa_indices or [])

    current_central = central_addr
    rpa_idx = 0

    # Initial connection
    conn_pdu = build_connect_ind(
        init_a=current_central,
        adv_a=periph_addr,
        conn_aa=aa,
        interval=24,
        latency=0,
        timeout=100,
    )
    events.append(
        SyntheticEvent(
            ts_usec=t,
            chan=37,
            aa=BLE_ADV_AA,
            body=conn_pdu,
            direction=0,
        )
    )

    t += 10_000
    for idx, counter in enumerate(counter_sequence):
        # Rotate address if requested at this index
        if idx in rotate_set and rpa_sequence and rpa_idx < len(rpa_sequence):
            current_central = rpa_sequence[rpa_idx]
            rpa_idx += 1
            # Synthesize new connection event reflecting address rotation
            t += 10_000
            reconn_pdu = build_connect_ind(
                init_a=current_central,
                adv_a=periph_addr,
                conn_aa=aa,
                interval=24,
                latency=0,
                timeout=100,
            )
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=reconn_pdu,
                    direction=0,
                )
            )
            t += 5_000

        corrupt = idx in corrupt_set
        sn = idx % 2
        nesn = (idx + 1) % 2

        write_pdu = build_att_signed_write(
            csrk=csrk,
            handle=handle,
            value=value,
            counter=counter,
            corrupt_mac=corrupt,
            nesn=nesn,
            sn=sn,
        )
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=chan,
                aa=aa,
                body=write_pdu,
                direction=0,
            )
        )
        t += interval_usec

    return generate_synthetic_pcap(events, output_path=output_path)


def generate_bat_allowlist_trace(
    allowlist_enabled: bool = True,
    target_rpa: str = "AA:BB:CC:DD:EE:01",
    foreign_rpa: str = "11:22:33:44:55:66",
    periph_addr: str = "AA:BB:CC:DD:EE:02",
    output_path: str | Path | None = None,
    mode: str = "selective_probe",
    fast_interval_ms: float = 30.0,
    slow_interval_ms: float = 1200.0,
    conn_params: ConnectionParameters | tuple[int, int, int, int] | None = None,
    base_time_usec: int = 1_000_000,
) -> bytes:
    """Generate Auto-Connection & Allowlist (BAT Attack) PCAP trace fixture.

    Modes:
    1. 'selective_probe':
       - Peripheral advertises ADV_IND.
       - Foreign prober sends SCAN_REQ.
       - If allowlist_enabled: Peripheral remains silent (no SCAN_RSP).
       - If not allowlist_enabled: Peripheral replies with SCAN_RSP within T_IFS (150us).
       - Target authorized central sends SCAN_REQ.
       - Peripheral replies with SCAN_RSP within T_IFS (150us).
    2. 'directed':
       - Fast burst of ADV_DIRECT_IND packets carrying TargetA = target_rpa.
       - Followed by CONNECT_IND from target_rpa to periph_addr.
    3. 'reconnection_timing':
       - Demonstrates differential fast advertising (20-50ms) vs slow standby advertising (1000-2500ms)
       - Negotiates specific connection parameter tuple <Interval, Latency, Timeout, Hop>.

    Args:
        allowlist_enabled: True if peripheral enforces Filter Accept List, False if open advertiser.
        target_rpa: Authorized companion central RPA.
        foreign_rpa: Unauthorized scanner / probing RPA.
        periph_addr: Peripheral RPA / MAC address.
        output_path: Optional file path to write PCAP file to.
        mode: Scenario mode ('selective_probe', 'directed', or 'reconnection_timing').
        fast_interval_ms: Fast advertising interval in milliseconds (default 30.0 ms).
        slow_interval_ms: Slow advertising interval in milliseconds (default 1200.0 ms).
        conn_params: Optional ConnectionParameters or 4-tuple.
        base_time_usec: Starting timestamp in microseconds.

    Returns:
        PCAP file bytes.
    """
    events: list[SyntheticEvent] = []
    t = base_time_usec

    if mode == "directed":
        # Fast burst of ADV_DIRECT_IND (Core spec high duty cycle interval <= 3.75ms)
        direct_interval_usec = 3_750
        for _ in range(5):
            direct_pdu = build_adv_direct_ind(
                adv_a=periph_addr, target_a=target_rpa, tx_random=True, rx_random=True
            )
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=direct_pdu,
                    direction=1,
                )
            )
            t += direct_interval_usec

        # Companion central connects
        t += 1_000
        conn_pdu = build_connect_ind(
            init_a=target_rpa,
            adv_a=periph_addr,
            conn_aa=0x12345678,
            interval=24,
            latency=0,
            timeout=100,
        )
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=conn_pdu,
                direction=0,
            )
        )

    elif mode == "reconnection_timing":
        # Fast recovery advertising
        fast_usec = int(fast_interval_ms * 1_000)
        for _ in range(4):
            adv_pdu = build_adv_ind(adv_a=periph_addr, ad_data=b"\x02\x01\x06")
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=adv_pdu,
                    direction=1,
                )
            )
            t += fast_usec

        # If connection occurs or falls back to slow standby advertising
        slow_usec = int(slow_interval_ms * 1_000)
        for _ in range(3):
            adv_pdu = build_adv_ind(adv_a=periph_addr, ad_data=b"\x02\x01\x06")
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=adv_pdu,
                    direction=1,
                )
            )
            t += slow_usec

        # Connection with specific profile parameters
        if conn_params is not None:
            if isinstance(conn_params, ConnectionParameters):
                params = conn_params
            else:
                params = ConnectionParameters(*conn_params)
            t += 1_000
            conn_pdu = build_connect_ind(
                init_a=target_rpa,
                adv_a=periph_addr,
                conn_aa=0x12345678,
                interval=params.interval,
                latency=params.latency,
                timeout=params.timeout,
                hop=params.hop_increment,
            )
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=conn_pdu,
                    direction=0,
                )
            )

    else:
        # Default: 'selective_probe'
        # 1. Peripheral advertises ADV_IND
        adv_pdu = build_adv_ind(adv_a=periph_addr, ad_data=b"\x02\x01\x06")
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=adv_pdu,
                direction=1,
            )
        )

        # 2. Foreign / unauthorized scanner sends SCAN_REQ
        t += 1_000
        scan_req_foreign = build_scan_req(scan_a=foreign_rpa, adv_a=periph_addr)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=scan_req_foreign,
                direction=0,
            )
        )

        # 3. Allowlist decision:
        # If open: replies with SCAN_RSP within T_IFS (150us).
        # If allowlisted: silent drop (no response on channel).
        if not allowlist_enabled:
            t += 150  # T_IFS = 150 microseconds
            scan_rsp_pdu = build_scan_rsp(
                adv_a=periph_addr, scan_rsp_data=b"\x0a\x09TargetDev"
            )
            events.append(
                SyntheticEvent(
                    ts_usec=t,
                    chan=37,
                    aa=BLE_ADV_AA,
                    body=scan_rsp_pdu,
                    direction=1,
                )
            )

        # 4. Next advertising event (e.g. 30ms later)
        t += 30_000
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=adv_pdu,
                direction=1,
            )
        )

        # 5. Target authorized companion sends SCAN_REQ
        t += 1_000
        scan_req_target = build_scan_req(scan_a=target_rpa, adv_a=periph_addr)
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=scan_req_target,
                direction=0,
            )
        )

        # 6. Peripheral replies with SCAN_RSP within T_IFS (150us)
        t += 150
        scan_rsp_pdu = build_scan_rsp(
            adv_a=periph_addr, scan_rsp_data=b"\x0a\x09TargetDev"
        )
        events.append(
            SyntheticEvent(
                ts_usec=t,
                chan=37,
                aa=BLE_ADV_AA,
                body=scan_rsp_pdu,
                direction=1,
            )
        )

    return generate_synthetic_pcap(events, output_path=output_path)


# -----------------------------------------------------------------------------
# In-Memory Stream Helpers & Fluent Builder
# -----------------------------------------------------------------------------
def events_to_packet_messages(events: list[SyntheticEvent]) -> list[PacketMessage]:
    """Convert a sequence of SyntheticEvent objects to Sniffle PacketMessage objects."""
    messages: list[PacketMessage] = []
    for ev in events:
        raw = PacketMessage.pack(
            body=ev.body,
            ts=ev.ts_usec,
            chan=ev.chan,
            rssi=ev.rssi,
            phy=ev.phy,
            crc_err=ev.crc_err,
            direction=ev.direction,
        )
        messages.append(PacketMessage(raw))
    return messages


def events_to_captured_packets(
    events: list[SyntheticEvent], base_epoch: float | None = 1700000000.0
) -> list[CapturedBlePacket]:
    """Convert SyntheticEvents to CapturedBlePackets via round-trip in-memory PCAP parsing."""
    pcap_data = generate_synthetic_pcap(events, base_epoch=base_epoch)
    stream = io.BytesIO(pcap_data)
    with PcapBleReader(stream) as reader:
        return list(reader)


def generate_synthetic_stream(events: list[SyntheticEvent]) -> Iterator[PacketMessage]:
    """Generator yielding PacketMessage instances from SyntheticEvents."""
    yield from events_to_packet_messages(events)


def generate_synthetic_captured_stream(
    events: list[SyntheticEvent], base_epoch: float | None = 1700000000.0
) -> Iterator[CapturedBlePacket]:
    """Generator yielding CapturedBlePacket instances from SyntheticEvents."""
    yield from events_to_captured_packets(events, base_epoch=base_epoch)


class SyntheticTraceGenerator:
    """Fluent builder for constructing, serializing, and exporting synthetic BLE traces."""

    def __init__(
        self,
        base_epoch: float = 1700000000.0,
        conn_aa: int = 0x12345678,
        default_chan: int = 37,
    ) -> None:
        self.base_epoch: float = base_epoch
        self.conn_aa: int = conn_aa
        self.default_chan: int = default_chan
        self.events: list[SyntheticEvent] = []
        self._current_time_usec: int = 1_000_000

    @property
    def current_time_usec(self) -> int:
        """Current microsecond cursor timestamp."""
        return self._current_time_usec

    def advance_time(self, delta_usec: int) -> SyntheticTraceGenerator:
        """Advance cursor timestamp by delta microseconds."""
        self._current_time_usec += delta_usec
        return self

    def add_event(self, event: SyntheticEvent) -> SyntheticTraceGenerator:
        """Append a custom SyntheticEvent."""
        self.events.append(event)
        self._current_time_usec = max(self._current_time_usec, event.ts_usec)
        return self

    def add_adv_ind(
        self,
        adv_a: str | bytes,
        ad_data: bytes = b"",
        delta_usec: int = 30_000,
        chan: int = 37,
    ) -> SyntheticTraceGenerator:
        """Append an ADV_IND packet."""
        self._current_time_usec += delta_usec
        pdu = build_adv_ind(adv_a=adv_a, ad_data=ad_data)
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=BLE_ADV_AA,
                body=pdu,
                direction=1,
            )
        )

    def add_adv_direct_ind(
        self,
        adv_a: str | bytes,
        target_a: str | bytes,
        delta_usec: int = 3_750,
        chan: int = 37,
    ) -> SyntheticTraceGenerator:
        """Append an ADV_DIRECT_IND packet."""
        self._current_time_usec += delta_usec
        pdu = build_adv_direct_ind(adv_a=adv_a, target_a=target_a)
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=BLE_ADV_AA,
                body=pdu,
                direction=1,
            )
        )

    def add_scan_req(
        self,
        scan_a: str | bytes,
        adv_a: str | bytes,
        delta_usec: int = 1_000,
        chan: int = 37,
    ) -> SyntheticTraceGenerator:
        """Append a SCAN_REQ packet."""
        self._current_time_usec += delta_usec
        pdu = build_scan_req(scan_a=scan_a, adv_a=adv_a)
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=BLE_ADV_AA,
                body=pdu,
                direction=0,
            )
        )

    def add_scan_rsp(
        self,
        adv_a: str | bytes,
        scan_rsp_data: bytes = b"",
        delta_usec: int = 150,
        chan: int = 37,
    ) -> SyntheticTraceGenerator:
        """Append a SCAN_RSP packet."""
        self._current_time_usec += delta_usec
        pdu = build_scan_rsp(adv_a=adv_a, scan_rsp_data=scan_rsp_data)
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=BLE_ADV_AA,
                body=pdu,
                direction=1,
            )
        )

    def add_connect_ind(
        self,
        init_a: str | bytes,
        adv_a: str | bytes,
        conn_aa: int | None = None,
        delta_usec: int = 1_000,
        interval: int = 24,
        latency: int = 0,
        timeout: int = 100,
        hop: int = 5,
        chan: int = 37,
    ) -> SyntheticTraceGenerator:
        """Append a CONNECT_IND packet."""
        self._current_time_usec += delta_usec
        use_aa = conn_aa if conn_aa is not None else self.conn_aa
        self.conn_aa = use_aa
        pdu = build_connect_ind(
            init_a=init_a,
            adv_a=adv_a,
            conn_aa=use_aa,
            interval=interval,
            latency=latency,
            timeout=timeout,
            hop=hop,
        )
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=BLE_ADV_AA,
                body=pdu,
                direction=0,
            )
        )

    def add_att_signed_write(
        self,
        csrk: bytes,
        handle: int = 0x0012,
        value: bytes = b"\x01",
        counter: int = 0,
        corrupt_mac: bool = False,
        delta_usec: int = 50_000,
        chan: int = 1,
    ) -> SyntheticTraceGenerator:
        """Append an ATT_SIGNED_WRITE_CMD packet on data channel."""
        self._current_time_usec += delta_usec
        pdu = build_att_signed_write(
            csrk=csrk,
            handle=handle,
            value=value,
            counter=counter,
            corrupt_mac=corrupt_mac,
        )
        return self.add_event(
            SyntheticEvent(
                ts_usec=self._current_time_usec,
                chan=chan,
                aa=self.conn_aa,
                body=pdu,
                direction=0,
            )
        )

    def build_pcap_bytes(self) -> bytes:
        """Export all events to standard DLT 256 PCAP bytes."""
        return generate_synthetic_pcap(self.events, base_epoch=self.base_epoch)

    def save_pcap(self, path: str | Path) -> Path:
        """Write trace to PCAP file and return resolved Path."""
        out_p = Path(path).resolve()
        generate_synthetic_pcap(self.events, output_path=out_p, base_epoch=self.base_epoch)
        return out_p

    def to_packet_messages(self) -> list[PacketMessage]:
        """Convert all events to PacketMessage objects."""
        return events_to_packet_messages(self.events)

    def to_captured_packets(self) -> list[CapturedBlePacket]:
        """Convert all events to CapturedBlePacket objects."""
        return events_to_captured_packets(self.events, base_epoch=self.base_epoch)

    def __iter__(self) -> Iterator[SyntheticEvent]:
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)
