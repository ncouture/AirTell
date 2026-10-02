"""Two-ended BLE pairing relay testbed and Security Manager Protocol (SMP) handshake analysis."""

from __future__ import annotations

import collections
import enum
import threading
from dataclasses import dataclass, field
from typing import Optional


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
    failure_code: Optional[PairingFailureCode]
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

    def drain_next_packet(self) -> Optional[RelayedLinkLayerPacket]:
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
    ) -> Optional[PairingHandshakeEvent]:
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
