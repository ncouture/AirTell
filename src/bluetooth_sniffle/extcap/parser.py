"""Live BLE JSON Dissector and Field Normalization Engine.

Parses both Elasticsearch line-delimited JSON (-T ek) and standard streaming JSON (-T json)
from Tshark, extracts and normalizes Link Layer fields, classifies tracking networks,
and pushes standardized observations into the application EventQueue.
"""

from __future__ import annotations

import collections
import json
import logging
import re
import threading
import time
from typing import Any, Optional

from app.queue_bridge import EventQueue

logger = logging.getLogger(__name__)

# PDU Type mapping according to Bluetooth Core Spec Link Layer specification
PDU_TYPE_NAMES: dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND",
}


def normalize_mac_address(raw_mac: str | None) -> str:
    """Normalize MAC address string to standard uppercase colon-separated format."""
    if not raw_mac:
        return "00:00:00:00:00:00"
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw_mac).upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return raw_mac.strip().upper()


def normalize_hex_payload(raw: Any) -> str:
    """Flatten and normalize raw payload or list of hex strings into unified hex string."""
    if raw is None:
        return ""
    if isinstance(raw, list):
        return "".join(normalize_hex_payload(item) for item in raw)
    if isinstance(raw, str):
        return raw.replace(":", "").replace(" ", "").replace("-", "").lower()
    return ""


def format_company_id(raw_id: Any) -> str:
    """Format company identifier to standard hex string (e.g. '0x004c')."""
    if raw_id is None:
        return ""
    if isinstance(raw_id, list):
        if not raw_id:
            return ""
        raw_id = raw_id[0]
    val_str = str(raw_id).strip()
    if val_str.startswith("0x") or val_str.startswith("0X"):
        try:
            val_int = int(val_str, 16)
            return f"0x{val_int:04x}"
        except ValueError:
            return val_str.lower()
    try:
        val_int = int(val_str)
        return f"0x{val_int:04x}"
    except ValueError:
        return val_str.lower()


class TsharkBleJsonParser:
    """Dissects Tshark JSON packet records into normalized BLE telemetry observations."""

    def __init__(
        self,
        event_queue: Optional[EventQueue] = None,
        default_channel: int = 37,
        max_buffered_records: int = 2000,
    ) -> None:
        """Initialize the JSON stream dissector.

        Args:
            event_queue: Optional singleton EventQueue to push observations to.
            default_channel: Fallback channel if packet does not encode radio channel.
            max_buffered_records: Maximum internal observations retained before dropping oldest.
        """
        self.event_queue: Optional[EventQueue] = event_queue
        self.default_channel: int = default_channel
        self.max_buffered_records: int = max_buffered_records

        self.buffered_observations: collections.deque[dict[str, Any]] = collections.deque(
            maxlen=max_buffered_records
        )
        self._lock: threading.Lock = threading.Lock()
        self._total_parsed: int = 0
        self._parse_errors: int = 0

    def parse_line(self, line: str) -> dict[str, Any] | None:
        """Parse a single line from Tshark stdout stream.

        Args:
            line: Raw line from stdout.

        Returns:
            Normalized observation dictionary, or None if skipped (e.g. EK index header) or malformed.
        """
        clean = line.strip()
        if not clean:
            return None

        # Ignore Elasticsearch bulk index lines: {"index":{"_index":...}}
        if clean.startswith('{"index"') or clean.startswith("{'index'"):
            return None

        # Strip trailing commas if line comes from streaming JSON array
        if clean.endswith(","):
            clean = clean[:-1].strip()

        if clean in ("[", "]"):
            return None

        try:
            doc = json.loads(clean)
        except Exception:
            self._parse_errors += 1
            return None

        if not isinstance(doc, dict):
            return None

        return self.parse_packet_dict(doc)

    def parse_packet_dict(self, doc: dict[str, Any]) -> dict[str, Any] | None:
        """Dissect packet dictionary from either -T ek or -T json format.

        Args:
            doc: Parsed dictionary from JSON.

        Returns:
            Normalized observation dictionary or None if record is empty or invalid.
        """
        if not doc:
            return None

        # Extract layers dictionary from either standard JSON (_source.layers) or EK (layers)
        layers: dict[str, Any] = {}
        if "_source" in doc and isinstance(doc["_source"], dict):
            layers = doc["_source"].get("layers", {})
        elif "layers" in doc and isinstance(doc["layers"], dict):
            layers = doc["layers"]
        else:
            layers = doc

        if not layers:
            return None

        frame_data: dict[str, Any] = layers.get("frame", {})
        btle_data: dict[str, Any] = layers.get("btle", {})
        btle_rf_data: dict[str, Any] = layers.get("btle_rf", {})
        btcommon_data: Any = layers.get("btcommon", {})

        # 1. Extract and normalize Timestamp
        ts = self._extract_timestamp(doc, frame_data)
        datetime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

        # 2. Extract and normalize MAC Address
        raw_mac = self._find_first_matching(
            [
                btle_data.get("btle.advertising_address"),
                btle_data.get("btle_btle_advertising_address"),
                btle_data.get("btle.initiator_address"),
                btle_data.get("btle_btle_initiator_address"),
                btcommon_data.get("btcommon.eir_ad.entry.device_address") if isinstance(btcommon_data, dict) else None,
                btcommon_data.get("btcommon_btcommon_eir_ad_entry_device_address") if isinstance(btcommon_data, dict) else None,
            ]
        )
        if not raw_mac:
            return None

        mac_address = normalize_mac_address(raw_mac)

        # 3. Extract RSSI (dBm)
        rssi = self._extract_rssi(btle_data, btle_rf_data)

        # 4. Extract Channel
        channel = self._extract_channel(btle_data, btle_rf_data)

        # 5. Extract PDU Type
        pdu_type = self._extract_pdu_type(btle_data)

        # 6. Extract Raw Payload & Scan Response
        raw_payload = self._extract_payload(btle_data, btcommon_data)

        # 7. Extract Company ID
        company_id = self._extract_company_id(btle_data, btcommon_data)

        # 8. Classify Network and Ephemeral Key
        network_type, ephemeral_key = self._classify_tracking_network(
            company_id=company_id,
            raw_payload=raw_payload,
            mac_address=mac_address,
        )

        observation: dict[str, Any] = {
            "timestamp": ts,
            "datetime_str": datetime_str,
            "channel": channel,
            "rssi": rssi,
            "mac_address": mac_address,
            "network_type": network_type,
            "ephemeral_key": ephemeral_key,
            "raw_payload": raw_payload,
            "pdu_type": pdu_type,
            "company_id": company_id,
        }

        # Store in internal bounded ring buffer
        with self._lock:
            self.buffered_observations.append(observation)
            self._total_parsed += 1

        # Push to application-wide EventQueue if registered
        if self.event_queue is not None:
            self.event_queue.push(observation)

        return observation

    def _extract_timestamp(self, doc: dict[str, Any], frame_data: dict[str, Any]) -> float:
        """Extract epoch timestamp float."""
        candidates = [
            frame_data.get("frame_frame_time_epoch"),
            frame_data.get("frame.time_epoch"),
            doc.get("timestamp"),
        ]
        for c in candidates:
            if c is not None:
                try:
                    val = float(c)
                    # If in milliseconds, convert to seconds
                    if val > 1e11:
                        val /= 1000.0
                    return val
                except (ValueError, TypeError):
                    pass
        return time.time()

    def _extract_rssi(self, btle_data: dict[str, Any], btle_rf_data: dict[str, Any]) -> int:
        """Extract RSSI in integer dBm."""
        candidates = [
            btle_rf_data.get("btle_rf_btle_rf_signal_dbm"),
            btle_rf_data.get("btle_rf.signal_dbm"),
            btle_data.get("btle_btle_rssi"),
            btle_data.get("btle.rssi"),
        ]
        for c in candidates:
            if c is not None:
                try:
                    return int(c)
                except (ValueError, TypeError):
                    pass
        return -60

    def _extract_channel(self, btle_data: dict[str, Any], btle_rf_data: dict[str, Any]) -> int:
        """Extract BLE advertising channel."""
        candidates = [
            btle_rf_data.get("btle_rf_btle_rf_channel"),
            btle_rf_data.get("btle_rf.channel"),
            btle_data.get("btle_btle_channel"),
            btle_data.get("btle.channel"),
        ]
        for c in candidates:
            if c is not None:
                try:
                    ch = int(c)
                    if ch in (37, 38, 39):
                        return ch
                    # Some dissectors represent channel as RF index 0, 12, 39
                    if ch == 0:
                        return 37
                    if ch == 12:
                        return 38
                except (ValueError, TypeError):
                    pass
        return self.default_channel

    def _extract_pdu_type(self, btle_data: dict[str, Any]) -> str:
        """Decode Link Layer PDU type to human-readable string."""
        raw_pdu = self._find_first_matching(
            [
                btle_data.get("btle_btle_advertising_header_pdu_type"),
                btle_data.get("btle.advertising_header.pdu_type"),
                btle_data.get("btle.advertising_header_tree", {}).get("btle.advertising_header.pdu_type")
                if isinstance(btle_data.get("btle.advertising_header_tree"), dict)
                else None,
            ]
        )
        if raw_pdu is not None:
            try:
                pdu_int = int(str(raw_pdu), 16) if str(raw_pdu).startswith("0x") else int(raw_pdu)
                return PDU_TYPE_NAMES.get(pdu_int, f"PDU_0x{pdu_int:02x}")
            except (ValueError, TypeError):
                pass
        return "ADV_IND"

    def _extract_payload(self, btle_data: dict[str, Any], btcommon_data: Any) -> str:
        """Extract all advertising hex payload fragments."""
        parts: list[str] = []

        # From btle scan response or direct payload
        scan_data = btle_data.get("btle_btle_scan_response_data") or btle_data.get("btle.scan_response_data")
        if scan_data:
            parts.append(normalize_hex_payload(scan_data))

        # From btle EIR / AD structures
        eir_data = btle_data.get("btcommon_btcommon_eir_ad_entry_data") or btle_data.get("btcommon.eir_ad.entry.data")
        if eir_data:
            parts.append(normalize_hex_payload(eir_data))

        if isinstance(btcommon_data, dict):
            c_data = btcommon_data.get("btcommon.eir_ad.entry.data") or btcommon_data.get("btcommon_btcommon_eir_ad_entry_data")
            if c_data:
                parts.append(normalize_hex_payload(c_data))

        return "".join(parts)

    def _extract_company_id(self, btle_data: dict[str, Any], btcommon_data: Any) -> str:
        """Extract and format manufacturer company identifier."""
        raw = self._find_first_matching(
            [
                btle_data.get("btcommon_btcommon_eir_ad_entry_company_id"),
                btle_data.get("btcommon.eir_ad.entry.company_id"),
                btcommon_data.get("btcommon_btcommon_eir_ad_entry_company_id") if isinstance(btcommon_data, dict) else None,
                btcommon_data.get("btcommon.eir_ad.entry.company_id") if isinstance(btcommon_data, dict) else None,
            ]
        )
        return format_company_id(raw)

    def _classify_tracking_network(
        self,
        company_id: str,
        raw_payload: str,
        mac_address: str,
    ) -> tuple[str, str]:
        """Classify tracking protocol and extract ephemeral public key."""
        payload_lower = raw_payload.lower()

        # 1. Apple Find My (Company ID 0x004c, Type 0x12 or Find My offline payload)
        if company_id == "0x004c":
            if "1219" in payload_lower or "4c001219" in payload_lower:
                idx = payload_lower.find("1219")
                key_fragment = payload_lower[idx + 4 : idx + 4 + 44]
                return "Apple Find My", key_fragment or f"apple_{mac_address[-5:].replace(':', '')}"
            return "Apple Find My", f"apple_{mac_address[-5:].replace(':', '')}"

        if "4c001219" in payload_lower:
            idx = payload_lower.find("4c001219")
            key_fragment = payload_lower[idx + 8 : idx + 8 + 44]
            return "Apple Find My", key_fragment or f"apple_{mac_address[-5:].replace(':', '')}"

        # 2. Google Find Hub / Fast Pair (UUID 0xFE9F)
        if "fe9f" in payload_lower or "feaa" in payload_lower:
            idx = payload_lower.find("fe9f") if "fe9f" in payload_lower else payload_lower.find("feaa")
            key_fragment = payload_lower[idx : idx + 40]
            return "Google Find Hub", key_fragment or f"google_{mac_address[-5:].replace(':', '')}"

        # 3. Samsung SmartThings Find (Company ID 0x0075 or payload 7500)
        if company_id == "0x0075" or "7500" in payload_lower:
            idx = payload_lower.find("7500") if "7500" in payload_lower else 0
            key_fragment = payload_lower[idx : idx + 32]
            return "Samsung SmartThings Find", key_fragment or f"samsung_{mac_address[-5:].replace(':', '')}"

        # 4. Tile Tracker (UUID 0xFEED)
        if "feed" in payload_lower:
            idx = payload_lower.find("feed")
            key_fragment = payload_lower[idx : idx + 32]
            return "Tile", key_fragment or f"tile_{mac_address[-5:].replace(':', '')}"

        return "Unknown", ""

    def _find_first_matching(self, candidates: list[Any]) -> Any:
        """Return the first non-None, non-empty candidate from list."""
        for c in candidates:
            if c is not None and c != "" and c != []:
                if isinstance(c, list):
                    return c[0]
                return c
        return None

    def drain_observations(self, max_count: int | None = None) -> list[dict[str, Any]]:
        """Drain buffered observations in FIFO order.

        Args:
            max_count: Maximum items to drain.

        Returns:
            List of observation records.
        """
        with self._lock:
            if max_count is None:
                items = list(self.buffered_observations)
                self.buffered_observations.clear()
                return items
            batch: list[dict[str, Any]] = []
            for _ in range(min(max_count, len(self.buffered_observations))):
                batch.append(self.buffered_observations.popleft())
            return batch
