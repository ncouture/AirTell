"""Thread-safe singleton EventQueue bridge between Sniffle background threads and Streamlit."""

from __future__ import annotations

import collections
import threading
import time
from typing import Any

import streamlit as st


class EventQueue:
    """Thread-safe bounded queue with automatic overflow protection for live telemetry."""

    def __init__(self, maxsize: int = 10000) -> None:
        """Initialize EventQueue with capacity limit.

        Args:
            maxsize: Maximum number of events retained before dropping oldest.
        """
        self.maxsize = maxsize
        self._deque: collections.deque[dict[str, Any]] = collections.deque(maxlen=maxsize)
        self._lock = threading.Lock()

    def push(self, item: dict[str, Any]) -> bool:
        """Push a telemetry event into the queue in a thread-safe manner.

        Args:
            item: Telemetry dictionary to queue.

        Returns:
            True on successful queueing.
        """
        with self._lock:
            self._deque.append(item)
        return True

    def drain(self, max_items: int = 500) -> list[dict[str, Any]]:
        """Drain up to `max_items` events from the head of the queue without blocking.

        Args:
            max_items: Maximum items to retrieve in this batch.

        Returns:
            List of drained event dictionaries.
        """
        batch: list[dict[str, Any]] = []
        with self._lock:
            for _ in range(min(max_items, len(self._deque))):
                batch.append(self._deque.popleft())
        return batch

    def drain_all(self) -> list[dict[str, Any]]:
        """Drain all pending events from the queue.

        Returns:
            List of all drained event dictionaries.
        """
        with self._lock:
            items = list(self._deque)
            self._deque.clear()
        return items

    def get_recent(self, max_items: int = 500) -> list[dict[str, Any]]:
        """Retrieve up to `max_items` most recent events from the queue without draining.

        Args:
            max_items: Maximum recent items to return.

        Returns:
            List of recent event dictionaries in chronological order.
        """
        with self._lock:
            if not self._deque:
                return []
            items = list(self._deque)
            return items[-max_items:]

    def get_all(self) -> list[dict[str, Any]]:
        """Return a snapshot list of all buffered events without modifying the queue.

        Returns:
            List of all queued event dictionaries.
        """
        with self._lock:
            return list(self._deque)

    def peek(self, count: int = 100) -> list[dict[str, Any]]:
        """Peek at the oldest `count` buffered events without removing them.

        Args:
            count: Number of oldest items to inspect.

        Returns:
            List of peeked event dictionaries.
        """
        with self._lock:
            return list(self._deque)[:count]

    def size(self) -> int:
        """Return current number of items in queue.

        Returns:
            Count of queued events.
        """
        with self._lock:
            return len(self._deque)

    def push_packet(self, pkt: Any) -> bool:
        """Convert a BLE packet into an EventQueue dictionary and push it.

        Args:
            pkt: PacketMessage, dict, or BLE packet-like object.

        Returns:
            True on successful push.
        """
        item = packet_to_event_dict(pkt)
        return self.push(item)

    def is_empty(self) -> bool:
        """Check if queue is empty.

        Returns:
            True if empty, False otherwise.
        """
        with self._lock:
            return len(self._deque) == 0

    def clear(self) -> None:
        """Clear all events from queue."""
        with self._lock:
            self._deque.clear()


def packet_to_event_dict(pkt: Any) -> dict[str, Any]:
    """Convert a PacketMessage or raw BLE packet structure into an EventQueue dictionary.

    Args:
        pkt: PacketMessage, dict, or object with BLE frame fields.

    Returns:
        Structured observation dictionary ready for EventQueue ingestion.
    """
    if isinstance(pkt, dict):
        out = dict(pkt)
        if "timestamp" not in out:
            out["timestamp"] = time.time()
        if "datetime_str" not in out:
            out["datetime_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(out["timestamp"]))
        if "channel" not in out:
            out["channel"] = 37
        if "rssi" not in out:
            out["rssi"] = -60
        if "mac_address" not in out:
            out["mac_address"] = "00:00:00:00:00:00"
        if "network_type" not in out:
            out["network_type"] = "Unknown"
        if "ephemeral_key" not in out:
            out["ephemeral_key"] = ""
        if "raw_payload" not in out:
            out["raw_payload"] = ""
        return out

    now = time.time()
    if hasattr(pkt, "ts_epoch") and isinstance(pkt.ts_epoch, (int, float)) and pkt.ts_epoch > 0:
        ts_val = float(pkt.ts_epoch)
    elif hasattr(pkt, "timestamp") and isinstance(pkt.timestamp, (int, float)) and pkt.timestamp > 0:
        ts_val = float(pkt.timestamp)
    else:
        ts_val = now

    datetime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_val))
    chan = int(getattr(pkt, "chan", getattr(pkt, "channel", 37)))
    rssi = int(getattr(pkt, "rssi", -60))

    body = getattr(pkt, "body", b"")
    if not isinstance(body, (bytes, bytearray)):
        if isinstance(body, str):
            try:
                body = bytes.fromhex(body)
            except ValueError:
                body = b""
        else:
            body = b""

    raw_payload_hex = bytes(body).hex()
    mac_str = "00:00:00:00:00:00"
    adv_payload_hex = ""

    if len(body) >= 8:
        adv_a_bytes = body[2:8]
        mac_str = ":".join(f"{b:02X}" for b in reversed(adv_a_bytes))
        adv_payload_hex = body[8:].hex()
    elif len(body) > 0:
        adv_payload_hex = body.hex()

    net_type = "Unknown"
    eph_key = ""
    try:
        from airtell.scripts.ble_antistalking_tracker import classify_payload

        net_type, eph_key = classify_payload(adv_payload_hex or raw_payload_hex)
        if net_type == "Tile Tracker":
            net_type = "Tile"
    except Exception:
        pass

    if net_type == "Unknown":
        payload_lower = (adv_payload_hex or raw_payload_hex).lower()
        if "4c000215" in payload_lower or "4c001219" in payload_lower:
            net_type = "Apple Find My"
            idx = payload_lower.find("4c000215") if "4c000215" in payload_lower else payload_lower.find("4c001219")
            eph_key = payload_lower[idx + 8 : idx + 8 + 32]
        elif "fe9f" in payload_lower or "feaa" in payload_lower:
            net_type = "Google Find Hub"
            idx = payload_lower.find("fe9f") if "fe9f" in payload_lower else payload_lower.find("feaa")
            eph_key = payload_lower[idx : idx + 32]
        elif "feed" in payload_lower:
            net_type = "Tile"
            idx = payload_lower.find("feed")
            eph_key = payload_lower[idx : idx + 32]
        elif "7500" in payload_lower:
            net_type = "Samsung SmartThings Find"
            idx = payload_lower.find("7500")
            eph_key = payload_lower[idx : idx + 32]

    return {
        "timestamp": ts_val,
        "datetime_str": datetime_str,
        "channel": chan,
        "rssi": rssi,
        "mac_address": mac_str,
        "network_type": net_type,
        "ephemeral_key": eph_key,
        "raw_payload": adv_payload_hex or raw_payload_hex,
        "raw_bytes": bytes(body),
    }


@st.cache_resource
def get_event_queue() -> EventQueue:
    """Obtain or initialize the application-wide singleton EventQueue.

    Returns:
        Shared EventQueue instance.
    """
    return EventQueue(maxsize=10000)

