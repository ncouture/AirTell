"""Thread-safe singleton EventQueue bridge between Sniffle background threads and Streamlit."""

from __future__ import annotations

import collections
import threading
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

    def size(self) -> int:
        """Return current number of items in queue.

        Returns:
            Count of queued events.
        """
        with self._lock:
            return len(self._deque)

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


@st.cache_resource
def get_event_queue() -> EventQueue:
    """Obtain or initialize the application-wide singleton EventQueue.

    Returns:
        Shared EventQueue instance.
    """
    return EventQueue(maxsize=10000)
