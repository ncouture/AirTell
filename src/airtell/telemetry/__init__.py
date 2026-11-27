"""Telemetry storage, event streaming queue, and structured analytics package."""

from __future__ import annotations

from airtell.telemetry.queue_bridge import (
    EventQueue,
    get_event_queue,
    packet_to_event_dict,
)
from airtell.telemetry.storage import (
    DatabaseBackend,
    DuckDBBackend,
    SQLiteBackend,
    get_database_backend,
)

__all__ = [
    "DatabaseBackend",
    "SQLiteBackend",
    "DuckDBBackend",
    "get_database_backend",
    "EventQueue",
    "get_event_queue",
    "packet_to_event_dict",
]
