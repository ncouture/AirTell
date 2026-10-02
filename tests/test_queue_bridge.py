"""Unit tests for the thread-safe singleton EventQueue bridge."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from app.queue_bridge import EventQueue, get_event_queue


def test_queue_initialization_and_capacity() -> None:
    """Validate queue capacity and basic push/size behavior."""
    q = EventQueue(maxsize=10)
    assert q.size() == 0
    assert q.is_empty()

    for i in range(10):
        assert q.push({"packet_id": i})
    assert q.size() == 10
    assert not q.is_empty()


def test_queue_overflow_protection() -> None:
    """Validate that overflow drops oldest items or rejects without hanging."""
    q = EventQueue(maxsize=5)
    for i in range(5):
        q.push({"val": i})

    # Pushing beyond maxsize drops oldest or handles gracefully
    q.push({"val": 99})
    assert q.size() <= 5

    items = q.drain_all()
    assert len(items) == 5
    # The newest item should be retained
    assert any(item.get("val") == 99 for item in items)


def test_queue_drain_batching() -> None:
    """Validate batch draining limits."""
    q = EventQueue(maxsize=100)
    for i in range(25):
        q.push({"seq": i})

    batch = q.drain(max_items=10)
    assert len(batch) == 10
    assert q.size() == 15

    remaining = q.drain_all()
    assert len(remaining) == 15
    assert q.is_empty()


def test_queue_concurrent_producers_and_consumer() -> None:
    """Validate thread-safe concurrent push and drain operations."""
    q = EventQueue(maxsize=2000)
    num_threads = 4
    items_per_thread = 200
    consumed: list[dict[str, Any]] = []
    stop_event = threading.Event()

    def producer(thread_id: int) -> None:
        for j in range(items_per_thread):
            q.push({"thread": thread_id, "idx": j})
            time.sleep(0.0001)

    def consumer() -> None:
        while not stop_event.is_set() or not q.is_empty():
            batch = q.drain(max_items=50)
            consumed.extend(batch)
            time.sleep(0.0005)

    consumer_thread = threading.Thread(target=consumer)
    consumer_thread.start()

    producer_threads = [
        threading.Thread(target=producer, args=(t_id,))
        for t_id in range(num_threads)
    ]
    for pt in producer_threads:
        pt.start()
    for pt in producer_threads:
        pt.join()

    # Let consumer finish draining
    stop_event.set()
    consumer_thread.join(timeout=2.0)

    # Remaining in queue if any
    consumed.extend(q.drain_all())
    assert len(consumed) == num_threads * items_per_thread


def test_singleton_get_event_queue() -> None:
    """Validate singleton accessor returns stable instance."""
    q1 = get_event_queue()
    q2 = get_event_queue()
    assert q1 is q2
