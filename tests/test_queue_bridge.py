"""Unit tests for the thread-safe singleton EventQueue bridge."""

from __future__ import annotations

import ast
import sys
import threading
import time
from pathlib import Path
from typing import Any

from airtell.telemetry.queue_bridge import EventQueue, get_event_queue, packet_to_event_dict


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

    producer_threads = [threading.Thread(target=producer, args=(t_id,)) for t_id in range(num_threads)]
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


def test_queue_non_destructive_reads() -> None:
    """Validate that get_recent, get_all, and peek read queue items without removing them."""
    q = EventQueue(maxsize=100)
    for i in range(10):
        q.push({"pkt": i})

    assert q.size() == 10

    # peek
    oldest_3 = q.peek(3)
    assert len(oldest_3) == 3
    assert [p["pkt"] for p in oldest_3] == [0, 1, 2]
    assert q.size() == 10

    # get_recent
    recent_4 = q.get_recent(4)
    assert len(recent_4) == 4
    assert [p["pkt"] for p in recent_4] == [6, 7, 8, 9]
    assert q.size() == 10

    # get_all
    all_items = q.get_all()
    assert len(all_items) == 10
    assert [p["pkt"] for p in all_items] == list(range(10))
    assert q.size() == 10


def test_queue_non_positive_count_boundaries() -> None:
    """Validate get_recent, peek, and drain return empty lists for zero or negative counts."""
    q = EventQueue(maxsize=10)
    for i in range(5):
        q.push({"pkt": i})

    assert q.get_recent(0) == []
    assert q.get_recent(-1) == []
    assert q.get_recent(-5) == []
    assert q.peek(0) == []
    assert q.peek(-1) == []
    assert q.peek(-5) == []
    assert q.drain(0) == []
    assert q.drain(-1) == []
    assert q.size() == 5


def test_airtell_package_and_repo_have_no_streamlit_or_app_dependencies() -> None:
    """Validate via AST that airtell has no streamlit/plotly/app imports and removed artifacts stay absent."""
    import airtell.telemetry.queue_bridge as qb

    repo_root = Path(__file__).resolve().parent.parent
    forbidden_roots = {"streamlit", "plotly", "app"}

    for py_file in sorted((repo_root / "src" / "airtell").rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in forbidden_roots, f"Forbidden import '{alias.name}' in {py_file}"
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_roots, f"Forbidden import from '{node.module}' in {py_file}"

    for val in qb.__dict__.values():
        mod_name = getattr(val, "__name__", "")
        assert not (isinstance(mod_name, str) and mod_name.split(".")[0] in forbidden_roots)
    assert "streamlit" not in sys.modules

    assert not (repo_root / "app").exists(), "Deleted app/ directory must not exist"
    assert not (repo_root / ".streamlit").exists(), "Deleted .streamlit/ directory must not exist"
    assert not (repo_root / "conductor" / "code_styleguides" / "streamlit.md").exists()

    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    assert "streamlit" not in pyproject_text.lower()
    assert "plotly" not in pyproject_text.lower()
    assert "pandas" in pyproject_text.lower()


def test_singleton_get_event_queue_thread_safe_concurrent_init() -> None:
    """Validate concurrent calls to get_event_queue() always return the exact same singleton."""
    import airtell.telemetry.queue_bridge as qb

    original = qb._DEFAULT_EVENT_QUEUE
    try:
        qb._DEFAULT_EVENT_QUEUE = None
        results: list[EventQueue] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            instance = get_event_queue()
            with lock:
                results.append(instance)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 8
        assert all(item is results[0] for item in results)
    finally:
        qb._DEFAULT_EVENT_QUEUE = original


def test_packet_to_event_dict_and_push_packet() -> None:
    """Validate dict normalization and raw BLE packet conversion via push_packet."""
    partial = packet_to_event_dict({"rssi": -42})
    assert partial["rssi"] == -42
    assert partial["channel"] == 37
    assert partial["mac_address"] == "00:00:00:00:00:00"
    assert partial["network_type"] == "Unknown"

    class FakePacket:
        ts_epoch = 1729000000.0
        chan = 38
        rssi = -51
        # 2-byte header + 6-byte reversed AdvA (AA:BB:CC:DD:EE:FF) + Apple Find My signature
        body = bytes([0x00, 0x10, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]) + bytes.fromhex("4c001219" + "ab" * 16)

    q = EventQueue(maxsize=10)
    assert q.push_packet(FakePacket()) is True
    assert q.size() == 1
    ev = q.drain(1)[0]
    assert ev["channel"] == 38
    assert ev["rssi"] == -51
    assert ev["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert ev["network_type"] == "Apple Find My"
