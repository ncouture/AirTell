"""Empirical adversarial stress test suite for Milestone M1 (#73 through #92).

Authored by challenger_m1_1.
Tests verify:
1. Multi-threaded SQLite connection lifecycle and FD leak assertions under 20 concurrent threads (#73).
2. DuckDB SQLite ATTACH path escaping with apostrophes, multiple single quotes, SQL injections, and unicode (#74).
3. TsharkExtcapRunner stderr draining under high-volume stderr (>256 KB, 512 KB) without deadlocking (#75).
4. Sniffle PCAP reader clean ValueError handling across corrupted/truncated packet fuzzing (#78).
"""

from __future__ import annotations

import io
import os
import sqlite3
import struct
import sys
import threading
import time
from pathlib import Path

import pytest
from sniffle.pcap import PcapBleReader as SnifflePcapReader

from airtell.extcap.runner import TsharkConfig, TsharkExtcapRunner
from airtell.telemetry.storage import DuckDBBackend, SQLiteBackend

# ============================================================================
# 1. Multi-threaded SQLite Connection Stress Test (#73)
# ============================================================================


def get_process_open_fds() -> set[int]:
    """Retrieve currently open file descriptor numbers for this process."""
    try:
        return {int(fd) for fd in os.listdir(f"/proc/{os.getpid()}/fd")}
    except Exception:
        return set()


def test_sqlite_multithreaded_stress_fd_leak_check(tmp_path: Path) -> None:
    """Simulate 20 concurrent threads reading/writing and verify clean connection closure & no FD leak."""
    db_file = tmp_path / "stress_concurrent.sqlite"
    backend = SQLiteBackend(str(db_file), timeout=30.0)

    num_threads = 20
    ops_per_thread = 15
    thread_conns: list[sqlite3.Connection] = []
    thread_conns_lock = threading.Lock()
    barrier = threading.Barrier(num_threads)
    errors: list[Exception] = []

    def test_conn_active(c: sqlite3.Connection) -> bool:
        try:
            cur = c.execute("SELECT 1")
            return cur.fetchone()[0] == 1
        except Exception:
            return False

    # Barrier for threads to wait after operations until backend.close() is called
    close_barrier = threading.Barrier(num_threads + 1)
    closed_check_results: dict[int, bool] = {}

    def worker(thread_idx: int) -> None:
        try:
            conn = backend.connect()
            with thread_conns_lock:
                thread_conns.append(conn)

            # Wait for all 20 threads to connect before hammering the DB
            barrier.wait(timeout=10.0)

            for i in range(ops_per_thread):
                backend.insert_observation(
                    mac_address=f"AA:BB:CC:DD:EE:{thread_idx:02X}",
                    rssi=-50 - (i % 30),
                    network_type="Apple",
                    ephemeral_key=f"key_{thread_idx}_{i}",
                    channel=37 + (i % 3),
                    raw_payload=f"payload_t{thread_idx}_op{i}",
                )
                obs = backend.get_observations(limit=5)
                assert isinstance(obs, list)

            # Confirm connection is active before close
            assert test_conn_active(conn) is True

            # Wait for main thread to call backend.close()
            close_barrier.wait(timeout=10.0)

            # Now test if connection is closed
            try:
                conn.execute("SELECT 1")
                closed_check_results[thread_idx] = False  # Should NOT succeed
            except sqlite3.ProgrammingError as e:
                # "Cannot operate on a closed database."
                closed_check_results[thread_idx] = "closed database" in str(e).lower()

        except Exception as exc:
            errors.append(exc)

    thread_conns.clear()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()

    # Wait for all threads to finish their operations and reach close_barrier
    # (they will wait at close_barrier)
    # The main thread joins the barrier after giving workers time
    time.sleep(1.0)
    # Close backend before signaling workers to check
    backend.close()
    close_barrier.wait(timeout=10.0)

    for t in threads:
        t.join(timeout=30.0)

    assert not errors, f"Errors encountered during concurrent workers: {errors}"
    assert len(closed_check_results) == num_threads
    for t_idx, was_closed in closed_check_results.items():
        assert was_closed is True, f"Thread {t_idx} connection was not closed by backend.close()!"

    # Verify internal connection registry is empty
    assert len(backend._all_conns) == 0

    # Ensure no lingering unclosed SQLite FDs
    fds_after = get_process_open_fds()
    # Any DB file FDs should no longer point to db_file
    for fd in fds_after:
        try:
            link = os.readlink(f"/proc/{os.getpid()}/fd/{fd}")
            assert str(db_file) not in link, f"Leaked file descriptor {fd} pointing to {link}"
        except OSError:
            pass


def test_sqlite_close_from_background_thread(tmp_path: Path) -> None:
    """Verify closing the backend from a secondary background thread closes all connections."""
    db_file = tmp_path / "bg_close.sqlite"
    backend = SQLiteBackend(str(db_file), timeout=15.0)

    conns: list[sqlite3.Connection] = []

    def conn_creator() -> None:
        c = backend.connect()
        c.execute("SELECT 1")
        conns.append(c)

    threads = [threading.Thread(target=conn_creator) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(conns) == 5

    # Close from a completely different thread
    close_thread = threading.Thread(target=backend.close)
    close_thread.start()
    close_thread.join()

    for c in conns:
        with pytest.raises(sqlite3.ProgrammingError):
            c.execute("SELECT 1")


def test_sqlite_50_concurrent_threads_stress_and_fd_closure(tmp_path: Path) -> None:
    """Stress test 50 concurrent worker threads performing inserts and queries,

    asserting backend.close() closes all 50 connections and leaves 0 open database file descriptors.
    """
    db_file = tmp_path / "stress_50_threads.sqlite"
    backend = SQLiteBackend(str(db_file), timeout=60.0)

    num_threads = 50
    ops_per_thread = 5
    worker_conns: dict[int, sqlite3.Connection] = {}
    conns_lock = threading.Lock()
    start_barrier = threading.Barrier(num_threads)
    work_done_barrier = threading.Barrier(num_threads + 1)
    close_event = threading.Event()

    worker_errors: list[tuple[int, Exception]] = []
    post_close_errors: dict[int, Exception] = {}

    def get_open_db_fds() -> list[tuple[int, str]]:
        open_fds = []
        fd_dir = f"/proc/{os.getpid()}/fd"
        try:
            for fname in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fname))
                    if str(db_file) in target:
                        open_fds.append((int(fname), target))
                except OSError:
                    pass
        except Exception:
            pass
        return open_fds

    def worker(t_idx: int) -> None:
        try:
            conn = backend.connect()
            with conns_lock:
                worker_conns[t_idx] = conn

            # Synchronize start across all 50 threads
            start_barrier.wait(timeout=15.0)

            for i in range(ops_per_thread):
                backend.insert_observation(
                    mac_address=f"AA:BB:CC:DD:{t_idx:02X}:{i:02X}",
                    rssi=-50 - (i * 2),
                    network_type="Apple" if i % 2 == 0 else "Tile",
                    ephemeral_key=f"eph_key_{t_idx}_{i}",
                    channel=37 + (i % 3),
                    raw_payload=f"stress_payload_t{t_idx}_i{i}",
                )
                obs = backend.get_observations(limit=2)
                assert isinstance(obs, list)

            # Assert connection is functional before close
            cur = conn.execute("SELECT COUNT(*) FROM observations")
            count = cur.fetchone()[0]
            assert count >= ops_per_thread

            # Signal work complete, wait for main thread to close backend
            work_done_barrier.wait(timeout=30.0)
            assert close_event.wait(timeout=15.0) is True

            # Attempt query on the thread's connection handle
            try:
                conn.execute("SELECT 1")
            except Exception as exc:
                post_close_errors[t_idx] = exc

        except Exception as exc:
            worker_errors.append((t_idx, exc))

    threads = [threading.Thread(target=worker, args=(i,), name=f"worker-{i}") for i in range(num_threads)]
    for t in threads:
        t.start()

    # Wait for all 50 workers to finish operations and reach barrier
    work_done_barrier.wait(timeout=30.0)
    assert not worker_errors, f"Errors occurred during worker operations: {worker_errors}"
    assert len(worker_conns) == num_threads

    # Verify that open file descriptors exist before close
    fds_before = get_open_db_fds()
    assert len(fds_before) >= num_threads, f"Expected >= {num_threads} open FDs before close, got {len(fds_before)}"

    # Close the backend from main thread
    backend.close()

    # Check open file descriptors immediately after close
    fds_after = get_open_db_fds()
    assert len(fds_after) == 0, f"Leaked file descriptors after close: {fds_after}"

    # Release worker threads to check their connections
    close_event.set()

    for t in threads:
        t.join(timeout=30.0)

    # All 50 threads must report ProgrammingError with 'closed database'
    assert len(post_close_errors) == num_threads, (
        f"Only {len(post_close_errors)} of {num_threads} threads caught post-close errors. "
        f"Missing threads: {set(range(num_threads)) - set(post_close_errors.keys())}"
    )

    for t_idx, exc in post_close_errors.items():
        assert isinstance(exc, sqlite3.ProgrammingError), (
            f"Thread {t_idx} received unexpected error type {type(exc)}: {exc}"
        )
        assert "closed database" in str(exc).lower(), (
            f"Thread {t_idx} received error not indicating closed database: {exc}"
        )

    # Verify from main thread that none of the 50 connection references can be operated on
    for t_idx, conn in worker_conns.items():
        with pytest.raises(sqlite3.ProgrammingError, match="(?i)closed database"):
            conn.execute("SELECT 1")

    # Verify backend's internal tracking set is empty
    assert len(backend._all_conns) == 0


def test_sqlite_concurrent_close_idempotency_stress(tmp_path: Path) -> None:
    """Stress test concurrent close() calls across multiple threads to verify thread safety and idempotency."""
    db_file = tmp_path / "concurrent_close.sqlite"
    backend = SQLiteBackend(str(db_file), timeout=30.0)

    num_threads = 20
    conns: list[sqlite3.Connection] = []
    conns_lock = threading.Lock()
    barrier = threading.Barrier(num_threads)

    def worker(idx: int) -> None:
        c = backend.connect()
        with conns_lock:
            conns.append(c)
        backend.insert_observation(
            mac_address=f"11:22:33:44:55:{idx:02X}",
            rssi=-70,
            network_type="Apple",
            ephemeral_key=f"k_{idx}",
        )
        barrier.wait(timeout=10.0)

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join(timeout=15.0)

    assert len(conns) == num_threads

    # 10 concurrent closer threads
    num_closers = 10
    closer_barrier = threading.Barrier(num_closers)
    closer_errors: list[Exception] = []

    def closer() -> None:
        try:
            closer_barrier.wait(timeout=10.0)
            backend.close()
        except Exception as exc:
            closer_errors.append(exc)

    closers = [threading.Thread(target=closer) for _ in range(num_closers)]
    for t in closers:
        t.start()
    for t in closers:
        t.join(timeout=15.0)

    assert not closer_errors, f"Errors during concurrent close: {closer_errors}"
    assert len(backend._all_conns) == 0

    # Ensure all connections were cleanly closed
    for c in conns:
        with pytest.raises(sqlite3.ProgrammingError, match="(?i)closed database"):
            c.execute("SELECT 1")


def test_sqlite_memory_backend_multithreaded_close_stress() -> None:
    """Validate in-memory SQLite backend multithreaded close properly invalidates shared conn."""
    backend = SQLiteBackend(":memory:")
    conns: list[sqlite3.Connection] = []
    barrier = threading.Barrier(5)

    def worker() -> None:
        c = backend.connect()
        conns.append(c)
        barrier.wait()

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All threads got the memory connection
    assert len(conns) == 5
    backend.close()

    for c in conns:
        with pytest.raises(sqlite3.ProgrammingError, match="(?i)closed database"):
            c.execute("SELECT 1")
    assert backend._mem_conn is None


# ============================================================================
# 2. DuckDB SQLite ATTACH Path Escaping Stress Test (#74)
# ============================================================================


@pytest.mark.parametrize(
    "subpath",
    [
        "single_'quote.sqlite",
        "double_''quotes.sqlite",
        "many_'''quotes''''in_row.sqlite",
        "don't_break_user's_data.sqlite",
        "quotes_at_edges_'middle'_end'.sqlite",
        "symbols_!@#$^&()_+-=~.sqlite",
        "spaces in 'directory name'/my 'test' db.sqlite",
        "injection_'; ATTACH ':memory:' AS injected; --.sqlite",
        "injection_'; DROP TABLE observations; --.sqlite",
        "injection_' OR '1'='1.sqlite",
        "unicode_résumé_привет_🦀_test.sqlite",
    ],
)
def test_duckdb_sqlite_attach_path_escaping(tmp_path: Path, subpath: str) -> None:
    """Stress-test DuckDB SQLite ATTACH path escaping with apostrophes, injections, and symbols."""
    full_path = tmp_path / subpath
    full_path.parent.mkdir(parents=True, exist_ok=True)
    db_path_str = str(full_path)

    # Initialize and populate SQLite backend
    sqlite_be = SQLiteBackend(db_path_str)
    sqlite_be.insert_observation(
        mac_address="11:22:33:44:55:66",
        rssi=-65,
        network_type="Tile",
        ephemeral_key="tile_key_001",
        channel=38,
        raw_payload="01020304",
    )
    sqlite_be.close()

    # Now attach through DuckDBBackend
    duck_be = DuckDBBackend(db_path_str)
    try:
        # Query observations table through the attached SQLite view
        df = duck_be.query_df("SELECT count(*) as total, max(rssi) as max_rssi FROM observations;")
        assert len(df) == 1
        assert df["total"].iloc[0] == 1
        assert df["max_rssi"].iloc[0] == -65

        # Query with filter
        df2 = duck_be.query_df("SELECT mac_address, ephemeral_key FROM observations WHERE network_type = 'Tile';")
        assert len(df2) == 1
        assert df2["mac_address"].iloc[0] == "11:22:33:44:55:66"
        assert df2["ephemeral_key"].iloc[0] == "tile_key_001"
    finally:
        duck_be.close()


# ============================================================================
# 3. Tshark Stderr Draining Stress Test (>256 KB) (#75)
# ============================================================================


def test_tshark_high_volume_stderr_draining_stress(tmp_path: Path) -> None:
    """Simulate >256 KB (specifically 512 KB) of stderr output without deadlocking or dropped stdout."""
    mock_script = tmp_path / "mock_tshark_stress.py"
    # Write a mock tshark that emits 5,000 lines of 100 bytes each (>500 KB) to stderr,
    # interleaved with stdout packet lines, while pipe buffer is 64 KB.
    mock_script.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "# Emit 5,120 lines x 100 chars = 512 KB of stderr\n"
        "for i in range(5120):\n"
        "    sys.stderr.write(f'STDERR_ERROR_LINE_{i:05d}_' + 'X' * 70 + '\\n')\n"
        "    if i % 500 == 0:\n"
        "        sys.stdout.write(f'stdout_packet_{i}\\n')\n"
        "        sys.stdout.flush()\n"
        "sys.stderr.flush()\n"
        "sys.stdout.write('stdout_final_packet\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.2)\n"
    )
    mock_script.chmod(0o755)

    config = TsharkConfig(serport="/dev/ttyUSB0")
    runner = TsharkExtcapRunner(config=config, ring_buffer_size=5000, tshark_bin=str(mock_script))

    start_time = time.time()
    assert runner.start() is True

    # Poll until process finishes or timeout at 10s (deadlock would hang forever)
    while runner.is_running() and (time.time() - start_time) < 10.0:
        time.sleep(0.1)

    elapsed = time.time() - start_time
    assert elapsed < 10.0, "Runner deadlocked on >512 KB stderr output!"

    lines = runner.drain_lines()
    assert "stdout_final_packet" in lines
    assert runner.errors_logged >= 5000
    assert runner.stop() is True
    assert runner.is_running() is False


# ============================================================================
# 4. Sniffle PCAP Reader Malformed Packet Fuzzing (#78)
# ============================================================================


def create_valid_pcap_header() -> bytes:
    """Create a standard 24-byte PCAP global header."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256)


def create_valid_packet(body: bytes = b"\x00\x03\x01\x02\x03") -> bytes:
    """Create a valid raw packet buffer with header and payload."""
    # body[1] is length of body - 2 -> 3
    # payload: 14 bytes header + body + 3 bytes CRC
    # flags: 0x0413 (valid flags)
    rf_chan = 0  # channel 37
    rssi = -60
    aa = 0x8E89BED6
    flags = 0x0413
    payload_hdr = struct.pack("<BbbBIHI", rf_chan, rssi, 0, 0, aa, flags, 0)
    crc_bytes = b"\x12\x34\x56"
    payload = payload_hdr + body + crc_bytes
    pkt_hdr = struct.pack("<IIII", 1000, 500, len(payload), len(payload))
    return pkt_hdr + payload


def test_sniffle_pcap_reader_fuzz_header_truncation() -> None:
    """Feed partial/truncated packet records and verify EOFError or clean handling without AssertionError."""
    global_hdr = create_valid_pcap_header()

    for cut in range(1, 16):
        data = global_hdr + (b"\xaa" * cut)
        reader = SnifflePcapReader(io.BytesIO(data))
        with pytest.raises(EOFError):
            reader.read_packet()


def test_sniffle_pcap_reader_fuzz_size_mismatch() -> None:
    """Feed mismatched size1 != size2 in packet header and verify clean ValueError."""
    global_hdr = create_valid_pcap_header()

    for s1, s2 in [(10, 20), (100, 50), (65535, 1)]:
        record = struct.pack("<IIII", 0, 0, s1, s2) + b"\x00" * min(s1, 100)
        reader = SnifflePcapReader(io.BytesIO(global_hdr + record))
        with pytest.raises(ValueError, match="Mismatched packet size"):
            reader.read_packet()


def test_sniffle_pcap_reader_fuzz_payload_truncation() -> None:
    """Feed truncated payload at various byte lengths (< 17 bytes) and verify clean ValueError."""
    global_hdr = create_valid_pcap_header()

    for length in range(0, 17):
        pkt_hdr = struct.pack("<IIII", 0, 0, length, length)
        payload = b"\x00" * length
        reader = SnifflePcapReader(io.BytesIO(global_hdr + pkt_hdr + payload))
        with pytest.raises(ValueError, match="Truncated packet payload"):
            reader.read_packet()


def test_sniffle_pcap_reader_fuzz_invalid_flags() -> None:
    """Feed corrupted flags missing 0x0413 bits and verify clean ValueError."""
    global_hdr = create_valid_pcap_header()

    invalid_flags = [0x0000, 0x0400, 0x0013, 0x0410, 0x0403, 0xFFFF ^ 0x0413]
    for flag in invalid_flags:
        if (flag & 0x0413) == 0x0413:
            continue
        payload_hdr = struct.pack("<BbbBIHI", 0, -50, 0, 0, 0x8E89BED6, flag, 0)
        payload = payload_hdr + b"\x00\x01\xaa\x00\x00\x00"
        pkt_hdr = struct.pack("<IIII", 0, 0, len(payload), len(payload))
        reader = SnifflePcapReader(io.BytesIO(global_hdr + pkt_hdr + payload))
        with pytest.raises(ValueError, match="Invalid packet flags"):
            reader.read_packet()


def test_sniffle_pcap_reader_fuzz_body_length_corruption() -> None:
    """Feed corrupted body lengths (len(body) != body[1] + 2) and verify clean ValueError."""
    global_hdr = create_valid_pcap_header()

    # Valid payload header with valid flags
    payload_hdr = struct.pack("<BbbBIHI", 0, -50, 0, 0, 0x8E89BED6, 0x0413, 0)
    crc = b"\x11\x22\x33"

    # Case A: body length < 2 bytes
    payload_short = payload_hdr + b"\x00" + crc
    pkt_hdr_short = struct.pack("<IIII", 0, 0, len(payload_short), len(payload_short))
    reader_short = SnifflePcapReader(io.BytesIO(global_hdr + pkt_hdr_short + payload_short))
    with pytest.raises(ValueError, match="Truncated or corrupted PDU body"):
        reader_short.read_packet()

    # Case B: body[1] claims 20 bytes, but body has only 5 bytes
    body_corrupted = b"\x00\x14\x01\x02\x03"
    payload_mismatch = payload_hdr + body_corrupted + crc
    pkt_hdr_mismatch = struct.pack("<IIII", 0, 0, len(payload_mismatch), len(payload_mismatch))
    reader_mismatch = SnifflePcapReader(io.BytesIO(global_hdr + pkt_hdr_mismatch + payload_mismatch))
    with pytest.raises(ValueError, match="Truncated or corrupted PDU body"):
        reader_mismatch.read_packet()


def test_sniffle_pcap_reader_random_fuzzing_no_assertion_error() -> None:
    """Fuzz reader with 100 pseudo-random byte streams and assert NO AssertionError is ever raised."""
    import random

    rng = random.Random(42)
    global_hdr = create_valid_pcap_header()

    for trial in range(100):
        # Generate random length between 1 and 256 bytes
        rand_bytes = rng.randbytes(rng.randint(1, 256))
        stream = io.BytesIO(global_hdr + rand_bytes)
        reader = SnifflePcapReader(stream)

        try:
            reader.read_packet()
        except (ValueError, EOFError):
            # Expected exceptions on malformed packet input
            pass
        except AssertionError as exc:
            pytest.fail(f"Trial {trial}: Reader raised AssertionError instead of clean exception: {exc}")
        except Exception:
            # Other exceptions may occur if deep decoders fail, but never AssertionError
            pass
