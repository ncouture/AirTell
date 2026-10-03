"""Multi-Dongle Topology Orchestration and Port Contention Guard.

Coordinates concurrent Tshark extcap streams across multiple Sniffle USB dongles
(Topology A dual-channel aggregation and Topology B cross-band sniffing) with
non-destructive port contention checks to protect active logging processes.
"""

from __future__ import annotations

import errno
import logging
import os
import threading
import time
from typing import Any, Optional

from app.queue_bridge import EventQueue, get_event_queue
from bluetooth_sniffle.extcap.parser import TsharkBleJsonParser
from bluetooth_sniffle.extcap.runner import TsharkConfig, TsharkExtcapRunner

logger = logging.getLogger(__name__)


def get_process_holding_port(port: str) -> str | None:
    """Inspect system processes to identify any process actively using the serial port.

    Args:
        port: Device node path (e.g. '/dev/ttyUSB0').

    Returns:
        Description string with process command line and PID, or None if not found.
    """
    my_pid = os.getpid()
    parent_pid = os.getppid()
    proc_dir = "/proc"
    if not os.path.isdir(proc_dir):
        return None

    try:
        for entry in os.listdir(proc_dir):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in (my_pid, parent_pid):
                continue

            # 1. Check open file descriptors first (authoritative proof of port hold)
            fd_dir = os.path.join(proc_dir, entry, "fd")
            try:
                for fd in os.listdir(fd_dir):
                    fd_path = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(fd_path)
                        if target == port:
                            cmdline = ""
                            try:
                                with open(os.path.join(proc_dir, entry, "cmdline"), "rb") as f:
                                    cmdline = f.read().decode("utf-8", errors="ignore").replace("\x00", " ").strip()
                            except Exception:
                                pass
                            desc = f"{cmdline} " if cmdline else ""
                            return f"Process {desc}(PID {pid}) holds open descriptor to {port}"
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                pass

            # 2. Check process commandline for active sniffer tools
            cmdline_path = os.path.join(proc_dir, entry, "cmdline")
            try:
                with open(cmdline_path, "rb") as f:
                    content = f.read().decode("utf-8", errors="ignore").replace("\x00", " ")
                    if port in content and any(
                        sub in content
                        for sub in (
                            "ble_antistalking_tracker.py",
                            "sniff_receiver.py",
                            "sniffle_extcap.py",
                            "sniff_pcap.py",
                            "tshark",
                        )
                    ):
                        return f"{content.strip()} (PID {pid})"
            except (OSError, PermissionError):
                pass
    except Exception as exc:
        logger.debug("Process inspection check error: %s", exc)

    return None


def check_port_availability(port: str) -> tuple[bool, str]:
    """Non-destructively test whether a serial device node is available for capture.

    Args:
        port: Device node path (e.g. '/dev/ttyUSB0').

    Returns:
        Tuple of (is_available, status_description).
    """
    if not os.path.exists(port):
        return False, f"Device node {port} does not exist or was not found on host."

    # Guard: check if known Sniffle / tracker process holds it
    holding_proc = get_process_holding_port(port)
    if holding_proc:
        return False, f"Port {port} is currently locked by active process: {holding_proc}"

    # Guard: test non-blocking open
    try:
        fd = os.open(port, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
        os.close(fd)
        return True, f"Port {port} is Available."
    except OSError as exc:
        if exc.errno == errno.EBUSY:
            return False, f"Port {port} is currently locked by another process (EBUSY)."
        if exc.errno == errno.EACCES:
            return False, f"Insufficient permissions to access serial port {port} (EACCES)."
        return False, f"Error accessing serial port {port}: {exc}"


class TsharkTopologyManager:
    """Orchestrates Tshark extcap capture pipelines across single and dual dongle setups."""

    def __init__(
        self,
        event_queue: Optional[EventQueue] = None,
        ring_buffer_size: int = 2000,
        tshark_bin: str = "tshark",
    ) -> None:
        """Initialize topology manager.

        Args:
            event_queue: Shared EventQueue singleton instance.
            ring_buffer_size: Maximum buffer capacity per runner.
            tshark_bin: Path or command name for tshark executable.
        """
        self.event_queue: EventQueue = event_queue or get_event_queue()
        self.parser: TsharkBleJsonParser = TsharkBleJsonParser(event_queue=self.event_queue)
        self.ring_buffer_size: int = ring_buffer_size
        self.tshark_bin: str = tshark_bin

        self.runners: dict[str, TsharkExtcapRunner] = {}
        self._consumer_threads: dict[str, threading.Thread] = {}
        self._stop_event: threading.Event = threading.Event()
        self._lock: threading.RLock = threading.RLock()

        self._active_topology: str = "None"
        self._error: str | None = None
        self._packets_captured: int = 0

    def is_running(self) -> bool:
        """Return True if any topology runner is actively executing."""
        with self._lock:
            return any(r.is_running() for r in self.runners.values())

    def start_topology_a(
        self,
        port1: str = "/dev/ttyUSB0",
        port2: str = "/dev/ttyUSB1",
        chan1: int = 37,
        chan2: int = 38,
        rssi_cutoff: int | None = None,
        display_filter: str | None = "btle.advertising_address",
        output_format: str = "ek",
        **kwargs: Any,
    ) -> bool:
        """Start Topology A: Concurrent dual-channel sniffing across two dongles.

        Args:
            port1: Primary Sniffle dongle serial port.
            port2: Secondary Sniffle dongle serial port.
            chan1: Primary advertising channel (e.g. 37).
            chan2: Secondary advertising channel (e.g. 38 or 39).
            rssi_cutoff: Minimum RSSI cutoff filter (e.g. -80).
            display_filter: Wireshark display filter string.
            output_format: Output format ('ek' or 'json').
            **kwargs: Extra extcap arguments.

        Returns:
            True if dual-channel topology successfully initialized and started.

        Raises:
            ValueError: If port1 and port2 are identical.
        """
        if port1 == port2:
            raise ValueError(f"Primary and secondary radios cannot share the same serial port: {port1}")

        # Check port availability to prevent colliding with active background sniffing
        avail1, reason1 = check_port_availability(port1)
        if not avail1:
            with self._lock:
                self._error = f"Primary port unavailable: {reason1}"
            logger.warning(self._error)
            return False

        avail2, reason2 = check_port_availability(port2)
        if not avail2:
            with self._lock:
                self._error = f"Secondary port unavailable: {reason2}"
            logger.warning(self._error)
            return False

        self.stop()

        cfg1 = TsharkConfig(
            serport=port1,
            advchan=chan1,
            rssi=rssi_cutoff,
            display_filter=display_filter,
            output_format=output_format,
            **kwargs,
        )
        cfg2 = TsharkConfig(
            serport=port2,
            advchan=chan2,
            rssi=rssi_cutoff,
            display_filter=display_filter,
            output_format=output_format,
            **kwargs,
        )

        runner1 = TsharkExtcapRunner(
            config=cfg1,
            ring_buffer_size=self.ring_buffer_size,
            tshark_bin=self.tshark_bin,
        )
        runner2 = TsharkExtcapRunner(
            config=cfg2,
            ring_buffer_size=self.ring_buffer_size,
            tshark_bin=self.tshark_bin,
        )

        with self._lock:
            self.runners = {port1: runner1, port2: runner2}
            self._stop_event.clear()
            self._error = None

        if not runner1.start():
            self.stop()
            with self._lock:
                self._error = f"Failed to start Tshark on primary port {port1}."
            return False

        if not runner2.start():
            self.stop()
            with self._lock:
                self._error = f"Failed to start Tshark on secondary port {port2}."
            return False

        # Launch consumer threads to drain and parse streams from both runners
        self._start_consumer(port1, runner1)
        self._start_consumer(port2, runner2)

        with self._lock:
            self._active_topology = "Topology A"

        logger.info("Topology A started successfully on ports %s (Ch %d) and %s (Ch %d).", port1, chan1, port2, chan2)
        return True

    def start_topology_b(
        self,
        port: str = "/dev/ttyUSB0",
        chan: int = 37,
        rssi_cutoff: int | None = None,
        display_filter: str | None = "btle.advertising_address",
        output_format: str = "ek",
        **kwargs: Any,
    ) -> bool:
        """Start Topology B: Single-radio sniffing, keeping alternate radio available.

        Args:
            port: Target serial port.
            chan: Target advertising channel (37, 38, or 39).
            rssi_cutoff: Minimum RSSI cutoff filter.
            display_filter: Wireshark display filter.
            output_format: Output format ('ek' or 'json').
            **kwargs: Extra extcap arguments.

        Returns:
            True if single-radio topology started successfully.
        """
        avail, reason = check_port_availability(port)
        if not avail:
            with self._lock:
                self._error = f"Port unavailable: {reason}"
            logger.warning(self._error)
            return False

        self.stop()

        cfg = TsharkConfig(
            serport=port,
            advchan=chan,
            rssi=rssi_cutoff,
            display_filter=display_filter,
            output_format=output_format,
            **kwargs,
        )
        runner = TsharkExtcapRunner(
            config=cfg,
            ring_buffer_size=self.ring_buffer_size,
            tshark_bin=self.tshark_bin,
        )

        with self._lock:
            self.runners = {port: runner}
            self._stop_event.clear()
            self._error = None

        if not runner.start():
            self.stop()
            with self._lock:
                self._error = f"Failed to start Tshark on port {port}."
            return False

        self._start_consumer(port, runner)

        with self._lock:
            self._active_topology = "Topology B"

        logger.info("Topology B started successfully on port %s (Ch %d).", port, chan)
        return True

    def _start_consumer(self, port: str, runner: TsharkExtcapRunner) -> None:
        """Spawn background consumer thread that drains runner stdout lines and parses them."""
        def _consumer() -> None:
            while not self._stop_event.is_set():
                lines = runner.drain_lines(max_count=100)
                if not lines:
                    time.sleep(0.02)
                    continue
                for line in lines:
                    obs = self.parser.parse_line(line)
                    if obs:
                        with self._lock:
                            self._packets_captured += 1

        t = threading.Thread(
            target=_consumer,
            daemon=True,
            name=f"tshark-consumer-{port}",
        )
        t.start()
        with self._lock:
            self._consumer_threads[port] = t

    def dispatch_line(self, port: str, line: str) -> dict[str, Any] | None:
        """Manually dispatch a raw packet line into the parser and queue (for testing/mocking).

        Args:
            port: Originating serial port path.
            line: Raw JSON line string.

        Returns:
            Normalized observation dictionary if parsed, None otherwise.
        """
        obs = self.parser.parse_line(line)
        if obs:
            with self._lock:
                self._packets_captured += 1
        return obs

    def stop(self) -> bool:
        """Stop all active Tshark extcap runners and stream consumer threads."""
        with self._lock:
            self._stop_event.set()
            runners = list(self.runners.values())
            threads = list(self._consumer_threads.values())

        for r in runners:
            try:
                r.stop()
            except Exception as exc:
                logger.error("Error stopping runner on %s: %s", r.config.serport, exc)

        for t in threads:
            if t.is_alive():
                t.join(timeout=0.5)

        with self._lock:
            self.runners.clear()
            self._consumer_threads.clear()
            self._active_topology = "None"

        return True

    def get_status(self) -> dict[str, Any]:
        """Return aggregated operational telemetry for monitoring and UI display.

        Returns:
            Dictionary with active topology, running status, counters, and runner metrics.
        """
        with self._lock:
            runners_info: dict[str, Any] = {}
            for port, r in self.runners.items():
                runners_info[port] = r.get_metrics()

            return {
                "running": any(r.is_running() for r in self.runners.values()),
                "topology": self._active_topology,
                "error": self._error,
                "packets_captured": self._packets_captured,
                "runners": runners_info,
            }
