"""Asynchronous Tshark Extcap Process Manager and Stream Engine.

Constructs command arguments targeting sniffle extcap plugin, manages subprocess lifecycles,
and streams line-buffered JSON output into a thread-safe ring buffer.
"""

from __future__ import annotations

import collections
import dataclasses
import logging
import signal
import subprocess
import threading
import types
from typing import Any

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TsharkConfig:
    """Configuration options for tshark sniffing with sniffle extcap plugin."""

    interface: str = "sniffle"
    serport: str = "/dev/ttyUSB0"
    mode: str = "passive_scan"
    advchan: int | str = 37
    rssi: int | None = None
    mac: str | None = None
    irk: str | None = None
    string: str | None = None
    extadv: bool = False
    longrange: bool = False
    crcerr: bool = False
    display_filter: str | None = "btle.advertising_address"
    output_format: str = "ek"
    line_buffered: bool = True
    extra_args: list[str] = dataclasses.field(default_factory=list)

    def to_command_args(self, tshark_bin: str = "tshark") -> list[str]:
        """Construct command argument list for subprocess execution.

        Args:
            tshark_bin: Path or executable name for tshark.

        Returns:
            List of command line arguments.
        """
        args: list[str] = [tshark_bin, "-i", self.interface]

        # Primary extcap options
        args.extend(["-o", f"extcap.sniffle.serport:{self.serport}"])
        args.extend(["-o", f"extcap.sniffle.mode:{self.mode}"])
        args.extend(["-o", f"extcap.sniffle.advchan:{self.advchan}"])

        if self.rssi is not None:
            args.extend(["-o", f"extcap.sniffle.rssi:{self.rssi}"])

        if self.mac is not None:
            args.extend(["-o", f"extcap.sniffle.mac:{self.mac}"])

        if self.irk is not None:
            args.extend(["-o", f"extcap.sniffle.irk:{self.irk}"])

        if self.string is not None:
            args.extend(["-o", f"extcap.sniffle.string:{self.string}"])

        if self.extadv:
            args.extend(["-o", "extcap.sniffle.extadv:true"])

        if self.longrange:
            args.extend(["-o", "extcap.sniffle.longrange:true"])

        if self.crcerr:
            args.extend(["-o", "extcap.sniffle.crcerr:true"])

        if self.display_filter:
            args.extend(["-Y", self.display_filter])

        args.extend(["-T", self.output_format])

        if self.line_buffered:
            args.append("-l")

        if self.extra_args:
            args.extend(self.extra_args)

        return args

    def to_shell_command(self, tshark_bin: str = "tshark") -> str:
        """Render shell-friendly command string with quoted options for debugging.

        Args:
            tshark_bin: Path or executable name for tshark.

        Returns:
            Formatted shell command string.
        """
        raw_args = self.to_command_args(tshark_bin)
        rendered: list[str] = []
        i = 0
        while i < len(raw_args):
            arg = raw_args[i]
            if arg == "-o" and i + 1 < len(raw_args):
                rendered.append(f'-o "{raw_args[i + 1]}"')
                i += 2
            elif " " in arg:
                rendered.append(f'"{arg}"')
                i += 1
            else:
                rendered.append(arg)
                i += 1
        return " ".join(rendered)


class TsharkExtcapRunner:
    """Manages the background execution of tshark capturing with Sniffle extcap."""

    def __init__(
        self,
        config: TsharkConfig,
        ring_buffer_size: int = 2000,
        tshark_bin: str = "tshark",
    ) -> None:
        """Initialize runner with given configuration and buffer size.

        Args:
            config: Extcap and tshark command options.
            ring_buffer_size: Maximum unconsumed lines retained in ring buffer.
            tshark_bin: Binary executable for tshark.
        """
        self.config: TsharkConfig = config
        self.ring_buffer_size: int = ring_buffer_size
        self.tshark_bin: str = tshark_bin

        self.ring_buffer: collections.deque[str] = collections.deque(maxlen=ring_buffer_size)
        self._stderr_buffer: collections.deque[str] = collections.deque(maxlen=500)
        self._lock: threading.RLock = threading.RLock()

        self._process: subprocess.Popen[str] | None = None
        self._worker_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stop_event: threading.Event = threading.Event()
        self._running: bool = False

        self._lines_read: int = 0
        self._bytes_read: int = 0
        self._errors_logged: int = 0

    @property
    def pid(self) -> int | None:
        """Return process ID of running tshark instance or None."""
        with self._lock:
            return self._process.pid if self._process else None

    def is_running(self) -> bool:
        """Check if subprocess and worker threads are actively running."""
        with self._lock:
            if not self._running or self._process is None:
                return False
            # Check if process unexpectedly exited
            ret = self._process.poll()
            if ret is not None:
                self._running = False
                return False
            return True

    def _ingest_line(self, line: str) -> None:
        """Add a raw line from stdout to the ring buffer.

        Args:
            line: Stripped or raw line string.
        """
        clean = line.strip()
        if not clean:
            return
        with self._lock:
            self.ring_buffer.append(clean)
            self._lines_read += 1
            self._bytes_read += len(clean)

    def _read_stdout_worker(self, proc: subprocess.Popen[str]) -> None:
        """Background thread reader for stdout."""
        try:
            if proc.stdout is None:
                return
            for line in proc.stdout:
                if self._stop_event.is_set():
                    break
                self._ingest_line(line)
        except Exception as exc:
            logger.debug("Tshark stdout worker ended: %s", exc)
        finally:
            with self._lock:
                if self._process == proc and proc.poll() is not None:
                    self._running = False

    def _read_stderr_worker(self, proc: subprocess.Popen[str]) -> None:
        """Background thread reader for stderr."""
        try:
            if proc.stderr is None:
                return
            for line in proc.stderr:
                clean = line.strip()
                if clean:
                    with self._lock:
                        self._stderr_buffer.append(clean)
                        self._errors_logged += 1
                if self._stop_event.is_set():
                    break
        except Exception as exc:
            logger.debug("Tshark stderr worker ended: %s", exc)

    def start(self) -> bool:
        """Spawn the tshark extcap subprocess and start background stream readers.

        Returns:
            True if process successfully started, False if already running.

        Raises:
            FileNotFoundError: If tshark binary is not found on host.
        """
        with self._lock:
            if self._running and self._process is not None and self._process.poll() is None:
                return False

            cmd = self.config.to_command_args(self.tshark_bin)
            logger.info("Starting tshark extcap runner: %s", " ".join(cmd))

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                )
            except FileNotFoundError as exc:
                self._running = False
                raise FileNotFoundError(
                    f"Tshark executable '{self.tshark_bin}' was not found on system PATH."
                ) from exc

            self._process = proc
            self._running = True
            self._stop_event.clear()

        # Start background stream reading threads
        self._worker_thread = threading.Thread(
            target=self._read_stdout_worker,
            args=(proc,),
            daemon=True,
            name=f"tshark-stdout-{self.config.serport}",
        )
        self._worker_thread.start()

        self._stderr_thread = threading.Thread(
            target=self._read_stderr_worker,
            args=(proc,),
            daemon=True,
            name=f"tshark-stderr-{self.config.serport}",
        )
        self._stderr_thread.start()

        return True

    def stop(self, timeout: float = 2.0) -> bool:
        """Terminate the tshark subprocess gracefully, escalating to SIGKILL if needed.

        Args:
            timeout: Maximum seconds to wait after SIGTERM before escalating to SIGKILL.

        Returns:
            True once process has halted.
        """
        with self._lock:
            proc = self._process
            if proc is None:
                self._running = False
                return True
            self._stop_event.set()

        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Tshark PID %d did not terminate on SIGTERM within %.2fs; escalating to SIGKILL.",
                    proc.pid,
                    timeout,
                )
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception as exc:
                    logger.error("Error killing tshark PID %d: %s", proc.pid, exc)
            except Exception as exc:
                logger.error("Error terminating tshark PID %d: %s", proc.pid, exc)

        # Close streams safely
        try:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        except Exception:
            pass

        try:
            if proc.stderr and not proc.stderr.closed:
                proc.stderr.close()
        except Exception:
            pass

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)

        if self._stderr_thread and self._stderr_thread.is_alive():
            self._stderr_thread.join(timeout=1.0)

        with self._lock:
            self._running = False
            self._process = None

        return True

    def drain_lines(self, max_count: int | None = None) -> list[str]:
        """Retrieve and remove buffered stdout lines in FIFO order without blocking.

        Args:
            max_count: Maximum lines to pop. If None, drains all current lines.

        Returns:
            List of popped string lines.
        """
        with self._lock:
            if max_count is None:
                lines = list(self.ring_buffer)
                self.ring_buffer.clear()
                return lines
            batch: list[str] = []
            for _ in range(min(max_count, len(self.ring_buffer))):
                batch.append(self.ring_buffer.popleft())
            return batch

    def pop_line(self) -> str | None:
        """Pop the oldest line from the ring buffer.

        Returns:
            String line or None if buffer is empty.
        """
        with self._lock:
            if self.ring_buffer:
                return self.ring_buffer.popleft()
            return None

    def get_metrics(self) -> dict[str, Any]:
        """Return operational metrics for monitoring and dashboard display.

        Returns:
            Dictionary containing running status, counters, and buffer size.
        """
        with self._lock:
            return {
                "running": self.is_running(),
                "pid": self._process.pid if self._process else None,
                "lines_read": self._lines_read,
                "bytes_read": self._bytes_read,
                "buffer_size": len(self.ring_buffer),
                "errors_logged": self._errors_logged,
                "port": self.config.serport,
                "channel": self.config.advchan,
            }

    def get_stderr_logs(self) -> list[str]:
        """Return a snapshot of recent stderr log lines.

        Returns:
            List of recent stderr lines.
        """
        with self._lock:
            return list(self._stderr_buffer)

    def __enter__(self) -> TsharkExtcapRunner:
        """Start process upon entering context."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Halt process upon exiting context."""
        self.stop()
