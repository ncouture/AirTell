#!/usr/bin/env python
#

"""BLE Anti-Stalking Tracker & Multi-Channel Offline Finding Logger.

Interfaces with Sniffle-enabled CC2652P USB dongles (via CLI output or direct serial/mock stream),
classifies crowdsourced tracking networks (Apple Find My, Google Find Hub, Tile, Samsung SmartThings Find),
extracts rotating ephemeral public keys, records observations into SQLite, and provides
sliding-window heuristics and alert dispatching (including optional Twilio SMS / Desktop notifications).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()  # project root's .env

logger = logging.getLogger("airtell.tracker")


# Concurrency guard to prevent thread starvation under heavy burst loads
_DISPATCH_SEMAPHORE = threading.BoundedSemaphore(value=16)


def format_webhook_payload(alert_data: Any) -> dict[str, Any]:
    """Formats an alert dictionary or string into a standardized JSON-serializable webhook payload.

    Schema conforms to:
    - timestamp (unix float) and timestamp_iso (ISO 8601 UTC string)
    - tracker_id (ephemeral public key fragment or MAC address)
    - network_type (Apple Find My, Google Find Hub, Tile, etc.)
    - packet_count (int)
    - duration and duration_seconds (float, in seconds)
    - max_rssi (int, in dBm)
    - mean_rssi and avg_rssi (float, in dBm)
    - alert_level (HIGH or CRITICAL)
    - alert_message (human-readable string summary)
    """
    now = time.time()
    if not isinstance(alert_data, dict):
        msg = str(alert_data or "")
        return {
            "timestamp": now,
            "timestamp_iso": datetime.now(tz=timezone.utc).isoformat(),
            "tracker_id": "Unknown",
            "network_type": "Unknown",
            "packet_count": 0,
            "duration": 0.0,
            "duration_seconds": 0.0,
            "max_rssi": 0,
            "mean_rssi": 0.0,
            "avg_rssi": 0.0,
            "alert_level": "HIGH",
            "alert_message": msg,
        }

    def _safe_float(val: Any, default: float = 0.0) -> float:
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def _safe_int(val: Any, default: int = 0) -> int:
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _safe_str(val: Any, default: str = "") -> str:
        if val is None:
            return default
        s = str(val).strip()
        return s if s else default

    raw_ts = alert_data.get("timestamp")
    ts = _safe_float(raw_ts, now)
    try:
        iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        iso_ts = datetime.now(tz=timezone.utc).isoformat()

    first_s = _safe_float(alert_data.get("first_seen"), ts)
    last_s = _safe_float(alert_data.get("last_seen"), ts)

    raw_dur = alert_data.get("duration")
    if raw_dur is None:
        raw_dur = alert_data.get("duration_seconds")
    if raw_dur is None:
        raw_dur = max(0.0, last_s - first_s)
    duration_sec = max(0.0, _safe_float(raw_dur, 0.0))

    raw_id = alert_data.get("identifier")
    if raw_id is None:
        raw_id = alert_data.get("tracker_id")
    tracker_id = _safe_str(raw_id, "Unknown")

    net_type = _safe_str(alert_data.get("network_type"), "Unknown")

    raw_count = alert_data.get("observation_count")
    if raw_count is None:
        raw_count = alert_data.get("packet_count")
    pkt_count = _safe_int(raw_count, 0)

    max_r = _safe_int(alert_data.get("max_rssi"), 0)

    raw_mean = alert_data.get("avg_rssi")
    if raw_mean is None:
        raw_mean = alert_data.get("mean_rssi")
    mean_r = _safe_float(raw_mean, 0.0)

    raw_level = alert_data.get("alert_level")
    if raw_level is not None and str(raw_level).strip():
        alert_lvl = str(raw_level).strip()
    else:
        alert_lvl = "CRITICAL" if max_r >= -60 else "HIGH"

    alert_msg = _safe_str(alert_data.get("alert_message"), "")

    return {
        "timestamp": ts,
        "timestamp_iso": iso_ts,
        "tracker_id": tracker_id,
        "network_type": net_type,
        "packet_count": pkt_count,
        "duration": round(duration_sec, 2),
        "duration_seconds": round(duration_sec, 2),
        "max_rssi": max_r,
        "mean_rssi": round(mean_r, 2),
        "avg_rssi": round(mean_r, 2),
        "alert_level": alert_lvl,
        "alert_message": alert_msg,
    }


def dispatch_webhook_alert(
    alert_data: dict[str, Any] | str,
    webhook_url: str,
    secret: Optional[str] = None,
    timeout: float = 5.0,
    headers: Optional[dict[str, str]] = None,
    async_dispatch: bool = False,
) -> bool:
    """Dispatches a structured JSON threat alert to an external HTTP webhook endpoint.

    Args:
        alert_data: Dictionary or string containing tracker alert details.
        webhook_url: Target HTTP/HTTPS endpoint URL.
        secret: Optional secret for HMAC-SHA256 signing (X-Signature-SHA256) and Bearer auth.
        timeout: Request timeout in seconds (default 5.0).
        headers: Additional HTTP headers to include.
        async_dispatch: If True, dispatch request asynchronously in a daemon thread.

    Returns:
        True if dispatched successfully (or dispatched asynchronously), False otherwise.
    """
    if not webhook_url:
        return False

    payload = format_webhook_payload(alert_data)
    payload_json = json.dumps(payload, sort_keys=True, default=str)
    payload_bytes = payload_json.encode("utf-8")

    req_headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "AirTell-Tracker/0.2.0",
    }

    if secret:
        secret_str = secret if isinstance(secret, str) else str(secret)
        sig = hmac.new(secret_str.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        req_headers["X-Signature-SHA256"] = sig
        req_headers["Authorization"] = f"Bearer {secret_str}"

    if headers:
        req_headers.update(headers)

    def _send() -> bool:
        try:
            req = urllib.request.Request(
                url=webhook_url,
                data=payload_bytes,
                headers=req_headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                if 200 <= code < 300:
                    logger.info("Webhook alert posted successfully to %s (HTTP %d)", webhook_url, code)
                    return True
                logger.warning("Webhook alert to %s returned HTTP status %d", webhook_url, code)
                return False
        except urllib.error.HTTPError as http_err:
            logger.error(
                "Failed to post webhook alert to %s: HTTP %d %s",
                webhook_url,
                http_err.code,
                http_err.reason,
            )
            return False
        except (urllib.error.URLError, TimeoutError) as net_err:
            logger.error(
                "Network connection error posting webhook alert to %s: %s",
                webhook_url,
                net_err,
            )
            return False
        except Exception as exc:
            logger.error("Failed to post webhook alert to %s: %s", webhook_url, exc)
            return False

    if async_dispatch:
        def _async_webhook_worker() -> None:
            if not _DISPATCH_SEMAPHORE.acquire(blocking=False):
                logger.warning("Dispatcher concurrency limit reached; dropping excess webhook alert.")
                return
            try:
                _send()
            finally:
                _DISPATCH_SEMAPHORE.release()

        thread = threading.Thread(
            target=_async_webhook_worker,
            name="AirTell-Webhook-Dispatcher",
            daemon=True,
        )
        thread.start()
        return True

    return _send()


def dispatch_desktop_notification(
    alert_data: dict[str, Any] | str,
    title: Optional[str] = None,
    system_override: Optional[str] = None,
    async_dispatch: bool = False,
) -> bool:
    """Dispatches a native cross-platform OS desktop notification.

    Supports:
      - Linux: notify-send
      - macOS: osascript
      - Windows: PowerShell or ctypes MessageBox

    Gracefully falls back when running in headless environments or when platform binaries
    are unavailable.

    Args:
        alert_data: Alert dict or text message.
        title: Notification title override.
        system_override: Optional platform string ('linux', 'darwin', 'windows') for testing.
        async_dispatch: If True, spawn notification delivery in a background daemon thread.

    Returns:
        True if notification was launched successfully, False on failure or fallback.
    """
    def _safe_str(val: Any, default: str = "") -> str:
        if val is None:
            return default
        s = str(val).strip()
        return s if s else default

    def _safe_int(val: Any, default: int = 0) -> int:
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _safe_float(val: Any, default: float = 0.0) -> float:
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    if isinstance(alert_data, dict):
        level = _safe_str(alert_data.get("alert_level"), "HIGH")
        net = _safe_str(alert_data.get("network_type"), "BLE Device")
        raw_count = alert_data.get("observation_count")
        if raw_count is None:
            raw_count = alert_data.get("packet_count")
        count = _safe_int(raw_count, 0)

        raw_dur = alert_data.get("duration")
        if raw_dur is None:
            raw_dur = alert_data.get("duration_seconds")
        dur_sec = max(0.0, _safe_float(raw_dur, 0.0))
        dur_min = dur_sec / 60.0

        max_r_val = alert_data.get("max_rssi")
        max_r = _safe_int(max_r_val, 0) if max_r_val is not None else "N/A"

        raw_id = alert_data.get("identifier")
        if raw_id is None:
            raw_id = alert_data.get("tracker_id")
        ident = _safe_str(raw_id, "Unknown")
        short_id = ident[:16]

        notif_title = title or f"🚨 AirTell Alert: {level} Threat"
        notif_body = (
            alert_data.get("alert_message")
            or f"{net} ({short_id}...) seen {count} times over {dur_min:.1f} mins (Max RSSI: {max_r} dBm)"
        )
    else:
        notif_title = title or "🚨 AirTell Anti-Stalking Alert"
        notif_body = str(alert_data or "")

    # Sanitize title and body
    notif_title = str(notif_title).replace("\0", "")
    notif_body = str(notif_body).replace("\0", "")

    def _deliver() -> bool:
        plat = (system_override or sys.platform).lower()
        try:
            if plat.startswith("linux"):
                if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
                    logger.warning("Headless environment detected; skipping notify-send.")
                    return False
                binary = shutil.which("notify-send")
                if not binary:
                    logger.warning("notify-send executable not found; skipping desktop notification.")
                    return False
                cmd = [binary, "-u", "critical", notif_title, notif_body]
                res = subprocess.run(cmd, capture_output=True, timeout=5.0, check=True)
                return res.returncode == 0
            elif plat == "darwin":
                binary = shutil.which("osascript")
                if not binary:
                    logger.warning("osascript executable not found; skipping desktop notification.")
                    return False
                clean_title = notif_title.replace("\r", " ").replace("\n", " ")
                clean_body = notif_body.replace("\r", " ").replace("\n", " ")
                safe_title = clean_title.replace("\\", "\\\\").replace('"', '\\"')
                safe_body = clean_body.replace("\\", "\\\\").replace('"', '\\"')
                script = f'display notification "{safe_body}" with title "{safe_title}"'
                res = subprocess.run([binary, "-e", script], capture_output=True, timeout=5.0, check=True)
                return res.returncode == 0
            elif plat.startswith("win"):
                ps_bin = shutil.which("powershell") or shutil.which("powershell.exe")
                if ps_bin:
                    clean_title = notif_title.replace("\r", " ").replace("\n", " ")
                    clean_body = notif_body.replace("\r", " ").replace("\n", " ")
                    safe_title = clean_title.replace("'", "''")
                    safe_body = clean_body.replace("'", "''")
                    ps_script = (
                        f"[reflection.assembly]::loadwithpartialname('System.Windows.Forms'); "
                        f"[System.Windows.Forms.MessageBox]::Show('{safe_body}', '{safe_title}', 0, 48)"
                    )
                    res = subprocess.run(
                        [ps_bin, "-NoProfile", "-Command", ps_script],
                        capture_output=True,
                        timeout=5.0,
                        check=True,
                    )
                    return res.returncode == 0
                else:
                    if sys.platform.startswith("win"):
                        import ctypes

                        try:
                            ctypes.windll.user32.MessageBoxTimeoutW(0, notif_body, notif_title, 0x30, 0, 5000)
                        except Exception:
                            ctypes.windll.user32.MessageBoxW(0, notif_body, notif_title, 0x30)
                        return True
                    logger.warning("PowerShell not found and host is not Windows; cannot display notification.")
                    return False
            else:
                logger.warning("Unsupported desktop notification platform: %s", plat)
                return False
        except Exception as exc:
            logger.error("Failed to dispatch desktop notification: %s", exc)
            return False

    if async_dispatch:
        def _async_desktop_worker() -> None:
            if not _DISPATCH_SEMAPHORE.acquire(blocking=False):
                logger.warning("Dispatcher concurrency limit reached; dropping excess desktop notification.")
                return
            try:
                _deliver()
            finally:
                _DISPATCH_SEMAPHORE.release()

        thread = threading.Thread(
            target=_async_desktop_worker,
            name="AirTell-Desktop-Dispatcher",
            daemon=True,
        )
        thread.start()
        return True

    return _deliver()


class BLETrackerDB:
    """Thread-safe SQLite and DuckDB database manager for BLE observations and anti-stalking alerts."""

    def __init__(
        self,
        db_path: str,
        webhook_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        enable_desktop_notify: Optional[bool] = None,
        backend_type: Optional[str] = None,
        enable_duckdb: Optional[bool] = None,
    ) -> None:
        self.db_path = db_path
        self.webhook_url = webhook_url if webhook_url is not None else os.getenv("WEBHOOK_URL", "")
        self.webhook_secret = webhook_secret if webhook_secret is not None else os.getenv("WEBHOOK_SECRET", "")
        if enable_desktop_notify is not None:
            self.enable_desktop_notify = enable_desktop_notify
        else:
            self.enable_desktop_notify = os.getenv("DESKTOP_NOTIFY", "").strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        self.init_db()

        self.duckdb_backend: Optional[Any] = None
        self._sqlite_backend: Optional[Any] = None
        if enable_duckdb is not None:
            self.enable_duckdb = enable_duckdb
        elif backend_type is not None:
            self.enable_duckdb = backend_type.lower() in ("duckdb", "duck", "auto")
        else:
            env_val = os.getenv("DATABASE_BACKEND", os.getenv("AIRTELL_DB_BACKEND", "")).lower()
            if env_val:
                self.enable_duckdb = env_val in ("duckdb", "duck", "auto")
            else:
                self.enable_duckdb = os.getenv("AIRTELL_DUCKDB_ACCELERATION", "1").lower() in (
                    "1",
                    "true",
                    "yes",
                    "on",
                )

        if self.enable_duckdb:
            self.attach_duckdb()

    def attach_duckdb(self, threads: Optional[int] = None, memory_limit: Optional[str] = None) -> bool:
        """Attach DuckDB vectorized engine to accelerate analytical queries."""
        if threads is None:
            try:
                threads = int(os.getenv("DUCKDB_THREADS", "4"))
            except ValueError:
                threads = 4
        if memory_limit is None:
            memory_limit = os.getenv("DUCKDB_MEMORY_LIMIT", "2GB")

        try:
            from airtell.telemetry.storage import DuckDBBackend

            self.duckdb_backend = DuckDBBackend(self.db_path, threads=threads, memory_limit=memory_limit)
            self.enable_duckdb = True
            return True
        except Exception as e:
            logger.debug("DuckDB backend attachment not enabled: %s", e)
            self.duckdb_backend = None
            self.enable_duckdb = False
            return False

    def disable_duckdb(self) -> None:
        """Disable DuckDB acceleration and fall back strictly to SQLite."""
        if self.duckdb_backend:
            try:
                self.duckdb_backend.close()
            except Exception:
                pass
            self.duckdb_backend = None
        self.enable_duckdb = False

    def close(self) -> None:
        """Close and release database backends."""
        self.disable_duckdb()
        if self._sqlite_backend is not None:
            try:
                self._sqlite_backend.close()
            except Exception:
                pass
            self._sqlite_backend = None

    @property
    def backend(self) -> Any:
        if self.enable_duckdb and self.duckdb_backend is not None:
            return self.duckdb_backend
        if self._sqlite_backend is None:
            from airtell.telemetry.storage import SQLiteBackend

            self._sqlite_backend = SQLiteBackend(self.db_path)
        return self._sqlite_backend

    def get_observations(
        self,
        limit: int = 1000,
        network_type: Optional[str] = None,
        search_query: Optional[str] = None,
        channel: Optional[int] = None,
        min_rssi: Optional[int] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        as_df: bool = False,
    ) -> Any:
        """Query observation records using accelerated backend."""
        return self.backend.get_observations(
            limit=limit,
            network_type=network_type,
            search_query=search_query,
            channel=channel,
            min_rssi=min_rssi,
            start_time=start_time,
            end_time=end_time,
            as_df=as_df,
        )

    def get_rssi_timeseries(
        self,
        network_types: Optional[list[str]] = None,
        min_rssi: Optional[int] = None,
        limit: int = 2000,
        as_df: bool = False,
    ) -> Any:
        """Retrieve chronological RSSI time series using accelerated backend."""
        return self.backend.get_rssi_timeseries(
            network_types=network_types,
            min_rssi=min_rssi,
            limit=limit,
            as_df=as_df,
        )

    def get_channel_distribution(self) -> dict[int, int]:
        """Compute packet observation count distribution across BLE channels."""
        return self.backend.get_channel_distribution()

    def get_tracker_frequencies(
        self,
        min_count: int = 1,
        limit: int = 100,
        as_df: bool = False,
    ) -> Any:
        """Aggregate tracker observation counts, signal stats, and time spans."""
        return self.backend.get_tracker_frequencies(
            min_count=min_count,
            limit=limit,
            as_df=as_df,
        )

    def get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10.0)


    def init_db(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Table for raw observations
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    datetime_str TEXT,
                    mac_address TEXT,
                    rssi INTEGER,
                    network_type TEXT,
                    ephemeral_key TEXT,
                    channel INTEGER,
                    raw_payload TEXT
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_obs_time ON observations (timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_obs_key ON observations (ephemeral_key)"
            )

            # Table for anti-stalking alerts
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    datetime_str TEXT,
                    identifier TEXT,
                    network_type TEXT,
                    observation_count INTEGER,
                    first_seen REAL,
                    last_seen REAL,
                    max_rssi INTEGER,
                    alert_message TEXT
                )
                """
            )

            # Table for whitelisted identifiers (ephemeral keys or MACs)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier_type TEXT NOT NULL,
                    identifier_value TEXT NOT NULL,
                    notes TEXT,
                    created_at REAL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_whitelist_val ON whitelists (identifier_value)"
            )

            # Table for analyst alert actions and incident notes
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER,
                    action_type TEXT NOT NULL,
                    analyst_note TEXT,
                    timestamp REAL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_action_alert ON alert_actions (alert_id)"
            )
            conn.commit()

    def insert_observation(
        self,
        mac_address: str,
        rssi: int,
        network_type: str,
        ephemeral_key: str,
        channel: int = 37,
        raw_payload: str = "",
        timestamp: Optional[float] = None,
    ) -> int:
        """Insert an observation record and return its row ID."""
        now = time.time() if timestamp is None else timestamp
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO observations (timestamp, datetime_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    dt_str,
                    mac_address,
                    rssi,
                    network_type,
                    ephemeral_key,
                    channel,
                    raw_payload,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def log_observation(
        self,
        mac_address: str,
        rssi: int,
        network_type: str,
        ephemeral_key: str,
        channel: int,
        raw_payload: str,
    ) -> None:
        self.insert_observation(
            mac_address=mac_address,
            rssi=rssi,
            network_type=network_type,
            ephemeral_key=ephemeral_key,
            channel=channel,
            raw_payload=raw_payload,
        )

    def log_alert(
        self,
        identifier: str,
        network_type: str,
        count: int,
        max_rssi: int,
        message: str,
        first_seen: Optional[float] = None,
        last_seen: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> int:
        """Insert an alert record and return its row ID."""
        now = time.time() if timestamp is None else timestamp
        f_seen = now if first_seen is None else first_seen
        l_seen = now if last_seen is None else last_seen
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (timestamp, datetime_str, identifier, network_type, observation_count, first_seen, last_seen, max_rssi, alert_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    dt_str,
                    identifier,
                    network_type,
                    count,
                    f_seen,
                    l_seen,
                    max_rssi,
                    message,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def add_whitelist(
        self, identifier_type: str, identifier_value: str, notes: str = ""
    ) -> int:
        """Add an identifier to the whitelist."""
        now = time.time()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO whitelists (identifier_type, identifier_value, notes, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (identifier_type, identifier_value.strip(), notes.strip(), now),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def is_whitelisted(self, identifier_type: str, identifier_value: str) -> bool:
        """Check if an identifier is whitelisted (case-insensitive)."""
        val_clean = identifier_value.strip().lower()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM whitelists
                WHERE identifier_type = ? AND LOWER(identifier_value) = ?
                """,
                (identifier_type, val_clean),
            )
            count = cursor.fetchone()[0]
            if count > 0:
                return True
            # Also check if value matches without identifier_type filter
            cursor.execute(
                """
                SELECT COUNT(*) FROM whitelists
                WHERE LOWER(identifier_value) = ?
                """,
                (val_clean,),
            )
            return cursor.fetchone()[0] > 0

    def get_whitelists(self) -> list[dict[str, Any]]:
        """Return all whitelisted identifiers."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, identifier_type, identifier_value, notes, created_at FROM whitelists ORDER BY id DESC"
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "identifier_type": r[1],
                    "identifier_value": r[2],
                    "notes": r[3],
                    "created_at": r[4],
                }
                for r in rows
            ]

    def remove_whitelist(self, whitelist_id: int) -> bool:
        """Delete an identifier from the whitelist by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM whitelists WHERE id = ?", (whitelist_id,))
            conn.commit()
            return cursor.rowcount > 0

    def record_alert_action(
        self, alert_id: int, action_type: str, analyst_note: str = ""
    ) -> int:
        """Record an analyst triage action or note on an alert."""
        now = time.time()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alert_actions (alert_id, action_type, analyst_note, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (alert_id, action_type, analyst_note.strip(), now),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_alert_actions(
        self, alert_id: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Retrieve recorded actions for a specific alert or all alerts."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if alert_id is not None:
                cursor.execute(
                    "SELECT id, alert_id, action_type, analyst_note, timestamp FROM alert_actions WHERE alert_id = ? ORDER BY id DESC",
                    (alert_id,),
                )
            else:
                cursor.execute(
                    "SELECT id, alert_id, action_type, analyst_note, timestamp FROM alert_actions ORDER BY id DESC"
                )
            rows = cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "alert_id": r[1],
                    "action_type": r[2],
                    "analyst_note": r[3],
                    "timestamp": r[4],
                }
                for r in rows
            ]

    def check_stalking_thresholds(
        self,
        window_seconds: int = 900,
        min_observations: int = 5,
        min_time_span: int = 300,
    ) -> list[str]:
        """Analyzes recent observations to detect persistent BLE tracking beacons.

        Args:
            window_seconds: Trailing window to evaluate (default 15 mins = 900s).
            min_observations: Minimum packet count required to trigger alert.
            min_time_span: Minimum duration device must be observed (default 5 mins = 300s).
        """
        now = time.time()
        cutoff = now - window_seconds

        query = """
            SELECT
                COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id,
                network_type,
                COUNT(*) as pkt_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                MAX(rssi) as max_rssi,
                AVG(rssi) as avg_rssi
            FROM observations
            WHERE timestamp >= ? AND network_type != 'Unknown'
            GROUP BY tracker_id, network_type
            HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?
        """
        results = None
        if self.enable_duckdb and self.duckdb_backend is not None:
            try:
                with getattr(self.duckdb_backend, "_lock", threading.RLock()):
                    results = self.duckdb_backend.con.execute(query, [cutoff, min_observations, min_time_span]).fetchall()
            except Exception as e:
                logger.debug("DuckDB query failed (%s), falling back to SQLite", e)
                results = None

        with self.get_connection() as conn:
            cursor = conn.cursor()
            if results is None:
                cursor.execute(query, (cutoff, min_observations, min_time_span))
                results = cursor.fetchall()

            alerts: list[str] = []
            for row in results:
                tracker_id, net_type, count, first_s, last_s, max_r, avg_r = row
                # Suppress whitelisted identifiers
                if self.is_whitelisted("ephemeral_key", tracker_id) or self.is_whitelisted("mac_address", tracker_id):
                    continue


                duration_min = (last_s - first_s) / 60.0

                # Suppress duplicate alerts for same tracker within 5 minutes
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM alerts
                    WHERE identifier = ? AND timestamp >= ?
                    """,
                    (tracker_id, now - 300),
                )
                recent_alert_count = cursor.fetchone()[0]

                if recent_alert_count == 0:
                    msg = (
                        f"POSSIBLE STALKER DETECTED: {net_type} beacon"
                        f" ({tracker_id[:16]}...) seen {count} times over"
                        f" {duration_min:.1f} mins (Max RSSI: {max_r} dBm)"
                    )
                    dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute(
                        """
                        INSERT INTO alerts (timestamp, datetime_str, identifier, network_type, observation_count, first_seen, last_seen, max_rssi, alert_message)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            now,
                            dt_str,
                            tracker_id,
                            net_type,
                            count,
                            first_s,
                            last_s,
                            max_r,
                            msg,
                        ),
                    )
                    alerts.append(msg)
            conn.commit()
            return alerts

    def check_stalking_heuristics(
        self,
        window_minutes: int = 15,
        min_observations: int = 5,
        min_duration_minutes: int = 5,
        webhook_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        enable_desktop_notify: Optional[bool] = None,
        cooldown_seconds: int = 300,
        deduplicate: bool = True,
        async_dispatch: bool = True,
    ) -> list[dict[str, Any]]:
        """Analyzes recent observations and returns threat alert dictionaries.

        Suppresses alerts for whitelisted devices and keys. Hooks into webhook
        and desktop notification dispatchers with cooldown deduplication.
        """
        now = time.time()
        window_seconds = window_minutes * 60
        min_time_span = min_duration_minutes * 60
        cutoff = now - window_seconds

        effective_url = webhook_url if webhook_url is not None else self.webhook_url
        effective_secret = webhook_secret if webhook_secret is not None else self.webhook_secret
        effective_desktop = enable_desktop_notify if enable_desktop_notify is not None else self.enable_desktop_notify

        query = """
            SELECT
                COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id,
                network_type,
                COUNT(*) as pkt_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                MAX(rssi) as max_rssi,
                AVG(rssi) as avg_rssi
            FROM observations
            WHERE timestamp >= ? AND network_type != 'Unknown'
            GROUP BY tracker_id, network_type
            HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?
        """
        results = None
        if self.enable_duckdb and self.duckdb_backend is not None:
            try:
                with getattr(self.duckdb_backend, "_lock", threading.RLock()):
                    results = self.duckdb_backend.con.execute(query, [cutoff, min_observations, min_time_span]).fetchall()
            except Exception as e:
                logger.debug("DuckDB query failed (%s), falling back to SQLite", e)
                results = None

        with self.get_connection() as conn:
            cursor = conn.cursor()
            if results is None:
                cursor.execute(query, (cutoff, min_observations, min_time_span))
                results = cursor.fetchall()

            alerts: list[dict[str, Any]] = []
            for row in results:
                tracker_id, net_type, count, first_s, last_s, max_r, avg_r = row
                if self.is_whitelisted("ephemeral_key", tracker_id) or self.is_whitelisted("mac_address", tracker_id):
                    continue


                duration_sec = max(0.0, float(last_s - first_s))
                duration_min = duration_sec / 60.0
                alert_lvl = "CRITICAL" if max_r >= -60 else "HIGH"
                msg = (
                    f"POSSIBLE STALKER DETECTED: {net_type} beacon"
                    f" ({tracker_id[:16]}...) seen {count} times over"
                    f" {duration_min:.1f} mins (Max RSSI: {max_r} dBm)"
                )

                # Check cooldown window against alerts table
                if cooldown_seconds > 0:
                    cursor.execute(
                        """
                        SELECT COUNT(*) FROM alerts
                        WHERE identifier = ? AND timestamp > ?
                        """,
                        (tracker_id, now - cooldown_seconds),
                    )
                    recent_alert_count = cursor.fetchone()[0]
                    is_in_cooldown = recent_alert_count > 0
                else:
                    is_in_cooldown = False

                if is_in_cooldown and deduplicate:
                    continue

                avg_val = round(float(avg_r), 2) if avg_r is not None else 0.0
                alert_dict: dict[str, Any] = {
                    "identifier": tracker_id,
                    "tracker_id": tracker_id,
                    "network_type": net_type,
                    "observation_count": count,
                    "packet_count": count,
                    "first_seen": first_s,
                    "last_seen": last_s,
                    "duration": round(duration_sec, 2),
                    "duration_seconds": round(duration_sec, 2),
                    "max_rssi": max_r,
                    "avg_rssi": avg_val,
                    "mean_rssi": avg_val,
                    "alert_level": alert_lvl,
                    "alert_message": msg,
                    "in_cooldown": is_in_cooldown,
                }

                if not is_in_cooldown:
                    dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute(
                        """
                        INSERT INTO alerts (timestamp, datetime_str, identifier, network_type, observation_count, first_seen, last_seen, max_rssi, alert_message)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            now,
                            dt_str,
                            tracker_id,
                            net_type,
                            count,
                            first_s,
                            last_s,
                            max_r,
                            msg,
                        ),
                    )
                    if effective_url:
                        dispatch_webhook_alert(
                            alert_dict,
                            webhook_url=effective_url,
                            secret=effective_secret,
                            async_dispatch=async_dispatch,
                        )
                    if effective_desktop:
                        dispatch_desktop_notification(
                            alert_dict,
                            async_dispatch=async_dispatch,
                        )

                alerts.append(alert_dict)
            conn.commit()
            return alerts


class SniffleLineParser:
    """Stateful multi-line parser for sniff_receiver.py stdout.

    Sniffle outputs each packet across several lines:
      1. Header:  ``Timestamp: ...  RSSI: -65  Channel: 37  ...``
      2. Decode:  ``AdvA: AA:BB:CC:DD:EE:FF (Static)`` (for advertising packets)
      3. Hexdump: ``0x0000:  02 01 06 ...``  (one or more lines)
      4. A blank line separating packets.

    The parser accumulates fields across lines and yields a complete
    ``(mac, rssi, payload_hex)`` tuple once the next packet header or a
    blank separator line is encountered.
    """

    # Header line produced by PacketMessage.str_header()
    _RE_HEADER = re.compile(r"RSSI:\s*(-?\d+)")
    # AdvA line produced by AdvaMessage.str_adva() / AdvExtIndMessage
    _RE_ADVA = re.compile(r"AdvA:\s*([0-9A-Fa-f:]{17})")
    # Hexdump lines produced by hexdump.hexdump()  e.g. "0x0000:  02 01 06 ...  .....L.."
    _RE_HEXLINE = re.compile(r"^0x[0-9A-Fa-f]{4}:\s{2}")

    def __init__(self) -> None:
        self._rssi: Optional[int] = None
        self._mac: Optional[str] = None
        self._hex_parts: list[str] = []

    def _flush(self) -> Optional[tuple[str, int, str]]:
        """Return a parsed result if we have all three components, then reset."""
        result: Optional[tuple[str, int, str]] = None
        if self._mac is not None and self._rssi is not None and self._hex_parts:
            payload_hex = "".join(self._hex_parts).lower()
            result = (self._mac, self._rssi, payload_hex)
        self._rssi = None
        self._mac = None
        self._hex_parts = []
        return result

    def feed(self, line: str) -> Optional[tuple[str, int, str]]:
        """Feed one stdout line; returns a parsed tuple when a packet is complete."""
        stripped = line.strip()

        # Blank / separator line → flush any accumulated packet
        if not stripped:
            return self._flush()

        # Comment or debug lines
        if stripped.startswith("#"):
            return None

        # --- Header line (starts a new packet) ---
        hdr = self._RE_HEADER.search(stripped)
        if hdr and "Timestamp:" in stripped:
            # A new header means the previous packet (if any) is complete
            result = self._flush()
            self._rssi = int(hdr.group(1))
            return result

        # --- AdvA line ---
        adva = self._RE_ADVA.search(stripped)
        if adva:
            self._mac = adva.group(1).upper()
            return None

        # --- Hexdump line ---
        hexm = self._RE_HEXLINE.match(stripped)
        if hexm:
            # Everything after "0xNNNN:  " up to the ASCII printable column.
            # The ASCII column is separated from hex bytes by two+ spaces
            # after the last hex byte.  Split off the "0xNNNN:  " prefix,
            # then take only [0-9a-fA-F] characters.
            after_prefix = stripped[hexm.end():]
            hex_only = re.sub(r"[^0-9A-Fa-f]", "", after_prefix.split("  ")[0])
            # Handle the second group (if present) separated by double-space
            parts = after_prefix.split("  ")
            hex_only = ""
            for part in parts:
                candidate = re.sub(r"[^0-9A-Fa-f]", "", part)
                # Stop when we hit the ASCII column (contains non-hex chars
                # and is much shorter as hex after stripping)
                if part and all(c in '0123456789abcdefABCDEF ' for c in part.strip()):
                    hex_only += candidate
                else:
                    break
            self._hex_parts.append(hex_only)
            return None

        return None


# Module-level parser instance used by parse_sniffle_line so the
# existing call-site in main() keeps working without changes.
_parser = SniffleLineParser()


def parse_sniffle_line(line: str) -> Optional[tuple[str, int, str]]:
    """Parses output lines from sniff_receiver stdout.

    Accumulates multi-line Sniffle output and returns a ``(mac, rssi,
    payload_hex)`` tuple once a complete advertising packet has been
    collected.  Returns ``None`` for intermediate / non-matching lines.
    """
    return _parser.feed(line)


def classify_payload(payload_hex: str) -> tuple[str, str]:
    """Classifies BLE advertising payload and extracts ephemeral key identifier."""
    payload_lower = payload_hex.lower()

    # Apple Find My: Manufacturer ID 0x004C (4c00), Type 0x12, Length 0x19
    if "4c001219" in payload_lower:
        idx = payload_lower.find("4c001219")
        # 22-byte (44 hex chars) ephemeral public key payload
        ephemeral_key = payload_lower[idx + 8 : idx + 8 + 44]
        return "Apple Find My", ephemeral_key

    # Google Fast Pair / Find Hub Service UUID 0xFE9F
    elif "fe9f" in payload_lower:
        idx = payload_lower.find("fe9f")
        ephemeral_key = payload_lower[idx : idx + 40]
        return "Google Find Hub", ephemeral_key

    # Tile Service UUID 0xFEED
    elif "feed" in payload_lower:
        idx = payload_lower.find("feed")
        ephemeral_key = payload_lower[idx : idx + 32]
        return "Tile Tracker", ephemeral_key

    # Samsung SmartThings Find (Manufacturer ID 0x0075)
    elif "7500" in payload_lower:
        idx = payload_lower.find("7500")
        ephemeral_key = payload_lower[idx : idx + 32]
        return "Samsung SmartThings Find", ephemeral_key

    return "Unknown", ""


def send_notification(
    alert_message: str | dict[str, Any],
    twilio_config: Optional[dict[str, str]] = None,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    enable_desktop_notify: bool = False,
) -> None:
    """Dispatches notification via Twilio SMS, Webhook, and/or Desktop notification."""
    if isinstance(alert_message, dict):
        msg_str = str(alert_message.get("alert_message") or "")
        alert_payload: dict[str, Any] | str = alert_message
    else:
        msg_str = str(alert_message or "")
        alert_payload = {"alert_message": msg_str}

    # Twilio SMS dispatch if credentials provided
    if twilio_config and twilio_config.get("account_sid") and twilio_config.get("auth_token"):
        try:
            from twilio.rest import Client

            client = Client(twilio_config["account_sid"], twilio_config["auth_token"])
            client.messages.create(
                body=f"🚨 [BLE Anti-Stalking Alert]\n{msg_str}",
                from_=twilio_config["from_number"],
                to=twilio_config["to_number"],
            )
            print(f"[+] SMS notification dispatched to {twilio_config['to_number']}.")
        except Exception as exc:
            print(f"[-] Twilio SMS dispatch failed: {exc}", file=sys.stderr)

    if webhook_url:
        dispatch_webhook_alert(
            alert_payload,
            webhook_url=webhook_url,
            secret=webhook_secret,
            async_dispatch=True,
        )

    if enable_desktop_notify:
        dispatch_desktop_notification(alert_message, async_dispatch=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BLE Anti-Stalking Tracker & SQLite Logger"
    )
    parser.add_argument(
        "-s",
        "--serial-port",
        default="/dev/ttyUSB0",
        help="Serial port for Sniffle dongle",
    )
    parser.add_argument(
        "-c", "--channel", type=int, default=37, help="BLE Advertising channel (37, 38, 39)"
    )
    parser.add_argument(
        "-db", "--database", type=str, default=os.environ.get("DATABASE", ""),
        help="Database connection string (only sqlite supported at the moment)"
    )
    parser.add_argument(
        "--twilio-sid", default=os.getenv("TWILIO_ACCOUNT_SID"), help="Twilio Account SID (or env)"
    )
    parser.add_argument(
        "--twilio-token", default=os.getenv("TWILIO_AUTH_TOKEN"), help="Twilio Auth Token (or env)"
    )
    parser.add_argument(
        "--twilio-from", default=os.getenv("TWILIO_FROM_NUMBER"), help="Twilio sender phone number"
    )
    parser.add_argument(
        "--twilio-to", default=os.getenv("TWILIO_TO_NUMBER"), help="Target alert phone number"
    )
    desktop_default = os.getenv("DESKTOP_NOTIFY", "").strip().lower() in ("1", "true", "yes", "on")
    parser.add_argument(
        "--webhook-url",
        default=os.getenv("WEBHOOK_URL", ""),
        help="Target HTTP/HTTPS webhook URL for alert dispatch (env: WEBHOOK_URL)",
    )
    parser.add_argument(
        "--webhook-secret",
        default=os.getenv("WEBHOOK_SECRET", ""),
        help="Shared secret for webhook HMAC SHA-256 signing or Bearer auth (env: WEBHOOK_SECRET)",
    )
    parser.add_argument(
        "--enable-desktop-notify",
        action="store_true",
        default=desktop_default,
        help="Enable native cross-platform OS desktop notifications (env: DESKTOP_NOTIFY)",
    )
    args = parser.parse_args()

    twilio_cfg: Optional[dict[str, str]] = None
    if args.twilio_sid and args.twilio_token and args.twilio_from and args.twilio_to:
        twilio_cfg = {
            "account_sid": args.twilio_sid,
            "auth_token": args.twilio_token,
            "from_number": args.twilio_from,
            "to_number": args.twilio_to,
        }

    db = BLETrackerDB(
        args.database,
        webhook_url=args.webhook_url,
        webhook_secret=args.webhook_secret,
        enable_desktop_notify=args.enable_desktop_notify,
    )
    print("[*] BLE Anti-Stalking Tracker Initialized.")
    print(f"[*] Database: {args.database}")
    print(f"[*] Port: {args.serial_port} | Channel: {args.channel}\n")

    base_dir = os.path.dirname(sys.argv[0])
    exe = os.path.join(f"{base_dir}", "sniff_receiver.py")
    cmd = [exe, "-s", args.serial_port, "-c", str(args.channel)]
    print(cmd)

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        print(proc)
        last_check_time = time.time()
        print(f"proc.stdout = {proc.stdout}")
        for line in proc.stdout:
            parsed = parse_sniffle_line(line)
            if parsed:
                mac, rssi, payload = parsed
                net_type, key = classify_payload(payload)

                # Log observation to SQLite
                db.log_observation(mac, rssi, net_type, key, args.channel, payload)

                if net_type != "Unknown":
                    print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] [{net_type}] MAC: "
                        f"{mac} | RSSI: {rssi} dBm | Key: {key[:16]}..."
                    )

                # Run anti-stalking heuristic check every 10 seconds
                now = time.time()
                if now - last_check_time >= 10:
                    alerts = db.check_stalking_heuristics(
                        webhook_url=args.webhook_url,
                        webhook_secret=args.webhook_secret,
                        enable_desktop_notify=args.enable_desktop_notify,
                    )
                    for alert in alerts:
                        msg = alert.get("alert_message", "")
                        print("\n" + "=" * 60)
                        print(f"⚠️  {msg}")
                        print("=" * 60 + "\n")
                        send_notification(msg, twilio_cfg)
                    last_check_time = now
        print("done...")
    except FileNotFoundError:
        print(
            "[-] Error: 'sniffle_receiver' executable not found in PATH.",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        print("\n[*] Tracker stopped by user.")


__all__ = [
    "BLETrackerDB",
    "SniffleLineParser",
    "classify_payload",
    "dispatch_desktop_notification",
    "dispatch_webhook_alert",
    "format_webhook_payload",
    "main",
    "parse_sniffle_line",
    "send_notification",
]


if __name__ == "__main__":
    main()
