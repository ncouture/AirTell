"""Pluggable DatabaseBackend abstraction supporting SQLite and DuckDB."""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

import pandas as pd

logger = logging.getLogger("airtell.telemetry.storage")

try:
    import duckdb

    HAS_DUCKDB = True
except ImportError:
    duckdb = None  # type: ignore[assignment]
    HAS_DUCKDB = False


class DatabaseBackend(ABC):
    """Abstract base class for telemetry and analytics database backends."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    @abstractmethod
    def connect(self) -> Any:
        """Establish or acquire underlying connection."""

    @abstractmethod
    def close(self) -> None:
        """Close connection and release underlying resources."""

    @abstractmethod
    def init_db(self) -> None:
        """Initialize database schema tables and indices."""

    @abstractmethod
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
        """Insert a BLE observation record and return its row ID."""

    @abstractmethod
    def insert_alert(
        self,
        identifier: str,
        network_type: str,
        observation_count: int,
        first_seen: float,
        last_seen: float,
        max_rssi: int,
        alert_message: str,
        timestamp: Optional[float] = None,
    ) -> int:
        """Insert an alert record and return its row ID."""

    @abstractmethod
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
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        """Query observation records with optional filtering."""

    @abstractmethod
    def get_rssi_timeseries(
        self,
        network_types: Optional[list[str]] = None,
        min_rssi: Optional[int] = None,
        limit: int = 2000,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        """Retrieve chronological RSSI signal observations for tracking beacons."""

    @abstractmethod
    def get_channel_distribution(self) -> dict[int, int]:
        """Compute packet observation count distribution across BLE channels."""

    @abstractmethod
    def get_tracker_frequencies(
        self,
        min_count: int = 1,
        limit: int = 100,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        """Aggregate tracker observation counts, signal stats, and time spans."""

    @abstractmethod
    def check_stalking_heuristics(
        self,
        window_seconds: int = 900,
        min_observations: int = 5,
        min_time_span: int = 300,
        window_minutes: Optional[int] = None,
        min_duration_minutes: Optional[int] = None,
        cooldown_seconds: int = 300,
        deduplicate: bool = True,
        now: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """Evaluate sliding-window heuristics for persistent tracking beacons."""

    @abstractmethod
    def add_whitelist(self, identifier_type: str, identifier_value: str, notes: str = "") -> int:
        """Add an identifier to the whitelist."""

    @abstractmethod
    def is_whitelisted(self, identifier_type: str, identifier_value: str) -> bool:
        """Check if an identifier is whitelisted."""

    @abstractmethod
    def get_whitelists(self) -> list[dict[str, Any]]:
        """Retrieve all whitelisted identifiers."""

    @abstractmethod
    def remove_whitelist(self, whitelist_id: int) -> bool:
        """Delete an identifier from the whitelist."""

    @abstractmethod
    def record_alert_action(self, alert_id: int, action_type: str, analyst_note: str = "") -> int:
        """Record an analyst triage action or note on an alert."""

    @abstractmethod
    def get_alert_actions(self, alert_id: Optional[int] = None) -> list[dict[str, Any]]:
        """Retrieve recorded actions for alerts."""

    @abstractmethod
    def get_alerts(self, limit: int = 200, as_df: bool = False) -> Union[list[dict[str, Any]], pd.DataFrame]:
        """Retrieve recorded anti-stalking alerts."""

    @abstractmethod
    def query_df(self, sql: str, params: Optional[list[Any]] = None) -> pd.DataFrame:
        """Execute a raw SQL query and return results directly as a pandas DataFrame."""


class SQLiteBackend(DatabaseBackend):
    """SQLite implementation of DatabaseBackend wrapping standard sqlite3."""

    def __init__(self, db_path: str, timeout: float = 10.0) -> None:
        super().__init__(db_path)
        self.timeout = timeout
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=self.timeout)
            self._mem_conn.row_factory = sqlite3.Row
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=self.timeout)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=self.timeout)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def close(self) -> None:
        with self._lock:
            if self._mem_conn is not None:
                try:
                    self._mem_conn.close()
                except Exception:
                    pass
                self._mem_conn = None
            if hasattr(self._local, "conn") and self._local.conn is not None:
                try:
                    self._local.conn.close()
                except Exception:
                    pass
                self._local.conn = None

    def init_db(self) -> None:
        with self._lock:
            with self.connect() as conn:
                cursor = conn.cursor()
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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_time ON observations (timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_key ON observations (ephemeral_key)")

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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_val ON whitelists (identifier_value)")

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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_action_alert ON alert_actions (alert_id)")
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
        now = time.time() if timestamp is None else timestamp
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO observations (timestamp, datetime_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, dt_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def insert_alert(
        self,
        identifier: str,
        network_type: str,
        observation_count: int,
        first_seen: float,
        last_seen: float,
        max_rssi: int,
        alert_message: str,
        timestamp: Optional[float] = None,
    ) -> int:
        now = time.time() if timestamp is None else timestamp
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self.connect() as conn:
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
                    observation_count,
                    first_seen,
                    last_seen,
                    max_rssi,
                    alert_message,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

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
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, channel, mac_address, rssi, network_type, ephemeral_key, raw_payload "
            "FROM observations WHERE 1=1"
        )
        params: list[Any] = []
        if network_type and network_type != "All":
            query += " AND network_type = ?"
            params.append(network_type)
        if search_query and search_query.strip():
            query += " AND (mac_address LIKE ? OR ephemeral_key LIKE ?)"
            wildcard = f"%{search_query.strip()}%"
            params.extend([wildcard, wildcard])
        if channel is not None:
            query += " AND channel = ?"
            params.append(channel)
        if min_rssi is not None:
            query += " AND rssi >= ?"
            params.append(min_rssi)
        if start_time is not None:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time is not None:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        if as_df:
            return self.query_df(query, params)

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_rssi_timeseries(
        self,
        network_types: Optional[list[str]] = None,
        min_rssi: Optional[int] = None,
        limit: int = 2000,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, mac_address, rssi, network_type, "
            "SUBSTR(COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address), 1, 16) as key_short, "
            "ephemeral_key, channel "
            "FROM observations WHERE network_type != 'Unknown'"
        )
        params: list[Any] = []
        if network_types:
            placeholders = ",".join("?" for _ in network_types)
            query += f" AND network_type IN ({placeholders})"
            params.extend(network_types)
        if min_rssi is not None:
            query += " AND rssi >= ?"
            params.append(min_rssi)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        if as_df:
            return self.query_df(query, params)

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_channel_distribution(self) -> dict[int, int]:
        query = "SELECT channel, COUNT(*) as pkt_count FROM observations WHERE channel IS NOT NULL GROUP BY channel ORDER BY channel ASC"
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return {int(row[0]): int(row[1]) for row in cursor.fetchall()}

    def get_tracker_frequencies(
        self,
        min_count: int = 1,
        limit: int = 100,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT "
            "COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id, "
            "network_type, "
            "COUNT(*) as observation_count, "
            "MAX(rssi) as max_rssi, "
            "AVG(rssi) as avg_rssi, "
            "MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen "
            "FROM observations "
            "WHERE network_type != 'Unknown' "
            "GROUP BY tracker_id, network_type "
            "HAVING COUNT(*) >= ? "
            "ORDER BY observation_count DESC, tracker_id ASC "
            "LIMIT ?"
        )
        params = [min_count, limit]
        if as_df:
            return self.query_df(query, params)

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                {
                    "tracker_id": r[0],
                    "network_type": r[1],
                    "observation_count": r[2],
                    "max_rssi": r[3],
                    "avg_rssi": round(float(r[4]), 2) if r[4] is not None else 0.0,
                    "first_seen": r[5],
                    "last_seen": r[6],
                }
                for r in rows
            ]

    def check_stalking_heuristics(
        self,
        window_seconds: int = 900,
        min_observations: int = 5,
        min_time_span: int = 300,
        window_minutes: Optional[int] = None,
        min_duration_minutes: Optional[int] = None,
        cooldown_seconds: int = 300,
        deduplicate: bool = True,
        now: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        curr_time = time.time() if now is None else now
        if window_minutes is not None:
            window_seconds = window_minutes * 60
        if min_duration_minutes is not None:
            min_time_span = min_duration_minutes * 60

        cutoff = curr_time - window_seconds
        query = (
            "SELECT "
            "COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id, "
            "network_type, "
            "COUNT(*) as pkt_count, "
            "MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen, "
            "MAX(rssi) as max_rssi, "
            "AVG(rssi) as avg_rssi "
            "FROM observations "
            "WHERE timestamp >= ? AND network_type != 'Unknown' "
            "GROUP BY tracker_id, network_type "
            "HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?"
        )

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (cutoff, min_observations, min_time_span))
            rows = cursor.fetchall()

            alerts: list[dict[str, Any]] = []
            for row in rows:
                tracker_id = row[0]
                net_type = row[1]
                count = row[2]
                first_s = row[3]
                last_s = row[4]
                max_r = row[5]
                avg_r = row[6]

                if self.is_whitelisted("ephemeral_key", tracker_id) or self.is_whitelisted("mac_address", tracker_id):
                    continue

                duration_sec = max(0.0, float(last_s - first_s))
                duration_min = duration_sec / 60.0
                alert_lvl = "CRITICAL" if max_r >= -60 else "HIGH"
                msg = (
                    f"POSSIBLE STALKER DETECTED: {net_type} beacon "
                    f"({tracker_id[:16]}...) seen {count} times over "
                    f"{duration_min:.1f} mins (Max RSSI: {max_r} dBm)"
                )

                if cooldown_seconds > 0:
                    cursor.execute(
                        "SELECT COUNT(*) FROM alerts WHERE identifier = ? AND timestamp > ?",
                        (tracker_id, curr_time - cooldown_seconds),
                    )
                    recent_count = cursor.fetchone()[0]
                    is_in_cooldown = recent_count > 0
                else:
                    is_in_cooldown = False

                if is_in_cooldown and deduplicate:
                    continue

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
                    "avg_rssi": round(float(avg_r), 2) if avg_r is not None else 0.0,
                    "mean_rssi": round(float(avg_r), 2) if avg_r is not None else 0.0,
                    "alert_level": alert_lvl,
                    "alert_message": msg,
                    "in_cooldown": is_in_cooldown,
                }

                if not is_in_cooldown:
                    dt_str = datetime.fromtimestamp(curr_time).strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute(
                        """
                        INSERT INTO alerts (timestamp, datetime_str, identifier, network_type, observation_count, first_seen, last_seen, max_rssi, alert_message)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            curr_time,
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
                alerts.append(alert_dict)
            conn.commit()
            return alerts

    def add_whitelist(self, identifier_type: str, identifier_value: str, notes: str = "") -> int:
        now = time.time()
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO whitelists (identifier_type, identifier_value, notes, created_at) VALUES (?, ?, ?, ?)",
                (identifier_type, identifier_value.strip(), notes.strip(), now),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def is_whitelisted(self, identifier_type: str, identifier_value: str) -> bool:
        val_clean = identifier_value.strip().lower()
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM whitelists WHERE identifier_type = ? AND LOWER(identifier_value) = ?",
                (identifier_type, val_clean),
            )
            if cursor.fetchone()[0] > 0:
                return True
            cursor.execute(
                "SELECT COUNT(*) FROM whitelists WHERE LOWER(identifier_value) = ?",
                (val_clean,),
            )
            return cursor.fetchone()[0] > 0

    def get_whitelists(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, identifier_type, identifier_value, notes, created_at FROM whitelists ORDER BY id DESC"
            )
            return [dict(r) for r in cursor.fetchall()]

    def remove_whitelist(self, whitelist_id: int) -> bool:
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM whitelists WHERE id = ?", (whitelist_id,))
            conn.commit()
            return cursor.rowcount > 0

    def record_alert_action(self, alert_id: int, action_type: str, analyst_note: str = "") -> int:
        now = time.time()
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO alert_actions (alert_id, action_type, analyst_note, timestamp) VALUES (?, ?, ?, ?)",
                (alert_id, action_type, analyst_note.strip(), now),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_alert_actions(self, alert_id: Optional[int] = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
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
            return [dict(r) for r in cursor.fetchall()]

    def get_alerts(self, limit: int = 200, as_df: bool = False) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, identifier, network_type, "
            "observation_count, first_seen, last_seen, max_rssi, alert_message "
            "FROM alerts ORDER BY id DESC LIMIT ?"
        )
        if as_df:
            return self.query_df(query, [limit])
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, [limit])
            return [dict(r) for r in cursor.fetchall()]

    def query_df(self, sql: str, params: Optional[list[Any]] = None) -> pd.DataFrame:
        with self.connect() as conn:
            return pd.read_sql_query(sql, conn, params=params)


class DuckDBBackend(DatabaseBackend):
    """DuckDB columnar analytics implementation of DatabaseBackend."""

    def __init__(
        self,
        db_path: str,
        threads: int = 4,
        memory_limit: str = "2GB",
    ) -> None:
        if not HAS_DUCKDB:
            raise ImportError("duckdb is required for DuckDBBackend. Install with: pip install duckdb")
        super().__init__(db_path)
        self.threads = threads
        self.memory_limit = memory_limit
        self._lock = threading.RLock()
        self._is_native = self.db_path.endswith(".duckdb")
        self._is_memory = self.db_path == ":memory:"

        # Delegate SQLite writes and initial schema setup to SQLiteBackend when attaching
        self._sqlite_fallback: Optional[SQLiteBackend] = None
        if not self._is_native and not self._is_memory:
            self._sqlite_fallback = SQLiteBackend(self.db_path)

        self.con = self._init_connection()
        self.init_db()

    def _init_connection(self) -> Any:
        with self._lock:
            if self._is_native:
                con = duckdb.connect(self.db_path)
            elif self._is_memory:
                con = duckdb.connect(":memory:")
            else:
                con = duckdb.connect(":memory:")
                # Attach SQLite database file
                abs_path = os.path.abspath(self.db_path)
                con.execute(f"ATTACH '{abs_path}' AS sqlite_db (TYPE SQLITE);")
                # Expose views in default schema for direct table access
                con.execute("CREATE OR REPLACE VIEW observations AS SELECT * FROM sqlite_db.observations;")
                con.execute("CREATE OR REPLACE VIEW alerts AS SELECT * FROM sqlite_db.alerts;")
                con.execute("CREATE OR REPLACE VIEW whitelists AS SELECT * FROM sqlite_db.whitelists;")
                con.execute("CREATE OR REPLACE VIEW alert_actions AS SELECT * FROM sqlite_db.alert_actions;")

            # Configure thread and memory tuning
            try:
                con.execute(f"SET threads TO {int(self.threads)};")
            except Exception as e:
                logger.debug("Failed setting DuckDB threads: %s", e)
            try:
                con.execute(f"SET max_memory = '{self.memory_limit}';")
            except Exception as e:
                logger.debug("Failed setting DuckDB max_memory: %s", e)

            return con

    def connect(self) -> Any:
        return self.con

    def close(self) -> None:
        with self._lock:
            if self.con is not None:
                try:
                    self.con.close()
                except Exception:
                    pass
                self.con = None
            if self._sqlite_fallback is not None:
                self._sqlite_fallback.close()

    def init_db(self) -> None:
        with self._lock:
            if self._sqlite_fallback is not None:
                self._sqlite_fallback.init_db()
                return

            # Native DuckDB tables
            self.con.execute("CREATE SEQUENCE IF NOT EXISTS obs_id_seq START 1;")
            self.con.execute(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    id BIGINT DEFAULT nextval('obs_id_seq') PRIMARY KEY,
                    timestamp DOUBLE,
                    datetime_str VARCHAR,
                    mac_address VARCHAR,
                    rssi INTEGER,
                    network_type VARCHAR,
                    ephemeral_key VARCHAR,
                    channel INTEGER,
                    raw_payload VARCHAR
                )
                """
            )
            self.con.execute("CREATE SEQUENCE IF NOT EXISTS alert_id_seq START 1;")
            self.con.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id BIGINT DEFAULT nextval('alert_id_seq') PRIMARY KEY,
                    timestamp DOUBLE,
                    datetime_str VARCHAR,
                    identifier VARCHAR,
                    network_type VARCHAR,
                    observation_count INTEGER,
                    first_seen DOUBLE,
                    last_seen DOUBLE,
                    max_rssi INTEGER,
                    alert_message VARCHAR
                )
                """
            )
            self.con.execute("CREATE SEQUENCE IF NOT EXISTS whitelist_id_seq START 1;")
            self.con.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelists (
                    id BIGINT DEFAULT nextval('whitelist_id_seq') PRIMARY KEY,
                    identifier_type VARCHAR NOT NULL,
                    identifier_value VARCHAR NOT NULL,
                    notes VARCHAR,
                    created_at DOUBLE
                )
                """
            )
            self.con.execute("CREATE SEQUENCE IF NOT EXISTS action_id_seq START 1;")
            self.con.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_actions (
                    id BIGINT DEFAULT nextval('action_id_seq') PRIMARY KEY,
                    alert_id BIGINT,
                    action_type VARCHAR NOT NULL,
                    analyst_note VARCHAR,
                    timestamp DOUBLE
                )
                """
            )

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
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.insert_observation(
                mac_address=mac_address,
                rssi=rssi,
                network_type=network_type,
                ephemeral_key=ephemeral_key,
                channel=channel,
                raw_payload=raw_payload,
                timestamp=timestamp,
            )

        now = time.time() if timestamp is None else timestamp
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            res = self.con.execute(
                """
                INSERT INTO observations (timestamp, datetime_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
                """,
                [now, dt_str, mac_address, rssi, network_type, ephemeral_key, channel, raw_payload],
            ).fetchone()
            return int(res[0]) if res else 0

    def insert_alert(
        self,
        identifier: str,
        network_type: str,
        observation_count: int,
        first_seen: float,
        last_seen: float,
        max_rssi: int,
        alert_message: str,
        timestamp: Optional[float] = None,
    ) -> int:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.insert_alert(
                identifier=identifier,
                network_type=network_type,
                observation_count=observation_count,
                first_seen=first_seen,
                last_seen=last_seen,
                max_rssi=max_rssi,
                alert_message=alert_message,
                timestamp=timestamp,
            )

        now = time.time() if timestamp is None else timestamp
        dt_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            res = self.con.execute(
                """
                INSERT INTO alerts (timestamp, datetime_str, identifier, network_type, observation_count, first_seen, last_seen, max_rssi, alert_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
                """,
                [
                    now,
                    dt_str,
                    identifier,
                    network_type,
                    observation_count,
                    first_seen,
                    last_seen,
                    max_rssi,
                    alert_message,
                ],
            ).fetchone()
            return int(res[0]) if res else 0

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
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, channel, mac_address, rssi, network_type, ephemeral_key, raw_payload "
            "FROM observations WHERE 1=1"
        )
        params: list[Any] = []
        if network_type and network_type != "All":
            query += " AND network_type = ?"
            params.append(network_type)
        if search_query and search_query.strip():
            query += " AND (mac_address LIKE ? OR ephemeral_key LIKE ?)"
            wildcard = f"%{search_query.strip()}%"
            params.extend([wildcard, wildcard])
        if channel is not None:
            query += " AND channel = ?"
            params.append(channel)
        if min_rssi is not None:
            query += " AND rssi >= ?"
            params.append(min_rssi)
        if start_time is not None:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time is not None:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        try:
            if as_df:
                return self.query_df(query, params)

            with self._lock:
                df = self.con.execute(query, params).df()
                return df.to_dict(orient="records")
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB get_observations failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.get_observations(
                    limit=limit,
                    network_type=network_type,
                    search_query=search_query,
                    channel=channel,
                    min_rssi=min_rssi,
                    start_time=start_time,
                    end_time=end_time,
                    as_df=as_df,
                )
            raise

    def get_rssi_timeseries(
        self,
        network_types: Optional[list[str]] = None,
        min_rssi: Optional[int] = None,
        limit: int = 2000,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, mac_address, rssi, network_type, "
            "SUBSTR(COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address), 1, 16) as key_short, "
            "ephemeral_key, channel "
            "FROM observations WHERE network_type != 'Unknown'"
        )
        params: list[Any] = []
        if network_types:
            placeholders = ",".join("?" for _ in network_types)
            query += f" AND network_type IN ({placeholders})"
            params.extend(network_types)
        if min_rssi is not None:
            query += " AND rssi >= ?"
            params.append(min_rssi)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        try:
            if as_df:
                return self.query_df(query, params)

            with self._lock:
                df = self.con.execute(query, params).df()
                return df.to_dict(orient="records")
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB get_rssi_timeseries failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.get_rssi_timeseries(
                    network_types=network_types,
                    min_rssi=min_rssi,
                    limit=limit,
                    as_df=as_df,
                )
            raise

    def get_channel_distribution(self) -> dict[int, int]:
        query = "SELECT channel, COUNT(*) as pkt_count FROM observations WHERE channel IS NOT NULL GROUP BY channel ORDER BY channel ASC"
        try:
            with self._lock:
                rows = self.con.execute(query).fetchall()
                return {int(row[0]): int(row[1]) for row in rows}
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB get_channel_distribution failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.get_channel_distribution()
            raise

    def get_tracker_frequencies(
        self,
        min_count: int = 1,
        limit: int = 100,
        as_df: bool = False,
    ) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT "
            "COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id, "
            "network_type, "
            "COUNT(*) as observation_count, "
            "MAX(rssi) as max_rssi, "
            "AVG(rssi) as avg_rssi, "
            "MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen "
            "FROM observations "
            "WHERE network_type != 'Unknown' "
            "GROUP BY tracker_id, network_type "
            "HAVING COUNT(*) >= ? "
            "ORDER BY observation_count DESC, tracker_id ASC "
            "LIMIT ?"
        )
        params = [min_count, limit]
        try:
            if as_df:
                return self.query_df(query, params)

            with self._lock:
                rows = self.con.execute(query, params).fetchall()
                return [
                    {
                        "tracker_id": r[0],
                        "network_type": r[1],
                        "observation_count": r[2],
                        "max_rssi": r[3],
                        "avg_rssi": round(float(r[4]), 2) if r[4] is not None else 0.0,
                        "first_seen": r[5],
                        "last_seen": r[6],
                    }
                    for r in rows
                ]
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB get_tracker_frequencies failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.get_tracker_frequencies(
                    min_count=min_count,
                    limit=limit,
                    as_df=as_df,
                )
            raise

    def check_stalking_heuristics(
        self,
        window_seconds: int = 900,
        min_observations: int = 5,
        min_time_span: int = 300,
        window_minutes: Optional[int] = None,
        min_duration_minutes: Optional[int] = None,
        cooldown_seconds: int = 300,
        deduplicate: bool = True,
        now: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        curr_time = time.time() if now is None else now
        if window_minutes is not None:
            window_seconds = window_minutes * 60
        if min_duration_minutes is not None:
            min_time_span = min_duration_minutes * 60

        cutoff = curr_time - window_seconds
        query = (
            "SELECT "
            "COALESCE(NULLIF(TRIM(ephemeral_key), ''), mac_address) AS tracker_id, "
            "network_type, "
            "COUNT(*) as pkt_count, "
            "MIN(timestamp) as first_seen, "
            "MAX(timestamp) as last_seen, "
            "MAX(rssi) as max_rssi, "
            "AVG(rssi) as avg_rssi "
            "FROM observations "
            "WHERE timestamp >= ? AND network_type != 'Unknown' "
            "GROUP BY tracker_id, network_type "
            "HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?"
        )

        try:
            with self._lock:
                rows = self.con.execute(query, [cutoff, min_observations, min_time_span]).fetchall()

                alerts: list[dict[str, Any]] = []
                for row in rows:
                    tracker_id = row[0]
                    net_type = row[1]
                    count = row[2]
                    first_s = row[3]
                    last_s = row[4]
                    max_r = row[5]
                    avg_r = row[6]

                    if self.is_whitelisted("ephemeral_key", tracker_id) or self.is_whitelisted("mac_address", tracker_id):
                        continue

                    duration_sec = max(0.0, float(last_s - first_s))
                    duration_min = duration_sec / 60.0
                    alert_lvl = "CRITICAL" if max_r >= -60 else "HIGH"
                    msg = (
                        f"POSSIBLE STALKER DETECTED: {net_type} beacon "
                        f"({tracker_id[:16]}...) seen {count} times over "
                        f"{duration_min:.1f} mins (Max RSSI: {max_r} dBm)"
                    )

                    if cooldown_seconds > 0:
                        cooldown_cutoff = curr_time - cooldown_seconds
                        res = self.con.execute(
                            "SELECT COUNT(*) FROM alerts WHERE identifier = ? AND timestamp > ?",
                            [tracker_id, cooldown_cutoff],
                        ).fetchone()
                        recent_count = res[0] if res else 0
                        is_in_cooldown = recent_count > 0
                    else:
                        is_in_cooldown = False

                    if is_in_cooldown and deduplicate:
                        continue

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
                        "avg_rssi": round(float(avg_r), 2) if avg_r is not None else 0.0,
                        "mean_rssi": round(float(avg_r), 2) if avg_r is not None else 0.0,
                        "alert_level": alert_lvl,
                        "alert_message": msg,
                        "in_cooldown": is_in_cooldown,
                    }

                    if not is_in_cooldown:
                        self.insert_alert(
                            identifier=tracker_id,
                            network_type=net_type,
                            observation_count=count,
                            first_seen=first_s,
                            last_seen=last_s,
                            max_rssi=max_r,
                            alert_message=msg,
                            timestamp=curr_time,
                        )
                    alerts.append(alert_dict)
                return alerts
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB check_stalking_heuristics failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.check_stalking_heuristics(
                    window_seconds=window_seconds,
                    min_observations=min_observations,
                    min_time_span=min_time_span,
                    window_minutes=window_minutes,
                    min_duration_minutes=min_duration_minutes,
                    cooldown_seconds=cooldown_seconds,
                    deduplicate=deduplicate,
                    now=now,
                )
            raise

    def add_whitelist(self, identifier_type: str, identifier_value: str, notes: str = "") -> int:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.add_whitelist(identifier_type, identifier_value, notes)
        now = time.time()
        with self._lock:
            res = self.con.execute(
                "INSERT INTO whitelists (identifier_type, identifier_value, notes, created_at) VALUES (?, ?, ?, ?) RETURNING id",
                [identifier_type, identifier_value.strip(), notes.strip(), now],
            ).fetchone()
            return int(res[0]) if res else 0

    def is_whitelisted(self, identifier_type: str, identifier_value: str) -> bool:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.is_whitelisted(identifier_type, identifier_value)
        val_clean = identifier_value.strip().lower()
        with self._lock:
            res = self.con.execute(
                "SELECT COUNT(*) FROM whitelists WHERE identifier_type = ? AND LOWER(identifier_value) = ?",
                [identifier_type, val_clean],
            ).fetchone()
            if res and res[0] > 0:
                return True
            res2 = self.con.execute(
                "SELECT COUNT(*) FROM whitelists WHERE LOWER(identifier_value) = ?",
                [val_clean],
            ).fetchone()
            return bool(res2 and res2[0] > 0)

    def get_whitelists(self) -> list[dict[str, Any]]:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.get_whitelists()
        with self._lock:
            df = self.con.execute(
                "SELECT id, identifier_type, identifier_value, notes, created_at FROM whitelists ORDER BY id DESC"
            ).df()
            return df.to_dict(orient="records")

    def remove_whitelist(self, whitelist_id: int) -> bool:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.remove_whitelist(whitelist_id)
        with self._lock:
            res = self.con.execute("DELETE FROM whitelists WHERE id = ? RETURNING id", [whitelist_id]).fetchall()
            return len(res) > 0

    def record_alert_action(self, alert_id: int, action_type: str, analyst_note: str = "") -> int:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.record_alert_action(alert_id, action_type, analyst_note)
        now = time.time()
        with self._lock:
            res = self.con.execute(
                "INSERT INTO alert_actions (alert_id, action_type, analyst_note, timestamp) VALUES (?, ?, ?, ?) RETURNING id",
                [alert_id, action_type, analyst_note.strip(), now],
            ).fetchone()
            return int(res[0]) if res else 0

    def get_alert_actions(self, alert_id: Optional[int] = None) -> list[dict[str, Any]]:
        if self._sqlite_fallback is not None:
            return self._sqlite_fallback.get_alert_actions(alert_id)
        with self._lock:
            if alert_id is not None:
                df = self.con.execute(
                    "SELECT id, alert_id, action_type, analyst_note, timestamp FROM alert_actions WHERE alert_id = ? ORDER BY id DESC",
                    [alert_id],
                ).df()
            else:
                df = self.con.execute(
                    "SELECT id, alert_id, action_type, analyst_note, timestamp FROM alert_actions ORDER BY id DESC"
                ).df()
            return df.to_dict(orient="records")

    def get_alerts(self, limit: int = 200, as_df: bool = False) -> Union[list[dict[str, Any]], pd.DataFrame]:
        query = (
            "SELECT id, datetime_str, timestamp, identifier, network_type, "
            "observation_count, first_seen, last_seen, max_rssi, alert_message "
            "FROM alerts ORDER BY id DESC LIMIT ?"
        )
        try:
            if as_df:
                return self.query_df(query, [limit])
            with self._lock:
                df = self.con.execute(query, [limit]).df()
                return df.to_dict(orient="records")
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB get_alerts failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.get_alerts(limit=limit, as_df=as_df)
            raise

    def query_df(self, sql: str, params: Optional[list[Any]] = None) -> pd.DataFrame:
        try:
            with self._lock:
                return self.con.execute(sql, params or []).df()
        except Exception as e:
            if self._sqlite_fallback is not None:
                logger.warning("DuckDB query_df failed (%s). Falling back to SQLite.", e)
                return self._sqlite_fallback.query_df(sql, params)
            raise


def get_database_backend(
    backend_type: Optional[str] = None,
    db_path: str = "data/ble_tracker.db",
    threads: Optional[int] = None,
    memory_limit: Optional[str] = None,
    **kwargs: Any,
) -> DatabaseBackend:
    """Factory creating a DatabaseBackend instance (SQLiteBackend or DuckDBBackend).

    Args:
        backend_type: "sqlite", "duckdb", or "auto" (defaults to DATABASE_BACKEND or "sqlite")
        db_path: Path to database file or ":memory:"
        threads: Thread count limit for DuckDB (defaults to DUCKDB_THREADS or 4)
        memory_limit: Memory limit string for DuckDB (defaults to DUCKDB_MEMORY_LIMIT or "2GB")
        **kwargs: Additional backend arguments

    Returns:
        Configured DatabaseBackend instance.
    """
    if backend_type is None:
        backend_type = os.getenv("DATABASE_BACKEND", os.getenv("AIRTELL_DB_BACKEND", "sqlite"))
    if threads is None:
        try:
            threads = int(os.getenv("DUCKDB_THREADS", "4"))
        except ValueError:
            threads = 4
    if memory_limit is None:
        memory_limit = os.getenv("DUCKDB_MEMORY_LIMIT", "2GB")

    b_type = (backend_type or "sqlite").strip().lower()

    if b_type in ("duckdb", "duck", "auto"):
        if HAS_DUCKDB:
            try:
                backend = DuckDBBackend(
                    db_path=db_path,
                    threads=threads,
                    memory_limit=memory_limit,
                    **kwargs,
                )
                logger.info("Initialized DuckDBBackend for %s (threads=%d, memory_limit=%s)", db_path, threads, memory_limit)
                return backend
            except Exception as e:
                logger.warning("Failed initializing DuckDBBackend on %s (%s). Falling back to SQLiteBackend.", db_path, e)
                return SQLiteBackend(db_path=db_path, **kwargs)
        else:
            logger.info("duckdb not installed. Falling back to SQLiteBackend.")
            return SQLiteBackend(db_path=db_path, **kwargs)

    return SQLiteBackend(db_path=db_path, **kwargs)
