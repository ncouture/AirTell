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
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()  # project root's .env

class BLETrackerDB:
    """Thread-safe SQLite database manager for BLE observations and anti-stalking alerts."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.init_db()

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

        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT
                    COALESCE(NULLIF(ephemeral_key, ''), mac_address) AS tracker_id,
                    network_type,
                    COUNT(*) as pkt_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    MAX(rssi) as max_rssi,
                    AVG(rssi) as avg_rssi
                FROM observations
                WHERE timestamp >= ? AND network_type != 'Unknown'
                GROUP BY tracker_id
                HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?
            """
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
    ) -> list[dict[str, Any]]:
        """Analyzes recent observations and returns threat alert dictionaries.

        Suppresses alerts for whitelisted devices and keys.
        """
        now = time.time()
        window_seconds = window_minutes * 60
        min_time_span = min_duration_minutes * 60
        cutoff = now - window_seconds

        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT
                    COALESCE(NULLIF(ephemeral_key, ''), mac_address) AS tracker_id,
                    network_type,
                    COUNT(*) as pkt_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    MAX(rssi) as max_rssi,
                    AVG(rssi) as avg_rssi
                FROM observations
                WHERE timestamp >= ? AND network_type != 'Unknown'
                GROUP BY tracker_id
                HAVING pkt_count >= ? AND (last_seen - first_seen) >= ?
            """
            cursor.execute(query, (cutoff, min_observations, min_time_span))
            results = cursor.fetchall()

            alerts: list[dict[str, Any]] = []
            for row in results:
                tracker_id, net_type, count, first_s, last_s, max_r, avg_r = row
                if self.is_whitelisted("ephemeral_key", tracker_id) or self.is_whitelisted("mac_address", tracker_id):
                    continue

                duration_min = (last_s - first_s) / 60.0
                msg = (
                    f"POSSIBLE STALKER DETECTED: {net_type} beacon"
                    f" ({tracker_id[:16]}...) seen {count} times over"
                    f" {duration_min:.1f} mins (Max RSSI: {max_r} dBm)"
                )
                alerts.append({
                    "identifier": tracker_id,
                    "network_type": net_type,
                    "observation_count": count,
                    "first_seen": first_s,
                    "last_seen": last_s,
                    "max_rssi": max_r,
                    "avg_rssi": avg_r,
                    "alert_message": msg,
                })
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


def send_notification(alert_message: str, twilio_config: Optional[dict[str, str]] = None) -> None:
    """Dispatches notification via Twilio SMS or terminal notification."""
    # Twilio SMS dispatch if credentials provided
    if twilio_config and twilio_config.get("account_sid") and twilio_config.get("auth_token"):
        try:
            from twilio.rest import Client

            client = Client(twilio_config["account_sid"], twilio_config["auth_token"])
            client.messages.create(
                body=f"🚨 [BLE Anti-Stalking Alert]\n{alert_message}",
                from_=twilio_config["from_number"],
                to=twilio_config["to_number"],
            )
            print(f"[+] SMS notification dispatched to {twilio_config['to_number']}.")
        except Exception as exc:
            print(f"[-] Twilio SMS dispatch failed: {exc}", file=sys.stderr)


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
    args = parser.parse_args()

    twilio_cfg: Optional[dict[str, str]] = None
    if args.twilio_sid and args.twilio_token and args.twilio_from and args.twilio_to:
        twilio_cfg = {
            "account_sid": args.twilio_sid,
            "auth_token": args.twilio_token,
            "from_number": args.twilio_from,
            "to_number": args.twilio_to,
        }

    db = BLETrackerDB(args.database)
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
        #assert proc.stdout is not None
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
                    alerts = db.check_stalking_thresholds()
                    for alert in alerts:
                        print("\n" + "=" * 60)
                        print(f"⚠️  {alert}")
                        print("=" * 60 + "\n")
                        send_notification(alert, twilio_cfg)
                    last_check_time = now
        print("done...")
    except FileNotFoundError:
        print(
            "[-] Error: 'sniffle_receiver' executable not found in PATH.",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        print("\n[*] Tracker stopped by user.")


if __name__ == "__main__":
    main()
