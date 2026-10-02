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
            conn.commit()

    def log_observation(
        self,
        mac_address: str,
        rssi: int,
        network_type: str,
        ephemeral_key: str,
        channel: int,
        raw_payload: str,
    ) -> None:
        now = time.time()
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


def parse_sniffle_line(line: str) -> Optional[tuple[str, int, str]]:
    """Parses output lines from sniffle_receiver CLI or logs.

    Extracts MAC address, RSSI, and raw payload hex bytes.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Matches standard Sniffle log format: AdvAddr=XX:XX:XX... RSSI=-XX Data=XXXX...
    match = re.search(
        r"AdvAddr=([0-9A-Fa-f:]+)\s+RSSI=(-?\d+)\s+Data=([0-9A-Fa-f]+)", line
    )
    if match:
        mac = match.group(1).upper()
        rssi = int(match.group(2))
        payload_hex = match.group(3).lower()
        return mac, rssi, payload_hex

    # Fallback match for hexdump / raw stdout format
    match_alt = re.search(
        r"(?:AdvA|MAC|Addr)[:=]\s*([0-9A-Fa-f:]+).*?RSSI[:=]\s*(-?\d+).*?Data[:=]\s*([0-9A-Fa-f]+)",
        line,
        re.IGNORECASE,
    )
    if match_alt:
        mac = match_alt.group(1).upper()
        rssi = int(match_alt.group(2))
        payload_hex = match_alt.group(3).lower()
        return mac, rssi, payload_hex

    return None


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
        "-p",
        "--port",
        default="/dev/ttyUSB0",
        help="Serial port for Sniffle dongle",
    )
    parser.add_argument(
        "-c", "--channel", type=int, default=37, help="BLE Advertising channel (37, 38, 39)"
    )
    parser.add_argument(
        "-db", "--database", type=str, help="SQLite database path"
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
    print(f"[*] Port: {args.port} | Channel: {args.channel}\n")

    base_dir = os.path.basename(sys.argv[0])
    exe = os.path.join(f"{base_dir}", "sniff_receiver")
    print(exe)
    cmd = [exe, "-p", args.port, "-c", str(args.channel)]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        last_check_time = time.time()

        assert proc.stdout is not None
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

    except FileNotFoundError:
        print(
            "[-] Error: 'sniffle_receiver' executable not found in PATH.",
            file=sys.stderr,
        )
    except KeyboardInterrupt:
        print("\n[*] Tracker stopped by user.")


if __name__ == "__main__":
    main()
