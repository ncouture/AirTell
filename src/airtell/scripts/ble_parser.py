#!/usr/bin/env python
#

"""Standalone Python BLE Offline Finding Parser.

Interfaces with sniff_receiver CLI or logs to capture raw BLE advertising packets
from a CC2652P dongle flashed with Sniffle firmware. Parses 31-byte advertising
payloads and isolates ephemeral public keys used by crowdsourced tracking networks
(Apple Find My, Google Find Hub, Tile, and Samsung SmartThings Find).
"""

import argparse
import subprocess
import sys
import os

try:
    from airtell.scripts.ble_antistalking_tracker import SniffleLineParser
except ImportError:
    from ble_antistalking_tracker import SniffleLineParser

# Module-level parser instance
_parser = SniffleLineParser()


def parse_sniffle_line(line: str):
    """Parses output lines from sniff_receiver stdout.

    Delegates to the stateful multi-line SniffleLineParser which accumulates
    header, AdvA, and hexdump lines before returning a complete
    ``(mac, rssi, payload_hex)`` tuple.
    """
    return _parser.feed(line)


def analyze_ble_payload(mac: str, rssi: int, payload_hex: str):
    """Analyzes advertisement payload for known Offline Finding (OF) beacons."""
    payload_lower = payload_hex.lower()

    # Apple Find My Payload pattern (Company ID 0x004C, Type 0x12, Length 0x19)
    if "4c001219" in payload_lower:
        idx = payload_lower.find("4c001219")
        # Extract 22-byte (44 hex chars) ephemeral public key payload
        public_key_bytes = payload_lower[idx + 8 : idx + 8 + 44]
        print(f"[+] [Apple Find My] MAC: {mac} | RSSI: {rssi} dBm | Key: {public_key_bytes}")
    elif "fe9f" in payload_lower:  # Google Fast Pair / Find Hub Service UUID
        idx = payload_lower.find("fe9f")
        key = payload_lower[idx : idx + 40]
        print(f"[+] [Google Find Hub] MAC: {mac} | RSSI: {rssi} dBm | Key: {key}")
    elif "feed" in payload_lower:  # Tile Service UUID
        idx = payload_lower.find("feed")
        key = payload_lower[idx : idx + 32]
        print(f"[+] [Tile Tracker] MAC: {mac} | RSSI: {rssi} dBm | Key: {key}")
    elif "7500" in payload_lower:  # Samsung SmartThings Find (0x0075)
        idx = payload_lower.find("7500")
        key = payload_lower[idx : idx + 32]
        print(f"[+] [Samsung SmartThings] MAC: {mac} | RSSI: {rssi} dBm | Key: {key}")


def run_sniffle_sniffer(port: str = "/dev/ttyUSB0", channel: int = 37):
    """Spawns sniff_receiver process on specified serial port and BLE channel."""
    base_dir = os.path.dirname(sys.argv[0])
    exe = os.path.join(f"{base_dir}", "sniff_receiver.py")
    cmd = [exe, "-s", port, "-c", str(channel)]
    print(cmd)
    print(f"[*] Starting Sniffle on {port} (Channel {channel})...")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            parsed = parse_sniffle_line(line)
            if parsed:
                mac, rssi, payload = parsed
                analyze_ble_payload(mac, rssi, payload)
    except FileNotFoundError:
        print("[-] 'sniff_receiver' command not found. Ensure Sniffle tools are in your PATH.")
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")


def main():
    parser = argparse.ArgumentParser(description="Python BLE Offline Finding Parser")
    parser.add_argument("port", nargs="?", default="/dev/ttyUSB0", help="Serial port for Sniffle dongle")
    parser.add_argument("channel", nargs="?", type=int, default=37, help="BLE Advertising channel (37, 38, 39)")
    args = parser.parse_args()

    run_sniffle_sniffer(args.port, args.channel)


if __name__ == "__main__":
    main()
