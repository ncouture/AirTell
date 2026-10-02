#!/usr/bin/env python
#

"""Standalone Python BLE Offline Finding Parser.

Interfaces with sniffle_receiver CLI or logs to capture raw BLE advertising packets
from a CC2652P dongle flashed with Sniffle firmware. Parses 31-byte advertising
payloads and isolates ephemeral public keys used by crowdsourced tracking networks
(Apple Find My, Google Find Hub, Tile, and Samsung SmartThings Find).
"""

import argparse
import re
import subprocess
import sys


def parse_sniffle_line(line: str):
    """Parses output lines from sniffle_receiver CLI.

    Extracts MAC address, RSSI, and raw payload hex bytes.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Matches MAC address, RSSI, and payload data in Sniffle log format
    match = re.search(
        r"AdvAddr=([0-9A-Fa-f:]+)\s+RSSI=(-?\d+)\s+Data=([0-9A-Fa-f]+)", line
    )
    if match:
        mac = match.group(1).upper()
        rssi = int(match.group(2))
        payload_hex = match.group(3).lower()
        return mac, rssi, payload_hex

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
    """Spawns sniffle_receiver process on specified serial port and BLE channel."""
    cmd = ["sniffle_receiver", "-p", port, "-c", str(channel)]
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
        print("[-] 'sniffle_receiver' command not found. Ensure Sniffle tools are in your PATH.")
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
