"""Offline PCAP and Session Capture Replay view with Link Layer dissection."""

from __future__ import annotations

import io
import json
import sqlite3
import time
from typing import Any, Optional

import pandas as pd
import streamlit as st

from bluetooth_sniffle.protocol.mac import mac_to_str
from bluetooth_sniffle.sniff.pcap import PcapBleReader
from scripts.ble_antistalking_tracker import BLETrackerDB, classify_payload


def parse_uploaded_pcap(pcap_bytes: bytes) -> list[dict[str, Any]]:
    """Parse raw bytes of a DLT 256 PCAP into packet observation records.

    Args:
        pcap_bytes: Binary contents of a PCAP file.

    Returns:
        List of parsed packet observation dictionaries.
    """
    observations: list[dict[str, Any]] = []
    if not pcap_bytes:
        return observations

    stream = io.BytesIO(pcap_bytes)
    try:
        with PcapBleReader(stream) as reader:
            for pkt in reader:
                body = pkt.body
                # Standard ADV PDU header has 2 bytes: Type/Flags + Length
                # followed by 6 bytes of AdvA (MAC address)
                mac_str = "00:00:00:00:00:00"
                adv_payload_hex = ""
                if len(body) >= 8:
                    mac_bytes = body[2:8]
                    mac_str = mac_to_str(mac_bytes)
                    adv_payload = body[8:]
                    adv_payload_hex = adv_payload.hex()
                elif len(body) > 0:
                    adv_payload_hex = body.hex()

                net_type, eph_key = classify_payload(adv_payload_hex)
                dt_str = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(pkt.ts_epoch)
                )

                observations.append({
                    "timestamp": pkt.ts_epoch,
                    "datetime_str": dt_str,
                    "channel": pkt.ble_chan,
                    "rssi": pkt.rssi,
                    "mac_address": mac_str,
                    "network_type": net_type,
                    "ephemeral_key": eph_key,
                    "raw_payload": adv_payload_hex,
                })
    except Exception as e:
        st.warning(f"Warning parsing PCAP stream: {e}")

    return observations


def parse_session_json(json_bytes: bytes) -> list[dict[str, Any]]:
    """Parse a JSON session export file into observation records.

    Args:
        json_bytes: Binary contents of a JSON session capture file.

    Returns:
        List of validated packet dictionaries.
    """
    try:
        data = json.loads(json_bytes.decode("utf-8"))
        if isinstance(data, list):
            return [dict(item) for item in data if isinstance(item, dict)]
        return []
    except Exception as e:
        st.warning(f"Error parsing session JSON: {e}")
        return []


def render_offline_replay(
    tracker_db: Optional[BLETrackerDB] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Render the Offline PCAP & Session Replay view."""
    st.subheader("📁 Offline PCAP & Session Replay")
    st.markdown(
        "Upload and dissect saved DLT 256 PCAP captures and JSON telemetry sessions without active radio hardware."
    )

    uploaded_file = st.file_uploader(
        "Select Capture File (.pcap, .pcapng, .json):",
        type=["pcap", "json"],
        help="Upload Wireshark/DLT 256 PCAP files or exported Bluetooth-Sniffle JSON captures.",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        filename = uploaded_file.name.lower()

        if filename.endswith(".json"):
            records = parse_session_json(file_bytes)
        else:
            records = parse_uploaded_pcap(file_bytes)

        st.success(f"Parsed **{len(records):,}** packets from `{uploaded_file.name}`.")

        if records:
            df = pd.DataFrame(records)
            st.dataframe(
                df[["datetime_str", "channel", "mac_address", "rssi", "network_type", "ephemeral_key"]],
                width="stretch",
            )

            # Button to ingest into current database session
            if tracker_db and st.button("📥 Import Packets into Session Database"):
                imported = 0
                for r in records:
                    tracker_db.insert_observation(
                        mac_address=r["mac_address"],
                        rssi=r["rssi"],
                        network_type=r["network_type"],
                        ephemeral_key=r["ephemeral_key"],
                        channel=r["channel"],
                        raw_payload=r["raw_payload"],
                        timestamp=r["timestamp"],
                    )
                    imported += 1
                st.success(f"Successfully imported {imported:,} records into database! You can now analyze them in Telemetry, RSSI Trends, and Alert Feed.")
