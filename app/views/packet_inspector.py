"""Deep Packet Inspector view with multi-protocol filtering, AD structure decoding, and hex dumps."""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

import pandas as pd
import streamlit as st

AD_TYPE_NAMES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "Tx Power Level",
    0x16: "Service Data - 16-bit UUID",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0xFF: "Manufacturer Specific Data",
}


def decode_ad_structures(payload_hex: str) -> list[dict[str, Any]]:
    """Parse raw BLE advertising payload bytes into Advertising Data (AD) structures.

    Args:
        payload_hex: Hexadecimal string of advertising payload.

    Returns:
        List of decoded AD structure dictionaries.
    """
    structures: list[dict[str, Any]] = []
    if not payload_hex:
        return structures

    try:
        raw_bytes = bytes.fromhex(payload_hex.strip())
    except ValueError:
        return structures

    idx = 0
    total_len = len(raw_bytes)
    while idx < total_len:
        length = raw_bytes[idx]
        if length == 0:
            break
        if idx + 1 + length > total_len:
            # Malformed or truncated structure; capture remainder
            ad_type = raw_bytes[idx + 1] if idx + 1 < total_len else 0
            data_bytes = raw_bytes[idx + 2 :]
            structures.append({
                "length": length,
                "ad_type_hex": f"0x{ad_type:02x}",
                "ad_type_name": AD_TYPE_NAMES.get(ad_type, "Unknown Type (Truncated)"),
                "data_hex": data_bytes.hex(),
                "data_ascii": "",
            })
            break

        ad_type = raw_bytes[idx + 1]
        data_bytes = raw_bytes[idx + 2 : idx + 1 + length]
        ascii_repr = ""
        try:
            ascii_repr = data_bytes.decode("ascii").strip()
            if not ascii_repr.isprintable():
                ascii_repr = ""
        except Exception:
            ascii_repr = ""

        structures.append({
            "length": length,
            "ad_type_hex": f"0x{ad_type:02x}",
            "ad_type_name": AD_TYPE_NAMES.get(ad_type, f"User Defined (0x{ad_type:02x})"),
            "data_hex": data_bytes.hex(),
            "data_ascii": ascii_repr,
        })
        idx += 1 + length

    return structures


def render_packet_inspector(conn: Optional[sqlite3.Connection]) -> None:
    """Render the Deep Packet Inspector view."""
    st.subheader("🔍 Deep Packet Inspector & Protocol Dissection")
    st.markdown(
        "Low-level Link Layer payload analysis, BLE Advertising Data (AD) structure dissection, and raw hex exploration."
    )

    if not conn:
        st.warning("Database unavailable.")
        return

    # Filter row
    f_col1, f_col2, f_col3 = st.columns([2, 2, 1])
    with f_col1:
        net_options = ["All", "Apple Find My", "Google Find Hub", "Tile", "Samsung SmartThings Find", "Unknown"]
        selected_net = st.selectbox("Protocol Filter:", options=net_options)
    with f_col2:
        search_query = st.text_input("Filter by MAC or Key Substring:")
    with f_col3:
        row_limit = st.selectbox("Max Packets:", options=[100, 250, 500, 1000], index=1)

    query = """
    SELECT id, datetime_str, channel, mac_address, rssi, network_type, ephemeral_key, raw_payload
    FROM observations
    WHERE 1=1
    """
    params: list[Any] = []
    if selected_net != "All":
        query += " AND network_type = ?"
        params.append(selected_net)
    if search_query:
        query += " AND (mac_address LIKE ? OR ephemeral_key LIKE ?)"
        wildcard = f"%{search_query.strip()}%"
        params.extend([wildcard, wildcard])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(row_limit)

    try:
        df = pd.read_sql_query(query, conn, params=params)
    except Exception as e:
        st.error(f"Error executing packet query: {e}")
        return

    if df.empty:
        st.info("No packets match current filter parameters.")
        return

    st.write(f"Showing **{len(df)}** packets:")
    st.dataframe(
        df[["id", "datetime_str", "channel", "mac_address", "rssi", "network_type", "ephemeral_key"]],
        width="stretch",
    )

    st.markdown("#### 🔬 Detailed Payload Inspector")
    selected_pkt_id = st.selectbox(
        "Select Packet ID for Deep Dissection:",
        options=list(df["id"].values),
    )

    if selected_pkt_id is not None:
        pkt_row = df[df["id"] == selected_pkt_id].iloc[0]
        raw_hex = str(pkt_row["raw_payload"] or "")

        p_col1, p_col2 = st.columns([1, 1])
        with p_col1:
            st.markdown(f"**MAC Address:** `{pkt_row['mac_address']}`")
            st.markdown(f"**Network Protocol:** `{pkt_row['network_type']}`")
            st.markdown(f"**Channel:** `Ch {pkt_row['channel']}` | **RSSI:** `{pkt_row['rssi']} dBm`")
            st.markdown(f"**Ephemeral Public Key:** `{pkt_row['ephemeral_key'] or 'N/A'}`")
            st.code(raw_hex, language="text")

        with p_col2:
            st.markdown("**Advertising Data (AD) Structures:**")
            ad_structs = decode_ad_structures(raw_hex)
            if ad_structs:
                for idx, struct in enumerate(ad_structs, start=1):
                    with st.expander(f"AD #{idx}: {struct['ad_type_name']} ({struct['ad_type_hex']})", expanded=True):
                        st.write(f"- **Length:** {struct['length']} bytes")
                        st.write(f"- **Hex Data:** `{struct['data_hex']}`")
                        if struct["data_ascii"]:
                            st.write(f"- **ASCII Decoded:** `{struct['data_ascii']}`")
            else:
                st.info("No AD structures decoded from payload.")
