# Capturing and Dissecting Apple AirDrop BLE Advertisements

## Overview

Apple devices broadcast Bluetooth Low Energy (BLE) advertisements to announce capabilities and initiate peer-to-peer services (such as AirDrop, AirPlay, and Handoff) under the **Apple Continuity Protocol**.

When a user opens the iOS Share Sheet, toggles AirDrop in Control Center, or activates device discovery ("Everyone" or "Contacts Only"), the iOS device transmits specific bit flags in its advertising payload indicating that **AirDrop receiving is enabled**.

This guide details the exact byte structure, bitmask mechanics, and commands for capturing and dissecting these packets using **TShark** and **Sniffle**.

---

## Packet Structure & Byte Breakdown

Consider an exemplary Apple Continuity advertisement packet captured by Sniffle:

```text
0x0000:  60 17 55 44 33 22 11 00  02 01 1a 02 0a 09 0a ff  `.UD3"..........
0x0010:  4c 00 10 05 06 18 12 34  56                       L......4V
```

### Protocol Layer Decomposition

1. **BLE Advertising Data (AD) Structure Header**:
   - `0x0A`: AD structure length (10 bytes follow).
   - `0xFF`: AD Type = **Manufacturer Specific Data (MSD)**.
2. **Apple Company Identifier**:
   - `0x004C` (transmitted little-endian as `4C 00`): Apple, Inc.
3. **Apple Continuity Message Sub-Type**:
   - `0x10`: **Nearby Info Message** (`apple_message_types[0x10]`).
4. **Length**:
   - `0x05`: 5 bytes of Nearby Info data follow.
5. **Action & Status Byte (`0x06`)**:
   - High 4 bits (`0x06 >> 4 = 0x0`): Activity / Action code (e.g. unknown or idle).
   - Low 4 bits (`0x06 & 0x0F = 0x06`): Status bitflags:
     - `Bit 0 (0x01)`: Primary iCloud account device.
     - `Bit 2 (0x04, 0b0100)`: **AirDrop Receive Enabled**.

> **Evaluation Rule:** Any Apple Continuity packet of sub-type `0x10` where `(status_byte & 0x04) != 0` indicates that the device has AirDrop receiving enabled.

---

## Capturing with TShark & Sniffle Extcap

Wireshark dissects BLE advertising data under the `btcommon.eir_ad` display filter tree.

### Wireshark Filter Logic
- **Apple Company ID**: `btcommon.eir_ad.entry.company_id == 0x004c`
- **Nearby Info Sub-Type**: `btcommon.eir_ad.entry.data[0] == 0x10`
- **AirDrop Receive Bitmask**: `btcommon.eir_ad.entry.data[2] & 0x04 == 0x04`

Combined filter expression:
```text
btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04
```

---

## Practical Command Recipes

### 1. Live Terminal Stream (Filtered)
Capture live packets on advertising channel 37 and display only matching AirDrop packets:

```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -Y "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04"
```

### 2. Live Capture with Verbose Dissection & Hex Dump
Inspect the complete protocol tree and raw hex payload:

```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -Y "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04" \
  -V -x
```

### 3. Capture-All & Offline Two-Pass Filter
Because `-w` directly streams all packets from the interface to disk, record raw traffic first, then extract matching packets into a dedicated PCAP using `-2 -R`:

```bash
# Step 1: Record all advertisements
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -w /tmp/all_ads.pcap

# Step 2: Extract AirDrop-enabled packets to a clean PCAP
tshark -r /tmp/all_ads.pcap \
  -2 \
  -R "btcommon.eir_ad.entry.company_id == 0x004c && btcommon.eir_ad.entry.data[0] == 0x10 && btcommon.eir_ad.entry.data[2] & 0x04 == 0x04" \
  -w /tmp/airdrop_only.pcap
```

### 4. Sniffle Native Decoder
Inspect the extracted PCAP using the Sniffle command-line decoder:

```bash
python3 scripts/pcap_decoder.py -d /tmp/airdrop_only.pcap
```
