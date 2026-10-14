# Using TShark with Sniffle & Reading PCAP Files

## Key Concept: Extcap Plugins vs. PCAP Readers

In Wireshark and `tshark`, **extcap plugins** (such as `sniffle_extcap.py`) serve as **live capture interfaces** designed to capture streaming packets from external hardware dongles over a serial port (`/dev/ttyUSB*`). They are **not** file dissectors and cannot be used to open or read saved `.pcap` files.

You **do not need `sniffle_extcap.py` to read capture files**. Wireshark and `tshark` have native built-in support for the standard BLE link-layer format (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`, DLT 256) recorded by Sniffle.

---

## Part 1: Reading Saved PCAP Files with TShark

`tshark` reads existing capture files natively using the `-r` (`--read-file`) option.

### 1. Basic Packet Summary
```bash
tshark -r /tmp/ads_cap.pcap
```

### 2. Detailed Packet Dissection (Tree View)
To view full protocol fields and dissection trees:
```bash
# Decode and display the full packet tree (limit to first 5 packets with -c)
tshark -r /tmp/ads_cap.pcap -V -c 5
```

### 3. Display Filters
Apply Wireshark display filters with `-Y`:
```bash
# Filter for packets from a specific advertising address
tshark -r /tmp/ads_cap.pcap -Y "btle.advertising_address == aa:bb:cc:dd:ee:01"

# Filter for advertising indications (ADV_IND) only
tshark -r /tmp/ads_cap.pcap -Y "btle.advertising_header.pdu_type == 0"

# Filter by minimum RSSI signal strength
tshark -r /tmp/ads_cap.pcap -Y "btle_rf.signal_dbm >= -60"
```

### 4. Extracting Specific Fields
Extract delimited fields for scripting or data analysis:
```bash
tshark -r /tmp/ads_cap.pcap -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e btle.advertising_address \
  -e btle_rf.signal_dbm \
  -e btle_rf.rf_channel
```

### 5. Resolving MAC OUI Vendors
Enable MAC name resolution (`-N m`) while preserving the raw advertising address:
```bash
tshark -r /tmp/ads_cap.pcap -N m -Y "btle.advertising_address"
```

---

## Part 2: Using `sniffle_extcap.py` with TShark (Live Capture)

The extcap plugin streams live packets from a physical Sniffle BLE dongle into `tshark`.

### 1. Installation & Verification
Ensure `sniffle_extcap.py` is executable and linked into your personal Wireshark extcap directory:
```bash
chmod +x scripts/sniffle_extcap.py
mkdir -p ~/.local/lib/wireshark/extcap
ln -s $(pwd)/scripts/sniffle_extcap.py ~/.local/lib/wireshark/extcap/
```

Verify that `tshark` detects the interface:
```bash
tshark -D | grep sniffle
```
Output:
```text
sniffle (Sniffle BLE sniffer)
```

### 2. Passing Extcap Parameters in TShark
`tshark` passes extcap options using preference strings via `-o "extcap.sniffle.<option>:<value>"`. The `serport` parameter is required.

#### Live Terminal Stream
```bash
tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0"
```

#### Live Capture to a PCAP File
```bash
tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0" -w /tmp/ads_cap.pcap
```

### 3. Available Extcap Configuration Options

| Option | Example Values | Description |
| :--- | :--- | :--- |
| `extcap.sniffle.serport` | `/dev/ttyUSB0` | **(Required)** Serial device path |
| `extcap.sniffle.mode` | `passive_scan`, `active_scan`, `conn_follow` | Sniffer operating mode (default: `conn_follow`) |
| `extcap.sniffle.advchan` | `auto`, `all`, `37`, `38`, `39` | Advertising channel to listen on (default: `auto`) |
| `extcap.sniffle.mac` | `AA:BB:CC:DD:EE:FF` | Filter/follow by advertiser MAC address |
| `extcap.sniffle.rssi` | `-80` | Minimum RSSI filter threshold (-128 to 0) |
| `extcap.sniffle.extadv` | `true`, `false` | Capture BT5 extended advertisements |
| `extcap.sniffle.longrange` | `true`, `false` | Use long range (coded) PHY for primary advertising |
| `extcap.sniffle.crcerr` | `true`, `false` | Capture packets with CRC errors |

---

## Part 3: Dual-Dongle Parallel Capture Recipes

By utilizing two Sniffle dongles on `/dev/ttyUSB0` and `/dev/ttyUSB1`, you can eliminate channel-hop blindness by monitoring multiple primary channels simultaneously:

### Dual-Channel Parallel Logging (Channels 37 & 38)
```bash
# Terminal 1: Monitor Channel 37 via Dongle 1
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -w /tmp/ch37_capture.pcap

# Terminal 2: Monitor Channel 38 via Dongle 2
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB1" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:38" \
  -w /tmp/ch38_capture.pcap
```

### JSON Stream Export with Tee
Stream live JSON with OUI resolution while appending to disk:
```bash
tshark -i sniffle \
  -o "extcap.sniffle.serport:/dev/ttyUSB0" \
  -o "extcap.sniffle.mode:passive_scan" \
  -o "extcap.sniffle.advchan:37" \
  -T json \
  -N m \
  -Y "btle.advertising_address" | tee -a /tmp/live_stream.json
```
