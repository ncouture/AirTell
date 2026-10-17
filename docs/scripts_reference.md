# Scripts Directory Technical Reference

This document provides a comprehensive operational and technical reference for all executable scripts and binaries located in the `scripts/` directory.

---

## Quick Reference Table

| Script / Tool | Type | Role | Key Arguments | Primary Input | Output |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [`advertiser.py`](#1-advertiserpy) | Python CLI | Peripheral transmitter & emulator | `-s`, `-b`, `-n` | Serial UART | Over-the-air BLE advertisements |
| [`ble_antistalking_tracker.py`](#2-ble_antistalking_trackerpy) | Python CLI | SQLite logger & threat heuristics | `-p`, `-c`, `-db`, `--twilio-*` | `sniff_receiver` stdout | SQLite DB & SMS alerts |
| [`ble_parser.py`](#3-ble_parserpy) | Python CLI | Offline Finding key extractor | `-p`, `-c` | Live RF or stdout lines | Classified tracker public keys |
| [`crackle`](#4-crackle) | C ELF Executable | BLE legacy encryption cracker | `-i`, `-o`, `-v`, `-l` | Captured PCAP file | Decrypted PCAP / PCAPNG file |
| [`initiator.py`](#5-initiatorpy) | Python CLI | Central connection initiator & tester | `-s`, `-m`, `-i`, `-S`, `-P` | Live RF & Serial UART | `CONNECT_IND`, ping & updates |
| [`pcap_decoder.py`](#6-pcap_decoderpy) | Python CLI | Offline PCAP advertisement dissector | `pcap`, `-d`, `-q` | PCAP capture file | Dissected AD structures & hexdump |
| [`radar_tomography.py`](#7-radar_tomographypy) | Python CLI | Radio tomographic sensing engine | `--simulate`, `--port1`, `--port2` | Multi-channel RSSI stream | 2D attenuation map & coordinates |
| [`relay_master.py`](#8-relay_masterpy) | Python CLI | Link layer relay (central role) | `-s`, `-m`, `-f`, `-F`, `-o` | Target peripheral RF | TCP tunnel stream (port 7352) |
| [`relay_slave.py`](#9-relay_slavepy) | Python CLI | Link layer relay (peripheral role) | `-s`, `-M`, `-q` | TCP tunnel stream | Replayed BLE advertisements |
| [`reset.py`](#10-resetpy) | Python CLI | Hardware MCU & state reset | `-s`, `-b` | Serial UART | Firmware reset confirmation |
| [`scanner.py`](#11-scannerpy) | Python CLI | Active BLE scanner & RSSI aggregator | `-s`, `-c`, `-r`, `-l`, `-d`, `-o` | Live RF | Sorted RSSI table & PCAP |
| [`sniffle_extcap.py`](#12-sniffle_extcappy) | Python Extcap | Wireshark live capture interface | `--capture`, `--fifo`, `--serport` | Hardware serial | Wireshark named pipe FIFO |
| [`sniff_receiver.py`](#13-sniff_receiverpy) | Python CLI | Core packet sniffer & connection follower | `-s`, `-c`, `-m`, `-i`, `-e`, `-o` | Live RF | Terminal packets & PCAP stream |
| [`uart_test.py`](#14-uart_testpy) | Python CLI | Serial round-trip latency benchmark | `-s`, `-b` | Serial UART | Round-trip latency (ms) |
| [`version_check.py`](#15-version_checkpy) | Python CLI | Firmware version & API validator | `-s`, `-b` | Serial UART | API level & firmware version |

---

## Detailed Script Descriptions

### 1. `advertiser.py`
* **Purpose**: Configures the connected Sniffle hardware to act as a connectable BLE peripheral device.
* **Mechanism**: Generates a random static address, sets radio TX power to +5 dBm, and transmits legacy advertisements (`ADV_IND`) on advertising channel 37 every 200 ms. Responds to `SCAN_REQ` with a configurable Complete Local Name in `SCAN_RSP` and accepts incoming connection attempts.
* **Usage**:
  ```bash
  python3 scripts/advertiser.py -s /dev/ttyUSB0 -n "BeaconLab"
  ```
* **Options**:
  - `-s`, `--serport`: Sniffer serial port name (auto-detected if omitted).
  - `-b`, `--baudrate`: Serial port baud rate (default: 2,000,000 baud).
  - `-n`, `--name`: Broadcast local name in scan response (default: "NCC Goat").

---

### 2. `ble_antistalking_tracker.py`
* **Purpose**: Anti-stalking engine and SQLite database logger for crowdsourced tracker networks (Apple Find My, Google Find Hub, Tile, and Samsung SmartThings Find).
* **Mechanism**: Spawns `sniff_receiver.py` as a subprocess, ingests raw advertising lines via `SniffleLineParser`, extracts rotating cryptographic keys, inserts records into `observations` table, and runs sliding-window heuristics to flag persistent tags across rotating MAC addresses. Dispatches real-time alerts via HTTP webhooks (with HMAC SHA-256 signatures), native OS desktop notifications (Linux `notify-send`, macOS `osascript`, Windows PowerShell), and optional SMS alerts via Twilio.
* **Usage**:
  ```bash
  python3 scripts/ble_antistalking_tracker.py -s /dev/ttyUSB0 -c 37 -db data/ble_tracker.db \
      --webhook-url https://security.corp.internal/ble-alerts \
      --webhook-secret "s3cr3t_antistalking_k3y" \
      --enable-desktop-notify
  ```
* **Options**:
  - `-s`, `--serial-port`: Serial device port (default: `/dev/ttyUSB0`).
  - `-c`, `--channel`: Primary advertising channel (37, 38, or 39).
  - `-db`, `--database`: SQLite database destination path (or `DATABASE` env var).
  - `--webhook-url`: Destination HTTP/HTTPS webhook URL for alert POST requests (or `WEBHOOK_URL` env var).
  - `--webhook-secret`: Shared secret for HMAC-SHA256 signature verification (`X-Signature-SHA256`) and Bearer authentication (`Authorization: Bearer <secret>`) (or `WEBHOOK_SECRET` env var).
  - `--enable-desktop-notify`: Enable native OS desktop notifications (or `DESKTOP_NOTIFY=1` env var).
  - `--twilio-sid`, `--twilio-token`, `--twilio-from`, `--twilio-to`: Twilio SMS credentials and phone numbers.

* **Webhook Payload Schema**:
  The HTTP POST payload is delivered as a JSON body with the following schema:
  ```json
  {
    "timestamp": 1700000000.0,
    "timestamp_iso": "2023-11-14T22:13:20+00:00",
    "tracker_id": "0102030405060708090a0b0c",
    "network_type": "Apple Find My",
    "packet_count": 8,
    "duration": 600.0,
    "duration_seconds": 600.0,
    "max_rssi": -55,
    "mean_rssi": -62.4,
    "avg_rssi": -62.4,
    "alert_level": "CRITICAL",
    "alert_message": "POSSIBLE STALKER DETECTED: Apple Find My beacon seen 8 times over 10.0 mins (Max RSSI: -55 dBm)"
  }
  ```

* **HMAC Signature Verification**:
  Receiving webhook endpoints can verify authenticity by computing the HMAC-SHA256 hex digest of the raw HTTP request body against the shared secret:
  ```python
  import hmac, hashlib

  computed_sig = hmac.new(secret.encode("utf-8"), request_body_bytes, hashlib.sha256).hexdigest()
  is_valid = hmac.compare_digest(computed_sig, request.headers.get("X-Signature-SHA256", ""))
  ```

* **Desktop Notifications & Headless Fallback**:
  - **Linux**: Dispatches high-urgency notifications using `notify-send -u critical`. Gracefully falls back (skips execution without error) when running headlessly without `DISPLAY` or `WAYLAND_DISPLAY`, or when the binary is not installed.
  - **macOS**: Dispatches native notifications via AppleScript (`osascript`).
  - **Windows**: Dispatches alert popups using PowerShell `System.Windows.Forms.MessageBox` or Windows `ctypes`.
  - **Deduplication Cooldown**: Alert storms are suppressed using a configurable 300-second (5-minute) cooldown window recorded in the SQLite `alerts` table.

---

### 3. `ble_parser.py`
* **Purpose**: Lightweight standalone stream dissector that extracts public key fragments from Offline Finding (OF) beacons.
* **Mechanism**: Parses raw hex payloads from `sniff_receiver.py`. Matches Apple Find My (`0x004C`, type `0x12`), Google Fast Pair (`0xFE9F`), Tile (`0xFEED`), and Samsung SmartThings Find (`0x0075`).
* **Usage**:
  ```bash
  python3 scripts/ble_parser.py -p /dev/ttyUSB0 -c 37
  ```

---

### 4. `crackle`
* **Purpose**: High-speed C-based BLE encryption cracking utility for Bluetooth LE legacy pairing.
* **Mechanism**: Cracks BLE Just Works and Passkey Entry legacy pairing handshakes by brute-forcing the Temporary Key (TK) using $M_{rand}$ and $S_{rand}$, and derives the Short Term Key (STK) and Long Term Key (LTK).
* **Usage**:
  ```bash
  ./scripts/crackle -i /tmp/pairing.pcap -o /tmp/decrypted.pcapng -v
  ```
* **Options**:
  - `-i <input.pcap>`: Path to input PCAP containing connection handshake.
  - `-o <output.pcap>`: Path to output decrypted PCAP/PCAPNG.
  - `-v`: Verbose connection and cracking output.
  - `-l <ltk_hex>`: Decrypt existing capture using pre-shared LTK.

---

### 5. `initiator.py`
* **Purpose**: Tests BLE connections by acting as an active central device (initiator).
* **Mechanism**: Scans for a target peripheral (by MAC address, IRK, or search string), sends a `CONNECT_IND` packet, transitions to a connected central role, sends periodic `LL_PING_REQ` packets, and executes connection parameter updates (`LL_CONNECTION_UPDATE_IND`).
* **Usage**:
  ```bash
  python3 scripts/initiator.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF
  ```
* **Options**:
  - `-s`, `--serport`: Sniffer serial port name.
  - `-m`, `--mac`: Target peripheral MAC address.
  - `-i`, `--irk`: Target peripheral Identity Resolving Key.
  - `-S`, `--string`: Target advertisement match string.
  - `-P`, `--public`: Target MAC address is public (default: random).

---

### 6. `pcap_decoder.py`
* **Purpose**: Offline dissector for Sniffle PCAP files (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`).
* **Mechanism**: Reads binary PCAPs generated by `sniff_receiver.py` or `scanner.py`, validates packet CRC and link-layer headers, and decomposes advertising data into structured AD records (Flags, Local Names, UUIDs, Manufacturer Specific Data).
* **Usage**:
  ```bash
  python3 scripts/pcap_decoder.py -d /tmp/capture.pcap
  ```
* **Options**:
  - `pcap`: Input PCAP capture file.
  - `-d`, `--decode`: Deep decode of advertising data structures.
  - `-q`, `--quiet`: Omit empty connection data packets from output.

---

### 7. `radar_tomography.py`
* **Purpose**: 2D Radio Tomographic Imaging (RTI) engine for device-free indoor localization and human presence sensing.
* **Mechanism**: Ingests multi-channel RSSI streams from two Sniffle dongles (e.g., Receiver 1 on Ch 37 and Receiver 2 on Ch 38). Projects RSSI attenuation onto a spatial ellipse weighting model, solving an inverse problem using Tikhonov regularization to image physical motion.
* **Usage**:
  ```bash
  # Headless simulation run:
  python3 scripts/radar_tomography.py --simulate --headless --max-frames 25

  # Live dual-dongle capture:
  python3 scripts/radar_tomography.py --port1 /dev/ttyUSB0 --port2 /dev/ttyUSB1 --chan1 37 --chan2 38
  ```
* **Options**:
  - `--simulate`: Run deterministic in-memory RF simulation.
  - `--replay <file>`: Replay recorded JSON RSSI session.
  - `--headless`: Run without graphical matplotlib window.
  - `--port1`, `--port2`: Primary and secondary serial dongle paths.
  - `--chan1`, `--chan2`: Channels assigned to each receiver.
  - `--grid-res`: Grid voxel resolution in meters (default: 0.2).

---

### 8. `relay_master.py`
* **Purpose**: Central component of Link Layer Traffic Relay attacks, co-located near genuine peripheral.
* **Mechanism**: Captures advertising and scan responses from target peripheral, sends payload over TCP to `relay_slave.py`, and upon notification connects to the genuine peripheral, forwarding link-layer frames bidirectionally.
* **Usage**:
  ```bash
  python3 scripts/relay_master.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF -f -F -o /tmp/relay.pcap
  ```

---

### 9. `relay_slave.py`
* **Purpose**: Peripheral component of Link Layer Traffic Relay attacks, co-located near genuine central.
* **Mechanism**: Connects to `relay_master.py` over TCP, clones target peripheral's MAC address and payload, broadcasts advertisements, accepts connection from central, and tunnels frames over TCP.
* **Usage**:
  ```bash
  python3 scripts/relay_slave.py -s /dev/ttyUSB1 -M 127.0.0.1
  ```

---

### 10. `reset.py`
* **Purpose**: Recovers locked or non-responsive Sniffle hardware.
* **Mechanism**: Sends byte-level firmware reset opcodes and performs `mark_and_flush` sequence over UART to synchronize host-dongle state without requiring physical board disconnection.
* **Usage**:
  ```bash
  python3 scripts/reset.py -s /dev/ttyUSB0
  ```

---

### 11. `scanner.py`
* **Purpose**: Active BLE discovery tool that collects advertisements, issues scan requests, and outputs a consolidated RSSI summary.
* **Mechanism**: Enters active scanning mode, suppresses repetitive duplicate stream output, and prints an aggregated report sorted by average RSSI upon stopping (`Ctrl-C`).
* **Usage**:
  ```bash
  python3 scripts/scanner.py -s /dev/ttyUSB0 -c 37 -r -60 -d
  ```

---

### 12. `sniffle_extcap.py`
* **Purpose**: Official Wireshark / TShark extcap interface plugin.
* **Mechanism**: Implements Wireshark Extcap interface protocol. Pipes live serial packets into a named FIFO pipe in `DLT_BLUETOOTH_LE_LL_WITH_PHDR` format, allowing Wireshark to configure channels, MAC filters, and modes via graphical controls.
* **Usage**:
  ```bash
  tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0" -w /tmp/live.pcap
  ```

---

### 13. `sniff_receiver.py`
* **Purpose**: Primary host-side packet sniffing and connection-following engine.
* **Mechanism**: Streams link-layer packets over UART, hops across advertising channels (37, 38, 39) when target filters are active, follows connections onto data channels, measures frequency hops, and saves PCAPs.
* **Usage**:
  ```bash
  # Targeted connection following:
  python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF -o conn.pcap

  # Passive multi-channel scan:
  python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -c 38 -a -r -50
  ```

---

### 14. `uart_test.py`
* **Purpose**: Diagnostic benchmarking tool measuring serial bus latency and transfer integrity.
* **Mechanism**: Sends variable-length random byte tokens (`COMMAND_MARKER`) to Sniffle firmware and calculates round-trip latency upon receiving matching `MESSAGE_MARKER` responses.
* **Usage**:
  ```bash
  python3 scripts/uart_test.py -s /dev/ttyUSB0
  ```

---

### 15. `version_check.py`
* **Purpose**: Hardware communication verification and firmware version query tool.
* **Mechanism**: Issues `COMMAND_GET_VERSION` and verifies major, minor, patch, and API level compatibility.
* **Usage**:
  ```bash
  python3 scripts/version_check.py -s /dev/ttyUSB0
  ```

---

### 16. Radar Tomography Test Suite Scripts
* **`test_radar_cli.py`**: Validates command-line argument parsing and flag handling for `radar_tomography.py`.
* **`test_radar_public.py`**: Verifies dynamic ambient transmitter discovery and link pair creation in public mode.
* **`test_radar_signal.py`**: Tests signal attenuation modeling, ellipse weight calculation, and Gaussian perturbation generation.
* **`test_radar_tomography.py`**: End-to-end integration tests verifying tomographic grid reconstruction and target coordinate detection.
