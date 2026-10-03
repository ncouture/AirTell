# Sniffle CLI Operations Guide

This guide documents the command line utilities included with Sniffle in `scripts/`. It covers hardware verification, active scanning, packet sniffing, connection tracking, link-layer transmission, relay attacks, radio tomography, and offline packet analysis.

---

## Overview of Sniffle CLI Tools

Sniffle pairs host-side Python utilities with firmware running on supported Texas Instruments hardware (CC1352, CC2652, CC2651, CC1354) and compatible boards such as the Sonoff Zigbee 3.0 USB Dongle Plus and CatSniffer v3.

The Python scripts in `scripts/` communicate with the hardware over a serial interface using a base64-encoded binary command protocol.

The primary CLI utilities include:

* `version_check.py`: Probes the connected hardware and reports the firmware version and API level.
* `uart_test.py`: Runs a round-trip echo test to measure serial communication latency and packet integrity.
* `reset.py`: Sends reset commands to the firmware to recover from lockups or clear state.
* `scanner.py`: Performs active BLE scanning, collects advertisements and scan responses, and prints an aggregated summary sorted by signal strength.
* `sniff_receiver.py`: Captures advertisements and connection traffic, supports 3-channel primary advertising hopping, extended advertising, coded PHY, and PCAP export.
* `sniffle_extcap.py`: Extcap plugin enabling live capture directly in Wireshark and TShark.
* `pcap_decoder.py`: Decodes captured PCAP files offline and parses Bluetooth advertising data structures.
* `advertiser.py`: Transmits connectable legacy advertisements with a configurable device name and accepts incoming connections.
* `initiator.py`: Connects to a target peripheral and acts as a central device, sending link-layer test PDUs.
* `relay_master.py`: Acts as the central component of a link-layer relay, capturing peripheral advertising data and forwarding traffic over TCP.
* `relay_slave.py`: Acts as the peripheral component of a link-layer relay, impersonating the target peripheral and tunnelling link-layer frames to the master.
* `radar_tomography.py`: Passive radio tomographic imaging engine that processes multi-channel RSSI streams to detect and track indoor movement.

---

## Hardware Serial Port Detection & Baud Rates

### Auto-Detection Order

Sniffle automatically searches for supported hardware in the following order:

1. **TI XDS110 debug probe** (USB VID `0451`, PID `BEF3`). On Linux, XDS110 presents two CDC-ACM ports (typically `/dev/ttyACM0` and `/dev/ttyACM1`). Sniffle selects the first port in alphabetical order (`/dev/ttyACM0`).
2. **Sonoff Zigbee 3.0 USB Dongle Plus** (USB VID `10C4`, PID `EA60`). On Linux, this appears as `/dev/ttyUSB0` or `/dev/ttyUSB1`.
3. **CatSniffer v3** (USB VID `2E8A`, PID `00C0`). On Linux, this appears as `/dev/ttyACM0`.

If multiple devices are connected, or if a different USB-to-serial adapter is used, specify the port explicitly with `-s <port>` (for example, `-s /dev/ttyUSB1`).

### Baud Rate Selection

The default baud rate for Sniffle is **2,000,000 baud** (2M).

Certain older Sonoff dongles manufactured with the Silicon Labs CP2102 (non-N) bridge chip have a hardware limit of **921,600 baud**. For these devices, flash the `CC2652P1F_1M` firmware variant and pass `-b 921600` to all CLI commands.

---

## Hardware Verification & Diagnostics

Before capturing packets, verify that the hardware is responsive, that the firmware API version matches the host scripts, and that serial transfer latency is within acceptable limits.

### 1. Checking Firmware Version

Run `version_check.py` to confirm communication with the hardware:

```bash
python3 scripts/version_check.py
```

To specify an explicit port and baud rate:

```bash
python3 scripts/version_check.py -s /dev/ttyUSB0 -b 2000000
```

Expected output:

```text
VersionMeasurement(major=1, minor=10, patch=0, api_level=0)
```

If the tool reports `API level mismatch`, update either the firmware on the hardware or the Python host scripts so their API versions match. If the tool reports `Timeout probing firmware version`, check USB permissions (`sudo usermod -aG dialout $USER`) or run `reset.py`.

### 2. Testing UART Latency & Stability

`uart_test.py` sends random byte sequences (`cmd_marker`) of varying lengths to the hardware and measures round-trip time:

```bash
python3 scripts/uart_test.py -s /dev/ttyUSB0
```

Expected output:

```text
success, len 142, latency 2.1 ms
success, len 89, latency 1.8 ms
success, len 210, latency 2.4 ms
```

If round-trip latency exceeds 15 to 30 ms consistently on TI Launchpad boards, the XDS110 debugger firmware is buffering serial transfers. Consult the section on XDS110 UART latency below for the patch to enable interrupt-driven transfers.

### 3. Resetting Firmware State

If the sniffer firmware stops reporting packets or enters an unexpected state, use `reset.py` to issue software resets and flush UART buffers:

```bash
python3 scripts/reset.py -s /dev/ttyUSB0
```

Expected output:

```text
Sending reset commands...
Trying a mark and flush to get things flowing...
Reset success.
```

---

## Active Device Discovery (`scanner.py`)

The `scanner.py` utility discovers nearby advertising devices without flooding the terminal with continuous packet streams. It issues active scan requests, records unique MAC addresses, calculates RSSI statistics, and prints an aggregated summary sorted by signal strength when stopped (`Ctrl-C`):

```bash
python3 scripts/scanner.py -s /dev/ttyUSB0 -c 37 -r -60 -d -o /tmp/scan.pcap
```

* `-c 37`: Listens on advertising channel 37 (valid: 37, 38, 39).
* `-r -60`: Drops packets with RSSI lower than -60 dBm.
* `-d`, `--decode`: Deeply decodes Bluetooth SIG advertising data types.
* `-l`, `--longrange`: Scans on Bluetooth 5 coded (long range) PHY.
* `-o`: Writes received frames to PCAP.

---

## Packet Sniffing & Targeted Connection Following (`sniff_receiver.py`)

`sniff_receiver.py` is the primary sniffer engine.

### Modes of Operation

1. **Connection following mode (default):** Listens for advertisements, detects connection establishment (`CONNECT_IND` or `AUX_CONNECT_REQ`), and automatically follows the connection onto the 37 data channels.
2. **Passive scan mode (`-a` / `--advonly`):** Captures advertising packets without following connections.
3. **Active scan mode (`-A` / `--scan`):** Sends scan requests to capture scan responses without following connections.

### Three-Channel Advertising Hopping

Standard single-channel sniffers listen on only one primary channel. Because peripherals cycle advertisements across channels 37, 38, and 39, a central may send `CONNECT_IND` on channel 38 or 39, causing a single-channel sniffer to miss the connection entirely.

When a target filter (`-m`, `-i`, or `-S`) is specified **without explicitly fixing the channel via `-c`**, Sniffle hops between channels 37, 38, and 39 following the target advertiser.

#### Target by MAC Address:
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -m 12:34:56:78:9A:BC -o target_session.pcap
```

#### Target by Identity Resolving Key (IRK):
If the peripheral uses Resolvable Private Addresses (RPAs), pass its 128-bit big-endian IRK to resolve addresses dynamically:
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -i 4E0BEA5355866BE38EF0AC2E3F0EBC22 -o rpa_session.pcap
```

#### Target by Advertisement Payload String:
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -S "SmartLock" -o target.pcap
```

#### Bluetooth 5 Extended Advertising:
```bash
# Capture auxiliary advertising packets:
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -e -r -55

# Hop primary channels while capturing auxiliary pointers:
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -e -H -m 12:34:56:78:9A:BC
```

#### Encrypted Connection Parameter Preloading:
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -m 12:34:56:78:9A:BC -Q 6:6,39:6 -o encrypted_session.pcap
```

---

## Offline PCAP Dissection (`pcap_decoder.py`)

Decode captured PCAPs offline to inspect advertisement payloads, manufacturer data, and connection parameters:

```bash
python3 scripts/pcap_decoder.py -d /tmp/target_session.pcap
```

Quiet mode (suppress empty link-layer data packets):
```bash
python3 scripts/pcap_decoder.py -q -d /tmp/target_session.pcap
```

---

## Live Capture in Wireshark via Extcap (`sniffle_extcap.py`)

`sniffle_extcap.py` integrates Sniffle directly with Wireshark and TShark. When installed, Wireshark lists "Sniffle" as an available capture interface, allowing configuration through graphical controls.

### Installing the Plugin

#### Linux and macOS:
```bash
mkdir -p ~/.local/lib/wireshark/extcap
ln -s $(pwd)/scripts/sniffle_extcap.py ~/.local/lib/wireshark/extcap/
chmod +x ~/.local/lib/wireshark/extcap/sniffle_extcap.py
```

#### Verifying Detection:
```bash
tshark -D | grep -i sniffle
```
Output:
```text
sniffle (Sniffle BLE sniffer)
```

#### Live Capture via TShark:
```bash
tshark -i sniffle -o "extcap.sniffle.serport:/dev/ttyUSB0" -w /tmp/live.pcap
```

---

## Link-Layer Transmission & Emulation

Sniffle supports active link-layer transmission. The firmware provides low-level control of transmitted link-layer PDUs without going through a host HCI stack.

### Peripheral Emulation with `advertiser.py`

`advertiser.py` configures Sniffle to act as a connectable peripheral device. It generates a random static address, sets TX power to +5 dBm, advertises on channel 37 every 200 ms, and accepts connection requests:

```bash
python3 scripts/advertiser.py -s /dev/ttyUSB0 -n "Test Peripheral"
```

* `-n`, `--name`: Local name broadcast in the scan response data (defaults to "NCC Goat").
* `-s`: Serial port for the transmitting board.

When a central device connects, `advertiser.py` prints incoming packets and maintains connection state.

### Central Connection Testing with `initiator.py`

`initiator.py` scans for a specified target peripheral, transmits a `CONNECT_IND` packet to establish a connection, and acts as the central device:

```bash
# Connect by target MAC address:
python3 scripts/initiator.py -s /dev/ttyUSB0 -m 12:34:56:78:9A:BC

# Connect to a public address (non-random):
python3 scripts/initiator.py -s /dev/ttyUSB0 -m 12:34:56:78:9A:BC -P

# Connect by target name string:
python3 scripts/initiator.py -s /dev/ttyUSB0 -S "Test Peripheral"
```

Once connected, `initiator.py` exercises the connection by periodically sending `LL_PING_REQ` packets (every fourth message) and issuing an `LL_CONNECTION_UPDATE_IND` update packet at packet counter 64.

---

## Link-Layer Traffic Relay Attacks

Sniffle can perform link-layer relay attacks against Bluetooth LE connections. The relay consists of two Sniffle devices communicating over a network:

1. **Relay master (`relay_master.py`)**: Placed near the legitimate peripheral device. It captures advertising and scan response data, listens on TCP port 7352, and connects to the genuine peripheral when instructed.
2. **Relay slave (`relay_slave.py`)**: Placed near the legitimate central device. It connects to the master over TCP, clones the genuine peripheral's address and advertising payload, accepts connections from the central, and tunnels all link-layer traffic.

```text
[Central (C)]  <---BLE--->  [Relay Slave (P_r)]  <---TCP (7352)--->  [Relay Master (C_r)]  <---BLE--->  [Peripheral (P)]
```

### Step 1: Start the Relay Master (on `/dev/ttyUSB0`)

```bash
python3 scripts/relay_master.py -s /dev/ttyUSB0 -m 12:34:56:78:9A:BC -f -F -o /tmp/relay_capture.pcap
```

* `-s /dev/ttyUSB0`: Serial port of the master Sniffle board.
* `-m 12:34:56:78:9A:BC`: MAC address of the target peripheral.
* `-f`, `--fastslave`: Requests a fast connection interval on the slave side to reduce latency.
* `-F`, `--fastmaster`: Instructs the master to request a fast connection interval on the real target.
* `-o /tmp/relay_capture.pcap`: Saves all forwarded link-layer frames to PCAP.
* `-p`, `--pause`: Prompts for a key press on the master before starting the relay session.

The master script binds TCP port 7352 on `0.0.0.0` and waits for the slave to connect.

### Step 2: Start the Relay Slave (on `/dev/ttyUSB1`)

```bash
python3 scripts/relay_slave.py -s /dev/ttyUSB1 -M 127.0.0.1
```

* `-s /dev/ttyUSB1`: Serial port of the slave Sniffle board.
* `-M 127.0.0.1`: IP address of the relay master machine.

See [`docs/relay_specifications.md`](relay_specifications.md) for full protocol specifications, sequence diagrams, and timing constraints.

---

## Radio Tomographic Imaging & Passive Sensing (`radar_tomography.py`)

`radar_tomography.py` is a 2D radio tomographic imaging engine. It uses RSSI perturbations across RF links between ambient BLE transmitters and Sniffle receivers to detect and locate moving physical objects or people without requiring them to carry a device.

### 1. Simulating Indoor Human Sensing (Mock Mode)

To verify the tomographic reconstruction pipeline without physical hardware:

```bash
python3 scripts/radar_tomography.py --simulate --headless --max-frames 20
```

### 2. Replaying a Recorded RF Dataset

To replay pre-recorded RSSI samples from a JSON file:

```bash
python3 scripts/radar_tomography.py --replay data/radar_sample_data.json --headless
```

### 3. Live Dual-Dongle Multi-Channel Operation

To run live spatial tomography using two physical Sniffle boards acting as distributed receivers:

```bash
python3 scripts/radar_tomography.py \
  --port1 /dev/ttyUSB0 \
  --port2 /dev/ttyUSB1 \
  --chan1 37 \
  --chan2 38 \
  --public-mode \
  --room-width 15.0 \
  --room-height 10.0 \
  --grid-res 0.2
```

* `--port1`, `--port2`: Serial ports for Sniffle Receiver 1 (`R1`) and Receiver 2 (`R2`).
* `--chan1`, `--chan2`: Primary advertising channels assigned to each receiver.
* `--public-mode`: Automatically discovers ambient public BLE transmitters in the room.
* `--room-width`, `--room-height`: Room dimensions in meters.
* `--grid-res`: Resolution of spatial reconstruction cells in meters.

---

## Step-by-Step Multi-CLI Workflows

### Workflow 1: Discovery, Targeted Capture, and Offline Analysis

1. Discover target devices and identify the MAC address:
   ```bash
   python3 scripts/scanner.py -s /dev/ttyUSB0 -r -50 -d
   ```
2. Start targeted sniffing with three-channel hopping:
   ```bash
   python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF -o /tmp/target_session.pcap
   ```
3. Trigger a connection from the mobile app. Observe Sniffle detect the connection request and follow it onto data channels.
4. Press `Ctrl-C` after the session completes.
5. Inspect recorded packets offline:
   ```bash
   python3 scripts/pcap_decoder.py -q -d /tmp/target_session.pcap
   ```

### Workflow 2: End-to-End Hardware Loopback and Transmission Test

Validates link-layer transmission using two Sniffle boards connected to the same computer (`/dev/ttyUSB0` and `/dev/ttyUSB1`):

1. Check both ports with `lsof`:
   ```bash
   lsof /dev/ttyUSB0 || echo "USB0 is ready"
   lsof /dev/ttyUSB1 || echo "USB1 is ready"
   ```
2. Reset both boards:
   ```bash
   python3 scripts/reset.py -s /dev/ttyUSB0
   python3 scripts/reset.py -s /dev/ttyUSB1
   ```
3. Start the peripheral emulator on Board 1:
   ```bash
   python3 scripts/advertiser.py -s /dev/ttyUSB0 -n "SniffleLab"
   ```
4. Connect to the peripheral using the initiator on Board 2:
   ```bash
   python3 scripts/initiator.py -s /dev/ttyUSB1 -S "SniffleLab"
   ```
5. Observe the initiator detect the advertisement, transmit `CONNECT_IND`, send periodic `LL_PING_REQ` packets, and issue connection updates.

### Workflow 3: Capturing and Decrypting Legacy Pairing Traffic

1. Put the target peripheral into pairing mode.
2. Launch `sniff_receiver.py` with parameter preloading enabled:
   ```bash
   python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF -Q 6:6,39:6 -o /tmp/pairing.pcap
   ```
3. Initiate pairing from the central device (for example, enter PIN `123456`).
4. Stop capture with `Ctrl-C` after pairing completes.
5. Process the capture with `crackle`:
   ```bash
   ./scripts/crackle -i /tmp/pairing.pcap -o /tmp/decrypted_pairing.pcapng -v
   ```
6. Inspect the decrypted link-layer data:
   ```bash
   python3 scripts/pcap_decoder.py -q /tmp/decrypted_pairing.pcapng
   ```

---

## CLI Reference Summary Table

| Script | Primary Function | Key Arguments | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| `version_check.py` | Verify firmware version and API level | `-s`, `-b` | Hardware UART | Terminal version report |
| `uart_test.py` | Test serial link latency and stability | `-s`, `-b` | Hardware UART | Latency measurements |
| `reset.py` | Reset firmware and flush buffers | `-s`, `-b` | Hardware UART | Reset status |
| `scanner.py` | Active BLE discovery and RSSI summary | `-s`, `-b`, `-c`, `-r`, `-l`, `-d`, `-o` | Live RF | Terminal summary, PCAP |
| `sniff_receiver.py` | Sniff BLE5 advertisements and connections | `-s`, `-b`, `-c`, `-m`, `-i`, `-S`, `-r`, `-a`, `-A`, `-e`, `-H`, `-l`, `-q`, `-Q`, `-d`, `-o` | Live RF | Terminal packets, PCAP |
| `sniffle_extcap.py` | Wireshark extcap capture interface | `--capture`, `--fifo`, `--extcap-config`, `--serport`, `--mac`, `--irk`, `--mode` | Hardware UART | Wireshark FIFO stream |
| `pcap_decoder.py` | Offline PCAP packet and AD structure parser | `pcap`, `-q`, `-d` | PCAP file | Terminal decode and hexdump |
| `advertiser.py` | Peripheral advertiser and connectable emulator | `-s`, `-b`, `-n` | CLI arguments | Transmitted BLE frames |
| `initiator.py` | Central connection initiator and tester | `-s`, `-b`, `-c`, `-m`, `-i`, `-S`, `-l`, `-P` | Live RF | Transmitted BLE frames |
| `relay_master.py` | Central relay forwarder (peripheral-facing) | `-s`, `-c`, `-m`, `-i`, `-S`, `-P`, `-q`, `-Q`, `-f`, `-p`, `-F`, `-o` | Live RF, TCP | TCP stream, PCAP |
| `relay_slave.py` | Peripheral relay emulator (central-facing) | `-s`, `-M`, `-q` | TCP stream | Live RF, forwarded frames |
| `radar_tomography.py`| Radio tomographic imaging engine | `--simulate`, `--replay`, `--headless`, `--port1`, `--port2`, `--chan1`, `--chan2`, `--public-mode` | Live RF, JSON, or mock | Terminal metrics, 2D plots |

---

## Troubleshooting & Maintenance

### Checking If Device Is In Use (`lsof`)

```bash
lsof /dev/ttyUSB0
# Exit code 0: Device is open and in use by another process.
# Exit code non-zero: Device is idle and available.
```

### Serial Port Permissions

On Linux, accessing USB serial devices (`/dev/ttyACM*` or `/dev/ttyUSB*`) requires membership in the `dialout` group:

```bash
sudo usermod -aG dialout $USER
```

Log out and log back in for group changes to take effect.

### Handling Firmware Lockups

If the sniffer stops receiving packets while advertising traffic is known to be present:

1. Run `python3 scripts/reset.py -s /dev/ttyUSB0` to issue software synchronization markers and resets.
2. If the board does not recover, press the physical hardware reset button on the board.
3. Verify that the device is running the expected baud rate (2,000,000 baud default, or 921,600 baud for older CP2102 dongles).

### Minimizing Packet Loss

* **Distance:** When filtering by RSSI (`-r`), place the sniffer within 10 to 30 cm of the target.
* **Hopping:** Always omit `-c` when using `-m`, `-i`, or `-S` for connection tracking so Sniffle hops across channels 37, 38, and 39.
* **RF Environment:** Busy 2.4 GHz environments with high Wi-Fi traffic can cause dropped packets during the connection establishment window. Position the sniffer antenna close to the transmitter to maximize signal-to-noise ratio.
