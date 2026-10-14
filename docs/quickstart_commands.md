# Sniffle Quickstart Commands & Dual-Dongle Playbook

## Overview

This guide centralizes standard commands and operational playbooks for single and dual Sniffle CC2652P / Sonoff ZBDongle-P adapters running the Sniffle firmware.

---

## 1. Quickstart Commands

### Checking Device Availability (`lsof`)

Always verify that the hardware device nodes are not in use before launching a sniffer:

```bash
lsof /dev/ttyUSB0 || echo "USB0 is idle and ready"
lsof /dev/ttyUSB1 || echo "USB1 is idle and ready"
```

### Primary Sniffing Commands

#### Baseline Sniffer Output (Live Stream)
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -b 2000000
```
*(For older CP2102 dongles limited to 921,600 baud, use `-b 921600`)*

#### Dongle 1: Scan & Record All Advertisements
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -b 2000000 -a -o /tmp/ads_capture.pcap
```

#### Dongle 2: Target Specific Peripheral & Follow Connection
```bash
python3 scripts/sniff_receiver.py -s /dev/ttyUSB1 -b 2000000 -m AA:BB:CC:DD:EE:FF -o /tmp/device_connection.pcap
```

#### Offline PCAP Decoding
```bash
python3 scripts/pcap_decoder.py -d /tmp/ads_capture.pcap > /tmp/decoded-ads_cap.txt
```

---

## 2. Multi-Dongle Workflow Capabilities

Flashing [nccgroup/Sniffle](https://github.com/nccgroup/Sniffle) onto Sonoff ZBDongle-P (Texas Instruments CC2652P) adapters converts Zigbee adapters into hardware-level **Bluetooth Low Energy (BLE 4.x and BLE 5)** packet sniffers.

A single Sniffle dongle scans primary advertising channels (37, 38, 39) and follows connections. However, once a dongle locks onto and follows an active connection, its radio is occupied hopping channels with that specific connection.

Running two dongles simultaneously on `/dev/ttyUSB0` and `/dev/ttyUSB1` enables three primary topologies:

### A. Continuous Scanner + Targeted Connection Follower
Keep Dongle 1 running as a wide-band advertisement scanner (`sniff_receiver.py -a` or `scanner.py`) to monitor all local broadcasts and RSSI levels, while assigning Dongle 2 to lock onto a specific MAC address (`-m`) or IRK (`-i`) and capture the full session.

### B. Simultaneous Target Tracking & Multi-Connection Capture
Sniff two independent encrypted or unencrypted BLE connections concurrently without missing packet handshakes.

### C. Differential RF Capture & Range Diagnostics
Place Dongle 1 near the central device (e.g., smartphone) and Dongle 2 near the peripheral (e.g., smart lock) to diagnose packet drops, signal attenuation, or transmission retries.

### D. Master / Slave Link Layer Traffic Relay
Coordinate Dongle 1 (`relay_master.py`) and Dongle 2 (`relay_slave.py`) to tunnel link-layer traffic across arbitrary network distances. See [`docs/relay_specifications.md`](relay_specifications.md).

---

## 3. Host Platform Serial Configuration

| Platform | Serial Port Pattern | Permission Configuration |
| :--- | :--- | :--- |
| **Linux** | `/dev/ttyUSB0`, `/dev/ttyUSB1` | Add user to dialout group: `sudo usermod -aG dialout $USER` |
| **macOS** | `/dev/cu.usbserial-*` | Standard driver permissions |
| **Windows** | `COM3`, `COM4` | Device Manager driver installation (Silicon Labs CP210x) |

---

## 4. Live Wireshark Streaming via Extcap

1. Locate your Wireshark personal extcap folder:
   - Wireshark $\rightarrow$ **Help** $\rightarrow$ **About Wireshark** $\rightarrow$ **Folders** $\rightarrow$ **Extcap path**.
2. Create a symlink to `sniffle_extcap.py`:
   ```bash
   mkdir -p ~/.local/lib/wireshark/extcap
   ln -s $(pwd)/scripts/sniffle_extcap.py ~/.local/lib/wireshark/extcap/
   chmod +x scripts/sniffle_extcap.py
   ```
3. Restart Wireshark. Each attached Sniffle dongle appears as a distinct capture interface (e.g., `Sniffle /dev/ttyUSB0`), allowing channel and target filtering directly from the GUI gear icon.
