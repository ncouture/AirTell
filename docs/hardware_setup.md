# Hardware Setup & Multi-Dongle Deployment Guide

## Overview

By flashing the open-source **Sniffle** firmware onto Texas Instruments CC1352 / CC2652 hardware—such as the **Sonoff ZBDongle-P** (CC2652P + CP2102N)—you convert inexpensive 2.4 GHz Zigbee bridges into enterprise-grade **Bluetooth Low Energy (BLE 4.x & BLE 5)** packet sniffers and transmitters.

---

## Supported Radio Hardware

| Hardware Board | Microcontroller | USB-to-UART Bridge | Default Baud Rate | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Sonoff Zigbee 3.0 Dongle Plus** | TI CC2652P | CP2102N | 2,000,000 baud | High-performance, portable aluminum enclosure. |
| **Sonoff Dongle (2022 Revision)** | TI CC2652P | CP2102 (non-N) | 921,600 baud | Requires slower `_1M.hex` firmware build. |
| **TI LaunchPad CC26x2R1** | TI CC2652R1 | TI XDS110 Debugger | 2,000,000 baud | Dual CDC-ACM serial ports (`/dev/ttyACM0`). |
| **CatSniffer v3** | TI CC1352P + RP2040 | Raspberry Pi RP2040 | 2,000,000 baud | Multi-protocol board. |

---

## Flashing Sniffle Firmware onto Sonoff CC2652P

Flashing uses the Texas Instruments serial bootloader via [`cc2538-bsl`](https://github.com/JelmerT/cc2538-bsl):

### 1. Standard CP2102N Dongles (2,000,000 Baud)
```bash
python3 cc2538-bsl.py -p /dev/ttyUSB0 --bootloader-sonoff-usb -ewv sniffle_cc1352p1_cc2652p1.hex
```

### 2. CP2102 (Non-N) Dongles (921,600 Baud)
If your dongle is an older revision with the CP2102 non-N chip:
```bash
python3 cc2538-bsl.py -p /dev/ttyUSB0 --bootloader-sonoff-usb -ewv sniffle_cc1352p1_cc2652p1_1M.hex
```

> **WARNING:** Do not flash an incompatible build variant or you risk locking yourself out of the bootloader.

---

## Host Configuration & Serial Permissions

### Linux
Ensure your user account belongs to the `dialout` group:
```bash
sudo usermod -aG dialout $USER
```
Log out and log back in for changes to take effect. Verify device enumeration:
```bash
ls -l /dev/ttyUSB*
```

### Device Usage Verification (`lsof`)
Always confirm that devices are not held open by background processes before launching a new capture session:
```bash
lsof /dev/ttyUSB0 || echo "USB0 is ready"
lsof /dev/ttyUSB1 || echo "USB1 is ready"
```

---

## Dual-Dongle Operational Topologies

A single Sniffle dongle is capable of scanning channels 37, 38, and 39. However, once a single dongle locks onto and follows an active BLE connection, its radio is occupied hopping channels with that specific connection.

Running two dongles simultaneously on `/dev/ttyUSB0` and `/dev/ttyUSB1` unlocks multi-device workflows:

### 1. Dual-Channel Parallel Logging
Eliminates channel-hop blind spots by locking Dongle 1 to Channel 37 and Dongle 2 to Channel 38:
```bash
# Terminal 1: Dongle 1 on Channel 37
python3 scripts/sniff_receiver.py -s /dev/ttyUSB0 -c 37 -a -o /tmp/ch37.pcap

# Terminal 2: Dongle 2 on Channel 38
python3 scripts/sniff_receiver.py -s /dev/ttyUSB1 -c 38 -a -o /tmp/ch38.pcap
```

### 2. Continuous Scanner + Targeted Connection Follower
Keep Dongle 1 running as a wide-band scanner to discover local broadcasts, while Dongle 2 follows a specific MAC connection:
```bash
# Dongle 1: Wide-band scanner
python3 scripts/scanner.py -s /dev/ttyUSB0 -c 37 -r -60

# Dongle 2: Target specific peripheral
python3 scripts/sniff_receiver.py -s /dev/ttyUSB1 -m AA:BB:CC:DD:EE:FF -o target.pcap
```

### 3. Master / Slave Link Layer Traffic Relay
Deploy Dongle 1 as a relay master ($C_r$) near the genuine peripheral and Dongle 2 as a relay slave ($P_r$) near the central:
```bash
# Terminal 1: Relay Master
python3 scripts/relay_master.py -s /dev/ttyUSB0 -m AA:BB:CC:DD:EE:FF -f -F -o /tmp/relay.pcap

# Terminal 2: Relay Slave
python3 scripts/relay_slave.py -s /dev/ttyUSB1 -M 127.0.0.1
```
See [`docs/relay_specifications.md`](relay_specifications.md) for full details.
