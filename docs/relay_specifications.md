# Link Layer Traffic Relay Specifications (Dual-Dongle Topology)

## Overview

This specification defines the architecture, protocol flow, timing requirements, and operational procedures for executing Bluetooth Low Energy (BLE) Link Layer Traffic Relay attacks using two Sniffle devices.

The relay architecture bridges a genuine BLE central device (e.g., a smartphone or access controller) and a genuine BLE peripheral device (e.g., a smart lock, vehicle, or medical monitor) across arbitrary network distances while bypassing link-layer range restrictions.

---

## Relaying Link Layer Traffic

Sniffle can be used to perform [link-layer relaying](https://hardwear.io/netherlands-2022/presentation/bluetooth-LE-link-layer-relay-attacks.pdf)
of Bluetooth LE traffic. When performing relaying, one Sniffle device acts as a
BLE central (using `relay_master.py`) and a second Sniffle device acts as a BLE
peripheral (using `relay_slave.py`). Master and slave are historic terms for BLE
central and peripheral respectively. The relay master captures advertising and
scan response data from the genuine peripheral, then passes it to the relay slave.
The relay slave transmits advertisements and scan responses mimicking the genuine
peripheral and accepts connections. Upon accepting a connection, the relay slave
notifies the relay master, which then initiates a connection to the genuine
peripheral. From this point onwards, all link layer packets are forwarded
between the relay master and slave.

The relay master script provides functionality to request faster connection
intervals on one or both sides of the relay to reduce latency. If using the XDS110
as a USB/UART bridge, be aware that the XDS110 firmware introduces additional
latency to the relay unless you modify it as described below.

Please note that the relay master script creates a network listener that binds
to all interfaces (0.0.0.0), and the network protocol used to communicate
between the relaying devices provides no security. Only use these scripts in
trusted network environments.

Usage of the relay master (central) and slave (peripheral) scripts is shown below.
At present, extended advertising is not supported by the relay scripts.

```text
usage: relay_master.py [-h] [-s SERPORT] [-c {37,38,39}] [-m MAC] [-i IRK] [-S STRING]
                       [-P] [-q] [-Q PRELOAD] [-f] [-p] [-F] [-o OUTPUT]

Relay master script for Sniffle BLE5 sniffer

options:
  -h, --help            show this help message and exit
  -s, --serport SERPORT
                        Sniffer serial port name
  -c, --advchan {37,38,39}
                        Advertising channel to listen on
  -m, --mac MAC         Specify target MAC address
  -i, --irk IRK         Specify target IRK
  -S, --string STRING   Specify target by advertisement search string
  -P, --public          Supplied MAC address is public
  -q, --quiet           Don't show empty packets
  -Q, --preload PRELOAD
                        Preload expected encrypted connection parameter changes
  -f, --fastslave       Relay slave should request a fast connection interval
  -p, --pause           Wait for key press on master before relaying
  -F, --fastmaster      Relay master should specify a fast connection interval
  -o, --output OUTPUT   PCAP output file name
```

```text
usage: relay_slave.py [-h] [-s SERPORT] [-M MASTERADDR] [-q]

Relay slave script for Sniffle BLE5 sniffer

options:
  -h, --help            show this help message and exit
  -s, --serport SERPORT
                        Sniffer serial port name
  -M, --masteraddr MASTERADDR
                        IP address of relay master
  -q, --quiet           Don't show empty packets
```

---

## Master / Slave Topology Specification

The relay uses a **two-device hardware topology**. In a single-host laboratory or bench-test configuration, both devices plug into the same host:

```text
  GENUINE CENTRAL (C)                                        GENUINE PERIPHERAL (P)
  [Smartphone / Keyfob]                                      [Smart Lock / Beacon]
          │                                                            │
   (BLE Over-the-Air)                                           (BLE Over-the-Air)
          │                                                            │
          ▼                                                            ▼
┌──────────────────┐                                          ┌──────────────────┐
│   RELAY SLAVE    │                                          │   RELAY MASTER   │
│   (Peripheral)   │                                          │    (Central)     │
│   /dev/ttyUSB1   │                                          │   /dev/ttyUSB0   │
└─────────┬────────┘                                          └────────┬─────────┘
          │                                                            │
          │                   TCP Tunnel (Port 7352)                   │
          └────────────────────────────────────────────────────────────┘
```

### Role Allocation

| Component | Serial Node | Script | Radio Role | Physical Placement |
| :--- | :--- | :--- | :--- | :--- |
| **Relay Master** ($C_r$) | `/dev/ttyUSB0` | `scripts/relay_master.py` | BLE Central (Initiator) | Co-located with Genuine Peripheral ($P$) |
| **Relay Slave** ($P_r$) | `/dev/ttyUSB1` | `scripts/relay_slave.py` | BLE Peripheral (Advertiser) | Co-located with Genuine Central ($C$) |

---

## Detailed Protocol Sequence & State Machine

```text
Genuine Central (C)    Relay Slave (P_r)           Relay Master (C_r)    Genuine Peripheral (P)
        │                      │                           │                     │
        │                      │                     [Sniff Advert] <────── ADV_IND
        │                      │                     SCAN_REQ ──────────────────>│
        │                      │                     [Sniff Rsp]    <────── SCAN_RSP
        │                      │                           │                     │
        │                      │<── TCP: Payload Cloned ───│                     │
        │                      │                           │                     │
        │<────── ADV_IND ──────│ [Transmit Cloned Adv]     │                     │
        │─────── SCAN_REQ ────>│                           │                     │
        │<────── SCAN_RSP ─────│                           │                     │
        │                      │                           │                     │
        │────── CONNECT_IND ──>│ [Connection Accepted]     │                     │
        │                      │─── TCP: CONNECT_IND ─────>│                     │
        │                      │                           │ [Wait next advert]  │
        │                      │                           │ <───── ADV_IND ─────│
        │                      │                           │ ───── CONNECT_IND ─>│
        │                      │                           │                     │
        │                      ╔═══════════════════════════╗                     │
        │                      ║  Active Relay Connection  ║                     │
        │                      ╚═══════════════════════════╝                     │
        │────── LL_DATA ──────>│─── TCP: FORWARD_DATA ────>│────── LL_DATA ─────>│
        │<───── LL_DATA ───────│<── TCP: FORWARD_DATA ─────│<───── LL_DATA ──────│
```

### Execution Phases

1. **Hardware Verification**:
   - Check device locks using `lsof /dev/ttyUSB0` and `lsof /dev/ttyUSB1` to confirm both dongles are idle (exit code non-zero).
2. **Master Initialization**:
   - `relay_master.py` binds TCP socket `0.0.0.0:7352`.
   - Opens `/dev/ttyUSB0` at 2,000,000 baud (or 921,600 baud for CP2102).
   - Configures radio to listen on advertising channel 37, 38, or 39 for the target MAC, IRK, or payload string.
3. **Slave Initialization**:
   - `relay_slave.py` opens `/dev/ttyUSB1`.
   - Establishes TCP connection to master (`127.0.0.1:7352` locally or remote IP).
   - Performs a round-trip network latency ping exchange.
4. **Advertising Capture & Mimicry**:
   - Master captures `ADV_IND` and optional `SCAN_RSP` from genuine peripheral $P$.
   - Master transmits the raw advertising payload over TCP to the slave.
   - Slave configures its Sniffle radio to broadcast identical advertisements and respond to scan requests, masquerading as the peripheral.
5. **Connection Handshake Relay**:
   - Genuine central $C$ transmits `CONNECT_IND` to the slave $P_r$.
   - Slave immediately notifies master $C_r$ over TCP.
   - Master catches the next advertising interval of peripheral $P$ and transmits `CONNECT_IND`.
6. **Transparent Link-Layer Forwarding**:
   - Link Layer Data packets (`DPacketMessage`, `LlDataContMessage`) are forwarded bidirectionally.
   - Encryption (AES-CCM) is passed transparently without requiring decryption keys.

---

## Latency Reduction & Timing Constraints

BLE connection supervision timeouts (`connSupervisionTimeout`) range from 100 ms to 32 seconds (default 2–5 seconds). When link-layer packets traverse a serial bus and network socket, round-trip latency must stay well below the connection supervision timeout to prevent connection drop.

### 1. Connection Interval Optimization
- **`--fastslave` (`-f`)**: Causes the relay slave to request a connection interval update with a 7.5 ms interval (minimum permissible under BLE specifications) upon connection from central $C$.
- **`--fastmaster` (`-F`)**: Causes the relay master to initiate the genuine peripheral connection using a fast interval (7.5 ms).

### 2. TI XDS110 DMA Latency Mitigation
If using TI CC26x2 LaunchPad boards with integrated XDS110 debuggers, the default firmware uses DMA buffering that accumulates UART bytes for up to 15–30 ms before flushing. For relay attacks, this can cause packet timeouts.

To patch XDS110 firmware version 3.0.0.28 for low-latency interrupt mode:
```bash
cd ~/ti/uniflash_8.6.0/deskdb/content/TICloudAgent/linux/ccs_base/common/uscif/xds110/
cp firmware_3.0.0.28.bin firmware_3.0.0.28_fastuart.bin
printf '\x00\x1f' | dd of=firmware_3.0.0.28_fastuart.bin bs=1 seek=$((0x0A14)) conv=notrunc
sha256sum firmware_3.0.0.28_fastuart.bin
# Must match: c226f2e9cb2b9f0bc111ca11f2903d58d4065293468623428c0e8eeb22086dcf
./xdsdfu -m
./xdsdfu -f firmware_3.0.0.28_fastuart.bin -r
```

---

## Preloaded Encrypted Parameters (`-Q`)

If the connection is encrypted, link-layer control messages (such as `LL_CONNECTION_UPDATE_IND` and `LL_PHY_UPDATE_IND`) are encrypted. Sniffle cannot decrypt them without the Long Term Key (LTK), but needs the new connection interval to follow hopping.

Preload expected connection updates using `-Q <Interval>:<DeltaInstant>`:
- `Interval`: Multiples of 1.25 ms (e.g., `6` = 7.5 ms).
- `DeltaInstant`: Connection events until activation (must be $\ge 6$).
- Example: `-Q 6:6,39:6`

---

## Network Security Notice

> [!WARNING]
> **Insecure Network Protocol Warning**
> `relay_master.py` binds to all interfaces (`0.0.0.0:7352`). The communication protocol between `relay_master.py` and `relay_slave.py` **provides no encryption, authentication, or replay protection**.
>
> If deploying over untrusted or routable networks (e.g., internet, public Wi-Fi):
> - Tunnel TCP port 7352 over an encrypted SSH connection:
>   ```bash
>   ssh -N -L 7352:localhost:7352 user@relay-master-host
>   ```
> - Or deploy over a dedicated VPN / WireGuard tunnel.

---

## Step-by-Step Dual-Dongle Recipe (USB0 / USB1)

### 1. Preflight Port Check
```bash
# Verify both devices are idle
lsof /dev/ttyUSB0 || echo "USB0 is free"
lsof /dev/ttyUSB1 || echo "USB1 is free"
```

### 2. Launch Relay Master on `/dev/ttyUSB0`
```bash
python3 scripts/relay_master.py \
  -s /dev/ttyUSB0 \
  -m 12:34:56:78:9A:BC \
  -f -F \
  -o /tmp/relay_capture.pcap
```

### 3. Launch Relay Slave on `/dev/ttyUSB1`
```bash
python3 scripts/relay_slave.py \
  -s /dev/ttyUSB1 \
  -M 127.0.0.1
```

### 4. Verify Live In-Use Status
```bash
lsof /dev/ttyUSB0  # Return code 0 (IN USE)
lsof /dev/ttyUSB1  # Return code 0 (IN USE)
```
Check the **Streamlit Top App Bar** or **Radio Controls** view: both dongles will show `IN USE` with green indicator dots.
