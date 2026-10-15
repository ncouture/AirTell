# AirTell Unified CLI Manual

**Authoritative Production-Grade Command-Line Reference & Operational Guide**  
**Framework**: `airtell` | **Specification Basis**: PoPETs 2025-0103 ("Your Signal, Their Data")

---

## Table of Contents

- [1. Overview & Architecture](#1-overview--architecture)
  - [CLI Invocation Syntax](#cli-invocation-syntax)
  - [Global Flags](#global-flags)
  - [Subcommand Alias Directory](#subcommand-alias-directory)
  - [Exit Codes Contract](#exit-codes-contract)
- [2. Zero-Device Scenarios (Offline PCAP Analysis & Simulation)](#2-zero-device-scenarios-offline-pcap-analysis--simulation)
  - [2.1 Offline PCAP Side-Channel Analysis (`sidechannel`)](#21-offline-pcap-side-channel-analysis-sidechannel)
  - [2.2 Trace Deanonymization & Trajectory Reconstruction (`deanonymize`)](#22-trace-deanonymization--trajectory-reconstruction-deanonymize)
  - [2.3 Full Offline Loopback Simulation (`mock-simulate`)](#23-full-offline-loopback-simulation-mock-simulate)
  - [2.4 In-Memory Software Simulation Suite](#24-in-memory-software-simulation-suite)
  - [2.5 Realistic Zero-Device Output Samples](#25-realistic-zero-device-output-samples)
- [3. Single-Device Scenarios (1 Sniffle Hardware Dongle)](#3-single-device-scenarios-1-sniffle-hardware-dongle)
  - [3.1 Supported Hardware Specifications](#31-supported-hardware-specifications)
  - [3.2 Hardware Port Verification & Dongle Health](#32-hardware-port-verification--dongle-health)
  - [3.3 Passive Single-Channel Packet Capture](#33-passive-single-channel-packet-capture)
  - [3.4 Live Stream Side-Channel Detection](#34-live-stream-side-channel-detection)
  - [3.5 Over-the-Air Rogue Tracking Beacon Injection](#35-over-the-air-rogue-tracking-beacon-injection)
  - [3.6 Realistic Single-Device Output Samples](#36-realistic-single-device-output-samples)
- [4. Dual-Device Scenarios (2 Sniffle Hardware Dongles)](#4-dual-device-scenarios-2-sniffle-hardware-dongles)
  - [4.1 Port Allocation & Collision Prevention](#41-port-allocation--collision-prevention)
  - [4.2 Topology A: Active Stimulator + Passive Observer](#42-topology-a-active-stimulator--passive-observer)
  - [4.3 Topology B: Dual-Channel Synchronized Passive Observer](#43-topology-b-dual-channel-synchronized-passive-observer)
  - [4.4 Full-Duplex BLE Pairing Relay & Replay (`relay`)](#44-full-duplex-ble-pairing-relay--replay-relay)
  - [4.5 Hardware Loopback Verification (`verify-hardware`)](#45-hardware-loopback-verification-verify-hardware)
  - [4.6 Realistic Dual-Device Output Samples](#46-realistic-dual-device-output-samples)
- [5. Exhaustive Subcommand Parameter Reference](#5-exhaustive-subcommand-parameter-reference)
  - [5.1 `sidechannel`](#51-sidechannel)
  - [5.2 `topology-a`](#52-topology-a)
  - [5.3 `topology-b`](#53-topology-b)
  - [5.4 `mock-simulate`](#54-mock-simulate)
  - [5.5 `verify-hardware`](#55-verify-hardware)
  - [5.6 `relay`](#56-relay)
  - [5.7 `deanonymize`](#57-deanonymize)
  - [5.8 `rogue-inject`](#58-rogue-inject)
- [6. Output Formats & Data Schemas](#6-output-formats--data-schemas)
  - [6.1 PCAP Wire Format (DLT 256)](#61-pcap-wire-format-dlt-256)
  - [6.2 JSON Session Telemetry Schema](#62-json-session-telemetry-schema)
  - [6.3 CSV Tabular Summary Schema](#63-csv-tabular-summary-schema)
- [7. Troubleshooting & Operational Guidance](#7-troubleshooting--operational-guidance)
  - [7.1 Linux Serial Port Permissions (`dialout`)](#71-linux-serial-port-permissions-dialout)
  - [7.2 Udev Rules for Non-Root Access](#72-udev-rules-for-non-root-access)
  - [7.3 Serial Port Contention & Lock Detection (`lsof`)](#73-serial-port-contention--lock-detection-lsof)
  - [7.4 Baud Rates & CP2102 Bridge Limits](#74-baud-rates--cp2102-bridge-limits)
  - [7.5 Missing Dongles & Auto-Discovery Diagnostics](#75-missing-dongles--auto-discovery-diagnostics)
  - [7.6 Synchronization Loss & Hardware Reset](#76-synchronization-loss--hardware-reset)
  - [7.7 Wireshark & TShark PCAP Dissection](#77-wireshark--tshark-pcap-dissection)

---

## 1. Overview & Architecture

The `airtell` unified executable orchestrates dual-dongle Bluetooth Low Energy (BLE) hardware, in-memory virtual radio buses, and protocol analysis engines. It evaluates crowdsourced tracking protocols (Apple Find My, Google Find Hub, Samsung SmartThings Find, Tile) and evaluates link-layer side-channels (differential encryption initiation, CSRK monotonic counters, and BAT allowlists) documented in PoPETs 2025-0103.

### CLI Invocation Syntax

```text
Usage: airtell [-h] [-v] [--version] <subcommand> [subcommand-options]
```

### Global Flags

- `-h`, `--help`: Output top-level usage syntax, command descriptions, and list of available subcommands. Exit code `0`.
- `-v`, `--verbose`: Enable detailed debug logging (`logging.DEBUG`). Format: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`. Default level is `logging.INFO`.
- `--version`: Output program version (`airtell 0.1.0`) and exit with code `0`.

### Subcommand Alias Directory

| Primary Subcommand | Command Aliases | Description |
| :--- | :--- | :--- |
| `sidechannel` | `side-channel`, `analyze-sidechannel` | Link-layer boolean side-channel analyzer |
| `topology-a` | `run-topology-a` | Stimulator (Dev 1) + Observer (Dev 2) |
| `topology-b` | `run-topology-b` | Dual-channel synchronized passive observer |
| `mock-simulate` | `mock-test` | 100% offline software loopback simulation |
| `verify-hardware` | *(none)* | 5-stage physical transmitter-receiver loopback |
| `relay` | *(none)* | Two-ended BLE pairing relay testbed |
| `deanonymize` | *(none)* | Trajectory reconstruction across RPA rotations |
| `rogue-inject` | *(none)* | Synthesize and inject rogue tracking beacons |

### Exit Codes Contract

The CLI enforces a deterministic semantic exit code contract:

| Exit Code | Classification | Trigger Conditions |
| :---: | :--- | :--- |
| **`0`** | **Clean / Success** | Command completed successfully with no errors. For `sidechannel`, indicates **no** exclusive-use side-channels detected (`has_detections == False`). |
| **`1`** | **Threat Detected / Verification Failed** | In `sidechannel`, exclusive-use side-channel signatures were **detected** (`has_detections == True`). In `verify-hardware`, fewer than 5 stages verified. In `mock-simulate`, missing beacon profiles or empty capture. In hardware allocation, insufficient dongles detected. |
| **`2`** | **Syntax / Device Error** | Invalid CLI argument, missing required input source, mutually conflicting input sources, nonexistent PCAP file, invalid CSRK hex or length, inaccessible serial interface, or out-of-bounds parameter. |

---

## 2. Zero-Device Scenarios (Offline PCAP Analysis & Simulation)

Zero-device scenarios operate strictly in software without physical radio hardware, serial cables, or root permissions. They are suitable for CI/CD pipelines, forensic trace triage, and algorithmic validation.

### 2.1 Offline PCAP Side-Channel Analysis (`sidechannel`)

The `sidechannel` command inspects Link-Layer packet traces (`.pcap` or `.pcapng` with DLT 256 headers) for three boolean side-channels that disclose device pairing or bypass Resolvable Private Address (RPA) randomization:
1. **Differential Encryption Initiation**: Identifies whether a peripheral possesses a shared Long-Term Key (`LL_START_ENC_RSP`) or rejects unauthenticated pairing attempts (`LL_REJECT_IND` / `LL_REJECT_EXT_IND`).
2. **CSRK Monotonic Counters**: Tracks 32-bit Connection Signature Resolving Key counters (`SC`) across signed writes, detecting counter increments, replay anomalies, or signature verification errors.
3. **Background Allowlist (BAT Attack)**: Detects selective probe response timing (~150 µs response to allowed peers vs silence to unbonded scanners) and connection parameter profiling.

#### Offline Analysis Commands

```bash
# 1. Comprehensive analysis across all analyzers with human-readable summary
airtell sidechannel -i captures/trace_session.pcap

# 2. Target-specific differential encryption inspection with JSON report export
airtell sidechannel -i captures/handshake.pcap --analyzer encryption --target "AA:BB:CC:DD:EE:02" --json -o reports/encryption_report.json

# 3. Cryptographic CSRK counter verification with 128-bit key
airtell sidechannel -i captures/signed_writes.pcap --analyzer csrk --csrk 00112233445566778899aabbccddeeff --json

# 4. BAT allowlist analysis with packet processing cap
airtell sidechannel -i captures/allowlist.pcap --analyzer bat --limit 500
```

### 2.2 Trace Deanonymization & Trajectory Reconstruction (`deanonymize`)

Evaluates tracking beacons across space and time to link rotating RPAs to the same physical mobile device:
- Detects static MAC leakage (Public or Random Static addresses in tracking frames).
- Identifies invariant IEEE OUI prefixes across rotations.
- Flags desynchronization between Link-Layer address rotation and payload key updates.

```bash
# Run deanonymization analysis on simulated multi-tag rotation trace
airtell deanonymize --mock

# Parameterized trajectory clustering with custom temporal gap and RSSI thresholds
airtell deanonymize --mock --max-gap 45.0 --max-rssi-delta 12.0

# Analyze offline PCAP trace
airtell deanonymize --pcap captures/session.pcap --max-gap 30.0 --max-rssi-delta 15.0
```

### 2.3 Full Offline Loopback Simulation (`mock-simulate`)

Coordinates a virtual stimulator and virtual observer over an in-memory `VirtualRadioBus`. Sequentially injects, captures, and validates all 6 standard beacon formats across all three primary advertising channels (37, 38, 39). Performs a bit-for-bit fidelity assertion ensuring 100% packet delivery.

```bash
# Execute standard simulation and verify delivery fidelity
airtell mock-simulate

# Full simulation generating complete PCAP, JSON, and CSV artifacts
airtell mock-simulate --duration-sec 2.0 --interval-ms 50 --pcap artifacts/mock_sim.pcap --json artifacts/mock_sim.json --csv artifacts/mock_sim.csv
```

### 2.4 In-Memory Software Simulation Suite

All adversarial and hardware subcommands support `--mock` execution for offline evaluation:

```bash
# In-memory side-channel stream simulation
airtell sidechannel --mock --analyzer all --summary

# Synthetic rogue tracking beacon injection
airtell rogue-inject --mock --network "Apple Find My" --count 5

# Synthetic pairing relay bridge emulation
airtell relay --mock --duration-sec 3.0

# 5-stage loopback verification in software
airtell verify-hardware --mock --burst-duration-sec 0.2 --interval-ms 50
```

### 2.5 Realistic Zero-Device Output Samples

#### Human-Readable Summary (`sidechannel --mock --summary`)
```text
======================================================================
AirTell Side-Channel Analysis Report
======================================================================
Overall Verdict:             PAIRED_SHARED_LTK
Detections Found:            YES
Target Filter:               None (all addresses)
Total Packets Processed:     17
Total Findings Emitted:      9
Confirmed Exclusive Devices: AA:BB:CC:DD:EE:01, AA:BB:CC:DD:EE:02
----------------------------------------------------------------------
Active Analyzer Results:
  * [DIFFERENTIAL_ENCRYPTION] Verdict: PAIRED_SHARED_LTK
    Summary: Observed 1 session(s) with confirmed shared LTK possession via LL_START_ENC_RSP across 1 connection(s).
    Findings (1):
      - [PAIRED_SHARED_LTK] AA:BB:CC:DD:EE:02 -> AA:BB:CC:DD:EE:01 (conf: 1.00)
  * [CSRK_COUNTER] Verdict: SEQUENTIAL_MONOTONIC
    Summary: Observed 5 strictly monotonic sequential signed write(s) with 0 anomalies.
    Findings (5):
      - [SEQUENTIAL_MONOTONIC] AA:BB:CC:DD:EE:01 -> AA:BB:CC:DD:EE:02 (conf: 0.90)
      - [SEQUENTIAL_MONOTONIC] AA:BB:CC:DD:EE:01 -> AA:BB:CC:DD:EE:02 (conf: 1.00)
      - [SEQUENTIAL_MONOTONIC] AA:BB:CC:DD:EE:01 -> AA:BB:CC:DD:EE:02 (conf: 1.00)
      - [SEQUENTIAL_MONOTONIC] AA:BB:CC:DD:EE:01 -> AA:BB:CC:DD:EE:02 (conf: 1.00)
      - [SEQUENTIAL_MONOTONIC] AA:BB:CC:DD:EE:01 -> AA:BB:CC:DD:EE:02 (conf: 1.00)
  * [BAT_ALLOWLIST] Verdict: ALLOWLIST_CONFIRMED
    Summary: BAT Allowlist side-channel confirmed: 1 peripheral(s) exhibited selective probe response to allowed peers and silence to unbonded scanners.
    Findings (3):
      - [PROFILE_MATCH] AA:BB:CC:DD:EE:02 -> AA:BB:CC:DD:EE:01 (conf: 0.95)
      - [PROFILE_MATCH] AA:BB:CC:DD:EE:02 -> AA:BB:CC:DD:EE:01 (conf: 0.95)
      - [ALLOWLIST_CONFIRMED] AA:BB:CC:DD:EE:02 -> AA:BB:CC:DD:EE:01 (conf: 1.00)
======================================================================
```

#### Simulation Verification (`mock-simulate`)
```text
2026-10-14 15:46:09,105 [INFO] airtell.topology.topology_a: Topology A started: Stimulator (mock://stimulator), Observer (mock://observer, Ch 37, Hop=True)
2026-10-14 15:46:09,832 [INFO] airtell.topology.topology_a: Topology A stopped cleanly.
2026-10-14 15:46:09,832 [INFO] __main__: Mock simulation completed: 100% fidelity, 18 packets captured across channels [37, 38, 39].
Mock simulation PASSED: 100% packet delivery fidelity verified across all primary channels.
```

---

## 3. Single-Device Scenarios (1 Sniffle Hardware Dongle)

Single-device workflows utilize exactly one physical USB Sniffle radio dongle connected to the host.

### 3.1 Supported Hardware Specifications

| Hardware Platform | USB VID:PID | UART Bridge Chip | Default Baud | RF Power Range | Physical Connector |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **Sonoff Zigbee 3.0 Dongle Plus** | `10C4:EA60` | Silicon Labs CP2102 / CP2102N | 921,600 / 2,000,000 | -20 to +10 dBm | External SMA Antenna |
| **TI CC26x2 / CC1352 LaunchPad** | `0451:BEF3` | TI XDS110 Class Application UART | 2,000,000 | -20 to +5 dBm | Micro-USB + Onboard Antenna |
| **Electronic Cats CatSniffer V3** | `2E8A:00C0` | Raspberry Pi RP2040 USB Bridge | 2,000,000 | -20 to +10 dBm | External SMA Antenna |

> ⚠️ **CP2102 Baud Rate Advisory**: Older Sonoff dongles contain Silicon Labs CP2102 (non-N) bridges that cannot exceed 921,600 baud. The framework automatically detects non-N revisions and caps baud rate to prevent UART FIFO overflow. See [7.4 Baud Rates & CP2102 Bridge Limits](#74-baud-rates--cp2102-bridge-limits).

### 3.2 Hardware Port Verification & Dongle Health

Check serial port connectivity, query running firmware versions, and perform hardware resets:

```bash
# Verify single-dongle port connectivity and baseline responsiveness
airtell verify-hardware --dev1 /dev/ttyUSB0 --burst-duration-sec 0.5

# Query active Sniffle firmware version directly via script helper
python3 -m airtell.scripts.version_check -s /dev/ttyUSB0

# Execute 5-stage reset burst and buffer flush via script helper
python3 -m airtell.scripts.reset -s /dev/ttyUSB0
```

### 3.3 Passive Single-Channel Packet Capture

Run passive advertising capture locked to channel 37, 38, or 39:

```bash
# Passive packet capture locked to advertising channel 37
airtell topology-a --dev2 /dev/ttyUSB0 --chan 37 --pcap /tmp/chan37.pcap

# Capture with target MAC address filter and RSSI threshold
python3 -m airtell.scripts.sniff_receiver -s /dev/ttyUSB0 -m "AA:BB:CC:DD:EE:FF" -r -75 -o captures/target.pcap
```

### 3.4 Live Stream Side-Channel Detection

Attaches protocol analyzers directly to an incoming serial stream on `/dev/ttyUSB0`:

```bash
# Run real-time side-channel analysis across all engines
airtell sidechannel --live /dev/ttyUSB0 --analyzer all --summary

# Monitor specific peripheral RPA with structured JSON export
airtell sidechannel --live /dev/ttyUSB0 --analyzer encryption --target "45:67:89:AB:CD:EF" --json -o live_sidechannel.json
```

**UART Synchronization**: On startup, `mark_and_flush()` sends `COMMAND_MARKER` (`0x00`) and drains the UART FIFO until `MESSAGE_MARKER` (`0x01`) is returned. This clears stale bytes from previous runs. Pressing `Ctrl-C` triggers a graceful shutdown that flushes remaining packets and finalizes open PCAP files.

### 3.5 Over-the-Air Rogue Tracking Beacon Injection

Injects crafted connectionless advertising bursts into the physical environment to evaluate tracking infrastructure:

```bash
# Inject Apple Find My beacon burst (5 packets, 1.0s interval)
airtell rogue-inject --port /dev/ttyUSB0 --network "Apple Find My" --count 5 --interval 1.0 --channel 37

# Inject Google Find Hub beacon with custom key and MAC address
airtell rogue-inject --port /dev/ttyUSB0 --network "Google Find Hub" --key "0102030405060708090a0b0c0d0e0f10" --mac "40:11:22:33:44:55" --count 10 --interval 0.5
```

### 3.6 Realistic Single-Device Output Samples

#### Rogue Beacon Injection (`rogue-inject`)
```text
Injected 5 rogue beacon packets for network 'Apple Find My' on channel 37 via /dev/ttyUSB0.
```

---

## 4. Dual-Device Scenarios (2 Sniffle Hardware Dongles)

Dual-device workflows coordinate two physical Sniffle dongles concurrently to execute coordinated red-teaming and traffic analysis.

### 4.1 Port Allocation & Collision Prevention

The framework utilizes `allocate_dual_ports(dev1, dev2)` from `airtell.device.serial_port`:
- When ports are omitted, it discovers connected devices via USB VID/PID and assigns two distinct devices.
- It guarantees invariant `dev1 != dev2`. If identical ports are specified, it exits with an allocation collision error.
- It checks port availability with `lsof` before opening to prevent conflicting processes from corrupting the stream.

### 4.2 Topology A: Active Stimulator + Passive Observer

Coordinates Device 1 as an active transmitter (broadcasting synthesized beacons with palindromic MACs) and Device 2 as a passive receiver capturing mobile scan requests (`SCAN_REQ`) and connection attempts:

```bash
airtell topology-a \
  --dev1 /dev/ttyUSB0 \
  --dev2 /dev/ttyUSB1 \
  --chan 37 \
  --burst-type ibeacon \
  --interval-ms 100 \
  --duration-sec 10.0 \
  --pcap captures/topo_a.pcap \
  --json captures/topo_a.json \
  --csv captures/topo_a.csv \
  --correlate
```

#### Physical Setup & RF Antenna Spacing for Topology A

```text
       +-------------------------------------------------+
       |                  Host Computer                  |
       |  (airtell topology-a --correlate)     |
       +--------------------+-----------------------+----+
                            |                       |
                 /dev/ttyUSB0                       /dev/ttyUSB1
                            |                       |
                     [Device 1: Tx]          [Device 2: Rx]
                      (Stimulator)             (Observer)
                     Antenna: Vert            Antenna: Vert
                            |                       ^
                 Broadcast: | (15-30 cm sep)        | Capture:
                 Palindromic|                       | SCAN_REQ /
                 iBeacon    |                       | SCAN_RSP
                            v                       |
                       +---------------------------------+
                       |       Victim BLE Device         |
                       |       (Smartphone / Tag)        |
                       |          (1 - 2 meters)         |
                       +---------------------------------+
```

- **Antenna Spacing**: Maintain **15 cm to 30 cm** physical separation between the Device 1 transmitting antenna and Device 2 receiving antenna. Placing them closer than 10 cm can saturate the Low-Noise Amplifier (LNA) on the receiver, blinding it to weaker response packets from the target device.
- **Power Supply**: Plug dongles into separate root USB controllers or an externally powered USB hub to prevent voltage drops during simultaneous transmission and reception.

### 4.3 Topology B: Dual-Channel Synchronized Passive Observer

Overcomes **channel-hop blindness** by locking Device 1 to Channel 37 and Device 2 to Channel 38 (or 39). Captured streams are merged in real time into a strictly timestamp-ordered PCAP file:

```bash
airtell topology-b \
  --dev1 /dev/ttyUSB0 \
  --dev2 /dev/ttyUSB1 \
  --chan1 37 \
  --chan2 38 \
  --duration-sec 30.0 \
  --pcap captures/topo_b_merged.pcap \
  --json captures/topo_b_telemetry.json \
  --csv captures/topo_b_summary.csv
```

#### Monotonic Timestamp Merging Architecture

- Independent reader threads push raw frames to separate internal queues.
- A background merger thread drains queues and sorts packets by hardware microsecond timestamp (`pkt.ts`).
- A **30 ms watermark window** prevents packet reordering caused by slight serial latency differences between USB-to-UART bridge chips.
- **Antenna Positioning**: Mount both antennas parallel with vertical polarization separated by **5 cm to 10 cm** to ensure identical spatial gain.

### 4.4 Full-Duplex BLE Pairing Relay & Replay (`relay`)

Deploys a full-duplex Link-Layer proxy between a legitimate central (mobile phone) and peripheral (smart lock/tag):
- **Device 1 (`--port1`)**: Acts as sniffer and central proxy near peripheral.
- **Device 2 (`--port2`)**: Acts as peripheral proxy near central.
- Relays Link-Layer PDUs, tunneling pairing handshakes (`SMP_PAIRING_REQUEST`, `SMP_PAIRING_FAILED`) and recording pairing failure reason codes.

```bash
airtell relay --port1 /dev/ttyUSB0 --port2 /dev/ttyUSB1 --duration-sec 60.0
```

#### Physical Setup & RF Isolation for BLE Relay

```text
+------------------------------------+       +------------------------------------+
|               ROOM A               |       |               ROOM B               |
|                                    |       |                                    |
|   [Real Central (C)]               |       |   [Real Peripheral (P)]            |
|       (Victim phone)               |       |       (Smart lock / tag)           |
|            | (RF Over-The-Air)     |       |            | (RF Over-The-Air)     |
|            v                       |       |            v                       |
|   [Relay Slave (P_r)]              |       |   [Relay Master (C_r)]             |
|   Dongle: /dev/ttyUSB1             |       |   Dongle: /dev/ttyUSB0             |
|   (Impersonating Peripheral)       |       |   (Impersonating Central)          |
+--------------------+---------------+       +--------------------+---------------+
                     |                                            |
                     +=========== TCP Socket / Relay Bridge ======+
                                  (127.0.0.1 or LAN Ethernet)
```

- **RF Isolation**: Direct over-the-air communication between Central and Peripheral must be prevented. Place Central and Relay Slave in Room A (or an RF shield box), and Peripheral and Relay Master in Room B.
- See [relay_specifications.md](relay_specifications.md) for timing parameters and PDU sequences.

### 4.5 Hardware Loopback Verification (`verify-hardware`)

Executes the automated 5-stage transmitter-to-receiver hardware verification specified in ORIGINAL_REQUEST §R4. Verifies that Device 1 broadcasts and Device 2 captures and decodes:
1. **Stage 1**: Apple iBeacon
2. **Stage 2**: Radius Networks AltBeacon
3. **Stage 3**: Google Eddystone-UID
4. **Stage 4**: Google Eddystone-URL
5. **Stage 5**: Google/Apple GAEN

```bash
airtell verify-hardware \
  --dev1 /dev/ttyUSB0 \
  --dev2 /dev/ttyUSB1 \
  --chan 37 \
  --burst-duration-sec 0.5 \
  --interval-ms 50 \
  --pcap /tmp/hw_verify.pcap \
  --json /tmp/hw_verify.json
```

### 4.6 Realistic Dual-Device Output Samples

#### Hardware Loopback Verification Output (`verify-hardware`)
```text
2026-10-14 15:47:21,006 [INFO] airtell.topology.topology_a: Topology A started: Stimulator (/dev/ttyUSB0), Observer (/dev/ttyUSB1, Ch 37, Hop=False)
2026-10-14 15:47:21,509 [INFO] __main__: Stage 1/5 (Apple iBeacon): PASSED
2026-10-14 15:47:22,013 [INFO] __main__: Stage 2/5 (Radius Networks AltBeacon): PASSED
2026-10-14 15:47:22,516 [INFO] __main__: Stage 3/5 (Google Eddystone-UID): PASSED
2026-10-14 15:47:23,020 [INFO] __main__: Stage 4/5 (Google Eddystone-URL): PASSED
2026-10-14 15:47:23,523 [INFO] __main__: Stage 5/5 (Google/Apple GAEN): PASSED
2026-10-14 15:47:23,524 [INFO] airtell.topology.topology_a: Topology A stopped cleanly.
Hardware loopback verification PASSED: 5/5 stages verified.
```

---

## 5. Exhaustive Subcommand Parameter Reference

Every option documented below corresponds directly to `create_parser()` in `src/airtell/cli.py`.

### 5.1 `sidechannel`

Aliases: `side-channel`, `analyze-sidechannel`

```text
Usage: airtell sidechannel [-h] (-i PCAP | --live LIVE | --mock)
                                    [--analyzer {all,encryption,csrk,bat}]
                                    [--target TARGET] [--csrk CSRK] [--json]
                                    [-o OUTPUT] [--summary] [--limit LIMIT]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `-i`, `--pcap`, `--input` | `str` | None | `None` | No* | Path to input PCAP / capture file |
| `--live` | `str` | None | `None` | No* | Serial port / interface for live sniffing stream |
| `--mock` | flag | None | `False` | No* | Run with mock simulation stream |
| `--analyzer` | `str` | `all`, `encryption`, `csrk`, `bat` | `"all"` | No | Analyzer selection: 'all', 'encryption', 'csrk', or 'bat' (default: all) |
| `--target` | `str` | None | `None` | No | Target MAC / RPA address filter |
| `--csrk` | `str` | None | `None` | No | 16-byte hex string CSRK for cryptographic signature verification |
| `--json` | flag | None | `False` | No | Output report in JSON format |
| `-o`, `--output` | `str` | None | `None` | No | File path to save output report (JSON or text) |
| `--summary` | flag | None | `False` | No | Include verbose human-readable summary |
| `--limit`, `--max-packets` | `int` | None | `None` | No | Maximum number of packets to process |

*\*Note: Exactly one input source (`--pcap`, `--live`, or `--mock`) is required.*

### 5.2 `topology-a`

Aliases: `run-topology-a`

```text
Usage: airtell topology-a [-h] [--dev1 DEV1] [--dev2 DEV2] [--mock]
                                   [--chan {37,38,39}]
                                   [--burst-type {ibeacon,altbeacon,eddystone-uid,eddystone-url,eddystone-tlm,gaen}]
                                   [--interval-ms INTERVAL_MS]
                                   [--duration-sec DURATION_SEC]
                                   [--pcap PCAP] [--json JSON] [--csv CSV]
                                   [--correlate]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--dev1` | `str` | None | `None` | No | Device 1 serial port (stimulator; auto-discovered if omitted) |
| `--dev2` | `str` | None | `None` | No | Device 2 serial port (observer; auto-discovered if omitted) |
| `--mock` | flag | None | `False` | No | Run with in-memory mock serial devices |
| `--chan` | `int` | `37`, `38`, `39` | `37` | No | Observer capture channel (default: 37) |
| `--burst-type` | `str` | `ibeacon`, `altbeacon`, `eddystone-uid`, `eddystone-url`, `eddystone-tlm`, `gaen` | `"ibeacon"` | No | Beacon advertising profile to inject (default: ibeacon) |
| `--interval-ms` | `int` | `20`..`65535` | `100` | No | Advertising interval in milliseconds (default: 100) |
| `--duration-sec` | `float` | `>= 0.0` | `5.0` | No | Total execution duration in seconds (default: 5.0) |
| `--pcap` | `str` | None | `None` | No | Output PCAP file path |
| `--json` | `str` | None | `None` | No | Output JSON session telemetry path |
| `--csv` | `str` | None | `None` | No | Output CSV summary path |
| `--correlate` | flag | None | `False` | No | Enable stimulus-response correlation engine |

### 5.3 `topology-b`

Aliases: `run-topology-b`

```text
Usage: airtell topology-b [-h] [--dev1 DEV1] [--dev2 DEV2] [--mock]
                                   [--chan1 {37,38,39}] [--chan2 {37,38,39}]
                                   [--duration-sec DURATION_SEC]
                                   [--pcap PCAP] [--json JSON] [--csv CSV]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--dev1` | `str` | None | `None` | No | Device 1 serial port (auto-discovered if omitted) |
| `--dev2` | `str` | None | `None` | No | Device 2 serial port (auto-discovered if omitted) |
| `--mock` | flag | None | `False` | No | Run with in-memory mock serial devices |
| `--chan1` | `int` | `37`, `38`, `39` | `37` | No | Channel for Device 1 (default: 37) |
| `--chan2` | `int` | `37`, `38`, `39` | `38` | No | Channel for Device 2 (default: 38; must differ from `chan1`) |
| `--duration-sec` | `float` | `>= 0.0` | `5.0` | No | Total execution duration in seconds (default: 5.0) |
| `--pcap` | `str` | None | `None` | No | Output PCAP file path |
| `--json` | `str` | None | `None` | No | Output JSON session telemetry path |
| `--csv` | `str` | None | `None` | No | Output CSV summary path |

### 5.4 `mock-simulate`

Aliases: `mock-test`

```text
Usage: airtell mock-simulate [-h] [--pcap PCAP] [--json JSON] [--csv CSV]
                                      [--duration-sec DURATION_SEC]
                                      [--interval-ms INTERVAL_MS]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--pcap` | `str` | None | `None` | No | Output PCAP file path (optional) |
| `--json` | `str` | None | `None` | No | Output JSON telemetry path (optional) |
| `--csv` | `str` | None | `None` | No | Output CSV summary path (optional) |
| `--duration-sec` | `float` | `>= 0.0` | `2.0` | No | Simulation duration in seconds (default: 2.0) |
| `--interval-ms` | `int` | `20`..`65535` | `50` | No | Stimulus injection interval in ms (default: 50) |

### 5.5 `verify-hardware`

Aliases: *(none)*

```text
Usage: airtell verify-hardware [-h] [--dev1 DEV1] [--dev2 DEV2] [--mock]
                                        [--chan {37,38,39}]
                                        [--burst-duration-sec BURST_DURATION_SEC]
                                        [--interval-ms INTERVAL_MS]
                                        [--pcap PCAP] [--json JSON] [--csv CSV]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--dev1` | `str` | None | `None` | No | Device 1 serial port |
| `--dev2` | `str` | None | `None` | No | Device 2 serial port |
| `--mock` | flag | None | `False` | No | Run in mock/offline mode (CI compatible) |
| `--chan` | `int` | `37`, `38`, `39` | `37` | No | Observer capture channel (default: 37) |
| `--burst-duration-sec` | `float` | `>= 0.0` | `0.5` | No | Duration for each burst stage in seconds (default: 0.5) |
| `--interval-ms` | `int` | `20`..`65535` | `50` | No | Advertising interval in milliseconds (default: 50) |
| `--pcap` | `str` | None | `None` | No | Output PCAP file path (optional) |
| `--json` | `str` | None | `None` | No | Output JSON telemetry path (optional) |
| `--csv` | `str` | None | `None` | No | Output CSV summary path (optional) |

### 5.6 `relay`

Aliases: *(none)*

```text
Usage: airtell relay [-h] [--port1 PORT1] [--port2 PORT2] [--mock]
                              [--duration-sec DURATION_SEC]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--port1` | `str` | None | `"/dev/ttyUSB0"` | No | Device 1 sniffer serial port |
| `--port2` | `str` | None | `"/dev/ttyUSB1"` | No | Device 2 proxy serial port |
| `--mock` | flag | None | `False` | No | Run in mock simulation mode |
| `--duration-sec` | `float` | `>= 0.0` | `5.0` | No | Relay execution duration in seconds |

### 5.7 `deanonymize`

Aliases: *(none)*

```text
Usage: airtell deanonymize [-h] [--pcap PCAP] [--mock]
                                    [--max-gap MAX_GAP]
                                    [--max-rssi-delta MAX_RSSI_DELTA]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--pcap` | `str` | None | `None` | No | PCAP capture file to analyze |
| `--mock` | flag | None | `False` | No | Run on mock synthetic traces |
| `--max-gap` | `float` | None | `30.0` | No | Max time gap for trajectory linkability in seconds |
| `--max-rssi-delta` | `float` | None | `15.0` | No | Max RSSI delta for trajectory linkability in dBm |

### 5.8 `rogue-inject`

Aliases: *(none)*

```text
Usage: airtell rogue-inject [-h]
                                     [--network {Apple Find My,Google Find Hub,Samsung SmartThings Find,Tile}]
                                     [--count COUNT] [--interval INTERVAL]
                                     [--jitter JITTER] [--port PORT]
                                     [--channel {37,38,39}] [--key KEY]
                                     [--mac MAC] [--mock]
```

| Option Flag(s) | Type | Choices | Default | Required? | Help Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `-h`, `--help` | flag | None | - | No | Show help message and exit |
| `--network` | `str` | `Apple Find My`, `Google Find Hub`, `Samsung SmartThings Find`, `Tile` | `"Apple Find My"` | No | Target tracking network |
| `--count` | `int` | None | `5` | No | Number of packets to inject in burst |
| `--interval` | `float` | None | `1.0` | No | Interval between packets in seconds |
| `--jitter` | `float` | None | `0.05` | No | Timing jitter in seconds |
| `--port` | `str` | None | `"/dev/ttyUSB0"` | No | Serial port for injection |
| `--channel` | `int` | `37`, `38`, `39` | `37` | No | Advertising channel |
| `--key` | `str` | None | `None` | No | Custom ephemeral public key hex string |
| `--mac` | `str` | None | `None` | No | Custom MAC address |
| `--mock` | flag | None | `False` | No | Simulate burst injection in mock mode |

---

## 6. Output Formats & Data Schemas

### 6.1 PCAP Wire Format (DLT 256)

All capture artifacts generated by `airtell` conform to libpcap with DLT 256 (`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`):

- **PCAP File Header (24 bytes)**:
  - Magic: `0xA1B2C3D4` (microsecond resolution)
  - Major/Minor: `2.4`
  - Snaplen: `65535`
  - LinkType: `256` (`DLT_BLUETOOTH_LE_LL_WITH_PHDR`)
- **Packet Record**:
  - `ts_sec` (4 bytes, uint32 LE)
  - `ts_usec` (4 bytes, uint32 LE)
  - `incl_len` (4 bytes, uint32 LE)
  - `orig_len` (4 bytes, uint32 LE)
- **Pseudo-Header (10 bytes)**:
  - `rf_channel` (uint8): 2.4 GHz physical RF channel index (0-39)
  - `signal_power` (int8): RSSI in dBm (-128 to 0)
  - `noise_power` (int8): Noise floor in dBm (-128)
  - `access_address_offenses` (uint8): AA bit errors (0)
  - `ref_access_address` (uint32 LE): `0x8E89BED6` for advertising channels
  - `flags` (uint16 LE): Bitmask containing `0x0001` (dewhitened), `0x0002` (signal power valid), `0x0400` (CRC checked), `0x0800` (CRC valid)
- **PDU Payload**: Raw Bluetooth LE Link-Layer PDU
- **Trailer**: 3-byte BLE CRC checksum

### 6.2 JSON Session Telemetry Schema

Structured session metadata exported via `--json`:

```json
{
  "metadata": {
    "session_id": "6a7bdc78-6dc7-4abc-a533-27d379cc5354",
    "topology": "Mock Simulation Harness",
    "start_timestamp_usec": 1001000,
    "end_timestamp_usec": 1018000,
    "start_time_iso": "2026-10-14T19:46:10.106401+00:00",
    "end_time_iso": "2026-10-14T19:46:10.123401+00:00",
    "duration_sec": 0.017,
    "total_packets": 18,
    "unique_devices_count": 1,
    "channel_packet_counts": {
      "37": 6,
      "38": 6,
      "39": 6
    }
  },
  "devices": [
    {
      "mac_address": "ED:6F:63:63:6F:ED",
      "address_type": "Random Static",
      "packet_count": 18,
      "rssi": { "min": -60, "max": -60, "avg": -60.0 },
      "first_seen_usec": 1001000,
      "last_seen_usec": 1018000,
      "first_seen_iso": "2026-10-14T19:46:10.106401+00:00",
      "last_seen_iso": "2026-10-14T19:46:10.123401+00:00",
      "observed_names": [],
      "manufacturer_profiles": [
        { "company_id": 76, "company_name": "Apple, Inc.", "data_hex": "0215..." }
      ],
      "service_uuids": ["0xFD6F", "0xFEAA"],
      "beacon_types": ["AltBeacon", "Eddystone-TLM", "Eddystone-UID", "Eddystone-URL", "GAEN", "iBeacon"],
      "channels_seen": [37, 38, 39]
    }
  ],
  "stimulus_response_events": [
    {
      "burst_id": "burst-001",
      "stimulus_mac": "C0:11:22:22:11:C0",
      "responder_mac": "54:E4:BD:11:22:33",
      "delta_ms": 3.42,
      "chan": 37,
      "rssi": -65
    }
  ]
}
```

### 6.3 CSV Tabular Summary Schema

When the `--csv <path>` option is passed to capture or simulation commands (`topology-a`, `topology-b`, `mock-simulate`, `deanonymize`), the session exporter generates an aggregated longitudinal per-device tracking table in comma-separated values (CSV) format.

Unlike raw per-packet logs, each row in this summary table corresponds to a distinct Bluetooth device MAC address observed during the capture session, compiling aggregated signal metrics, first/last observation timestamps, advertised names, service UUIDs, detected beacon protocols, and observation channels.

#### 6.3.1 Column Definitions

| Column | Data Type | Format & Nullability | Description |
|---|---|---|---|
| `mac_address` | `str` | `XX:XX:XX:XX:XX:XX` | Primary key representing the 48-bit Bluetooth device address (BD_ADDR) in uppercase hexadecimal. |
| `address_type` | `str` | Categorical string | Link-layer address classification: `Public`, `Random Static`, `RPA` (Resolvable Private Address), `Non-resolvable Private`, or `unknown`. |
| `packet_count` | `int` | Integer ($\ge 1$) | Total number of Link-Layer advertising and data packets captured from this device during the session. |
| `rssi_min` | `int` | Integer dBm (or empty `""`) | Minimum observed Received Signal Strength Indicator (RSSI) in dBm. Empty if `packet_count` is 0. |
| `rssi_max` | `int` | Integer dBm (or empty `""`) | Maximum observed Received Signal Strength Indicator (RSSI) in dBm. Empty if `packet_count` is 0. |
| `rssi_avg` | `float` | Float (2 decimal places) | Arithmetic mean RSSI across all packets captured for this device (e.g. `-60.0`, `-64.75`). |
| `first_seen_iso` | `str` | ISO 8601 UTC string | Wall-clock UTC timestamp (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`) of the first packet captured for this device. |
| `last_seen_iso` | `str` | ISO 8601 UTC string | Wall-clock UTC timestamp (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`) of the most recent packet captured for this device. |
| `duration_sec` | `float` | Seconds (3 decimal places) | Total observation span in seconds (`(last_seen - first_seen) / 1,000,000`). Evaluates to `0.0` for single-packet events. |
| `observed_names` | `str` | Semicolon-delimited | Semicolon-separated list of unique Complete or Shortened Local Names advertised in AD structures. Empty if no names were observed. |
| `service_uuids` | `str` | Semicolon-delimited | Semicolon-separated sorted list of unique 16-bit, 32-bit, or 128-bit Service UUIDs (e.g. `0x180D;0xFD6F;0xFEAA`). Empty if none observed. |
| `beacon_types` | `str` | Semicolon-delimited | Semicolon-separated list of identified beacon protocols (`AltBeacon`, `Eddystone-TLM`, `Eddystone-UID`, `Eddystone-URL`, `GAEN`, `iBeacon`, `FindMy`). Empty if not a recognized beacon. |
| `channels` | `str` | Semicolon-delimited | Semicolon-separated sorted list of 2.4 GHz RF channels on which packets from this device were captured (e.g. `37`, `38;39`, or `37;38;39`). |

#### 6.3.2 Example CSV Export

```csv
mac_address,address_type,packet_count,rssi_min,rssi_max,rssi_avg,first_seen_iso,last_seen_iso,duration_sec,observed_names,service_uuids,beacon_types,channels
54:E4:BD:11:22:33,Public,4,-68,-62,-64.5,2026-10-14T20:09:44.102300+00:00,2026-10-14T20:09:45.314500+00:00,1.212,SniffleHRM,0x180D,,37;38
6C:79:B8:AA:BB:CC,RPA,1,-72,-72,-72.0,2026-10-14T20:09:45.001200+00:00,2026-10-14T20:09:45.001200+00:00,0.0,,,,38
ED:6F:63:63:6F:ED,Random Static,18,-60,-60,-60.0,2026-10-14T20:09:43.800201+00:00,2026-10-14T20:09:43.817201+00:00,0.017,,0xFD6F;0xFEAA,AltBeacon;Eddystone-TLM;Eddystone-UID;Eddystone-URL;GAEN;iBeacon,37;38;39
```

#### 6.3.3 Stimulus-Response Event CSV Log (API / Secondary Export)

When utilizing the Python API (`telemetry_session.export_csv(path, table_type="events")` or `telemetry_session.export_events_csv(path)`), `TelemetrySession` exports the fine-grained stimulus-response correlation event log:

| Column | Type | Description |
|---|---|---|
| `burst_id` | `int` / `str` | Identifier of the active stimulation burst sequence. |
| `stimulus_mac` | `str` | MAC address of the active stimulator dongle. |
| `stimulus_type` | `str` | Injected beacon type (e.g. `iBeacon`, `AltBeacon`). |
| `response_pdu_type` | `str` | Received reaction PDU type (e.g. `SCAN_REQ`, `CONNECT_IND`). |
| `responder_mac` | `str` | MAC address of the device responding to the stimulus. |
| `responder_mac_type` | `str` | Address classification of the responder (`RPA`, `Public`, `Random Static`). |
| `delta_ms` | `float` | Latency in milliseconds between stimulus transmission and response reception. |
| `chan` | `int` | Primary RF advertising channel where the response was captured (`37`, `38`, `39`). |
| `rssi` | `int` | Received signal strength in dBm of the response frame. |
| `timestamp_usec` | `int` | Microsecond hardware timestamp of the response frame. |
| `timestamp_iso` | `str` | ISO 8601 UTC timestamp of the response frame. |

```csv
burst_id,stimulus_mac,stimulus_type,response_pdu_type,responder_mac,responder_mac_type,delta_ms,chan,rssi,timestamp_usec,timestamp_iso
burst-001,C0:11:22:22:11:C0,iBeacon,SCAN_REQ,54:E4:BD:11:22:33,Public,3.42,37,-65,1003420,2026-10-14T20:09:43.803420+00:00
burst-001,C0:11:22:22:11:C0,AltBeacon,SCAN_REQ,6C:79:B8:AA:BB:CC,RPA,8.15,38,-70,1008150,2026-10-14T20:09:43.808150+00:00
```

---

## 7. Troubleshooting & Operational Guidance

### 7.1 Linux Serial Port Permissions (`dialout`)

**Symptom**: `PermissionError: [Errno 13] Permission denied: '/dev/ttyUSB0'`  
**Cause**: Serial character devices (`/dev/ttyUSB*`, `/dev/ttyACM*`) are restricted to `root:dialout`.  
**Remediation**:
```bash
sudo usermod -a -G dialout,uucp $USER
newgrp dialout
```

### 7.2 Udev Rules for Non-Root Access

Create `/etc/udev/rules.d/99-sniffle.rules` for persistent non-root permissions and predictable device symlinks:

```udev
# Texas Instruments CC26x2 / CC1352 LaunchPad (XDS110)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="bef3", MODE="0666", GROUP="dialout"

# Sonoff Zigbee 3.0 USB Dongle Plus (CP2102 / CP2102N)
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666", GROUP="dialout"

# Electronic Cats CatSniffer V3 (RP2040)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="00c0", MODE="0666", GROUP="dialout"
```

Reload rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### 7.3 Serial Port Contention & Lock Detection (`lsof`)

**Symptom**: `OSError: [Errno 16] Device or resource busy: '/dev/ttyUSB0'`  
**Cause**: Background sniffer processes, `tshark`, or `ModemManager` hold open file descriptors.  
**Remediation**:
```bash
# Identify holding PID
lsof /dev/ttyUSB0

# Terminate holding process
kill -15 <PID>

# Disable ModemManager on dedicated sniffing hosts
sudo systemctl stop ModemManager
sudo systemctl disable ModemManager
```

See [device_status.md](device_status.md) for automated in-use detection details.

### 7.4 Baud Rates & CP2102 Bridge Limits

- **CP2102 (non-N)**: Hardware UART capped at **921,600 baud**. Attempting to communicate at 2,000,000 baud causes packet loss and Base64 framing corruption. The framework automatically detects non-N revisions and limits baud rate to `921600`.
- **CP2102N / TI XDS110 / RP2040**: Hardware UART supports full **2,000,000 baud**.

### 7.5 Missing Dongles & Auto-Discovery Diagnostics

If `allocate_dual_ports` raises `RuntimeError: Dual-device topology requires 2 Sniffle dongles`:
```bash
# Verify kernel detects USB devices
lsusb

# Inspect persistent device symlinks
ls -la /dev/serial/by-id/
```

### 7.6 Synchronization Loss & Hardware Reset

**Symptom**: `Marker sync timed out after 0.50 seconds` or unresponsiveness during capture.  
**Cause**: MCU crash, FIFO desynchronization, or unprogrammed factory firmware.  
**Remediation**:
```bash
# Execute soft reset and marker sync burst
python3 -m airtell.scripts.reset -s /dev/ttyUSB0
```
If using a LaunchPad, press the mechanical `RESET` button adjacent to the USB receptacle. If using a USB dongle, unplug and replug the adapter.

### 7.7 Wireshark & TShark PCAP Dissection

**Symptom**: Wireshark displays `[Malformed Packet: BT Common]`.  
**Cause**: Missing pseudo-header flags (`0x0400` CRC checked or `0x0800` CRC valid), or missing 3-byte BLE CRC checksum.  
**Validation**:
```bash
# Dissect capture with verbose link-layer tree in tshark
tshark -r captures/topo_a.pcap -V

# Decode AD structures using framework decoder
python3 -m airtell.scripts.pcap_decoder captures/topo_a.pcap -d
```
See [tshark.md](tshark.md) for additional display filters and extcap recipes.
