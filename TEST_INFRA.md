# Test Infrastructure & Validation Framework: Spectra Mesh OUI DB & PCAP Timeline

This document specifies the testing infrastructure, synthetic packet generators, execution strategies, and validation architecture for the Spectra Mesh OUI database integration and PCAP MAC timeline reporting engine in AirTell.

---

## 1. Overview & Test Architecture

The test suite validates compliance with requirements R1 through R4 from `ORIGINAL_REQUEST.md` and the system specifications defined in `PROJECT.md`. The validation harness uses a 4-tier testing hierarchy:

| Tier | Focus | Test Suite File | Test Count | Description |
|:---|:---|:---|:---:|:---|
| **Tier 1** | Feature Coverage in Isolation | `tests/test_e2e_ouidb_timeline.py` | 33 | Exhaustive coverage of features F1–F6 (≥5 tests per feature). |
| **Tier 2** | Boundary & Corner Cases | `tests/test_e2e_ouidb_timeline.py` | 25 | Degraded, extreme, and malformed inputs (B1–B5, ≥5 per category). |
| **Tier 3** | Cross-Feature Combinations | `tests/test_e2e_ouidb_timeline.py` | 7 | Pairwise feature interactions, multi-role devices, and filter compositions. |
| **Tier 4** | Real-World Application Scenarios | `tests/test_e2e_ouidb_timeline.py` | 7 | End-to-end execution against `app/data/merged.pcap` asserting ground truth. |
| **Unit** | Internal Engine Unit Tests | `spectramesh_ouidb/test_spectramesh_ouidb.py` | 61 | C extension structures, mmap safety, binary format, and thread safety. |
| **Total** | | | **133** | **Full OUI DB & Timeline Verification Suite** |

---

## 2. Directory Layout & Test Locations

```text
bluetooth-sniffle/
├── spectramesh_ouidb/
│   ├── oui_db.bin                 # Production 58,197-entry binary OUI database (SOUI v1)
│   ├── spectramesh_ouidb.py       # Python OuiDb interface
│   └── test_spectramesh_ouidb.py  # Engine unit tests (61 tests)
├── app/data/
│   └── merged.pcap                # 683 MB real-world BLE capture (8,899,578 packets, PCAPNG)
├── src/airtell/
│   ├── sniff/
│   │   ├── telemetry.py           # DeviceTelemetrySummary & resolve_device_oui
│   │   ├── timeline.py            # PcapTimelineReportGenerator & PcapTimelineReport
│   │   ├── pcap.py                # PcapBleReader & PcapBleWriter (DLT 256)
│   │   └── dissector.py           # BLE advertising PDU dissector
│   └── cli.py                     # CLI subcommand airtell pcap-timeline
├── tests/
│   ├── test_e2e_ouidb_timeline.py # Primary 4-tier E2E test suite (72 tests)
│   ├── test_pcap.py               # PCAP streaming reader/writer tests
│   └── test_dissector.py          # BLE Link Layer PDU dissection tests
├── TEST_INFRA.md                  # This document
└── TEST_READY.md                  # Test suite readiness & execution matrix
```

---

## 3. Synthetic Fixture Generation Strategy

To ensure rapid, deterministic, and isolated execution without requiring external dependencies, `tests/test_e2e_ouidb_timeline.py` includes programmatic generators:

### 3.1 Link Layer Advertising PDU Generator (`_build_adv_pdu`)
Generates bit-exact BLE advertising channel PDUs according to the Bluetooth Core Specification (v5.4, Vol 6, Part B, Section 2.3):
- **`ADV_IND` (PDU Type 0x0)**: Broadcast advertisements with `AdvA` and AD payload structures.
- **`ADV_DIRECT_IND` (PDU Type 0x1)**: Directed advertisements with `AdvA` and `TargetA` roles.
- **`ADV_NONCONN_IND` (PDU Type 0x2)**: Non-connectable beacons (e.g. iBeacon, Eddystone).
- **`SCAN_REQ` (PDU Type 0x3)**: Active scan requests with `ScanA` (scanner) and `AdvA` (advertiser).
- **`SCAN_RSP` (PDU Type 0x4)**: Scan responses carrying extended device names and MSD.
- **`CONNECT_IND` (PDU Type 0x5)**: Connection requests carrying `InitA`, `AdvA`, and 22-byte LL data.

Addresses are encoded with Link Layer Little-Endian byte order over the air, enabling validation of the canonical Big-Endian IEEE adapter.

### 3.2 Streaming PCAP Generator (`_create_synthetic_pcap_file`)
Leverages in-tree `PcapBleWriter` to serialize Link Layer packets into standard libpcap format (`DLT_BLUETOOTH_LE_LL_WITH_PHDR` / DLT 256):
- Writes standard 24-byte global header (`PCAP_MAGIC_USEC = 0xA1B2C3D4`).
- Writes 16-byte packet header with microsecond timestamp precision.
- Writes 10-byte pseudo-header specifying RF channel, normalized RSSI, and Link Layer flags.
- Appends 3-byte reverse-CRC.

### 3.3 Dynamic SOUI Binary Database Generator (`_make_soui_blob`)
Packages custom in-memory binary databases adhering to the packed `soui_header_t` binary specification:
- Generates arbitrary prefix counts across MA-L (/24), MA-M (/28), and MA-S (/36).
- Supports synthesizing colliding prefix hierarchies to deterministically prove Longest Prefix Match (LPM) precedence.
- Supports corrupt headers, invalid string offsets, and empty tables for boundary testing.

---

## 4. Real-World Dataset: `app/data/merged.pcap`

The primary production validation dataset is `app/data/merged.pcap`:
- **Format**: PCAPNG (magic `0x0A0D0D0A`), Link Layer RF encapsulation (DLT 161 / 256).
- **Volume**: 8,899,578 packets across 18 merged channel captures (683,034,112 bytes).
- **Duration**: 33,313 seconds (~9.25 hours).
- **MAC Distribution**: 96,080 unique MAC addresses (8,545 matching IEEE OUI DB, 21 matching surveillance classes).

### Ground Truth Surveillance Targets
The test suite validates detection of the following 21 surveillance devices observed in `merged.pcap`:

| MAC Address | Vendor | Category | Table | Prefix | Roles |
|:---|:---|:---|:---:|:---|:---:|
| `E4:38:83:D7:A5:B3` | Flock Safety | `alpr` | MA-L | `E4:38:83` | AdvA |
| `0C:9A:E6:37:F6:2D` | Sz Dji Technology Co.,Ltd | `drone` | MA-L | `0C:9A:E6` | AdvA |
| `4C:43:F6:30:A4:18` | Sz Dji Technology Co.,Ltd | `drone` | MA-L | `4C:43:F6` | AdvA |
| `88:29:85:3C:61:0D` | Sz Dji Technology Co.,Ltd | `drone` | MA-L | `88:29:85` | AdvA |
| `68:9A:87:20:6B:FF` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `68:9A:87:ED:21:EF` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `68:9A:87:72:0A:C3` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `68:9A:87:38:2D:88` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `68:9A:87:31:88:CD` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `68:9A:87:B5:DA:09` | Skydio, Inc. | `drone` | MA-L | `68:9A:87` | ScanA |
| `D0:3F:27:B0:07:6E` | Wyze Labs Inc | `camera` | MA-L | `D0:3F:27` | AdvA |
| `D0:3F:27:5A:C4:76` | Wyze Labs Inc | `camera` | MA-L | `D0:3F:27` | AdvA |
| `D0:3F:27:69:94:DE` | Wyze Labs Inc | `camera` | MA-L | `D0:3F:27` | AdvA |
| `80:48:2C:53:47:33` | Wyze Labs Inc | `camera` | MA-L | `80:48:2C` | AdvA |
| `2C:AA:8E:44:02:A1` | Wyze Labs Inc | `camera` | MA-L | `2C:AA:8E` | AdvA |
| `2C:AA:8E:D5:1E:4B` | Wyze Labs Inc | `camera` | MA-L | `2C:AA:8E` | AdvA |
| `74:EC:B2:97:05:FD` | Ring LLC | `camera` | MA-L | `74:EC:B2` | ScanA |
| `74:EC:B2:EB:79:68` | Ring LLC | `camera` | MA-L | `74:EC:B2` | ScanA |
| `74:EC:B2:28:3E:82` | Ring LLC | `camera` | MA-L | `74:EC:B2` | ScanA |
| `74:EC:B2:04:04:34` | Ring LLC | `camera` | MA-L | `74:EC:B2` | ScanA |
| `44:A6:42:A5:DE:34` | Hangzhou Hikvision Digital Tech | `camera` | MA-L | `44:A6:42` | AdvA |

---

## 5. Execution Guide & Runner Commands

### 5.1 Complete E2E Suite Execution
```bash
pytest -v tests/test_e2e_ouidb_timeline.py
```

### 5.2 Selective Tier Execution
```bash
# Tier 1: Feature coverage only
pytest -v tests/test_e2e_ouidb_timeline.py -k "TestTier1FeatureCoverage"

# Tier 2: Boundary and corner cases only
pytest -v tests/test_e2e_ouidb_timeline.py -k "TestTier2BoundaryAndCornerCases"

# Tier 3: Cross-feature combinations only
pytest -v tests/test_e2e_ouidb_timeline.py -k "TestTier3CrossFeatureCombinations"

# Tier 4: Real-world merged.pcap scenarios only
pytest -v tests/test_e2e_ouidb_timeline.py -k "TestTier4RealWorldApplicationScenarios"
```

### 5.3 Style & Lint Compliance
```bash
ruff check tests/test_e2e_ouidb_timeline.py
```

### 5.4 Rapid CI Execution with Limits
By passing `--limit 2000` or `--limit 300000`, the real-world PCAP tests execute in **< 1.5 seconds**, avoiding lengthy full-file scans during rapid feedback loops while maintaining genuine protocol verification.
