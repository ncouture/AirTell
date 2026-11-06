# TEST_READY: Spectra Mesh OUI DB Integration & PCAP MAC Timeline Report Suite

## 1. Single Execution Command

The complete End-to-End validation suite (Tiers 1–4) for the Spectra Mesh OUI database integration and PCAP MAC timeline generator can be executed with a single command:

```bash
pytest -v -W error tests/test_e2e_ouidb_timeline.py
```

To run style, lint, and formatting compliance across the test suite:

```bash
ruff check tests/test_e2e_ouidb_timeline.py
```

To run the complete repository test suite including all previous milestone unit and integration suites:

```bash
pytest -v tests/
```

---

## 2. Test Architecture & Tier Breakdown

The validation suite is partitioned into four distinct End-to-End tiers in `tests/test_e2e_ouidb_timeline.py` in addition to engine unit tests in `spectramesh_ouidb/`:

| Tier | Suite Class | Test Count | Description |
|:---|:---|:---:|:---|
| **Tier 1** | `TestTier1FeatureCoverage` | 33 | **Features in Isolation**: F1 (OUI engine & endianness), F2 (device classification), F3 (PDU ingestion), F4 (OUI filtering & chrono order), F5 (metadata enrichment), F6 (report formats & CLI). |
| **Tier 2** | `TestTier2BoundaryAndCornerCases` | 25 | **Boundary & Corner Cases**: B1 (empty/truncated PCAPs), B2 (pure RPA zero-match captures), B3 (LPM collisions /36 > /28 > /24), B4 (broadcast/multicast/malformed MACs), B5 (extreme timestamps & out-of-order packets). |
| **Tier 3** | `TestTier3CrossFeatureCombinations` | 7 | **Cross-Feature Combinations**: Multi-role devices (`AdvA` + `ScanA`), category and surveillance filtering combined with multi-format serialization, mixed prefix lengths, and telemetry congruence. |
| **Tier 4** | `TestTier4RealWorldApplicationScenarios` | 7 | **Real-World Application Scenarios**: Execution against `app/data/merged.pcap` asserting ground-truth detection of Flock Safety, DJI drones, Skydio drones, Wyze cameras, Ring scanners, and Hikvision cameras. |
| **Engine Unit** | `test_spectramesh_ouidb.py` | 61 | **C Extension & Mmap Primitives**: Binary SOUI header parsing, string pool offsets, binary search, memory-mapped safety, and multi-threading. |
| **Total** | | **133** | **Total Verification Tests for Spectra Mesh & Timeline Track** |

---

## 3. Feature Coverage Checklist

Every feature defined in `ORIGINAL_REQUEST.md` (R1–R4) and `PROJECT.md` is covered across Tier 1, Tier 2, and Tier 3:

- [x] **F1: Spectra Mesh OUI Lookups & Endianness Adapter**
  - `test_f01_mal_24bit_prefix_lookup`: 24-bit MA-L prefix matching (`E4:38:83` -> Flock Safety).
  - `test_f01_mam_28bit_prefix_lookup`: 28-bit MA-M prefix matching (`00:55:DA:B0/28` -> Interaxon Inc).
  - `test_f01_mas_36bit_prefix_lookup`: 36-bit MA-S prefix matching (`00:50:C2:0D:80/36` -> Charlotte's Web).
  - `test_f01_unknown_mac_returns_none`: Unassigned/random addresses return None.
  - `test_f01_wire_vs_canonical_endianness_resolution`: Radio Link Layer Little-Endian byte reversal to Big-Endian IEEE OUI.
  - `test_f01_wire_direct_fallback`: Fallback to wire direct evaluation when canonical reversed misses.

- [x] **F2: Device Class Resolution Across Categories**
  - `test_f02_device_class_camera`: Wyze Labs and Hikvision resolve to `"camera"` (`flags=1`, `is_surveillance=True`).
  - `test_f02_device_class_alpr`: Flock Safety resolves to `"alpr"` (`flags=2`, `is_surveillance=True`).
  - `test_f02_device_class_drone`: DJI and Skydio resolve to `"drone"` (`flags=3`, `is_surveillance=True`).
  - `test_f02_device_class_bodycam`: Axon Enterprise resolves to `"bodycam"` (`flags=6`, `is_surveillance=True`).
  - `test_f02_device_class_none_consumer`: Apple, Google, Espressif resolve to `"none"` (`flags=0`, `is_surveillance=False`).
  - `test_f02_airtell_telemetry_enrichment`: Telemetry summary enrichment with vendor, device_class, oui_prefix, and is_surveillance.

- [x] **F3: PCAP Ingestion with Advertising PDU Types**
  - `test_f03_pcap_ingest_adv_ind`: `ADV_IND` (0x0) extracting `AdvA` role.
  - `test_f03_pcap_ingest_scan_req`: `SCAN_REQ` (0x3) extracting `ScanA` (scanner) and `AdvA` (advertiser).
  - `test_f03_pcap_ingest_scan_rsp`: `SCAN_RSP` (0x4) extracting `AdvA`.
  - `test_f03_pcap_ingest_adv_direct_ind`: `ADV_DIRECT_IND` (0x1) extracting `AdvA` and `TargetA`.
  - `test_f03_pcap_ingest_connect_ind`: `CONNECT_IND` (0x5) extracting `InitA` and `AdvA`.

- [x] **F4: OUI Filtering & Chronological Ordering**
  - `test_f04_oui_filtering_excludes_random_addresses`: Non-OUI random private addresses excluded.
  - `test_f04_oui_filtering_retains_database_matches`: Verified database matches retained.
  - `test_f04_strict_chronological_ordering`: Ascending sort by earliest `first_seen`.
  - `test_f04_first_seen_and_last_seen_tracking`: Accurate earliest observation and latest observation tracking.
  - `test_f04_packet_count_increment`: Exact packet count tallying across multiple occurrences.

- [x] **F5: Timeline Metadata Enrichment Validation**
  - `test_f05_timestamp_metadata_iso8601`: Valid ISO 8601 UTC timestamp formatting.
  - `test_f05_packet_metadata_types_and_roles`: Accurate aggregation of observed PDU types and device roles.
  - `test_f05_database_prefix_and_table_metadata`: Accurate vendor name, prefix string, prefix bits (24, 28, 36), and table ("MA-L", "MA-M", "MA-S").
  - `test_f05_device_category_and_flags`: Category string and integer flags correspondence.
  - `test_f05_is_surveillance_flag_integrity`: Boolean `is_surveillance` strictly equivalent to `flags != 0`.

- [x] **F6: Timeline Report Serialization Formats & CLI**
  - `test_f06_report_to_dict`: Dictionary serialization with complete summary and entries.
  - `test_f06_report_to_json`: Valid JSON serialization parsable by standard parsers.
  - `test_f06_report_to_csv`: Valid CSV with standard column headers.
  - `test_f06_report_to_markdown`: Formatted Markdown table.
  - `test_f06_report_to_text`: Formatted human-readable plain text output.
  - `test_f06_cli_pcap_timeline_subcommand`: CLI parser registration of `pcap-timeline` and `timeline`.

---

## 4. Real-World Ground Truth Surveillance Assertions (`app/data/merged.pcap`)

The Tier 4 test suite validates the detection of known ground truth surveillance devices in `app/data/merged.pcap`:

| Target Device | MAC Address | Expected Vendor | Expected Category | Verified Roles | Test Function |
|:---|:---|:---|:---:|:---:|:---|
| **Flock Safety ALPR** | `E4:38:83:D7:A5:B3` | Flock Safety | `alpr` | AdvA | `test_s02_merged_pcap_flock_safety_alpr` |
| **DJI Drones** | `0C:9A:E6:37:F6:2D`<br>`4C:43:F6:30:A4:18`<br>`88:29:85:3C:61:0D` | Sz Dji Technology Co.,Ltd | `drone` | AdvA | `test_s03_merged_pcap_dji_drones` |
| **Skydio Drones** | `68:9A:87:20:6B:FF`<br>`68:9A:87:ED:21:EF`<br>`68:9A:87:72:0A:C3`<br>`68:9A:87:38:2D:88`<br>`68:9A:87:31:88:CD`<br>`68:9A:87:B5:DA:09` | Skydio, Inc. | `drone` | ScanA | `test_s04_merged_pcap_skydio_drone_scanners` |
| **Wyze Cameras** | `D0:3F:27:B0:07:6E`<br>`80:48:2C:53:47:33`<br>`2C:AA:8E:44:02:A1` | Wyze Labs Inc | `camera` | AdvA | `test_s05_merged_pcap_camera_devices` |
| **Ring Scanners** | `74:EC:B2:97:05:FD`<br>`74:EC:B2:EB:79:68`<br>`74:EC:B2:04:04:34` | Ring LLC | `camera` | ScanA | `test_s05_merged_pcap_camera_devices` |
| **Hikvision Camera** | `44:A6:42:A5:DE:34` | Hangzhou Hikvision Digital Tech | `camera` | AdvA | `test_s05_merged_pcap_camera_devices` |

---

## 5. Boundary, Corner & Adversarial Hardening Summary

Tier 2 exercises component resilience under edge-case conditions:
1. **Empty & Truncated PCAPs**: 0-byte captures, headers truncated mid-way, and short payloads are handled safely with descriptive `ValueError` or empty reports without unhandled exceptions.
2. **Zero-Match & Pure RPA Captures**: Captures with only rotating private addresses (RPAs) or unallocated prefixes produce clean empty reports across all export formats (JSON `[]`, CSV with headers, Markdown table).
3. **Longest Prefix Match (LPM) Collisions**: Synthetic colliding tables verify that 36-bit MA-S overrides 28-bit MA-M, which in turn overrides 24-bit MA-L. Adjacent nibbles in byte 3 (/28) and byte 4 (/36) are strictly distinguished.
4. **Special MAC Addresses**: Multicast (`01:00:5E:...`), broadcast (`FF:FF:FF:FF:FF:FF`), all-zero (`00:00:00:00:00:00`), mixed-case, and hyphenated addresses normalize properly.
5. **Extreme Timestamps**: Epoch zero (1970-01-01), year 2038+ timestamps, microsecond-resolution intervals, and out-of-order PCAP packets are ordered strictly chronologically by earliest observation.

---

## 6. Integrity Statement

In accordance with project integrity mandates:
- **Zero Mock Shortcuts**: All test assertions evaluate real data transformations, protocol parsing, and bit-level fields. No test results or verification strings are hardcoded in application logic.
- **Genuine Protocol Decoding**: Link Layer PDUs, AD structures, pseudo-headers, CRC polynomials, and beacon payloads maintain real state and execute genuine bit-level packing and unpacking.
- **Authoritative Expected Outputs**: Expected values are derived directly from the binary database `spectramesh_ouidb/oui_db.bin` and the verified ground truth of `app/data/merged.pcap`.
