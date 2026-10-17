# Specification: Complete CLI Adversarial Ingestion and Live UART Injection

## 1. Overview
Complete the CLI adversarial ingestion pipeline and physical hardware UART injection capabilities in `src/airtell/cli.py` to match the documented workflows in `docs/CLI.md`.
This enables end-to-end trace deanonymization from offline PCAPs (DLT 256 `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`), trajectory reconstruction, address rotation desynchronization analysis, static identifier leakage detection, and live over-the-air rogue tracking beacon injection over physical or simulated UART interfaces.

## 2. Functional Requirements

### FR1: Real PCAP Packet Ingestion in `airtell deanonymize` (Issues #13, #25, #26)
- Replace the CLI stub warning in `handle_deanonymize()` (`cli.py:666`) by instantiating `PcapBleReader` from `airtell.sniff.pcap`.
- Dissect Link-Layer advertising frames into `LinkabilityObservation` records:
  - Extract advertiser MAC address (`AdvA`), classification type (`Public`, `Random Static`, `NRPA`, `RPA`) using `classify_address()`.
  - Dissect advertising payloads and classify tracking network profiles (`Apple Find My`, `Google Find Hub`, `Samsung SmartThings Find`, `Tile`).
  - Isolate ephemeral public keys and rotating payload identifiers.
  - Record epoch timestamps and RSSI signal levels.
- Feed observations sequentially into:
  - `StaticLeakageDetector`: identifies non-randomized MAC usage with tracking keys and constant 24-bit OUI vendor prefixes across randomized addresses.
  - `RotationDesyncAnalyzer`: detects timing divergence where MAC addresses rotate while payload keys persist (`MAC_ROTATED_KEY_PERSISTED`) or keys rotate while MAC addresses persist (`KEY_ROTATED_MAC_PERSISTED`).
  - `TrajectoryReconstructor`: correlates discrete observations across address rotation boundaries into continuous spatial-temporal trajectories using configurable `--max-gap` and `--max-rssi-delta` thresholds.
- Output structured CLI summaries highlighting reconstructed trajectories, rotation desync events, and static leakage warnings.

### FR2: Robust Input Validation and Error Handling (Issue #42)
- Validate existence and readability of capture files provided via `--pcap`.
- Handle non-existent files with explicit diagnostic messages to `stderr` and non-zero exit codes.
- Handle empty (0-byte) files with explicit diagnostic messages to `stderr` and non-zero exit codes.
- Handle corrupted files, invalid PCAP magic numbers, and unsupported LinkTypes (DLT != 256) cleanly with informative diagnostics and non-zero exit codes.
- Ensure either `--pcap` or `--mock` is specified when invoking `deanonymize`.

### FR3: Live Hardware UART Injection in `airtell rogue-inject` (Issues #14, #27, #28)
- Connect `RogueBeaconGenerator` synthetic frame generation (supporting Apple Find My, Google Find Hub, Samsung SmartThings Find, and Tile profiles) to `SniffleDeviceController.configure_advertising()` when `--port` is supplied.
- Transmit generated payloads over UART into Sniffle firmware for over-the-air broadcasting.
- Support physical serial interfaces (`/dev/ttyUSB0`, etc.) and mock simulation (`--mock` or `mock://`).
- Ensure graceful teardown on SIGINT/Ctrl+C or completion, resetting dongle state with `COMMAND_RESET`.

### FR4: Burst Parameters & Channel Hopping Controls (Issue #41)
- Expand CLI options for `airtell rogue-inject` to support:
  - `--count`: number of packets to transmit in burst.
  - `--interval-ms` and `--interval`: burst interval in milliseconds and seconds.
  - `--jitter-ms` and `--jitter`: timing jitter bounds in milliseconds and seconds.
  - `--channels` and `--channel`: advertising channel specification (channels 37, 38, 39 or hopping sequences).
- Pass parameters into `RogueBeaconGenerator.generate_burst()`.

### FR5: Documentation Reconciliation (Issue #37)
- Reconcile `docs/CLI.md` and `README.md` to ensure every command example, argument table, default value, and output format accurately reflects the completed implementations of `deanonymize` and `rogue-inject`.
- Validate that all markdown documentation links and CLI snippet syntax parse cleanly with 0 errors via automated documentation validation tests.

## 3. Non-Functional Requirements
- **Performance**: High-throughput packet ingestion capable of streaming thousands of packets per second without memory degradation.
- **Reliability & Resilience**: Clean error handling with informative `stderr` diagnostics and standard non-zero exit codes (exit code 2 for CLI usage errors, 1 for hardware errors).
- **Code Quality**: Zero `ruff` lint warnings (`line-length = 120`, target Python 3.10+).
- **Test Coverage**: Comprehensive unit and integration tests in `tests/test_cli_adversarial.py` covering valid PCAP ingestion, error edge cases, mock injection bursts, and hardware UART frame dispatch.
- **Backwards Compatibility**: All 1,119 existing repository tests must pass.

## 4. Acceptance Criteria
- [ ] `airtell deanonymize --pcap <file.pcap>` ingests packets, generates linkability observations, and outputs structured trajectory, desync, and leakage summaries.
- [ ] `airtell deanonymize --pcap <invalid>` gracefully rejects non-existent, empty, and corrupted PCAPs with clear error diagnostics and non-zero exit codes.
- [ ] `airtell rogue-inject` supports `--count`, `--interval-ms`, `--jitter-ms`, and `--channels` across Apple, Google, Samsung, and Tile profiles.
- [ ] `airtell rogue-inject --port <port>` configures `SniffleDeviceController` advertising and transmits frames over UART with clean signal teardown.
- [ ] `docs/CLI.md` and `README.md` are reconciled and validate cleanly in `tests/test_docs_cli_validation.py`.
- [ ] Full automated test suite passes with 100% pass rate.
