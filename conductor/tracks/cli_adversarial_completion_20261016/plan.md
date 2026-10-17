# Implementation Plan: Complete CLI Adversarial Ingestion and Live UART Injection

## Phase 1: Conductor Track Scaffolding & Registry Indexing
- [x] Task: Scaffold Track 2 Conductor track directory and documentation (Issue #55)
  - [x] Create `conductor/tracks/cli_adversarial_completion_20261016/`
  - [x] Create `metadata.json`, `index.md`, `spec.md`, and `plan.md`
- [x] Task: Update `conductor/tracks.md` registry with Track 2 entry

## Phase 2: PCAP Ingestion & Translation for `airtell deanonymize`
- [x] Task: Implement Link-Layer packet dissection into `LinkabilityObservation` in `src/airtell/cli.py` (Issue #25)
  - [x] Extract MAC address, classification (`Public`, `Random Static`, `NRPA`, `RPA`), network type, and ephemeral keys
  - [x] Re-use and harmonize dissection logic with `classify_address()` and `classify_payload()`
- [x] Task: Wire `PcapBleReader` into `handle_deanonymize` in `src/airtell/cli.py` (Issues #13, #26)
  - [x] Replace placeholder stub at line 666 with streaming reader iteration
  - [x] Feed observations into `StaticLeakageDetector`, `RotationDesyncAnalyzer`, and `TrajectoryReconstructor`
  - [x] Render structured CLI report summarizing trajectories, desynchronizations, and leakage findings
- [x] Task: Add robust input validation and error handling for malformed or empty PCAPs (Issue #42)
  - [x] Validate file presence, accessibility, and non-zero size
  - [x] Catch PCAP header corruption and unsupported DLT formats with clear diagnostics and exit code 2

## Phase 3: Live Hardware UART Injection for `airtell rogue-inject`
- [x] Task: Add burst count, interval, and channel hopping parameters to `rogue-inject` parser (Issue #41)
  - [x] Add `--interval-ms`, `--jitter-ms`, and `--channels` arguments
  - [x] Update `RogueBeaconGenerator.generate_burst()` to support channel sequences and hopping
- [x] Task: Connect `RogueBeaconGenerator` to `SniffleDeviceController.configure_advertising()` (Issues #14, #27, #28)
  - [x] Connect to physical or mock serial dongle using `--port`
  - [x] Configure advertising parameters and push payloads over UART for over-the-air broadcasting
  - [x] Support Apple Find My, Google Find Hub, Samsung SmartThings Find, and Tile profiles
  - [x] Implement graceful teardown on SIGINT/Ctrl+C or completion resetting device state

## Phase 4: Documentation Reconciliation & Validation
- [x] Task: Reconcile CLI handler options and examples with documentation (Issue #37)
  - [x] Update `docs/CLI.md` options tables, synopses, and usage examples for `deanonymize` and `rogue-inject`
  - [x] Update `README.md` references to CLI documentation
  - [x] Verify markdown links and CLI snippet syntax via `tests/test_docs_cli_validation.py`

## Phase 5: Automated Integration Testing, Full Verification & Issue Closure
- [x] Task: Implement comprehensive CLI integration tests in `tests/test_cli_adversarial.py` (Issue #48)
  - [x] Test `airtell deanonymize --pcap <valid.pcap>` verifying trajectory output, desync analysis, and leakage detection
  - [x] Test `airtell deanonymize --pcap <missing/empty/corrupted>` verifying error messages and non-zero exit codes
  - [x] Test `airtell rogue-inject --mock` with burst parameters, counts, and profiles
  - [x] Test `airtell rogue-inject --port` with mock serial/controller verifying UART frame dispatch
- [x] Task: Run full regression test suite (`uv run pytest`) and linter (`uv run ruff check .`)
- [x] Task: Close all Track 2 GitHub issues (#55, #13, #25, #26, #42, #14, #27, #28, #41, #37, #48, #8)
