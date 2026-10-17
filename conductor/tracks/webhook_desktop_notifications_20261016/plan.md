# Implementation Plan: Webhook and OS Desktop Notification Dispatchers

## Phase 1: Conductor Track Scaffolding & Registry Indexing
- [x] Task: Scaffold Track 4 Conductor track directory and documentation (Issue #10)
  - [x] Create `conductor/tracks/webhook_desktop_notifications_20261016/`
  - [x] Create `metadata.json`, `index.md`, `spec.md`, and `plan.md`
- [x] Task: Update `conductor/tracks.md` registry with Track 4 entry

## Phase 2: HTTP Webhook Alert Dispatcher
- [x] Task: Implement `format_webhook_payload()` and `dispatch_webhook_alert()` in `src/airtell/scripts/ble_antistalking_tracker.py` (Issue #16)
  - [x] Structure JSON schema (unix & ISO 8601 timestamps, tracker ID, network type, packet count, duration, RSSI, alert level)
  - [x] Implement HMAC SHA-256 signing (`X-Signature-SHA256`) and Bearer authentication
  - [x] Guard with timeout and provide non-blocking asynchronous dispatch
  - [x] Gracefully catch and log errors without interrupting tracking loops

## Phase 3: Cross-Platform OS Desktop Notifications
- [x] Task: Implement `dispatch_desktop_notification()` in `src/airtell/scripts/ble_antistalking_tracker.py` (Issue #17)
  - [x] Support Linux `notify-send`
  - [x] Support macOS `osascript`
  - [x] Support Windows PowerShell / `ctypes`
  - [x] Implement headless detection and graceful fallback when binaries are missing

## Phase 4: Heuristic Hooking & Deduplication Cooldown Integration
- [x] Task: Hook dispatchers into `BLETrackerDB.check_stalking_heuristics()` (Issues #33, #34)
  - [x] Enforce deduplication and cooldown windows (default 300s) using the `alerts` table
  - [x] Prevent alert storms while keeping threat detection active
  - [x] Support runtime and database instance configuration for targets and secrets

## Phase 5: CLI Flags & Environment Variable Bindings
- [x] Task: Add CLI options and environment fallbacks to `ble_antistalking_tracker.py` (Issue #44)
  - [x] Add `--webhook-url` with `WEBHOOK_URL` fallback
  - [x] Add `--webhook-secret` with `WEBHOOK_SECRET` fallback
  - [x] Add `--enable-desktop-notify` with `DESKTOP_NOTIFY` fallback

## Phase 6: Automated Unit & Integration Testing
- [x] Task: Create comprehensive test suite in `tests/test_antistalking_dispatchers.py` (Issue #50)
  - [x] Test webhook JSON payload formatting and HMAC SHA-256 signatures
  - [x] Test webhook HTTP delivery, headers, timeouts, and error handling
  - [x] Test desktop notifications across Linux, macOS, and Windows with mock subprocesses
  - [x] Test headless Linux fallback and missing binary handling
  - [x] Test heuristic dispatch triggering, cooldown intervals, and deduplication
  - [x] Test CLI argument parsing and environment variable bindings
- [x] Task: Run repository test suite (`uv run pytest`) and linter (`uv run ruff check .`)

## Phase 7: Documentation Reconciliation & GitHub Issue Closures
- [x] Task: Update `docs/scripts_reference.md` and `docs/howto.md` (Issue #52)
- [x] Task: Close resolved GitHub issues (#16, #17, #33, #34, #44, #50, #52, #10)
