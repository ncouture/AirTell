# Specification: Webhook and OS Desktop Notification Dispatchers

## 1. Overview
Expand the anti-stalking threat detection framework in `src/airtell/scripts/ble_antistalking_tracker.py` beyond legacy Twilio SMS alerts.
This track provides real-time HTTP webhook alerting with JSON payload structuring, HMAC SHA-256 signatures / Bearer token authentication, and native cross-platform OS desktop notification popups across Linux (`notify-send`), macOS (`osascript`), and Windows (`PowerShell` / `ctypes`), hooked directly into `BLETrackerDB.check_stalking_heuristics()` with alert storm deduplication and cooldown windows.

## 2. Functional Requirements

### FR1: HTTP Webhook Alert Dispatcher (Issues #16, #33)
- Implement `dispatch_webhook_alert()` in `src/airtell/scripts/ble_antistalking_tracker.py` (and backward-compatibility shims).
- Support well-defined JSON schema containing:
  - `timestamp`: Unix epoch float.
  - `timestamp_iso`: ISO 8601 UTC string.
  - `tracker_id`: Extracted ephemeral key or pseudo-MAC address.
  - `network_type`: Classified crowdsourced network (Apple Find My, Google Find Hub, Tile Tracker, Samsung SmartThings Find).
  - `packet_count`: Number of observed packets within sliding window.
  - `duration` / `duration_seconds`: Total span of observations in seconds.
  - `max_rssi`: Strongest recorded signal strength (dBm).
  - `mean_rssi` / `avg_rssi`: Mean recorded signal strength (dBm).
  - `alert_level`: Threat level (`HIGH` or `CRITICAL` based on proximity/duration).
  - `alert_message`: Formatted human-readable alert string.
- Provide HMAC SHA-256 digest signing (`X-Signature-SHA256`) and Bearer token (`Authorization: Bearer <secret>`) when secret is provided.
- Ensure timeout-guarded, non-blocking asynchronous dispatch option (`async_dispatch=True`) with error logging without interrupting the sniffer loop.

### FR2: Cross-Platform OS Desktop Notifications (Issues #17, #34)
- Implement `dispatch_desktop_notification()` in `src/airtell/scripts/ble_antistalking_tracker.py`.
- Support multiple desktop environments:
  - Linux: `notify-send` with critical urgency flag.
  - macOS: `osascript` displaying native notifications.
  - Windows: PowerShell UI script or `ctypes` message box.
- Include graceful fallback handling when running in headless environments (`DISPLAY` / `WAYLAND_DISPLAY` missing) or when platform binaries are absent.
- Format notifications with threat level, tracker network type, duration, and maximum RSSI.

### FR3: Heuristic Triggering & Deduplication Cooldown (Issues #33, #34)
- Hook both webhook and desktop notification dispatchers into `BLETrackerDB.check_stalking_heuristics()`.
- Incorporate deduplication / cooldown windows (default 300s / 5 mins) against the `alerts` database table to prevent alert storms while maintaining active observation tracking.
- Allow optional runtime override of webhook URL, secret, desktop notification toggle, and cooldown duration.

### FR4: CLI Flags & Environment Variable Bindings (Issue #44)
- Add CLI options to `ble_antistalking_tracker.py`:
  - `--webhook-url` (env: `WEBHOOK_URL`)
  - `--webhook-secret` (env: `WEBHOOK_SECRET`)
  - `--enable-desktop-notify` (env: `DESKTOP_NOTIFY`)
- Ensure environment variables serve as default fallbacks when CLI options are omitted.

### FR5: Automated Unit & Integration Tests (Issue #50)
- Create `tests/test_antistalking_dispatchers.py` validating:
  - Webhook POST payload formatting, headers, HMAC signature generation, and HTTP error resilience.
  - Desktop notification execution commands across Linux, macOS, and Windows with mock subprocesses.
  - Heuristic triggering, cooldown/deduplication intervals, CLI arguments, and environment variable fallbacks.
- Verify 100% test pass rate across the full test suite (`uv run pytest`) and zero lint warnings (`uv run ruff check .`).

### FR6: Technical Documentation & Operational Guides (Issue #52, #10)
- Update `docs/scripts_reference.md` with complete CLI flags, webhook JSON schema, signature verification, and desktop notification details.
- Update `docs/howto.md` with end-to-end operational workflows, example curl receivers, and setup guides.

## 3. Non-Functional Requirements
- **Performance**: Non-blocking delivery ensures sniffer packet ingest and heuristic loops never block on network or OS notification latency.
- **Security**: Cryptographic HMAC-SHA256 ensures receiver authentication and payload integrity over unauthenticated HTTP or public webhooks.
- **Reliability & Resilience**: Missing binaries, headless Linux environments, or webhook HTTP timeouts fail gracefully without crashing tracker execution.
- **Code Quality**: Zero `ruff` lint warnings, Python 3.10+ typing standards.

## 4. Acceptance Criteria
- [x] Webhook alert dispatcher constructs valid JSON payloads with unix & ISO 8601 timestamps, tracker ID, network type, RSSI, and alert level.
- [x] Webhook requests support HMAC SHA-256 header and Bearer token authentication when secret is supplied.
- [x] Native OS desktop notifications execute correctly across Linux, macOS, and Windows, falling back gracefully in headless modes.
- [x] `BLETrackerDB.check_stalking_heuristics()` dispatches alerts to webhook and desktop notification targets with cooldown deduplication.
- [x] CLI flags `--webhook-url`, `--webhook-secret`, and `--enable-desktop-notify` bind correctly to environment variables `WEBHOOK_URL`, `WEBHOOK_SECRET`, and `DESKTOP_NOTIFY`.
- [x] Comprehensive test suite in `tests/test_antistalking_dispatchers.py` passes all unit and integration tests.
- [x] All repository tests pass (`uv run pytest`) and linter checks succeed with zero errors.
- [x] Technical references in `docs/scripts_reference.md` and `docs/howto.md` accurately document configuration and operational usage.
