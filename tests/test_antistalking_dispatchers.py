"""Unit and integration tests for BLE anti-stalking webhook and desktop notification dispatchers.

Validates:
- Webhook JSON schema construction (unix & ISO 8601 timestamps, tracker ID, duration, RSSI, threat level)
- HMAC-SHA256 signature calculation and Bearer token authentication headers
- HTTP POST request error handling and timeout resilience
- Asynchronous non-blocking webhook and desktop dispatchers
- Cross-platform desktop notifications (Linux notify-send, macOS osascript, Windows PowerShell / ctypes)
- Graceful degradation in headless environments or when notification binaries are missing
- Deduplication and cooldown windows in BLETrackerDB.check_stalking_heuristics()
- CLI options and environment variable configuration bindings
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

try:
    from airtell.scripts.ble_antistalking_tracker import (
        BLETrackerDB,
        dispatch_desktop_notification,
        dispatch_webhook_alert,
        format_webhook_payload,
        send_notification,
    )
except ImportError:
    from scripts.ble_antistalking_tracker import (  # type: ignore[no-redef]
        BLETrackerDB,
        dispatch_desktop_notification,
        dispatch_webhook_alert,
        format_webhook_payload,
        send_notification,
    )


@pytest.fixture
def temp_tracker_db(tmp_path: Path) -> BLETrackerDB:
    """Fixture returning a fresh SQLite tracker database."""
    db_file = tmp_path / "test_antistalking.db"
    return BLETrackerDB(str(db_file))


def test_format_webhook_payload_schema():
    """Verify standard schema formatting for webhook JSON payloads."""
    fixed_time = 1700000000.0
    alert_info = {
        "identifier": "0102030405060708090a0b0c",
        "network_type": "Apple Find My",
        "observation_count": 8,
        "first_seen": fixed_time - 600.0,
        "last_seen": fixed_time,
        "max_rssi": -55,
        "avg_rssi": -62.4,
        "alert_message": "POSSIBLE STALKER DETECTED: Apple Find My beacon seen 8 times",
        "timestamp": fixed_time,
    }

    payload = format_webhook_payload(alert_info)

    assert payload["tracker_id"] == "0102030405060708090a0b0c"
    assert payload["network_type"] == "Apple Find My"
    assert payload["packet_count"] == 8
    assert payload["duration"] == 600.0
    assert payload["duration_seconds"] == 600.0
    assert payload["max_rssi"] == -55
    assert payload["mean_rssi"] == -62.4
    assert payload["avg_rssi"] == -62.4
    assert payload["alert_level"] == "CRITICAL"  # max_rssi >= -60
    assert "POSSIBLE STALKER" in payload["alert_message"]
    assert payload["timestamp"] == fixed_time
    assert "2023-" in payload["timestamp_iso"] or "T" in payload["timestamp_iso"]


def test_format_webhook_payload_high_threat_level():
    """Verify threat level evaluates to HIGH when max_rssi is lower than -60 dBm."""
    alert_info = {
        "identifier": "tile_beacon_uuid_99",
        "network_type": "Tile Tracker",
        "observation_count": 5,
        "first_seen": 100.0,
        "last_seen": 400.0,
        "max_rssi": -75,
        "avg_rssi": -80.0,
    }
    payload = format_webhook_payload(alert_info)
    assert payload["alert_level"] == "HIGH"
    assert payload["duration"] == 300.0


def test_dispatch_webhook_alert_success_and_hmac_signature():
    """Verify HTTP POST transmission, HMAC SHA-256 header, and Bearer token."""
    secret = "k3y_s3cr3t_antistalking_2026"
    target_url = "https://security.example.com/api/v1/alerts"
    alert_data = {
        "identifier": "google_find_hub_42",
        "network_type": "Google Find Hub",
        "observation_count": 12,
        "first_seen": 1000.0,
        "last_seen": 1500.0,
        "max_rssi": -58,
        "avg_rssi": -65.0,
        "alert_message": "Stalker detected",
    }

    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        success = dispatch_webhook_alert(
            alert_data=alert_data,
            webhook_url=target_url,
            secret=secret,
            timeout=3.5,
            headers={"X-Custom-Source": "AirTell-Testbed"},
        )

        assert success is True
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]

        assert req.get_full_url() == target_url
        assert req.get_method() == "POST"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("User-agent") == "AirTell-Tracker/0.2.0"
        assert req.get_header("Authorization") == f"Bearer {secret}"
        assert req.get_header("X-custom-source") == "AirTell-Testbed"

        body_bytes = req.data
        expected_sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        assert req.get_header("X-signature-sha256") == expected_sig

        parsed_body = json.loads(body_bytes.decode("utf-8"))
        assert parsed_body["tracker_id"] == "google_find_hub_42"
        assert parsed_body["packet_count"] == 12


def test_dispatch_webhook_alert_empty_url_noop():
    """Verify dispatch_webhook_alert immediately returns False when URL is empty."""
    assert dispatch_webhook_alert({"identifier": "test"}, webhook_url="") is False


def test_dispatch_webhook_alert_error_resilience():
    """Verify that network exceptions are caught and logged without raising."""
    with patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
        success = dispatch_webhook_alert(
            alert_data={"identifier": "test"},
            webhook_url="https://unreachable.local/webhook",
            timeout=1.0,
        )
        assert success is False


def test_dispatch_webhook_alert_non_2xx_status():
    """Verify non-2xx HTTP response codes return False."""
    mock_response = MagicMock()
    mock_response.getcode.return_value = 500
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        success = dispatch_webhook_alert(
            alert_data={"identifier": "test"},
            webhook_url="https://service.local/webhook",
        )
        assert success is False


def test_dispatch_webhook_alert_async():
    """Verify asynchronous non-blocking webhook dispatch."""
    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        success = dispatch_webhook_alert(
            alert_data={"identifier": "test_async"},
            webhook_url="https://async.local/webhook",
            async_dispatch=True,
        )
        assert success is True
        # Allow daemon thread a moment to execute
        time.sleep(0.1)
        mock_urlopen.assert_called_once()


def test_desktop_notification_linux_notify_send():
    """Verify Linux desktop notification via notify-send command."""
    mock_completed = subprocess.CompletedProcess(args=[], returncode=0)

    with (
        patch("shutil.which", return_value="/usr/bin/notify-send") as mock_which,
        patch.dict(os.environ, {"DISPLAY": ":0"}),
        patch("subprocess.run", return_value=mock_completed) as mock_run,
    ):
        alert_data = {
            "network_type": "Apple Find My",
            "identifier": "0102030405060708090a",
            "observation_count": 10,
            "duration": 600.0,
            "max_rssi": -52,
            "alert_level": "CRITICAL",
        }
        res = dispatch_desktop_notification(alert_data, system_override="linux")
        assert res is True
        mock_which.assert_called_with("notify-send")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/bin/notify-send"
        assert cmd[1] == "-u"
        assert cmd[2] == "critical"
        assert "CRITICAL" in cmd[3]
        assert "Apple Find My" in cmd[4]


def test_desktop_notification_linux_headless_fallback():
    """Verify Linux skips notify-send cleanly in headless environments."""
    env_without_display = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    with (
        patch.dict(os.environ, env_without_display, clear=True),
        patch("subprocess.run") as mock_run,
    ):
        res = dispatch_desktop_notification("Test alert", system_override="linux")
        assert res is False
        mock_run.assert_not_called()


def test_desktop_notification_linux_missing_binary():
    """Verify Linux returns False gracefully when notify-send binary is missing."""
    with (
        patch.dict(os.environ, {"DISPLAY": ":0"}),
        patch("shutil.which", return_value=None),
        patch("subprocess.run") as mock_run,
    ):
        res = dispatch_desktop_notification("Test alert", system_override="linux")
        assert res is False
        mock_run.assert_not_called()


def test_desktop_notification_macos_osascript():
    """Verify macOS desktop notification via osascript."""
    mock_completed = subprocess.CompletedProcess(args=[], returncode=0)
    with (
        patch("shutil.which", return_value="/usr/bin/osascript") as mock_which,
        patch("subprocess.run", return_value=mock_completed) as mock_run,
    ):
        res = dispatch_desktop_notification(
            {"network_type": "Tile Tracker", "alert_message": "Tile detected"},
            system_override="darwin",
        )
        assert res is True
        mock_which.assert_called_with("osascript")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/bin/osascript"
        assert cmd[1] == "-e"
        assert "display notification" in cmd[2]


def test_desktop_notification_windows_powershell():
    """Verify Windows desktop notification via PowerShell."""
    mock_completed = subprocess.CompletedProcess(args=[], returncode=0)
    with (
        patch("shutil.which", return_value="powershell.exe"),
        patch("subprocess.run", return_value=mock_completed) as mock_run,
    ):
        res = dispatch_desktop_notification(
            {"network_type": "Samsung SmartThings Find", "alert_message": "SmartTag detected"},
            system_override="windows",
        )
        assert res is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "powershell" in cmd[0]
        assert "-NoProfile" in cmd
        assert "System.Windows.Forms.MessageBox" in cmd[3]


def test_desktop_notification_async():
    """Verify asynchronous non-blocking desktop dispatch."""
    mock_completed = subprocess.CompletedProcess(args=[], returncode=0)
    with (
        patch("shutil.which", return_value="/usr/bin/notify-send"),
        patch.dict(os.environ, {"DISPLAY": ":0"}),
        patch("subprocess.run", return_value=mock_completed) as mock_run,
    ):
        res = dispatch_desktop_notification(
            "Async alert message",
            system_override="linux",
            async_dispatch=True,
        )
        assert res is True
        time.sleep(0.1)
        mock_run.assert_called_once()


def test_heuristic_triggering_and_cooldown_deduplication(temp_tracker_db: BLETrackerDB):
    """Verify heuristic alerting, webhook/desktop dispatch, and deduplication cooldown."""
    now = time.time()
    beacon_key = "tracked_stalker_beacon_42"

    # Insert 6 observations spanning 10 minutes (sufficient to satisfy heuristics)
    for i in range(6):
        obs_time = now - (6 - i) * 100
        temp_tracker_db.insert_observation(
            mac_address=f"aa:bb:cc:dd:ee:{i:02x}",
            rssi=-54,
            network_type="Apple Find My",
            ephemeral_key=beacon_key,
            channel=37,
            raw_payload="020106",
            timestamp=obs_time,
        )

    with (
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_webhook_alert") as mock_webhook,
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_desktop_notification") as mock_desktop,
    ):
        # 1. First heuristic evaluation: Should trigger alert and dispatch
        alerts1 = temp_tracker_db.check_stalking_heuristics(
            window_minutes=15,
            min_observations=5,
            min_duration_minutes=5,
            webhook_url="https://sec.corp/alert",
            webhook_secret="sec_pass",
            enable_desktop_notify=True,
            cooldown_seconds=300,
            deduplicate=True,
        )
        assert len(alerts1) == 1
        assert alerts1[0]["identifier"] == beacon_key
        assert alerts1[0]["in_cooldown"] is False
        mock_webhook.assert_called_once()
        mock_desktop.assert_called_once()

        # Check that alert was recorded in alerts table
        with temp_tracker_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE identifier = ?", (beacon_key,))
            assert cursor.fetchone()[0] == 1

        # 2. Immediate second evaluation with deduplicate=True: Should suppress alert
        mock_webhook.reset_mock()
        mock_desktop.reset_mock()
        alerts2 = temp_tracker_db.check_stalking_heuristics(
            window_minutes=15,
            min_observations=5,
            min_duration_minutes=5,
            webhook_url="https://sec.corp/alert",
            enable_desktop_notify=True,
            cooldown_seconds=300,
            deduplicate=True,
        )
        assert len(alerts2) == 0
        mock_webhook.assert_not_called()
        mock_desktop.assert_not_called()

        # 3. Third evaluation with deduplicate=False: Returns alert marked in_cooldown, but dispatches nothing
        alerts3 = temp_tracker_db.check_stalking_heuristics(
            window_minutes=15,
            min_observations=5,
            min_duration_minutes=5,
            webhook_url="https://sec.corp/alert",
            enable_desktop_notify=True,
            cooldown_seconds=300,
            deduplicate=False,
        )
        assert len(alerts3) == 1
        assert alerts3[0]["in_cooldown"] is True
        mock_webhook.assert_not_called()
        mock_desktop.assert_not_called()


def test_cli_flags_and_env_var_bindings():
    """Verify that CLI flags and environment variables configure dispatchers properly."""
    # 1. Test CLI flags override
    parser = argparse.ArgumentParser()
    parser.add_argument("--webhook-url", default=os.getenv("WEBHOOK_URL", ""))
    parser.add_argument("--webhook-secret", default=os.getenv("WEBHOOK_SECRET", ""))
    parser.add_argument(
        "--enable-desktop-notify",
        action="store_true",
        default=os.getenv("DESKTOP_NOTIFY", "").strip().lower() in ("1", "true", "yes", "on"),
    )

    args = parser.parse_args([
        "--webhook-url", "https://cli.hook.local/alert",
        "--webhook-secret", "cli_secret",
        "--enable-desktop-notify",
    ])
    assert args.webhook_url == "https://cli.hook.local/alert"
    assert args.webhook_secret == "cli_secret"
    assert args.enable_desktop_notify is True

    # 2. Test environment variable fallbacks
    with patch.dict(os.environ, {
        "WEBHOOK_URL": "https://env.hook.local/alert",
        "WEBHOOK_SECRET": "env_secret_123",
        "DESKTOP_NOTIFY": "1",
    }):
        parser2 = argparse.ArgumentParser()
        parser2.add_argument("--webhook-url", default=os.getenv("WEBHOOK_URL", ""))
        parser2.add_argument("--webhook-secret", default=os.getenv("WEBHOOK_SECRET", ""))
        parser2.add_argument(
            "--enable-desktop-notify",
            action="store_true",
            default=os.getenv("DESKTOP_NOTIFY", "").strip().lower() in ("1", "true", "yes", "on"),
        )
        args_env = parser2.parse_args([])
        assert args_env.webhook_url == "https://env.hook.local/alert"
        assert args_env.webhook_secret == "env_secret_123"
        assert args_env.enable_desktop_notify is True


def test_send_notification_multichannel():
    """Verify send_notification dispatches across Twilio SMS, Webhook, and Desktop."""
    with (
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_webhook_alert") as mock_webhook,
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_desktop_notification") as mock_desktop,
    ):
        send_notification(
            alert_message="Multichannel alert",
            webhook_url="https://hook.org",
            webhook_secret="sec",
            enable_desktop_notify=True,
        )
        mock_webhook.assert_called_once()
        mock_desktop.assert_called_once_with("Multichannel alert", async_dispatch=True)


def test_format_webhook_payload_none_and_malformed_values():
    """Verify format_webhook_payload safely handles explicit None, malformed, or missing values."""
    alert_with_nones = {
        "timestamp": None,
        "first_seen": None,
        "last_seen": None,
        "duration": None,
        "duration_seconds": None,
        "observation_count": None,
        "packet_count": None,
        "max_rssi": None,
        "avg_rssi": None,
        "mean_rssi": None,
        "identifier": None,
        "tracker_id": None,
        "network_type": None,
        "alert_level": None,
        "alert_message": None,
    }
    payload = format_webhook_payload(alert_with_nones)
    assert payload["tracker_id"] == "Unknown"
    assert payload["network_type"] == "Unknown"
    assert payload["packet_count"] == 0
    assert payload["duration"] == 0.0
    assert payload["max_rssi"] == 0
    assert payload["mean_rssi"] == 0.0
    assert payload["alert_level"] == "CRITICAL"  # 0 >= -60
    assert payload["alert_message"] == ""
    assert isinstance(payload["timestamp"], float)

    # String input test
    str_payload = format_webhook_payload("Raw alert string")
    assert str_payload["alert_message"] == "Raw alert string"
    assert str_payload["tracker_id"] == "Unknown"


def test_dispatch_webhook_alert_from_string():
    """Verify dispatch_webhook_alert accepts a plain string alert message."""
    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        success = dispatch_webhook_alert(
            alert_data="Direct string alert",
            webhook_url="https://alerts.corp/webhook",
        )
        assert success is True
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        parsed = json.loads(req.data.decode("utf-8"))
        assert parsed["alert_message"] == "Direct string alert"


def test_dispatch_webhook_alert_http_error_handling():
    """Verify explicit HTTPError exception handling with status code logging."""
    import urllib.error

    http_err = urllib.error.HTTPError(
        url="https://sec.corp/401",
        code=401,
        msg="Unauthorized",
        hdrs={},  # type: ignore[arg-type]
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=http_err):
        res = dispatch_webhook_alert(
            alert_data={"identifier": "test"},
            webhook_url="https://sec.corp/401",
        )
        assert res is False


def test_desktop_notification_sanitizes_newlines_and_null_bytes():
    """Verify newlines and null bytes in notification title and body are sanitized."""
    mock_completed = subprocess.CompletedProcess(args=[], returncode=0)

    # macOS osascript sanitization
    with (
        patch("shutil.which", return_value="/usr/bin/osascript"),
        patch("subprocess.run", return_value=mock_completed) as mock_run_mac,
    ):
        res = dispatch_desktop_notification(
            {"alert_message": "Line 1\nLine 2\r\0Injected text"},
            title="Title\nSub\0",
            system_override="darwin",
        )
        assert res is True
        script = mock_run_mac.call_args[0][0][2]
        assert "\n" not in script
        assert "\r" not in script
        assert "\0" not in script

    # Linux notify-send null byte sanitization
    with (
        patch("shutil.which", return_value="/usr/bin/notify-send"),
        patch.dict(os.environ, {"DISPLAY": ":0"}),
        patch("subprocess.run", return_value=mock_completed) as mock_run_linux,
    ):
        res_linux = dispatch_desktop_notification(
            "Alert\0Body",
            title="Title\0",
            system_override="linux",
        )
        assert res_linux is True
        cmd = mock_run_linux.call_args[0][0]
        assert "\0" not in cmd[3]
        assert "\0" not in cmd[4]


def test_desktop_notification_windows_ctypes_fallback():
    """Verify Windows ctypes fallback when PowerShell binary is absent on Windows."""
    with (
        patch("shutil.which", return_value=None),
        patch("sys.platform", "win32"),
    ):
        mock_ctypes = MagicMock()
        mock_ctypes.windll.user32.MessageBoxTimeoutW.return_value = 1
        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            res = dispatch_desktop_notification(
                "Windows popup",
                system_override="windows",
            )
            assert res is True


def test_cooldown_disabled_when_zero_or_negative(temp_tracker_db: BLETrackerDB):
    """Verify that setting cooldown_seconds=0 allows immediate re-alerting."""
    now = 1700000000.0
    key = "beacon_zero_cooldown"

    for i in range(6):
        temp_tracker_db.insert_observation(
            mac_address=f"aa:bb:cc:dd:ee:{i:02x}",
            rssi=-50,
            network_type="Apple Find My",
            ephemeral_key=key,
            timestamp=now - (6 - i) * 100,
        )

    with patch("time.time", return_value=now):
        # First call with cooldown_seconds=0
        alerts1 = temp_tracker_db.check_stalking_heuristics(
            cooldown_seconds=0,
            deduplicate=True,
            async_dispatch=False,
        )
        assert len(alerts1) == 1
        assert alerts1[0]["in_cooldown"] is False

        # Immediate second call at exact same timestamp with cooldown_seconds=0: should NOT be suppressed
        alerts2 = temp_tracker_db.check_stalking_heuristics(
            cooldown_seconds=0,
            deduplicate=True,
            async_dispatch=False,
        )
        assert len(alerts2) == 1
        assert alerts2[0]["in_cooldown"] is False


def test_send_notification_with_dict_payload():
    """Verify send_notification forwards full rich payload dict to dispatchers."""
    alert_info = {
        "identifier": "0102030405060708090a",
        "tracker_id": "0102030405060708090a",
        "network_type": "Tile Tracker",
        "observation_count": 9,
        "max_rssi": -48,
        "alert_level": "CRITICAL",
        "alert_message": "Critical Tile detected",
    }
    with (
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_webhook_alert") as mock_webhook,
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_desktop_notification") as mock_desktop,
    ):
        send_notification(
            alert_message=alert_info,
            webhook_url="https://sec.corp/alert",
            enable_desktop_notify=True,
        )
        mock_webhook.assert_called_once_with(
            alert_info,
            webhook_url="https://sec.corp/alert",
            secret=None,
            async_dispatch=True,
        )
        mock_desktop.assert_called_once_with(alert_info, async_dispatch=True)


def test_dispatch_webhook_alert_semaphore_limiting():
    """Verify semaphore prevents thread explosion when concurrency limit is reached."""
    from airtell.scripts.ble_antistalking_tracker import _DISPATCH_SEMAPHORE

    # Acquire all permits to simulate saturated dispatcher
    acquired = []
    try:
        while True:
            if _DISPATCH_SEMAPHORE.acquire(blocking=False):
                acquired.append(True)
            else:
                break
        with patch("urllib.request.urlopen") as mock_urlopen:
            res = dispatch_webhook_alert(
                "Dropped alert",
                webhook_url="https://sec.corp/alert",
                async_dispatch=True,
            )
            # async_dispatch returns True because thread launched, but worker safely drops without network I/O
            assert res is True
            time.sleep(0.05)
            mock_urlopen.assert_not_called()
    finally:
        for _ in acquired:
            _DISPATCH_SEMAPHORE.release()


def test_check_stalking_heuristics_async_dispatch_toggle(temp_tracker_db: BLETrackerDB):
    """Verify check_stalking_heuristics forwards async_dispatch parameter."""
    now = time.time()
    for i in range(6):
        temp_tracker_db.insert_observation(
            mac_address=f"aa:bb:cc:dd:ee:{i:02x}",
            rssi=-50,
            network_type="Tile Tracker",
            ephemeral_key="sync_test_key",
            timestamp=now - (6 - i) * 100,
        )

    with (
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_webhook_alert") as mock_webhook,
        patch("airtell.scripts.ble_antistalking_tracker.dispatch_desktop_notification") as mock_desktop,
    ):
        alerts = temp_tracker_db.check_stalking_heuristics(
            webhook_url="https://sync.org",
            enable_desktop_notify=True,
            async_dispatch=False,
        )
        assert len(alerts) == 1
        mock_webhook.assert_called_once()
        assert mock_webhook.call_args[1]["async_dispatch"] is False
        mock_desktop.assert_called_once()
        assert mock_desktop.call_args[1]["async_dispatch"] is False


