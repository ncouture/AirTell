"""Unit tests for PWA static assets, manifest, service worker, and M3 design tokens."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_manifest_json_structure_and_fields() -> None:
    """Validate app/static/manifest.json structure, required fields, and theme colors."""
    manifest_path = REPO_ROOT / "app" / "static" / "manifest.json"
    assert manifest_path.exists(), f"Missing manifest at {manifest_path}"

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "name" in data
    assert "short_name" in data
    assert data.get("display") == "standalone"
    assert data.get("start_url") in ["/", "./", "."]
    assert data.get("theme_color") == "#0F141C"
    assert data.get("background_color") == "#0F141C"

    icons = data.get("icons", [])
    assert len(icons) > 0, "Manifest must specify at least one icon asset"
    for icon in icons:
        assert "src" in icon
        assert "sizes" in icon
        assert "type" in icon
        assert icon["type"] in ["image/png", "image/svg+xml"]


def test_service_worker_script_and_caching_strategy() -> None:
    """Validate app/static/service-worker.js presence and caching logic."""
    sw_path = REPO_ROOT / "app" / "static" / "service-worker.js"
    assert sw_path.exists(), f"Missing service worker at {sw_path}"

    content = sw_path.read_text(encoding="utf-8")
    # Verify core lifecycle events
    assert "addEventListener('install'" in content or 'addEventListener("install"' in content
    assert "addEventListener('activate'" in content or 'addEventListener("activate"' in content
    assert "addEventListener('fetch'" in content or 'addEventListener("fetch"' in content

    # Verify cache-first static shell strategy and offline fallback
    assert "caches.open" in content
    assert "cache" in content.lower()
    assert "manifest.json" in content


def test_streamlit_theme_config() -> None:
    """Validate .streamlit/config.toml contains Material Design v3 Dark Tactical tokens."""
    config_path = REPO_ROOT / ".streamlit" / "config.toml"
    assert config_path.exists(), f"Missing config at {config_path}"

    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    assert "theme" in config, "config.toml must have a [theme] section"
    theme = config["theme"]

    assert theme.get("base") == "dark"
    assert theme.get("primaryColor") == "#A8C7FA"
    assert theme.get("backgroundColor") == "#0F141C"
    assert theme.get("secondaryBackgroundColor") == "#1B2028"
    assert theme.get("textColor") == "#E1E2E8"


def test_pwa_html_injection_helper() -> None:
    """Validate PWA injection helper outputs correct manifest link and SW registration script."""
    from app.components.pwa import get_pwa_meta_tags

    html = get_pwa_meta_tags()
    assert 'rel="manifest"' in html
    assert 'manifest.json' in html
    assert 'serviceWorker.register' in html
    assert '#0F141C' in html
