"""Unit tests for M3 Top App Bar and expanding Navigation Rail components."""

from __future__ import annotations

from app.components.navigation import (
    NAVIGATION_VIEWS,
    get_m3_layout_css,
    get_top_app_bar_html,
)


def test_navigation_views_definition() -> None:
    """Validate 6 core operational views are defined with labels and icons."""
    expected_keys = {"telemetry", "rssi", "alerts", "inspector", "controls", "adversarial"}
    assert set(NAVIGATION_VIEWS.keys()) == expected_keys

    for key, item in NAVIGATION_VIEWS.items():
        assert "label" in item
        assert "icon" in item
        assert len(item["label"]) > 0
        assert len(item["icon"]) > 0


def test_top_app_bar_html_generation() -> None:
    """Validate top app bar HTML generation with hardware telemetry badges."""
    html = get_top_app_bar_html(
        dongle1_status="CC2652P #1: ACTIVE",
        dongle2_status="CC2652P #2: ACTIVE",
        active_channels="CH 37 / 38",
    )
    assert "BLUETOOTH-SNIFFLE" in html
    assert "CC2652P #1: ACTIVE" in html
    assert "CC2652P #2: ACTIVE" in html
    assert "CH 37 / 38" in html
    assert "#0F141C" in html or "surface" in html.lower()


def test_m3_layout_css_tokens() -> None:
    """Validate M3 Dark Tactical CSS contains typography and surface variables."""
    css = get_m3_layout_css()
    assert "#0F141C" in css
    assert "#A8C7FA" in css
    assert "#1B2028" in css
    assert "font-family" in css
    assert "sidebar" in css.lower() or "rail" in css.lower()
