"""Material Design v3 Top App Bar and expanding Navigation Rail components."""

from __future__ import annotations

import streamlit as st

NAVIGATION_VIEWS: dict[str, dict[str, str]] = {
    "telemetry": {
        "label": "Live Telemetry",
        "icon": "📡",
        "description": "Real-time packet throughput & channel overview",
    },
    "rssi": {
        "label": "RSSI Trends",
        "icon": "📈",
        "description": "Signal strength time series by tracker ID",
    },
    "alerts": {
        "label": "Threat Alerts",
        "icon": "🚨",
        "description": "Anti-stalking triage & incident feeds",
    },
    "inspector": {
        "label": "Packet Inspector",
        "icon": "🔍",
        "description": "Deep PDU & AD structure dissection",
    },
    "controls": {
        "label": "Radio Controls",
        "icon": "🎛️",
        "description": "Testbed orchestration & rogue beacon injection",
    },
    "adversarial": {
        "label": "Adversarial Testbed",
        "icon": "⚡",
        "description": "Pairing relay, identity deanonymization & evasion benchmarks",
    },
}


def get_m3_layout_css() -> str:
    """Return Material Design v3 Dark Tactical CSS rules for Streamlit layout."""
    return """
<style>
/* Material Design v3 Dark Tactical Design Tokens */
:root {
  --md-sys-color-background: #0F141C;
  --md-sys-color-surface: #0F141C;
  --md-sys-color-surface-container: #1B2028;
  --md-sys-color-surface-container-high: #252B35;
  --md-sys-color-primary: #A8C7FA;
  --md-sys-color-on-primary: #0A305F;
  --md-sys-color-primary-container: #1E3A5F;
  --md-sys-color-on-surface: #E1E2E8;
  --md-sys-color-on-surface-variant: #C4C7D0;
  --md-sys-color-outline: #2D3440;
  --md-sys-color-error: #F2B8B5;
  --md-sys-color-error-container: #601410;
  --md-sys-color-success: #A8E8BA;
  --font-family-tactical: 'Roboto Mono', 'SF Pro Display', ui-monospace, monospace;
}

/* Global App Surface */
.stApp {
  background-color: var(--md-sys-color-background);
  color: var(--md-sys-color-on-surface);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

/* Sidebar M3 Navigation Rail */
[data-testid="stSidebar"] {
  background-color: var(--md-sys-color-surface-container);
  border-right: 1px solid var(--md-sys-color-outline);
  padding-top: 1rem;
}

[data-testid="stSidebar"] hr {
  border-color: var(--md-sys-color-outline);
}

/* Navigation Rail Radio buttons styled as M3 pill selectors */
[data-testid="stSidebar"] .stRadio > div {
  gap: 0.35rem;
}

[data-testid="stSidebar"] .stRadio label {
  padding: 0.65rem 1rem;
  border-radius: 9999px;
  background-color: transparent;
  color: var(--md-sys-color-on-surface-variant);
  font-weight: 500;
  transition: all 0.15s ease-in-out;
  cursor: pointer;
  border: 1px solid transparent;
}

[data-testid="stSidebar"] .stRadio label:hover {
  background-color: var(--md-sys-color-surface-container-high);
  color: var(--md-sys-color-on-surface);
  border-color: var(--md-sys-color-outline);
}

[data-testid="stSidebar"] .stRadio input:checked + div,
[data-testid="stSidebar"] .stRadio label[data-checked="true"] {
  background-color: var(--md-sys-color-primary-container);
  color: var(--md-sys-color-primary);
  font-weight: 600;
}

/* M3 Top App Bar */
.m3-top-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1.25rem;
  background: linear-gradient(180deg, #1B2028 0%, #0F141C 100%);
  border: 1px solid var(--md-sys-color-outline);
  border-radius: 12px;
  margin-bottom: 1.25rem;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

.m3-top-bar-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-family: var(--font-family-tactical);
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--md-sys-color-primary);
}

.m3-status-pills {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.m3-status-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.25rem 0.65rem;
  font-family: var(--font-family-tactical);
  font-size: 0.75rem;
  font-weight: 600;
  background-color: var(--md-sys-color-surface-container-high);
  color: var(--md-sys-color-on-surface);
  border: 1px solid var(--md-sys-color-outline);
  border-radius: 6px;
}

.m3-status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background-color: var(--md-sys-color-success);
  box-shadow: 0 0 6px var(--md-sys-color-success);
}

.m3-status-dot-idle {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background-color: #8E919A;
  box-shadow: 0 0 4px rgba(142, 145, 154, 0.4);
}
</style>
""".strip()


def get_top_app_bar_html(
    dongle1_status: str = "CC2652P #1: ACTIVE",
    dongle2_status: str = "CC2652P #2: ACTIVE",
    active_channels: str = "CH 37 / 38",
    dongle1_active: bool | None = None,
    dongle2_active: bool | None = None,
) -> str:
    """Generate HTML snippet for M3 Top App Bar.

    Args:
        dongle1_status: Primary Sniffle dongle status text.
        dongle2_status: Secondary Sniffle dongle status text.
        active_channels: Monitored BLE advertising channels text.
        dongle1_active: Whether primary dongle is actively in use. If None,
            inferred from status string (False if 'IDLE' or 'NOT OPEN' in status).
        dongle2_active: Whether secondary dongle is actively in use. If None,
            inferred from status string (False if 'IDLE' or 'NOT OPEN' in status).

    Returns:
        Renderable HTML string.
    """
    if dongle1_active is None:
        dongle1_active = not any(w in dongle1_status.upper() for w in ["IDLE", "NOT OPEN", "INACTIVE"])
    if dongle2_active is None:
        dongle2_active = not any(w in dongle2_status.upper() for w in ["IDLE", "NOT OPEN", "INACTIVE"])

    dot1_class = "m3-status-dot" if dongle1_active else "m3-status-dot-idle"
    dot2_class = "m3-status-dot" if dongle2_active else "m3-status-dot-idle"

    return f"""
<div class="m3-top-bar" data-surface="#0F141C">
  <div class="m3-top-bar-title">
    <span>📡</span>
    <span>AIRTELL // BLUETOOTH-SNIFFLE TACTICAL TESTBED</span>
  </div>
  <div class="m3-status-pills">
    <div class="m3-status-pill">
      <span class="{dot1_class}"></span>
      <span>{dongle1_status}</span>
    </div>
    <div class="m3-status-pill">
      <span class="{dot2_class}"></span>
      <span>{dongle2_status}</span>
    </div>
    <div class="m3-status-pill">
      <span style="color: var(--md-sys-color-primary);">☵</span>
      <span>{active_channels}</span>
    </div>
  </div>
</div>
""".strip()


def render_m3_styles() -> None:
    """Inject M3 Dark Tactical CSS tokens into the application DOM."""
    st.html(get_m3_layout_css())


def render_top_app_bar(
    dongle1_status: str = "CC2652P #1: ACTIVE",
    dongle2_status: str = "CC2652P #2: ACTIVE",
    active_channels: str = "CH 37 / 38",
    dongle1_active: bool | None = None,
    dongle2_active: bool | None = None,
) -> None:
    """Render the M3 Top App Bar in the main content container."""
    st.html(
        get_top_app_bar_html(
            dongle1_status=dongle1_status,
            dongle2_status=dongle2_status,
            active_channels=active_channels,
            dongle1_active=dongle1_active,
            dongle2_active=dongle2_active,
        )
    )


def render_navigation(
    dongle1_status: str | None = None,
    dongle2_status: str | None = None,
) -> str:
    """Render the M3 expanding Navigation Rail in the sidebar.

    Args:
        dongle1_status: Optional status string for Dongle 1 (e.g., '/dev/ttyUSB0: IN USE').
        dongle2_status: Optional status string for Dongle 2 (e.g., '/dev/ttyUSB1: IDLE').

    Returns:
        The selected operational view key (e.g., 'telemetry', 'rssi', etc.).
    """
    render_m3_styles()

    st.sidebar.markdown(
        """
        <div style="padding: 0.5rem 0.25rem 1rem 0.25rem;">
          <div style="font-size: 0.75rem; font-weight: 700; letter-spacing: 0.1em; color: #A8C7FA; text-transform: uppercase;">
            Tactical Operations
          </div>
          <div style="font-size: 0.85rem; color: #C4C7D0; margin-top: 0.2rem;">
            Sniffle Dual-Dongle BLE
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    options = list(NAVIGATION_VIEWS.keys())
    format_map = {
        key: f"{meta['icon']}  {meta['label']}"
        for key, meta in NAVIGATION_VIEWS.items()
    }

    selected = st.sidebar.radio(
        label="Navigation Rail",
        options=options,
        format_func=lambda x: format_map.get(x, x),
        label_visibility="collapsed",
    )

    st.sidebar.divider()

    d1_text = dongle1_status or "/dev/ttyUSB0: IDLE"
    d2_text = dongle2_status or "/dev/ttyUSB1: IDLE"

    st.sidebar.markdown(
        f"""
        <div style="padding: 0.5rem; font-size: 0.72rem; color: #8E919A; line-height: 1.4;">
          <b style="color: #E1E2E8;">PWA Status:</b> Standalone Ready<br>
          <b style="color: #E1E2E8;">Cache:</b> Cache-First Shell<br>
          <b style="color: #E1E2E8;">Firmware:</b> Sniffle CC2652P<br>
          <b style="color: #E1E2E8;">Device 1:</b> {d1_text}<br>
          <b style="color: #E1E2E8;">Device 2:</b> {d2_text}
        </div>
        """,
        unsafe_allow_html=True,
    )

    return str(selected)
