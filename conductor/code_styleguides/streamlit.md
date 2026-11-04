# Streamlit UI & Component Style Guide

This document defines standards for developing and maintaining the AirTell Material Design v3 Tactical PWA Streamlit dashboard (`app/`).

## 1. Component Architecture & UI Elements

- **Native Streamlit Components**: Use official native Streamlit widgets and components (`st.dataframe`, `st.metric`, `st.sidebar`, `st.plotly_chart`, `st.tabs`, `st.expander`).
- **Data Display**: Prefer `st.dataframe` with column configurations over raw HTML tables. Use `st.metric` for single-value KPIs with delta indicators.
- **Visual Theming**: Maintain consistent Material Design v3 Dark Tactical aesthetics through custom theme CSS in `app/theme/` and standard CSS classes, without injecting fragile inline styles into widgets.

## 2. Event-Driven Updates & Concurrency

- **Non-Blocking Architecture**: Avoid blocking `time.sleep()` loops in UI rendering threads. Use event-driven queues (`src/airtell/telemetry/queue_bridge.py`) and Streamlit auto-refresh fragments/intervals for periodic polling.
- **Resource Caching**: Cache heavy computational models, static assets, and reference data using `@st.cache_data` or `@st.cache_resource` with clear TTL and maximum entry bounds.
- **Session State**: Explicitly initialize and type session state variables in `st.session_state` before reading to prevent KeyError exceptions across rerun cycles.

## 3. Database & Hardware Resource Management

- **Connection Lifecycle**: Never leave database connections open across Streamlit reruns. Always open connections with context managers or ensure proper closure in `finally:` blocks.
- **Thread Safety**: Storage backends (`SQLiteBackend`, `DuckDBBackend`) must use thread-safe access patterns (thread-local connections or mutex-protected pools) when queried from asynchronous background reader threads.
- **Graceful Hardware Degradation**: Check dongle availability (`check_port_availability`) before launching streaming runs. Render informative status badges (`AVAILABLE`, `BUSY`, `MISSING DEPENDENCIES`) rather than raising unhandled exceptions.
