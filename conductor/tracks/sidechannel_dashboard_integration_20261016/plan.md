# Implementation Plan: Streamlit Exclusive-Use Side-Channel Visualizer Tab

## Phase 1: Conductor Track Scaffolding & Registry Indexing
- [x] Task: Scaffold Track 1 Conductor track directory and documentation (Issue #54)
  - [x] Create `conductor/tracks/sidechannel_dashboard_integration_20261016/`
  - [x] Create `metadata.json`, `index.md`, `spec.md`, and `plan.md`
- [x] Task: Index Exclusive-Use BLE Side-Channel Suite into `conductor/product.md` and `conductor/tracks.md` (Issue #38)
  - [x] Add Section 7 in `conductor/product.md` detailing side-channel architecture
  - [x] Register Track entry in `conductor/tracks.md`

## Phase 2: Core Reporting & Markdown Export Engine
- [x] Task: Enhance `SideChannelSuiteReport` in `src/airtell/sidechannel/runner.py` (Issue #39)
  - [x] Implement `to_markdown_summary()` with executive summary, PoPETs indicators, analyzer breakdowns, discrete findings table, and remediation guidance
  - [x] Support JSON serialization and Markdown generation

## Phase 3: Dashboard View Integration & Visualizations
- [x] Task: Implement Plotly figure generators and data transformers in `app/views/adversarial_evaluation.py` (Issue #21, #22, #23)
  - [x] Implement `build_timing_oracle_figure()` for Link-Layer $T_{IFS} = 150\,\mu\text{s} \pm 2\,\mu\text{s}$ distribution vs silent drops (Issue #21)
  - [x] Implement `build_csrk_trajectory_figure()` for 32-bit `SignCounter` progression and cross-RPA linking (Issue #22)
  - [x] Implement `build_handshake_classification_df()` for `PAIRED_SHARED_LTK` vs `REJECTED_UNTRUSTED` classification table and hex payload inspector (Issue #23)
- [x] Task: Implement PoPETs empirical metrics cards and threat level indicators (Issue #24)
  - [x] Add metric cards for Monitored Sessions, Confirmed Devices, Findings, Suite Verdict, Accuracy, FPR, FNR, Handshake Success Rate
  - [x] Add triage threat banners based on detection presence
- [x] Task: Add 4th tab "⚡ Exclusive-Use Side-Channels" to `app/views/adversarial_evaluation.py` (Issue #12)
  - [x] Update `st.tabs([...])` in `render_adversarial_evaluation()`
  - [x] Render control header, target MAC filter, and CSRK options
- [x] Task: Implement file uploader for offline PCAP/PCAPNG analysis (Issue #19)
  - [x] Add `st.file_uploader` for `.pcap` and `.pcapng`
  - [x] Display capture metadata (name, size, packet count, duration)
- [x] Task: Implement live `EventQueue` and synthetic stream ingestion (Issue #20)
  - [x] Add ingestion mode toggle (Offline PCAP, Live Queue, Synthetic Simulation)
  - [x] Convert `EventQueue` items into `BlePacketRecord` without blocking UI
  - [x] Provide synthetic mock stream generation for instant offline testing
- [x] Task: Implement analysis caching with `@st.cache_data` (Issue #40)
  - [x] Wrap offline PCAP analysis in `@st.cache_data` keyed on buffer bytes and parameters
- [x] Task: Add JSON and Markdown export download actions (Issue #39)
  - [x] Wire `st.download_button` for JSON export
  - [x] Wire `st.download_button` for Markdown audit report export

## Phase 4: Verification, Test Suite & Issue Closure
- [x] Task: Add automated test suite in `tests/test_sidechannel_view.py` (Issue #47)
  - [x] Test `build_timing_oracle_figure()` with data and empty states
  - [x] Test `build_csrk_trajectory_figure()` with monotonic, cross-RPA, and anomaly data
  - [x] Test `build_handshake_classification_df()` with positive and negative handshakes
  - [x] Test `to_markdown_summary()` report formatting
  - [x] Test `@st.cache_data` runner execution
  - [x] Test `render_adversarial_evaluation()` structure and full tab rendering
- [x] Task: Verify existing test suite compatibility
  - [x] Update `tests/test_dashboard_views.py` tabs mock to accommodate 4th tab
  - [x] Run `uv run pytest` across full repository (all 1,090+ tests passing)
  - [x] Run `uv run ruff check` with zero warnings
- [x] Task: Close all Track 1 GitHub issues (Issue #7, #12, #19, #20, #21, #22, #23, #24, #38, #39, #40, #47, #54)
