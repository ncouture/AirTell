# Specification: Streamlit Exclusive-Use Side-Channel Visualizer Tab

## 1. Overview
Integrate the completed Exclusive-Use BLE Side-Channel Verification Suite (`src/airtell/sidechannel/`) directly into the AirTell Streamlit Material Design v3 dashboard under `app/views/adversarial_evaluation.py`.
This visualizer exposes empirical Link-Layer side-channel analysis tools (Differential Encryption Initiation, CSRK 32-bit SignCounter monotonicity, and BAT allowlist timing oracles) to analyze packet traces that bypass Resolvable Private Address (RPA) randomization (PoPETs 2025 / ACM CCS 2022).

## 2. Functional Requirements

### FR1: Dedicated 4th Tab in Adversarial View
- Add a 4th tab titled `"⚡ Exclusive-Use Side-Channels"` in `app/views/adversarial_evaluation.py` alongside Identity Deanonymization, Pairing Relay, and Evasion Benchmarks.
- Implement responsive Material Design v3 styling adhering to dark tactical theme tokens (`#0F141C`, `#1B2028`, `#A8C7FA`, `#F2B8B5`, `#A8E8BA`).

### FR2: Dual Ingestion & Synthetic Simulation
- **Offline File Ingestion**: Provide drag-and-drop `st.file_uploader` for `.pcap` and `.pcapng` capture files, displaying file metadata (name, byte size, packet counts).
- **Live Queue Streaming**: Ingest packets in real-time from the shared singleton `EventQueue` (`app/queue_bridge.py`) without blocking Streamlit UI execution.
- **Synthetic Testbed Stream**: Built-in mock stream simulation allowing immediate offline verification and demonstration of all 3 side-channel mechanisms without requiring external hardware or capture files.
- **Filtering & Target Options**: Support optional target MAC/RPA filtering, custom 16-byte CSRK hex input, and active analyzer multi-selection (`differential_encryption`, `csrk_counter`, `bat_allowlist`).

### FR3: Interactive Plotly Visualizations
- **Timing Oracle Scatter Plot**:
  - Visualize Link-Layer inter-frame space timing ($T_{IFS} = 150\,\mu\text{s} \pm 2\,\mu\text{s}$) on the Y-axis against observation sequence / time on the X-axis.
  - Highlight the $150\,\mu\text{s}$ BAT allowlist response band vs unbonded silent drops ($> 1000\,\mu\text{s}$).
  - Rich hover tooltips providing PDU type, RSSI, target MAC, and exact latency.
- **CSRK Counter Trajectory Chart**:
  - Plot 32-bit `SignCounter` monotonically increasing values across randomized resolvable private addresses (RPAs).
  - Color-code data points by rotating RPA while linking them via trajectory lines to demonstrate cross-RPA device re-identification.
  - Highlight counter anomalies (replays, rollbacks, jumps, MAC verification failures).
- **Encryption Handshake Status Classification Table**:
  - Classify Link-Layer handshakes into `PAIRED_SHARED_LTK` (`LL_START_ENC_RSP`) vs `REJECTED_UNTRUSTED` (`LL_REJECT_IND` / `LL_REJECT_EXT_IND` with `PIN_OR_KEY_MISSING`).
  - Render status badges and expandable inspection view for Link-Layer control PDU hex payloads, EDIV, and RAND.

### FR4: PoPETs Empirical Metrics & Executive Summaries
- Display summary metric cards: Monitored Sessions / Devices, Confirmed Exclusive Devices, Oracle Detections, Overall Suite Verdict.
- Display PoPETs empirical research indicators: Timing Oracle Precision ($150\,\mu\text{s} \pm 2\,\mu\text{s}$ window, TPR/Accuracy), False Positive Rate (FPR), False Negative Rate (FNR), Handshake Recognition Rate.
- Threat level banner providing immediate triage classification (Critical Vulnerability vs Secure RPA vs Inconclusive).

### FR5: Caching & Export Capabilities
- Cache heavy offline PCAP analysis runs using `@st.cache_data` keyed by file content bytes and parameters.
- Provide `st.download_button` for serialized JSON report (`report.to_json()`).
- Provide `st.download_button` for structured Markdown vulnerability audit report (`report.to_markdown_summary()`).

## 3. Non-Functional Requirements
- **Streamlit Compatibility**: Modern Streamlit compliance avoiding deprecated `use_container_width`; using `width="stretch"` or `width="content"`.
- **Zero-Crash Resilience**: Clean empty-state handling for all charts and tables when no packets or findings are present.
- **Code Quality**: Zero `ruff` lint warnings (`line-length = 120`, target Python 3.10+), full test coverage in `tests/test_sidechannel_view.py`.

## 4. Acceptance Criteria
- [ ] 4th tab `"⚡ Exclusive-Use Side-Channels"` renders in `app/views/adversarial_evaluation.py`.
- [ ] Offline PCAP/PCAPNG upload, live `EventQueue` ingestion, and synthetic simulation work reliably.
- [ ] Plotly Timing Oracle scatter plot, CSRK trajectory chart, and Handshake classification table render with tactical tokens.
- [ ] PoPETs research metric cards and threat badges display accurate aggregated statistics.
- [ ] JSON and Markdown reports are generated and downloadable via Streamlit download buttons.
- [ ] `@st.cache_data` caches PCAP analysis results across UI interactions.
- [ ] Automated unit and regression test suite passes cleanly in `tests/test_sidechannel_view.py`.
- [ ] All existing 1,089 tests continue to pass.
