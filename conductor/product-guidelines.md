# Product Guidelines: AirTell

## 1. Voice and Tone
- **Objective & Scientifically Rigorous**: Use precise technical terminology from the Bluetooth Core Specification and peer-reviewed privacy literature (e.g. PoPETs 2025-0103). Distinguish Link Layer PDUs, AD structures, and upper-layer public keys.
- **Defensive & Privacy-Centric**: Frame tool capabilities and outputs around security analysis, stalking mitigation, and privacy preservation.
- **Concise & Signal-Rich**: Provide structured terminal and log outputs without conversational filler.

## 2. Threat & Alert Hierarchy
Anti-stalking heuristics and notifications must classify detections into a standardized multi-level threat hierarchy:
1. **Suspicious (Persistent Beaconing)**: Rotating identifier observed consistently across time-window thresholds (e.g. $\ge 5$ packets spanning $\ge 5$ minutes in a 15-minute window).
2. **High Proximity**: Detected tag exhibiting strong signal levels ($\text{RSSI} > -55\text{ dBm}$), indicating immediate physical closeness.
3. **Unlinkability Hazard**: Target device failing to rotate MAC addresses in tandem with cryptographic payload rotations, or broadcasting static identifiers.

## 3. CLI UX & Output Principles
- **Dual Display Modes**:
  - **Default Mode**: Clean summary dashboard with live status updates, throughput counters, and formatted alert notifications.
  - **Verbose Mode (`--verbose`)**: Real-time packet-by-packet stream detailing Link Layer headers, decoded AD structures, and payload hex dumps.
- **Standardized Formats**:
  - Timestamps: ISO-8601 UTC strings and monotonic microsecond offsets.
  - MAC Addresses: Uppercase colon-delimited format (`XX:XX:XX:XX:XX:XX`) with explicit type labels (`Public`, `Static Random`, `NRPA`, `RPA`).
  - Units: Explicitly labeled (`dBm`, `MHz`, `µs`).
- **Fail-Safe Lifecycle**: Graceful shutdown on `SIGINT`/`SIGTERM` via `ShutdownCoordinator`, ensuring serial port release, buffer flushing, and valid PCAP header closure.

## 4. Web Dashboard UX & Visual Design System
- **Aesthetic**: Dark, tactical, Material Design v3 (M3) compliant theme with high-contrast accents optimized for low-light lab monitoring and RF security operations.
- **Navigation & Layout Architecture**:
  - PWA-capable web architecture with standalone display mode.
  - Top App Bar conforming to M3 App Bar guidelines for system status, active profile, and quick actions.
  - Expanding / tiling navigation rail on the side for major views (Live Telemetry, RSSI Analysis, Alert Feed, Packet Inspector, Settings).
  - Bottom navigation bar when appropriate on responsive/compact viewports.
- **Component Integrity**: Strict adherence to components developed and shipped by the official Streamlit project itself (or explicitly recommended in official Streamlit documentation), avoiding unvetted third-party plugins.

## 5. PWA Architecture, Service Worker & Offline Caching
- **Web App Manifest**: Complete `manifest.json` specifying standalone display, dark theme color (`#0F141C`), application identity, and multi-resolution icons (192px and 512px).
- **Service Worker Caching Strategy**:
  - **Static Shell Assets**: Cache-first strategy for app shell assets, UI styles, and static scripts to ensure instant offline launch.
  - **Telemetry & Alert Feeds**: Network-first strategy with local fallback storage, allowing analysts to review historical captures, graphs, and alert logs even if the connection to the host server drops.
  - **Background Synchronization**: Offline state mutations (annotations, filter presets) queued locally and synchronized once connectivity resumes.
  - **Lifecycle Updates**: Transparent, non-intrusive notification prompting the user when an updated service worker cache is ready to activate.
