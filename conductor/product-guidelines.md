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
  - **Default Mode**: Clean summary terminal output with live status updates, throughput counters, and formatted alert notifications.
  - **Verbose Mode (`--verbose`)**: Real-time packet-by-packet stream detailing Link Layer headers, decoded AD structures, and payload hex dumps.
- **Standardized Formats**:
  - Timestamps: ISO-8601 UTC strings and monotonic microsecond offsets.
  - MAC Addresses: Uppercase colon-delimited format (`XX:XX:XX:XX:XX:XX`) with explicit type labels (`Public`, `Static Random`, `NRPA`, `RPA`).
  - Units: Explicitly labeled (`dBm`, `MHz`, `µs`).
- **Fail-Safe Lifecycle**: Graceful shutdown on `SIGINT`/`SIGTERM` via `ShutdownCoordinator`, ensuring serial port release, buffer flushing, and valid PCAP header closure.
