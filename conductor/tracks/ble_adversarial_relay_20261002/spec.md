# Specification: BLE Tracker Deanonymization, Pairing Relay Evaluation & Rogue Beacon Testbed

## 1. Overview
Build an adversarial security evaluation testbed leveraging the dual-dongle Sniffle architecture to:
1. Detect and deanonymize rotating BLE tracking identifiers via multi-signal correlation (static MAC leakage detection, payload-to-address rotation timing divergence, and pairing protocol handshake timing).
2. Implement a two-ended BLE pairing relay testbed where Device 1 captures central connection/pairing requests, forwards them across a low-latency IPC queue to Device 2 operating as a peripheral proxy, and extracts success/failure feedback signals to link randomized Private Addresses (RPAs).
3. Construct a synthetic rogue beacon generator supporting Apple Find My, Google Find Hub, Samsung SmartThings Find, and Tile with parameterized rotation intervals, jitter, and signal attenuation to systematically evaluate the detection resilience and evasion thresholds of anti-stalking algorithms.

## 2. Functional Requirements

### FR1: Multi-Signal Rotating Identifier Deanonymizer
- **Static Address Leakage Detection**: Flag target tags broadcasting identical public keys alongside fixed MAC addresses, or transmitting constant IEEE OUI prefixes across address rotations.
- **Rotation Desynchronization Analysis**: Measure timing divergence $\Delta t = |t_{\text{MAC\_rotate}} - t_{\text{Payload\_rotate}}|$ between Link Layer AdvA address changes and cryptographic payload rotations. Identify persistent tracking tags where cryptographic keys outlive ephemeral MAC addresses.
- **Trajectory Linkability Engine**: Reconstruct tracking tag movement trails across address rotations by correlating RSSI gradients, advertisement interval jitter, and sequence numbers.

### FR2: Two-Ended Pairing Relay Testbed
- **Topology A Pairing Relay Mode**:
  - Device 1 (Observer/Sniffer) intercepts Link Layer connection indications (`CONNECT_IND`) and pairing requests (`LL_FEATURE_REQ`, `SMP_PAIRING_REQ`).
  - Low-latency thread-safe IPC bridge forwards serialized Link Layer packets between Device 1 and Device 2 with microsecond timestamp preservation.
  - Device 2 (Peripheral Proxy/Stimulator) simulates target BLE peripheral responses or forwards frames to real target devices.
- **Success/Failure Signal Deanonymization**:
  - Extract cryptographic confirmation (`SMP_PAIRING_CONFIRM`) and public key exchange status.
  - Correlate pairing error codes (`SMP_PAIRING_FAILED`, e.g. Passkey Entry Failed, Pairing Not Supported) against rotating MAC addresses to deanonymize target identities across address cycles.

### FR3: Synthetic Rogue Beacon Generator & Anti-Stalking Evasion Benchmark
- **Multi-Network Rogue Beacon Synthesis**:
  - Synthesize valid connectionless payloads for Apple Find My (`0x004C`/`0x12`), Google Find Hub (`0xFE9F`), Samsung SmartThings Find (`0x0075`), and Tile (`0xFEED`).
  - Support injection bursts with customizable inter-packet intervals (20 ms to 10.24 s), intentional rotation jitter, and RSSI attenuation profiles.
- **Anti-Stalking Evasion Benchmark Suite**:
  - Automated evaluation harness benchmarking `ble_antistalking_tracker.py` heuristic thresholds (15-minute sliding window, $\ge 5$ packets, $\ge 5$ min persistence span).
  - Simulate evasion patterns: burst-and-sleep tactics, address-rotation jittering, and signal dilution across advertising channels 37, 38, 39 to identify detection blind spots.

### FR4: CLI & Dashboard Integration
- Provide dedicated CLI subcommands (`bluetooth-sniffle relay`, `bluetooth-sniffle deanonymize`, `bluetooth-sniffle rogue-inject`).
- Integrate real-time relay metrics, linkability scoring, and evasion benchmark results into the M3 Streamlit dashboard.

## 3. Non-Functional Requirements
- **Latency**: Inter-dongle relay queue latency $< 5\text{ ms}$ to maintain Bluetooth Link Layer connection supervision timeouts.
- **Safety & Threading**: Graceful shutdown of relay threads on SIGINT/SIGTERM without port deadlock or orphaned subprocesses.
- **Testability**: 100% offline unit and integration test coverage using `VirtualRadioBus` and mock devices without requiring physical radios.

## 4. Acceptance Criteria
- [ ] Unit tests verify detection of static MAC leakage and rotation delay divergence with $>95\%$ precision on synthetic traces.
- [ ] Two-ended relay state machine correctly captures and forwards simulated pairing requests, logging success/failure status codes.
- [ ] Rogue beacon generator produces valid 31-byte advertising payloads across all 4 supported finding networks.
- [ ] Automated benchmark verifies whether rogue beacon injection triggers or evades `BLETrackerDB.check_stalking_heuristics()`.
- [ ] All new tests pass in CI (`uv run pytest`) and code satisfies `ruff check .` with zero warnings.

## 5. Out of Scope
- Hardware-in-the-loop over-the-air relay targeting non-consenting commercial devices.
- Breaking Bluetooth LE Secure Connections (LESC) ECDH cryptography (the relay operates at the protocol handshake layer).
