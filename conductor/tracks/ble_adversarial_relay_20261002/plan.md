# Implementation Plan: BLE Tracker Deanonymization, Pairing Relay Evaluation & Rogue Beacon Testbed

## Phase 1: Multi-Signal Rotating Identifier Deanonymizer
- [ ] Task: Write tests for static MAC leakage detection and rotation delay divergence
  - [ ] Write unit tests in `tests/test_adversarial_deanonymizer.py` for static MAC leakage flag across rotating cryptographic keys
  - [ ] Write unit tests verifying rotation delay divergence $\Delta t$ detection between address changes and payload updates
- [ ] Task: Implement `RotatingIdentifierAnalyzer` in `bluetooth_sniffle/adversarial/deanonymizer.py`
  - [ ] Implement `StaticLeakageDetector` identifying invariant public keys / constant OUI prefixes
  - [ ] Implement `RotationDesyncAnalyzer` measuring timing differences between AdvA and payload transitions
- [ ] Task: Implement linkability scoring and trajectory reconstruction
  - [ ] Implement trajectory correlation based on RSSI gradients and advertisement sequence continuity
  - [ ] Add unit test verifying trajectory recovery across multiple randomized private address rotations
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 2: Two-Ended Pairing Relay Architecture
- [ ] Task: Write unit and integration tests for pairing relay state machine and IPC bridge
  - [ ] Write unit tests in `tests/test_adversarial_relay.py` validating Link Layer frame forwarding and timestamp fidelity
  - [ ] Write tests simulating central pairing handshake capture and peripheral proxy frame response
- [ ] Task: Implement `PairingRelayBridge` in `bluetooth_sniffle/adversarial/relay.py`
  - [ ] Implement low-latency thread-safe IPC queue bridging Device 1 sniffer to Device 2 proxy
  - [ ] Implement Link Layer connection state tracker (`CONNECT_IND`, `LL_FEATURE_REQ`, `SMP_PAIRING_REQ`)
- [ ] Task: Implement pairing handshake inspection and success/failure signal extraction
  - [ ] Parse `SMP_PAIRING_CONFIRM` and `SMP_PAIRING_FAILED` status codes
  - [ ] Correlate pairing failure error patterns with rotating MAC addresses to establish device persistent identity
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 3: Synthetic Rogue Beacon Generator & Evasion Benchmark
- [ ] Task: Write unit tests for rogue beacon generator and anti-stalking evasion scenarios
  - [ ] Write unit tests in `tests/test_adversarial_rogue_beacon.py` for Find My, Find Hub, SmartThings, and Tile payload construction
  - [ ] Write tests evaluating detection triggers vs. evasion on sliding-window heuristics
- [ ] Task: Implement `RogueBeaconGenerator` in `bluetooth_sniffle/adversarial/rogue_beacon.py`
  - [ ] Implement frame builders with parameterized transmission intervals and jitter
  - [ ] Support realistic RSSI attenuation curves and channel-hopping sequences
- [ ] Task: Implement `AntiStalkingEvasionEvaluator` benchmarking `BLETrackerDB` heuristics
  - [ ] Implement evasion benchmark assessing burst-and-sleep tactics and rotation delay thresholds
  - [ ] Generate structured markdown/JSON evaluation reports detailing detection evasion rates
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)

## Phase 4: CLI, Dashboard Integration & End-to-End Verification
- [ ] Task: Write CLI and dashboard view tests for adversarial tools
  - [ ] Write CLI invocation tests in `tests/test_cli_adversarial.py`
  - [ ] Write dashboard view tests for relay telemetry and evasion benchmark controls
- [ ] Task: Implement CLI commands in `src/bluetooth_sniffle/cli.py`
  - [ ] Add `bluetooth-sniffle relay` command for two-ended pairing relay testbed
  - [ ] Add `bluetooth-sniffle deanonymize` command for trace analysis
  - [ ] Add `bluetooth-sniffle rogue-inject` command for benchmark generation
- [ ] Task: Integrate adversarial metrics and evasion controls into Streamlit M3 dashboard
  - [ ] Add Adversarial Testbed view to `app/views/` and wire into M3 navigation rail
  - [ ] Display live relay handshake states, linkability confidence scores, and evasion benchmark results
- [ ] Task: Full System End-to-End Verification
  - [ ] Run full test suite (`pytest -v -W error tests/`)
  - [ ] Verify `ruff check .` lint cleanliness
- [ ] Task: Phase Verification & Checkpoint (Refer to workflow.md)
