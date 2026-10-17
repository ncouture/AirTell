# Specification: Single-Dongle Passive Sniffing Mode for topology-a

## 1. Overview
Enable `TopologyAOrchestrator` and CLI commands to operate with a single Sniffle dongle for passive packet observation without requiring dual-dongle hardware.
This enables users with only one radio dongle to execute `airtell topology-a` in passive-only mode, capture packets on primary advertising channels (37, 38, 39), record PCAPs, export session telemetry (JSON and CSV), and stream real-time observations directly into the shared Streamlit `EventQueue`.

## 2. Functional Requirements

### FR1: Serial Port Single-Dongle Fallback (Issue #31)
- Update `allocate_dual_ports(dev1, dev2, allow_single: bool = False)` in `src/airtell/device/serial_port.py`.
- When `allow_single=True` and only 1 port is available or specified (e.g. `--dev2` or auto-discovery finding 1 port), gracefully fall back without raising `RuntimeError`.
- Return `(None, port)` so that port 2 is assigned to the passive observer while stimulator port 1 is `None`.
- Maintain default `allow_single=False` behavior for dual-device strict allocations.

### FR2: Topology A Single-Dongle Mode Support (Issues #15, #29)
- In `src/airtell/topology/topology_a.py`, update `TopologyAOrchestrator.create_hardware()` to allow `port1=None` when only passive observation is desired.
- Set `stimulator` to `None` when `port1` is omitted or when auto-discovery falls back to a single port.
- Update `create_mock()` with `single_dongle: bool = False` to support simulated single-dongle execution in offline tests.

### FR3: Stimulator Hardware & Operation Guards (Issue #30)
- In `TopologyAOrchestrator.start()`, guard `self.stimulator.open()` against `None`.
- In `TopologyAOrchestrator.stop()`, guard `self.stimulator.close()` against `None`.
- Guard `set_stimulus_mac()`, `inject_beacon()`, and `inject_burst_sequence()` to safely no-op/log warnings when `stimulator is None`.
- Ensure `get_stats()` reports `"single_dongle": True` and `"stimulator_port": None` cleanly without raising attribute errors.

### FR4: EventQueue Real-Time Streaming Bridge (Issue #32)
- Connect single-dongle observer packet reception directly to the shared `EventQueue` in `app/queue_bridge.py`.
- Format captured packets with channel, RSSI, timestamp, MAC address, tracking network classification, ephemeral key fragments, and raw payload hex.
- Stream observations directly to Live Telemetry, RSSI Trends, and Deep Packet Inspector views in Streamlit.

### FR5: CLI Handler Integration for Topology A (Issue #43)
- In `src/airtell/cli.py` (`handle_topology_a`), detect when only a single dongle is available or specified (`--dev2` provided without `--dev1`, `--single-dongle`, or auto-discovery finding 1 port with `allow_single=True`).
- Log an informative notice that stimulus injection is inactive and operate in passive capture mode.
- In passive capture mode, continue observer reception, write captured packets to PCAP, export telemetry (JSON/CSV), and push packets to `EventQueue`.

### FR6: Automated Unit & Integration Testing (Issue #49)
- Comprehensive test suite in `tests/test_topology_a_single_dongle.py` verifying:
  - Port allocation with 0, 1, and 2 available ports under `allow_single=True`.
  - Single-dongle hardware and mock lifecycle (`start()`, packet capture, PCAP writing, `stop()`).
  - Packet forwarding to `EventQueue`.
  - CLI `airtell topology-a` execution in single-dongle mode.

### FR7: Documentation Reconciliation
- Reconcile `docs/CLI.md` and `README.md` to document single-dongle `topology-a` execution.

## 3. Non-Functional Requirements
- **Performance**: Low-latency queueing from observer thread to `EventQueue` without dropping packets.
- **Reliability & Resilience**: Clean error handling; graceful fallback without `RuntimeError`.
- **Code Quality**: Zero `ruff` lint warnings (`line-length = 120`, target Python 3.10+).
- **Test Coverage**: 100% test pass rate across all unit and integration tests.
- **Backwards Compatibility**: All 1,144+ existing repository tests must pass.

## 4. Acceptance Criteria
- [x] `allocate_dual_ports(allow_single=True)` returns `(None, port)` when only 1 port is available or specified.
- [x] `allocate_dual_ports(allow_single=True)` raises `RuntimeError` when 0 ports are available.
- [x] `TopologyAOrchestrator.create_hardware()` creates instance with `stimulator=None` when `port1=None`.
- [x] `TopologyAOrchestrator.start()`, `stop()`, `inject_beacon()` execute cleanly when `stimulator is None`.
- [x] Packets captured in single-dongle mode are streamed into `EventQueue` and recorded to PCAP.
- [x] CLI `airtell topology-a` detects single-dongle mode, logs informative notices, and runs passive capture cleanly.
- [x] All automated tests pass with zero failures and zero lint warnings.
