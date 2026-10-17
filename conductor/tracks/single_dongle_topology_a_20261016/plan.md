# Implementation Plan: Single-Dongle Passive Sniffing Mode for topology-a

## Phase 1: Conductor Track Scaffolding & Registry Indexing [checkpoint: 4140e98]
- [x] Task: Scaffold Track 3 Conductor track directory and documentation (Issue #56) [4140e98]
  - [x] Create `conductor/tracks/single_dongle_topology_a_20261016/`
  - [x] Create `metadata.json`, `index.md`, `spec.md`, and `plan.md`
- [x] Task: Update `conductor/tracks.md` registry with Track 3 entry [4140e98]

## Phase 2: Serial Port Fallback Refactor [checkpoint: 4140e98]
- [x] Task: Update `allocate_dual_ports()` in `src/airtell/device/serial_port.py` (Issue #31) [4140e98]
  - [x] Add optional parameter `allow_single: bool = False`
  - [x] Return `(None, port)` when `allow_single=True` and only 1 port is available or specified
  - [x] Raise `RuntimeError` if 0 ports are available even with `allow_single=True`

## Phase 3: Topology A Single-Dongle Orchestrator & Stimulator Guards [checkpoint: 4140e98]
- [x] Task: Update `TopologyAOrchestrator.create_hardware()` in `src/airtell/topology/topology_a.py` (Issues #15, #29) [4140e98]
  - [x] Allow `port1=None` when only passive observation is desired
  - [x] Set `stimulator` to `None` when `port1` is omitted or single port allocated
  - [x] Add `single_dongle` parameter to `create_mock()`
- [x] Task: Guard stimulator calls across `TopologyAOrchestrator` (Issue #30) [4140e98]
  - [x] Guard `self.stimulator.open()` in `start()`
  - [x] Guard `self.stimulator.close()` in `stop()`
  - [x] Guard `set_stimulus_mac()`, `inject_beacon()`, and `inject_burst_sequence()`
  - [x] Update `get_stats()` to handle `stimulator=None`

## Phase 4: EventQueue Streaming Bridge for Streamlit Dashboard [checkpoint: 4140e98]
- [x] Task: Connect single-dongle observer packet reception directly to `EventQueue` (Issue #32) [4140e98]
  - [x] Add `packet_to_event_dict()` and `EventQueue.push_packet()` in `app/queue_bridge.py`
  - [x] Feed captured packets into `EventQueue` during `read_packet()` and `get_captured_packets()`
  - [x] Allow attaching `EventQueue` instance to `TopologyAOrchestrator`

## Phase 5: CLI Handler Integration for Topology A [checkpoint: 4140e98]
- [x] Task: Update `handle_topology_a` in `src/airtell/cli.py` (Issue #43) [4140e98]
  - [x] Detect single-dongle environment (`--dev2` without `--dev1`, `--single-dongle`, or auto-discovered single port)
  - [x] Log informative notice that stimulus injection is inactive and operate in passive capture mode
  - [x] Ensure packet capture, PCAP output, and JSON/CSV session telemetry work in single-dongle mode

## Phase 6: Automated Unit & Integration Testing [checkpoint: 4140e98]
- [x] Task: Create test suite in `tests/test_topology_a_single_dongle.py` (Issue #49) [4140e98]
  - [x] Test `allocate_dual_ports(allow_single=True)` with 1 port, 2 ports, and 0 ports
  - [x] Test `TopologyAOrchestrator` lifecycle (`start()`, packet capture, PCAP output, `stop()`) when `port1=None`
  - [x] Test packet forwarding to `EventQueue` in single-dongle mode
  - [x] Test CLI `airtell topology-a` execution in single-dongle mode
- [x] Task: Run full regression test suite (`uv run pytest`) and linter (`uv run ruff check .`) [4140e98]

## Phase 7: Documentation Reconciliation & GitHub Issue Closures [checkpoint: 4140e98]
- [x] Task: Reconcile `docs/CLI.md` and `README.md` [4140e98]
- [x] Task: Close resolved GitHub issues (#56, #15, #29, #30, #31, #32, #43, #49, #9) [4140e98]

## Git & GitHub Traceability

- **Branch**: [`feat/ble-exposure`](https://github.com/ncouture/AirTell/tree/feat/ble-exposure)
- **Pull Request**: [#58](https://github.com/ncouture/AirTell/pull/58)
- **Epic Issue**: [#9](https://github.com/ncouture/AirTell/issues/9) (Parent Plan: [#5](https://github.com/ncouture/AirTell/issues/5))
- **Resolving Commit**:
  - [`4140e9840b71743af686b21e4588f4148efd675f`](https://github.com/ncouture/AirTell/commit/4140e9840b71743af686b21e4588f4148efd675f) (`feat(topology): implement single-dongle passive sniffing mode for topology-a and Track 3 Conductor plan`)
- **Resolved Issues**: #9, #15, #29, #30, #31, #32, #43, #49, #56
