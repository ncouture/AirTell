# Specification: ARIEL Neurosymbolic Privacy Entailment & IDBLEED Link-Layer Defense Blueprint

## 1. Overview

Unify software Contextual Integrity (CI) neurosymbolic logical entailment (`src/airtell/ariel/`) with Bluetooth Low Energy (BLE) Link-Layer boolean side-channel verification (`src/airtell/sidechannel/idbleed_spec.py`) and constant-time protocol hardening (`src/airtell/defense/`). When an ambient application is denied access to personal data at the software API layer, the unified Edge Defense Gateway suppresses deterministic BLE control responses (`0x0D`, `0x11`, `0x02`, `0xD2`) across Resolvable Private Address (RPA) rotation windows (`Delta_RPA = 15 min`).

## 2. Functional Requirements

### FR1: ARIEL Neurosymbolic Logical Entailment Engine (`src/airtell/ariel/`)
* Represent Contextual Integrity information flows as frozen 5-tuples `R = {d_u, u, s, r, t}` (`InformationFlowRequest`) over historical user memories `D_u` (`UserDecisionMemory`).
* Validate hierarchical ontology rank mappings via strict Pydantic v2 schemas (`OntologySchema`, `ParameterMappingSchema` with `extra="forbid"` and `strict=True`).
* Implement Definition 4.1 (`<=_O`), Definition 4.2 (Rules 1 & 2), Online Phase Algorithm 1 (`ARIELSolver` with `d_H <= 1` soundness neighborhood), dynamic social role memory anchoring (`AdaptiveMemoryAnchoredMapper` for roles such as `"housemate"`), and `SPA` / `Education` domain benchmarks and memory-size ablations (`|D_u| in [10, 20, 40, 60]`).

### FR2: IDBLEED Link-Layer Verification Specification (`src/airtell/sidechannel/idbleed_spec.py`)
* Implement `OracleResult`, `LLOpcode` (20 opcodes), `ATTOpcode` (14 opcodes), `BLEFrame`, `LLEncryptionReqPayload`, and `ATTSignedWritePayload` with 64-bit truncated AES-CMAC (`compute_csrk_cmac`).
* Provide `LLEncryptionOracleEvaluator`, `CSRKSigningOracleEvaluator`, `AppAuthOracleEvaluator` (`0xFFF1`), `ActiveRelayProbeOrchestrator` (`Delta_RPA = 900.0 s`), `ble_packet_record_to_frame`, `IdbleedVerificationAnalyzer`, and root `idbleed_spec.py` wrapper.
* Re-export the public IDBLEED verification API from `airtell.sidechannel`.

### FR3: Edge Defense Gateway & Cross-Domain Coupling Verifier (`src/airtell/defense/`)
* Implement `IDBLEEDSideChannelMonitor` enforcing constant-time silent drops (`SILENT_DROP_CONSTANT_TIME`) and uniform delay padding (`DELAY_UNIFORM`) on `LL_REJECT_IND` (`0x0D`), `LL_REJECT_EXT_IND` (`0x11`), unauthenticated `LL_TERMINATE_IND` (`0x02`), and unverified/replayed `ATT_SIGNED_WRITE_CMD` (`0xD2`).
* Implement `CrossDomainCouplingVerifier` proving RPA linkability (`3/3` linked RPAs, `privacy_preserved=False`) on unhardened stacks vs complete unlinkability (`0/3` linked RPAs, `privacy_preserved=True`) under the hardened gateway.
* Implement `IntegratedDefenseGateway` enforcing all four systemic failure-mode mitigations (`default_to_inappropriate`, `contradictory_priors`, `ontology_hierarchy_misalignment`, `implicit_consent_trap`), HMAC-SHA256 `CryptographicLocalOptOutSwitch`, and `Gemma 3 4B IT` edge offloading (`LightweightEdgeOntologyOffloader`).

### FR4: Unified CLI, Tactical Dashboard View, & Architecture Blueprint
* Add `ariel` (`entailment`), `idbleed-verify` (`idbleed`), and `defense-gateway` (`gateway`) subcommands to `src/airtell/cli.py` and register them in `src/airtell/scripts/check_docs.py`.
* Add the `Privacy & Defense` Material Design v3 Streamlit view (`app/views/privacy_defense.py`) routed from `app/components/navigation.py` and `app/streamlit_app.py` while preserving all existing `NAVIGATION_VIEWS` test invariants.
* Author [`docs/ariel_idbleed_blueprint.md`](../../../docs/ariel_idbleed_blueprint.md) and index it across `docs/index.md`, `docs/CLI.md`, and `README.md`.

## 3. Acceptance Criteria
* [x] `ARIELSolver`, `IDBLEEDSideChannelMonitor`, `IntegratedDefenseGateway`, and `CrossDomainCouplingVerifier` pass unit and E2E integration suites under `pytest -W error`.
* [x] `airtell ariel`, `airtell idbleed-verify`, and `airtell defense-gateway` support `--json`, `--markdown`, and `-o`/`--output`.
* [x] `python3 idbleed_spec.py` and `python3 scripts/check_docs.py` pass with zero errors.
* [x] `ruff check src/ tests/ app/ docs/ conductor/` reports zero lint issues.
