# Implementation Plan: ARIEL Neurosymbolic Privacy Entailment & IDBLEED Link-Layer Defense Blueprint

## Phase 1: Wave 1 Core Subsystems [checkpoint: 06137e3]
- [x] Task: Implement `src/airtell/ariel/` neurosymbolic Contextual Integrity entailment engine (`models.py`, `ontology.py`, `solver.py`, `domains.py`, `evaluation.py`) and `tests/test_ariel_engine.py` [e1509b6]
- [x] Task: Implement `src/airtell/sidechannel/idbleed_spec.py`, root `idbleed_spec.py` entry point, and `tests/test_idbleed_spec.py` [06137e3]
- [x] Task: Implement `src/airtell/defense/` (`monitor.py`, `coupling.py`, `gateway.py`) and `tests/test_defense_gateway.py` [0f84995]

## Phase 2: Package Exports, Unified CLI & Dashboard Integration
- [x] Task: Re-export IDBLEED verification specification symbols in `src/airtell/sidechannel/__init__.py`
- [x] Task: Add `ariel` (`entailment`), `idbleed-verify` (`idbleed`), and `defense-gateway` (`gateway`) subcommands in `src/airtell/cli.py` and update `VALID_COMMAND_PREFIXES` in `src/airtell/scripts/check_docs.py`
- [x] Task: Implement `app/views/privacy_defense.py` (`render_privacy_defense`) and integrate into `app/components/navigation.py` and `app/streamlit_app.py` preserving `NAVIGATION_VIEWS` invariants

## Phase 3: Blueprint Documentation, Conductor Track & E2E Verification
- [x] Task: Author `docs/ariel_idbleed_blueprint.md` and link across `docs/index.md`, `docs/CLI.md`, and `README.md`
- [x] Task: Register `ariel_idbleed_defense_20261117` in `conductor/tracks.md`
- [x] Task: Add comprehensive E2E integration tests in `tests/test_ariel_idbleed_integration.py` and pass all repository quality gates (`ruff`, `check_docs.py`, `pytest -W error`, `idbleed_spec.py`)

## Git & Branch Traceability
- **Feature Branch**: `feat/ariel-idbleed-defense-blueprint`
- **Merged Wave 1 Commits**:
  - `swarm/ariel` (`e1509b65d15788a25d236572a217e5f0cc4f056c`)
  - `swarm/idbleed` (`06137e344108aff587c56f8304b5b8cb8b77c62e`)
  - `swarm/gateway` (`0f8499578a669ac51ee1e91341a3b9ebcb10a1ef`)
