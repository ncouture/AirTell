# Contributing to AirTell

This document outlines the developer workflows, coding standards, testing requirements, and governance rules for contributing to AirTell.

* [Environment setup](#environment-setup)
* [Local git configuration and pre-commit hooks](#local-git-configuration-and-pre-commit-hooks)
* [Daily development commands](#daily-development-commands)
* [Task lifecycle and test-driven development](#task-lifecycle-and-test-driven-development)
* [Conductor track management](#conductor-track-management)
* [Testing and verification workflows](#testing-and-verification-workflows)
* [Coding standards and Python conventions](#coding-standards-and-python-conventions)
* [Git, branch, and pull request workflow](#git-branch-and-pull-request-workflow)
* [Automated AI code review](#automated-ai-code-review)
* [Issue triage and community discussions](#issue-triage-and-community-discussions)

---

## Environment setup

AirTell requires Python 3.10 or newer. The project uses `uv` as its primary workspace and package manager (`uv.lock` and `pyproject.toml`), with full compatibility for standard `pip` and `venv` setups.

### Setup with uv (recommended)

```bash
git clone https://github.com/ncouture/AirTell.git
cd AirTell

uv venv .venv
source .venv/bin/activate

# Synchronize virtual environment and install workspace dependencies
uv sync

# Install optional SMS notification dependencies if working on alert dispatchers
uv sync --extra notifications
```

### Setup with standard pip and venv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e "./src/sniffle"
pip install -e ".[test]"
```

### System tools and hardware permissions

* Install `tshark` (Wireshark CLI) if working on `src/airtell/extcap/` or live JSON packet streaming.
* On Linux, add your user to the `dialout` (or `uucp`) group to access `/dev/ttyUSB*` serial ports without root privileges. See [Hardware Setup & Dongle Flashing](docs/hardware_setup.md) for bootloader and serial details.

---

## Local git configuration and pre-commit hooks

After cloning the repository, configure your local checkout so git settings and pre-commit hooks match the repository's linear-history and code quality requirements.

### 1. Required local git settings

The repository relies on a tracked `scripts` -> `src/airtell/scripts` symlink, executable script bits (`0755`), Unix line endings (`LF`), and linear rebase merges. Apply these settings in your local checkout:

```bash
# Ensure git preserves symlinks (required for scripts -> src/airtell/scripts)
git config --local core.symlinks true

# Track executable permission bits on standalone scripts
git config --local core.filemode true

# Preserve LF line endings on checkout and convert CRLF to LF on commit
git config --local core.autocrlf input

# Rebase local commits by default when pulling from origin
git config --local pull.rebase true
git config --local rebase.autoStash true

# Prune deleted remote-tracking branches automatically on fetch/pull
git config --local fetch.prune true

# Default push target to origin and automatically set upstream on new branches
git config --local remote.pushDefault origin
git config --local push.autoSetupRemote true
```

Verify your author identity (and optional GPG/SSH commit signing) before committing:

```bash
git config user.name
git config user.email
```

### 2. Git pre-commit hooks setup

AirTell ships a [`.pre-commit-config.yaml`](.pre-commit-config.yaml) configuration that runs automated checks before each commit:

* `ruff` (`--fix`) and `ruff-format` (`https://github.com/astral-sh/ruff-pre-commit`) for Python linting, import sorting, and formatting.
* `trailing-whitespace`, `end-of-file-fixer`, and `check-yaml` (`https://github.com/pre-commit/pre-commit-hooks`) for file hygiene.
* `check-docs` (`python3 scripts/check_docs.py`), a local repository hook triggered whenever `README.md`, `CONTRIBUTE.md`, or `docs/*.md` are modified, verifying all relative links, heading anchors, and CLI command snippets.

#### Option A: Using the `pre-commit` framework (recommended)

Install `pre-commit` and register the hook into `.git/hooks/pre-commit`:

```bash
# Install pre-commit (via uv tool, pipx, or pip)
uv tool install pre-commit
# Or inside the virtual environment:
# uv pip install pre-commit

# Install the git pre-commit hook into .git/hooks/pre-commit
pre-commit install

# Run all configured hooks across the entire repository to verify setup
pre-commit run --all-files
```

#### Option B: Standalone native `.git/hooks/pre-commit` script (no `pre-commit` binary required)

If you prefer not to install the `pre-commit` package, install a native shell hook directly in `.git/hooks/pre-commit` that runs Ruff and the documentation validator:

```bash
cat << 'EOF' > .git/hooks/pre-commit
#!/usr/bin/env bash
set -euo pipefail

if command -v uv >/dev/null 2>&1; then
    uv run ruff check src/ tests/ docs/ conductor/ scripts/
    uv run python3 scripts/check_docs.py
else
    ruff check src/ tests/ docs/ conductor/ scripts/
    python3 scripts/check_docs.py
fi
EOF
chmod +x .git/hooks/pre-commit
```

#### Option C: Optional `.git/hooks/pre-push` test gate

To prevent pushing branches with failing unit tests, you can also configure a local `.git/hooks/pre-push` hook:

```bash
cat << 'EOF' > .git/hooks/pre-push
#!/usr/bin/env bash
set -euo pipefail

if command -v uv >/dev/null 2>&1; then
    uv run pytest -q -W error tests/ --ignore=tests/benchmarks
else
    pytest -q -W error tests/ --ignore=tests/benchmarks
fi
EOF
chmod +x .git/hooks/pre-push
```

---

## Daily development commands

All development commands work either via `uv run` or directly inside an activated `.venv`:

```bash
# Run the AirTell unified CLI
uv run airtell --help
python3 -m airtell.cli --help

# Launch the Material Design v3 Streamlit tactical dashboard
uv run streamlit run app/streamlit_app.py

# Run the main unit, integration, and end-to-end test suite
uv run pytest -v -W error tests/

# Run the embedded Sniffle core unit test suite
uv run pytest -v src/sniffle/

# Run Ruff static analysis and import sorting checks
uv run ruff check src/ tests/ docs/ conductor/ scripts/

# Validate documentation markdown links, anchors, and CLI command snippets
uv run python3 scripts/check_docs.py
```

---

## Task lifecycle and test-driven development

AirTell follows a red-green-refactor test-driven development (TDD) workflow for all features and bug fixes:

1. Write failing tests first (red phase): Create or update a `tests/test_*.py` module that defines the expected behavior, boundary conditions, or bug reproduction. Run `uv run pytest` and confirm the new tests fail for the expected reason.
2. Implement the minimal fix or feature (green phase): Write the application code under `src/airtell/`, `app/`, or `scripts/` required to pass the tests. Re-run `uv run pytest` to verify all tests pass.
3. Refactor and clean up: Remove duplication, verify type annotations, and check performance in hot packet loops while keeping the test suite green.
4. Check test coverage: Target at least 80% coverage for modified modules:
   ```bash
   uv run pytest --cov=airtell --cov-report=term-missing tests/
   ```
5. Validate linting and documentation: Run `uv run ruff check` and `uv run python3 scripts/check_docs.py` before staging changes.

---

## Conductor track management

Major features, multi-phase refactors, and research deliverables are organized as tracks under [`conductor/`](conductor/index.md).

* [Product Definition](conductor/product.md) and [Tech Stack](conductor/tech-stack.md) define architectural boundaries. Any change to core dependencies or storage engines must be recorded in `conductor/tech-stack.md` before implementation.
* [Tracks Registry](conductor/tracks.md) indexes all active and completed engineering tracks.
* Each track resides in `conductor/tracks/<track_id>/` and contains:
  * `metadata.json`: Structured status (`pending`, `in_progress`, `completed`), timestamps, and track title.
  * `spec.md`: Requirements, architectural design, and acceptance criteria.
  * `plan.md`: Phased task checklist (`[ ]` pending, `[~]` in progress, `[x]` completed) with 7-character commit checkpoints (`[checkpoint: <sha>]`) and a `## Git & GitHub Traceability` section mapping resolving commits, branches, and PR numbers.
* See [Project Workflow](conductor/workflow.md) for the complete phase verification and checkpointing protocol.

---

## Testing and verification workflows

Every code change must be verified across the applicable test tiers before opening a pull request.

### 1. Offline mock simulation (zero hardware required)

All radio topologies, serial framing, and adversarial modules must be testable without physical CC2652 dongles using `MockSerialInterface` and `VirtualRadioBus` (`src/airtell/device/mock.py`):

```bash
# Verify mock simulation and artifact generation (PCAP, JSON, CSV)
uv run airtell mock-simulate --duration-sec 1.0 --interval-ms 50

# Run side-channel analyzers in mock mode
uv run airtell sidechannel --mock --analyzer all

# Run tracker deanonymization and rogue beacon injection in mock mode
uv run airtell deanonymize --mock --max-gap 30.0 --max-rssi-delta 15.0
uv run airtell rogue-inject --mock --network "Apple Find My" --count 5

# Verify simulated hardware discovery and dual-dongle topologies
uv run airtell verify-hardware --mock --burst-duration-sec 0.5 --interval-ms 50
uv run airtell topology-a --mock --burst-type ibeacon --duration-sec 0.5
uv run airtell topology-b --mock --chan1 37 --chan2 38 --duration-sec 0.5
```

### 2. Automated test suites

The `tests/` directory is organized by verification scope:

* Unit and protocol tests (`tests/test_*.py`): Test individual dissectors, wire framing, palindromic MAC generation, storage backends (`SQLiteBackend` and `DuckDBBackend`), and CLI argument parsing.
* Multi-tier end-to-end tests (`tests/e2e/`): Test feature integration (`test_tier1_features.py`), boundary conditions (`test_tier2_boundaries.py`), combinatorial options (`test_tier3_combinations.py`), operational scenarios (`test_tier4_scenarios.py`), and adversarial fuzzing (`test_tier5_adversarial.py`).
* Storage benchmarks (`tests/benchmarks/`): Measure batch insertion and analytical query latency across SQLite and DuckDB backends.
* Documentation and traceability tests (`tests/test_docs_cli_validation.py` and `tests/test_issue_traceability.py`): Verify that every CLI snippet in `README.md` and `docs/CLI.md` parses against `airtell.cli.create_parser()`, CSV schemas match `TelemetrySession`, and Conductor track commits exist in git history.

### 3. Hardware-in-the-loop verification

When modifying serial port allocation (`src/airtell/device/serial_port.py`), baud rate negotiation, or link-layer timing, validate against physical TI CC2652 / Sonoff dongles when available:

```bash
# Check if serial devices are currently open by another process
lsof /dev/ttyUSB0
lsof /dev/ttyUSB1

# Verify physical dongle responsiveness and firmware version
uv run airtell verify-hardware --dev1 /dev/ttyUSB0 --dev2 /dev/ttyUSB1
```

---

## Coding standards and Python conventions

Code must follow the [Python Style Guide](conductor/code_styleguides/python.md) and pass `ruff check` with zero warnings:

* Formatting and line length: Maximum line length is 120 characters (`pyproject.toml`), indented with 4 spaces.
* Type annotations: Use modern PEP 585 and PEP 604 native typing (`list[str]`, `dict[str, int]`, `int | None`) with `from __future__ import annotations` at the top of modules.
* Imports: Use explicit imports sorted into standard library, third-party, and local `airtell` / `sniffle` groups (`ruff` rule `I`). Do not use wildcard imports (`from module import *`) or mutate `sys.modules` at import time.
* Exception handling: Catch specific exception types (such as `serial.SerialException`, `ValueError`, `OSError`, or `struct.error`). Never use bare `except:` clauses.
* State and arguments: Avoid mutable default arguments (`def fn(items=None):`) and avoid global mutable hardware state in CLI scripts; encapsulate runtime state inside session or controller classes.
* Link-layer and parser safety: Over-the-air BLE packets are untrusted input. Dissectors must check slice bounds before unpacking bytes and never panic on truncated or malformed PDUs.
* Executable scripts: Standalone scripts in `scripts/` and `src/airtell/scripts/` must begin with `#!/usr/bin/env python3` and guard execution inside `if __name__ == "__main__": main()`.

---

## Git, branch, and pull request workflow

AirTell maintains a linear commit history on `main`. Every issue or feature follows a dedicated branch and rebase-merge workflow.

### 1. Branch naming

Create a descriptive branch from the latest `main`. Include the issue number when addressing a tracked GitHub issue:

```bash
git checkout main
git pull origin main
git checkout -b issue-<id>-<short-slug>
# Or for general feature / fix branches:
# feat/<short-slug>, fix/<short-slug>, docs/<short-slug>
```

### 2. Conventional commit messages

Format commit messages according to Conventional Commits:

```text
<type>(<scope>): <concise description> (#<issue-id>)
```

Allowed types:

* `feat`: New capability, topology, or analyzer
* `fix`: Bug fix, race condition, or bounds check
* `docs`: Documentation and guide updates
* `test`: New or hardened unit, integration, or E2E tests
* `refactor`: Internal code restructuring without behavior change
* `optimize`: Performance or memory improvements
* `chore` / `ci`: Build, dependency, Conductor plan, or GitHub Actions updates

### 3. Pre-push checklist

Run the full pre-commit verification sequence locally before pushing:

```bash
uv run ruff check src/ tests/ docs/ conductor/ scripts/
uv run python3 scripts/check_docs.py
uv run pytest -W error tests/
uv run pytest src/sniffle/
```

### 4. Rebasing, pull request creation, and merging

Push your branch, rebase onto `origin/main` to keep history linear, open a pull request via the GitHub CLI (`gh`), and rebase-merge once checks pass:

```bash
git fetch origin
git rebase origin/main
git push -u origin HEAD

# Create a pull request referencing the resolved issue
gh pr create --title "fix(scope): description (#123)" --body "Closes #123"

# Rebase-merge into main after review and verification
gh pr merge --rebase --delete-branch
```

### 5. Automated releases and changelog generation

AirTell automates semantic versioning and changelog maintenance via [Google Release Please Action (`googleapis/release-please-action@v5`)](https://github.com/googleapis/release-please-action) configured in [`.github/workflows/release-please.yml`](.github/workflows/release-please.yml):

* **Conventional Commits**: Every merged commit on `main` is evaluated by `release-please`. `feat:` commits increment minor versions (`0.2.0` -> `0.3.0`), and `fix:` commits increment patch versions (`0.2.0` -> `0.2.1`), while updating `CHANGELOG.md`, `pyproject.toml`, and `src/airtell/__init__.py`.
* **Release Pull Requests**: `release-please` maintains an open Release PR on `main` aggregating unreleased changes. Merging this PR creates a new GitHub Release and publishes git tags.
* **Dual-Tier Workflow Security**: The release workflow enforces dual-tier codeowner gating (Tier 1 `github.actor` expression and Tier 2 dynamic [`.github/CODEOWNERS`](.github/CODEOWNERS) verification) ensuring only repository codeowners can trigger release automation. See [GitHub Operations & AI Code Review](docs/GITHUB.md) for full details.

---

## Automated AI code review

AirTell includes an automated code review runner ([`scripts/code_review.py`](scripts/code_review.py)) powered by the Google Antigravity SDK and Gemini 3.8 Flash (high thinking), grounded in the [AirTell Research NotebookLM Workspace](https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6) and [`docs/AirTell-PoPETs.md`](docs/AirTell-PoPETs.md).

* Review criteria: Defined in [`.github/skills/code-review/SKILL.md`](.github/skills/code-review/SKILL.md), checking 1 us timer precision, CC2652 UART flow control, multi-radio synchronization, and zero-panic BLE packet parsing.
* Local review execution:
  ```bash
  # Review staged changes locally before committing
  python3 scripts/code_review.py --staged

  # Review current branch diff against origin/main and save report
  python3 scripts/code_review.py --base origin/main --output review.md
  ```
* CI dual-gate policy: In GitHub Actions ([`.github/workflows/code-review.yml`](.github/workflows/code-review.yml)), the AI review workflow runs only when both the PR author and the review requester are listed in [`.github/CODEOWNERS`](.github/CODEOWNERS). Codeowners can trigger a review by commenting `/review`, `/code-review`, or `/ai-review` on a PR, requesting a review in the UI, applying the `code-review` label, or dispatching the workflow manually. See [GitHub Operations & AI Code Review](docs/GITHUB.md) for full details.

---

## Issue triage and community discussions

* Bug reports and feature requests: All issues must use the structured forms in [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/config.yml). Bug reports require the operating topology, hardware/firmware details, and reproduction commands.
* Priority ordering: Issues are triaged by priority tags (`p0`, `p1`, `p2`, `p3`) and resolved in oldest-first order (lowest issue ID number first within each priority tier).
* GitHub Discussions: Open-ended RF forensics, PCAP teardowns, antenna setups, and privacy research questions belong in [GitHub Discussions](.github/DISCUSSIONS.md) rather than the issue tracker.
* Security vulnerabilities: Do not report undisclosed vulnerabilities in public issues. Use GitHub Private Vulnerability Reporting (`/security/advisories/new`) as configured in [`.github/ISSUE_TEMPLATE/config.yml`](.github/ISSUE_TEMPLATE/config.yml).
