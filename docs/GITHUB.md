# AirTell GitHub Operational Architecture & Repository Configurations

This document specifies the operational architecture, community governance, issue workflows, and automated AI review systems configured for the [**AirTell**](https://github.com/ncouture/AirTell) GitHub repository.

---

## Table of Contents
1. [Governance & Repository Ownership](#1-governance--repository-ownership)
2. [Community Discussions Architecture](#2-community-discussions-architecture)
3. [Issue Templates & Triage Engine](#3-issue-templates--triage-engine)
4. [AI Code Review System (Gemini 3.8 Flash & Antigravity SDK)](#4-ai-code-review-system)
   - [Architectural Skill Protocol](#architectural-skill-protocol)
   - [Google NotebookLM Grounding](#google-notebooklm-grounding)
   - [Dual-Gate Codeowner Authorization Policy](#dual-gate-codeowner-authorization-policy)
   - [CI/CD Workflow & Trigger Mechanics](#cicd-workflow--trigger-mechanics)
   - [Local CLI Execution](#local-cli-execution)
5. [Repository File Map](#5-repository-file-map)

---

## 1. Governance & Repository Ownership

Repository ownership is declared globally via [`.github/CODEOWNERS`](../.github/CODEOWNERS) to enforce architectural integrity across low-level CC2652 firmware bridges, UART line protocols, and side-channel analytics:

```text
# Global repository owner: applies to all files across the entire codebase
* @ncouture
```

### Operational Impact
- **Automatic Review Assignment**: Any Pull Request modifying files in the repository automatically requests a review from `@ncouture`.
- **Branch Protection Alignment**: Paired with branch protection on `main` requiring approved reviews from designated Code Owners before merging.
- **Workflow Authorization Gate**: Serves as the authoritative source of truth for triggering automated AI code reviews.

---

## 2. Community Discussions Architecture

AirTell uses **GitHub Discussions** as an open RF salon and research exchange to segregate open-ended signal analysis from reproducible codebase defects. Full maintainer protocols and the pinned welcome post are documented in [`.github/DISCUSSIONS.md`](../.github/DISCUSSIONS.md).

### Discussion Categories
1. **🎙️ RF Tradecraft & Signal Forensics**: Timing side-channels, clock drift, Apple Continuity / Google Fast Pair reverse-engineering, and sanitized `.pcap` teardowns.
2. **🛠️ Hardware Rigs & Testbed Engineering**: CC2652 dongle flashing, LaunchPad / Sonoff antennas, attenuation, and `VirtualRadioBus` mock harnesses.
3. **⚔️ Red Team Tradecraft & Stimulus Chains**: Active `SCAN_REQ` stimulus timing, persistence across MAC rotation intervals, and physical perimeter tracking.
4. **🛡️ Risk, Governance & Privacy Engineering**: Fleet privacy posture evaluations, empirical tracking benchmarks, and sensitive facility threat modeling.
5. **💡 Ideas, Feature Requests & Wild Experiments**: Protocol extensions, Wireshark dissectors, and Streamlit visualization ideas.

### Maintainer Triage Rules
- **Issues are for Bugs**: Hardware desyncs, UART buffer underruns, packet parsing panics, and CI testbed failures.
- **Convert Questions to Discussions**: Maintainers convert issues labeled `question`, `research`, or `hardware-rig` into Discussions rather than closing them.

---

## 3. Issue Templates & Triage Engine

Issue creation is governed by GitHub Issue Forms located in [`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/):

### 1. Template Chooser ([`config.yml`](../.github/ISSUE_TEMPLATE/config.yml))
- **`blank_issues_enabled: false`**: Disables unstructured issues to guarantee all submissions include essential RF/testbed telemetry.
- **Discussions Link**: Directly routes general questions, PCAP sharing, and hardware showcases to GitHub Discussions.
- **Security Vulnerability Link**: Points security researchers to GitHub Private Vulnerability Reporting (`/security/advisories/new`).

### 2. Bug Report Form ([`bug_report.yml`](../.github/ISSUE_TEMPLATE/bug_report.yml))
Enforces mandatory collection of critical environmental telemetry:
- **Operating Topology**: Dropdown selection (Topology A, Topology B, Topology C, CLI Side-Channel, UI Dashboard, or `VirtualRadioBus`).
- **Hardware Dongles & Firmware**: CC2652 model, USB ports, and Sniffle firmware versions (e.g., CC2652P on `/dev/ttyUSB0` with Sniffle v1.10.0).
- **Environment**: OS and Python versions.
- **Reproduction Steps**: Exact CLI commands and arguments.
- **Logs / Captures**: Code-formatted blocks for stack traces and Wireshark errors.

### 3. Feature Request Form ([`feature_request.yml`](../.github/ISSUE_TEMPLATE/feature_request.yml))
Requires contributors to articulate the research motivation, technical proposal, and alternative implementations considered.

---

## 4. AI Code Review System

AirTell deploys a specialized, automated code review agent built on the **Google Antigravity SDK (`google-antigravity`)** and powered by **Gemini 3.8 Flash with High Thinking**.

```
                           PR Event or Comment Trigger
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ .github/workflows/code-review.yml         │
                  │ Resolve: PR_AUTHOR & REQUESTER            │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ scripts/code_review.py                    │
                  │ --enforce-codeowners                      │
                  │ Dual-Gate Authorization Check             │
                  └─────────────────────┬─────────────────────┘
                                        │
               ┌────────────────────────┴────────────────────────┐
               ▼                                                 ▼
        ❌ Unauthorized                                  ✅ Authorized
  (PR author or requester                         (Both PR author & requester
   not in CODEOWNERS)                              in .github/CODEOWNERS)
               │                                                 │
  - Abort execution immediately                    - Load NotebookLM Research Context
  - Post policy warning to PR                      - Execute Gemini 3.8 Flash (Thinking=High)
                                                   - Post Review Report to PR & Step Summary
```

### Architectural Skill Protocol
The review protocol is codified in [`.github/skills/code-review/SKILL.md`](../.github/skills/code-review/SKILL.md) and targets five core dimensions:
1. **Link Layer & Serial Protocol Rigor**: CC2652 UART buffer flow control (2,000,000 baud), sync word detection, and FIFO buffer overflow protection during dense BLE bursts.
2. **Side-Channel & Timing Integrity**: Microsecond precision hardware timestamp preservation (1 µs timer counters), zero-allocation hot loops, and jitter calculation stability.
3. **Multi-Radio Topologies**: Cross-dongle clock synchronization and link-layer state tracking across Topology A, B, C, and `VirtualRadioBus` mock fidelity.
4. **Zero-Panic Parsers**: Defense against hostile, fuzzed over-the-air BLE PDUs and proprietary beacons (Apple Continuity, Google Fast Pair, SmartTags).
5. **Code Hygiene**: Modern Python (>=3.10) typing, Pydantic v2 schemas, and Ruff linting rules (`E`, `F`, `W`, `I`).

### Google NotebookLM Grounding
The code reviewer is grounded in the authoritative **[AirTell Research NotebookLM Workspace](https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6)** (*"AirTell Intel: 259 PoPETs + 2018 to 2026 Bluetooth related PDFs"*).
- **Dual-Tier Knowledge Loading**: In addition to web URL grounding, [`scripts/code_review.py`](../scripts/code_review.py) automatically ingests [`docs/AirTell-PoPETs.md`](AirTell-PoPETs.md) (the synchronized offline research index of all 259 papers) directly into the agent context.
- **Empirical Validation**: Reviews cross-reference link-layer heuristics, timing side-channels, and active stimulus patterns against empirical privacy research standards.

### Dual-Gate Codeowner Authorization Policy
To prevent abuse of high-thinking reasoning compute, code review execution is strictly enforced:
1. **Gate 1 (PR Creator)**: The Pull Request must have been created by a designated repository codeowner (`ncouture`).
2. **Gate 2 (Requester)**: The review must be explicitly requested by a designated repository codeowner (`ncouture`).

If either check fails, [`scripts/code_review.py`](../scripts/code_review.py) terminates immediately with exit code 1 and posts an explanatory policy notice to the PR, ensuring zero LLM API calls are dispatched.

### CI/CD Workflow & Trigger Mechanics
The GitHub Actions workflow at [`.github/workflows/code-review.yml`](../.github/workflows/code-review.yml) supports four on-demand trigger mechanisms:
1. **ChatOps Comment**: A codeowner comments `/review`, `/code-review`, or `/ai-review` on a PR (`issue_comment: [created]`).
2. **Review Requested**: A codeowner clicks "Request review" in the GitHub PR interface (`pull_request: [review_requested]`).
3. **Label Added**: A codeowner adds the label `code-review`, `ai-review`, or `review` to the PR (`pull_request: [labeled]`).
4. **Manual Dispatch**: A codeowner triggers the workflow via `workflow_dispatch` specifying the `pr_number`.

### Local CLI Execution
Developers and codeowners can run the AI code review runner locally on their development machines:

```bash
# Review uncommitted staged changes
python scripts/code_review.py --staged

# Review local branch against origin/main and write output to a file
python scripts/code_review.py --base origin/main --output review.md

# Enforce codeowner policy locally
python scripts/code_review.py \
  --base origin/main \
  --enforce-codeowners \
  --pr-author "ncouture" \
  --requester "ncouture"
```

---

## 5. Repository File Map

```text
.github/
├── CODEOWNERS                       # Repository code ownership (* @ncouture)
├── DISCUSSIONS.md                   # Discussions welcome post & maintainer guidelines
├── ISSUE_TEMPLATE/
│   ├── bug_report.yml               # Structured bug report issue form
│   ├── config.yml                   # Template chooser configuration & discussion links
│   └── feature_request.yml          # Feature & protocol enhancement issue form
├── skills/
│   └── code-review/
│       └── SKILL.md                 # Gemini 3.8 Flash (Thinking=High) AirTell review skill
└── workflows/
    └── code-review.yml              # CI/CD automated review workflow with codeowner gates

scripts/
└── code_review.py                   # Antigravity SDK review runner (symlinked to src/airtell/scripts/)

tests/
└── test_codeowner_enforcement.py    # Unit test suite verifying codeowner authorization policies
```
