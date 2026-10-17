# Specification: GitHub Issue & Conductor Track Commit/Branch/PR Traceability

## 1. Overview
During the execution of Tracks 1 through 5 (`sidechannel_dashboard_integration_20261016`, `cli_adversarial_completion_20261016`, `single_dongle_topology_a_20261016`, `webhook_desktop_notifications_20261016`, and `duckdb_high_throughput_analytics_20261016`), 51 GitHub issues (`#5` and `#7`–`#56`) in `ncouture/AirTell` were resolved and closed before the final git commits were recorded on the parent branch `feat/ble-exposure` or linked to an active Pull Request (`#58`).

This track audits every closed GitHub issue (`#5` and `#7`–`#56`), maps each issue to its exact resolving 40-character git commit SHA(s), branch (`feat/ble-exposure`), Pull Request (`#58`), parent Epic/Track issue ID, Conductor track directory, and modified files, and updates both the local Conductor `plan.md` files and every closed GitHub issue (comment and body) with clickable traceability links.

## 2. Functional Requirements
1. **Pull Request Consolidation**: Ensure an open Pull Request (`#58`) tracks branch `feat/ble-exposure` into `main` referencing all 51 resolved issues (`#5`, `#7`–`#56`) and all resolving commits.
2. **GitHub Issue Traceability Updates**: Update every closed issue (`#5` and `#7`–`#56`) on GitHub (`ncouture/AirTell`) so that both its closing resolution comment and its issue body include a structured traceability record containing:
   - Exact resolving 40-character commit SHA(s) and short SHA links (`https://github.com/ncouture/AirTell/commit/<sha>`)
   - Dedicated branch name (`feat/ble-exposure`, `https://github.com/ncouture/AirTell/tree/feat/ble-exposure`)
   - Pull Request number and link (`#58`, `https://github.com/ncouture/AirTell/pull/58`)
   - Parent Epic / Planning issue ID (`#5`, `#7`, `#8`, `#9`, `#10`, `#11`) and Conductor track path
   - Clickable file links (`https://github.com/ncouture/AirTell/blob/<sha>/<path>`) for all implementation and test files modified to resolve the issue
3. **Conductor Plan Checkpoint Annotations**: Update `plan.md` across all 5 feature tracks (`sidechannel_dashboard_integration_20261016`, `cli_adversarial_completion_20261016`, `single_dongle_topology_a_20261016`, `webhook_desktop_notifications_20261016`, `duckdb_high_throughput_analytics_20261016`) as well as `github_issue_traceability_20261017` with phase `[checkpoint: <sha>]` and task `[<sha>]` markers and a `## Git & GitHub Traceability` section.
4. **Automated Traceability Verification**: Provide a pytest test suite (`tests/test_issue_traceability.py`) verifying the completeness of the 51-issue traceability registry, git commit existence in local git history, per-commit file modification accuracy, and Conductor `plan.md` checkpoint annotations.

## 3. Complete Issue-to-Commit/Branch/PR Traceability Matrix

| Issue | Track / Epic | Branch | PR | Resolving Commit SHA(s) | Primary Files |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `#5` | Planning Root (Tracks 1–5: `#7`–`#11`) | `feat/ble-exposure` | `#58` (and `#57`) | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478`, `07cdd9299869f70baf926a35442ab162bba395f5`, `4140e9840b71743af686b21e4588f4148efd675f`, `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e`, `c74cedca99e580e26b6af7b61ca7d4038095310e`, `0581d4150d954ddffa5b7ae6491da861e097ec89` | `conductor/tracks.md`, `conductor/tracks/github_issue_traceability_20261017/spec.md` |
| `#7` | Track 1 Epic (Parent `#5`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `src/airtell/sidechannel/runner.py`, `tests/test_sidechannel_view.py`, `conductor/tracks/sidechannel_dashboard_integration_20261016/plan.md` |
| `#8` | Track 2 Epic (Parent `#5`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `src/airtell/adversarial/rogue_beacon.py`, `docs/CLI.md`, `tests/test_cli_adversarial.py`, `conductor/tracks/cli_adversarial_completion_20261016/plan.md` |
| `#9` | Track 3 Epic (Parent `#5`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/topology/topology_a.py`, `src/airtell/device/serial_port.py`, `app/queue_bridge.py`, `src/airtell/cli.py`, `tests/test_topology_a_single_dongle.py`, `conductor/tracks/single_dongle_topology_a_20261016/plan.md` |
| `#10` | Track 4 Epic (Parent `#5`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `docs/scripts_reference.md`, `docs/howto.md`, `tests/test_antistalking_dispatchers.py`, `conductor/tracks/webhook_desktop_notifications_20261016/plan.md` |
| `#11` | Track 5 Epic (Parent `#5`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `src/airtell/telemetry/storage.py`, `src/airtell/scripts/ble_antistalking_tracker.py`, `app/streamlit_app.py`, `tests/test_storage_backend.py`, `tests/benchmarks/test_storage_benchmarks.py`, `conductor/tracks/duckdb_high_throughput_analytics_20261016/plan.md` |
| `#12` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#13` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `tests/test_cli_adversarial.py` |
| `#14` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `src/airtell/adversarial/rogue_beacon.py`, `tests/test_cli_adversarial.py` |
| `#15` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/topology/topology_a.py`, `src/airtell/topology/base.py`, `tests/test_topology_a_single_dongle.py` |
| `#16` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_antistalking_dispatchers.py` |
| `#17` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_antistalking_dispatchers.py` |
| `#18` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `src/airtell/telemetry/storage.py`, `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_storage_backend.py` |
| `#19` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#20` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#21` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#22` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#23` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#24` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#25` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `tests/test_cli_adversarial.py` |
| `#26` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `tests/test_cli_adversarial.py` |
| `#27` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `tests/test_cli_adversarial.py` |
| `#28` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `src/airtell/adversarial/rogue_beacon.py`, `tests/test_cli_adversarial.py` |
| `#29` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/topology/topology_a.py`, `tests/test_topology_a_single_dongle.py` |
| `#30` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/topology/topology_a.py`, `tests/test_topology_a_single_dongle.py` |
| `#31` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/device/serial_port.py`, `tests/test_topology_a_single_dongle.py` |
| `#32` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `app/queue_bridge.py`, `src/airtell/topology/topology_a.py`, `tests/test_topology_a_single_dongle.py` |
| `#33` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_antistalking_dispatchers.py` |
| `#34` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_antistalking_dispatchers.py` |
| `#35` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `src/airtell/telemetry/storage.py`, `src/airtell/scripts/ble_antistalking_tracker.py`, `pyproject.toml`, `uv.lock` |
| `#36` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `src/airtell/telemetry/storage.py`, `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/benchmarks/test_storage_benchmarks.py` |
| `#37` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `docs/CLI.md`, `README.md`, `tests/test_cli_adversarial.py` |
| `#38` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `conductor/product.md`, `conductor/tracks.md` |
| `#39` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `src/airtell/sidechannel/runner.py`, `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#40` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `app/views/adversarial_evaluation.py`, `tests/test_sidechannel_view.py` |
| `#41` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `src/airtell/adversarial/rogue_beacon.py`, `tests/test_cli_adversarial.py` |
| `#42` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `src/airtell/cli.py`, `tests/test_cli_adversarial.py` |
| `#43` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `src/airtell/cli.py`, `docs/CLI.md`, `README.md`, `tests/test_topology_a_single_dongle.py` |
| `#44` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `src/airtell/scripts/ble_antistalking_tracker.py`, `tests/test_antistalking_dispatchers.py` |
| `#45` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `src/airtell/telemetry/storage.py`, `src/airtell/telemetry/__init__.py`, `tests/test_storage_backend.py` |
| `#46` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `app/streamlit_app.py`, `app/views/packet_inspector.py`, `app/views/rssi_trends.py`, `app/views/alert_feed.py`, `app/views/telemetry_overview.py`, `tests/test_dashboard_views.py` |
| `#47` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `tests/test_sidechannel_view.py`, `tests/test_dashboard_views.py` |
| `#48` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `tests/test_cli_adversarial.py` |
| `#49` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `tests/test_topology_a_single_dongle.py` |
| `#50` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `tests/test_antistalking_dispatchers.py` |
| `#51` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `tests/benchmarks/test_storage_benchmarks.py` |
| `#52` | Track 4 (`#10`) | `feat/ble-exposure` | `#58` | `5d525b8137bb01fe6d5972ffff158dd2d6a3f83e` | `docs/scripts_reference.md`, `docs/howto.md` |
| `#53` | Track 5 (`#11`) | `feat/ble-exposure` | `#58` | `c74cedca99e580e26b6af7b61ca7d4038095310e` | `docs/howto.md` |
| `#54` | Track 1 (`#7`) | `feat/ble-exposure` | `#58` | `9f6001b381479c5d635c5a4d0d4b628fbb1d7696`, `1938a045db97cc71420894fd6ad611cfa9bc5478` | `conductor/tracks/sidechannel_dashboard_integration_20261016/spec.md`, `conductor/tracks/sidechannel_dashboard_integration_20261016/plan.md`, `conductor/tracks.md` |
| `#55` | Track 2 (`#8`) | `feat/ble-exposure` | `#58` | `07cdd9299869f70baf926a35442ab162bba395f5` | `conductor/tracks/cli_adversarial_completion_20261016/spec.md`, `conductor/tracks/cli_adversarial_completion_20261016/plan.md`, `conductor/tracks.md` |
| `#56` | Track 3 (`#9`) | `feat/ble-exposure` | `#58` | `4140e9840b71743af686b21e4588f4148efd675f` | `conductor/tracks/single_dongle_topology_a_20261016/spec.md`, `conductor/tracks/single_dongle_topology_a_20261016/plan.md`, `conductor/tracks.md` |
