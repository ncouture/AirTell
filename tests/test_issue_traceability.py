"""Automated verification of GitHub issue and Conductor track commit/branch/PR traceability."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONDUCTOR_TRACKS_DIR = REPO_ROOT / "conductor" / "tracks"

EXPECTED_COMMITS = {
    "track_1_feat": "9f6001b381479c5d635c5a4d0d4b628fbb1d7696",
    "track_1_fix": "1938a045db97cc71420894fd6ad611cfa9bc5478",
    "track_2": "07cdd9299869f70baf926a35442ab162bba395f5",
    "track_3": "4140e9840b71743af686b21e4588f4148efd675f",
    "track_4": "5d525b8137bb01fe6d5972ffff158dd2d6a3f83e",
    "track_5": "c74cedca99e580e26b6af7b61ca7d4038095310e",
    "traceability": "0581d4150d954ddffa5b7ae6491da861e097ec89",
}

TRACK_ISSUE_MAPPING = {
    "sidechannel_dashboard_integration_20261016": {
        "epic": 7,
        "issues": [7, 12, 19, 20, 21, 22, 23, 24, 38, 39, 40, 47, 54],
        "commits": [
            "9f6001b381479c5d635c5a4d0d4b628fbb1d7696",
            "1938a045db97cc71420894fd6ad611cfa9bc5478",
        ],
    },
    "cli_adversarial_completion_20261016": {
        "epic": 8,
        "issues": [8, 13, 14, 25, 26, 27, 28, 37, 41, 42, 48, 55],
        "commits": ["07cdd9299869f70baf926a35442ab162bba395f5"],
    },
    "single_dongle_topology_a_20261016": {
        "epic": 9,
        "issues": [9, 15, 29, 30, 31, 32, 43, 49, 56],
        "commits": ["4140e9840b71743af686b21e4588f4148efd675f"],
    },
    "webhook_desktop_notifications_20261016": {
        "epic": 10,
        "issues": [10, 16, 17, 33, 34, 44, 50, 52],
        "commits": ["5d525b8137bb01fe6d5972ffff158dd2d6a3f83e"],
    },
    "duckdb_high_throughput_analytics_20261016": {
        "epic": 11,
        "issues": [11, 18, 35, 36, 45, 46, 51, 53],
        "commits": ["c74cedca99e580e26b6af7b61ca7d4038095310e"],
    },
}


def parse_spec_traceability_matrix() -> dict[int, dict[str, object]]:
    """Parse the 51-row markdown traceability matrix from github_issue_traceability_20261017/spec.md."""
    spec_path = CONDUCTOR_TRACKS_DIR / "github_issue_traceability_20261017" / "spec.md"
    spec_text = spec_path.read_text(encoding="utf-8")
    matrix: dict[int, dict[str, object]] = {}
    for line in spec_text.splitlines():
        if not line.startswith("| `#"):
            continue
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        assert len(cells) == 6, f"Malformed table row in spec.md: {line}"
        issue_num = int(cells[0].strip("`#"))
        commits = re.findall(r"\b[0-9a-f]{40}\b", cells[4])
        files = re.findall(r"`([^`]+)`", cells[5])
        matrix[issue_num] = {
            "track_col": cells[1],
            "branch": cells[2].strip("`"),
            "pr": cells[3],
            "commits": commits,
            "files": files,
        }
    return matrix


def test_all_51_issues_partitioned_without_gaps_or_duplicates() -> None:
    """Verify that issue #5 plus issues #7-#56 (51 total) are uniquely and completely mapped."""
    track_issues: list[int] = []
    for info in TRACK_ISSUE_MAPPING.values():
        track_issues.extend(info["issues"])  # type: ignore[arg-type]

    assert len(track_issues) == 50
    assert len(set(track_issues)) == 50
    assert sorted(track_issues) == list(range(7, 57))


def test_resolving_commits_exist_in_git_history() -> None:
    """Verify every recorded 40-char commit SHA exists as a valid commit object in git."""
    for label, sha in EXPECTED_COMMITS.items():
        assert len(sha) == 40, f"Commit {label} ({sha}) is not a full 40-char SHA"
        res = subprocess.run(
            ["git", "cat-file", "-t", sha],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert res.stdout.strip() == "commit", f"SHA {sha} for {label} is not a git commit"


def test_conductor_track_plans_have_checkpoints_and_traceability() -> None:
    """Verify each of the 5 Track plan.md files and the traceability track plan.md have valid checkpoints."""
    all_tracks_to_verify = {
        **TRACK_ISSUE_MAPPING,
        "github_issue_traceability_20261017": {
            "epic": 5,
            "issues": [5, *range(7, 57)],
            "commits": [EXPECTED_COMMITS["traceability"]],
        },
    }
    for track_id, info in all_tracks_to_verify.items():
        track_dir = CONDUCTOR_TRACKS_DIR / track_id
        assert track_dir.is_dir(), f"Missing track directory: {track_dir}"

        plan_file = track_dir / "plan.md"
        assert plan_file.is_file(), f"Missing plan.md in {track_dir}"
        plan_text = plan_file.read_text(encoding="utf-8")

        # Verify phase checkpoints exist
        checkpoints = re.findall(r"\[checkpoint:\s*([0-9a-f]{7})\]", plan_text)
        assert len(checkpoints) >= 3, f"Expected phase checkpoints in {plan_file}"

        # Verify traceability section references branch, PR #58, and full commit SHAs
        assert "## Git & GitHub Traceability" in plan_text, f"Missing traceability section in {plan_file}"
        assert "feat/ble-exposure" in plan_text
        assert "#58" in plan_text
        for sha in info["commits"]:  # type: ignore[union-attr]
            assert sha in plan_text, f"Missing full commit SHA {sha} in {plan_file}"
            assert sha[:7] in checkpoints, f"Missing short SHA {sha[:7]} in checkpoints of {plan_file}"

        # Verify every issue in the track is referenced in plan.md
        for issue_num in info["issues"]:  # type: ignore[union-attr]
            assert f"#{issue_num}" in plan_text, f"Issue #{issue_num} not referenced in {plan_file}"


def test_traceability_track_spec_covers_all_51_issues_and_verifies_commit_diffs() -> None:
    """Verify the 51-issue matrix in spec.md has valid commits and files actually touched by those commits."""
    trace_dir = CONDUCTOR_TRACKS_DIR / "github_issue_traceability_20261017"
    assert trace_dir.is_dir()

    meta = json.loads((trace_dir / "metadata.json").read_text(encoding="utf-8"))
    assert meta["track_id"] == "github_issue_traceability_20261017"
    assert meta["status"] == "completed"

    tracks_registry = (REPO_ROOT / "conductor" / "tracks.md").read_text(encoding="utf-8")
    assert "github_issue_traceability_20261017" in tracks_registry

    # Map each issue to its expected track commits
    expected_issue_commits: dict[int, list[str]] = {
        5: list(EXPECTED_COMMITS.values()),
    }
    for info in TRACK_ISSUE_MAPPING.values():
        for inum in info["issues"]:  # type: ignore[union-attr]
            expected_issue_commits[int(inum)] = list(info["commits"])  # type: ignore[arg-type]

    # Cache git diff file sets per commit SHA
    commit_changed_files: dict[str, set[str]] = {}
    for sha in EXPECTED_COMMITS.values():
        res = subprocess.run(
            ["git", "show", "--name-only", "--pretty=format:", sha],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        commit_changed_files[sha] = {line.strip() for line in res.stdout.splitlines() if line.strip()}

    matrix = parse_spec_traceability_matrix()
    all_issues = [5, *range(7, 57)]
    assert sorted(matrix.keys()) == all_issues

    for issue_num in all_issues:
        row = matrix[issue_num]
        assert row["branch"] == "feat/ble-exposure"
        assert "#58" in str(row["pr"])
        row_commits: list[str] = row["commits"]  # type: ignore[assignment]
        assert row_commits == expected_issue_commits[issue_num], (
            f"Issue #{issue_num} commits in spec.md ({row_commits}) != expected ({expected_issue_commits[issue_num]})"
        )

        row_files: list[str] = row["files"]  # type: ignore[assignment]
        assert len(row_files) >= 1, f"Issue #{issue_num} has no attributed files in spec.md"

        union_changed = set()
        for sha in row_commits:
            union_changed.update(commit_changed_files[sha])

        for rel_file in row_files:
            assert (REPO_ROOT / rel_file).is_file(), f"Issue #{issue_num} file {rel_file} does not exist on disk"
            assert rel_file in union_changed, (
                f"Issue #{issue_num} file {rel_file} was NOT modified in commits {[s[:7] for s in row_commits]}"
            )
