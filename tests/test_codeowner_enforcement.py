"""Unit tests for AirTell code review codeowner authorization policy, CLI configuration, and workflow YAML."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import airtell.scripts.code_review as code_review_mod
from airtell.scripts.code_review import (
    DEFAULT_MODEL,
    DEFAULT_THINKING_LEVEL,
    create_parser,
    get_codeowners,
    resolve_thinking_level,
    run_review,
    verify_codeowner_authorization,
)


def test_get_codeowners_from_repo():
    repo_root = Path(__file__).resolve().parent.parent
    codeowners_file = repo_root / ".github" / "CODEOWNERS"
    assert codeowners_file.exists(), ".github/CODEOWNERS must exist in the repository"

    owners = get_codeowners(codeowners_file)
    assert "ncouture" in owners, "Expected 'ncouture' to be defined in .github/CODEOWNERS"


def test_verify_codeowner_authorization_success():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="ncouture",
        pr_author="ncouture",
    )
    assert authorized is True
    assert "Authorized" in reason


def test_verify_codeowner_authorization_non_codeowner_author_authorized():
    """Verify that codeowner requests on non-codeowner PRs are authorized under R3."""
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="ncouture",
        pr_author="unauthorized_contributor",
    )
    assert authorized is True
    assert "Authorized" in reason
    assert "unauthorized_contributor" in reason


def test_verify_codeowner_authorization_unauthorized_requester_non_codeowner_author():
    """Verify that non-codeowner requests on non-codeowner PRs are blocked."""
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="unauthorized_requester",
        pr_author="unauthorized_contributor",
    )
    assert authorized is False
    assert "Review requester '@unauthorized_requester' is not a repository codeowner" in reason


def test_verify_codeowner_authorization_empty_author():
    """Verify that an empty or missing PR author is rejected with an informative error."""
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="ncouture",
        pr_author="   ",
    )
    assert authorized is False
    assert "PR author must be specified" in reason


def test_verify_codeowner_authorization_unauthorized_requester():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester="unauthorized_requester",
        pr_author="ncouture",
    )
    assert authorized is False
    assert "Review requester '@unauthorized_requester' is not a repository codeowner" in reason


def test_verify_codeowner_authorization_case_insensitive():
    repo_root = Path(__file__).resolve().parent.parent
    authorized, reason = verify_codeowner_authorization(
        project_root=repo_root,
        requester=" @NCOUTURE ",
        pr_author=" @NCouture ",
    )
    assert authorized is True

    authorized_empty, reason_empty = verify_codeowner_authorization(
        project_root=repo_root,
        requester="   ",
        pr_author="ncouture",
    )
    assert authorized_empty is False
    assert "Review requester must be specified" in reason_empty


def test_get_codeowners_ignores_inline_comments(tmp_path: Path):
    co_file = tmp_path / "CODEOWNERS"
    co_file.write_text("* @ncouture # @attacker_in_comment\n", encoding="utf-8")
    owners = get_codeowners(co_file)
    assert owners == {"ncouture"}


def test_code_review_defaults_gemini_4_argon_high(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AIRTELL_REVIEW_MODEL", raising=False)
    monkeypatch.delenv("AIRTELL_THINKING_LEVEL", raising=False)
    assert DEFAULT_MODEL == "gemini-4-argon"
    assert DEFAULT_THINKING_LEVEL == "HIGH"

    parser = create_parser()
    args = parser.parse_args([])
    assert args.model == "gemini-4-argon"
    assert args.thinking_level == "HIGH"


def test_code_review_env_empty_or_invalid_fallback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIRTELL_REVIEW_MODEL", "   ")
    monkeypatch.setenv("AIRTELL_THINKING_LEVEL", "   ")
    parser = create_parser()
    args = parser.parse_args([])
    assert args.model == "gemini-4-argon"
    assert args.thinking_level == "HIGH"

    monkeypatch.setenv("AIRTELL_THINKING_LEVEL", "invalid_level")
    parser2 = create_parser()
    args2 = parser2.parse_args([])
    assert args2.thinking_level == "HIGH"


def test_code_review_cli_custom_model_and_thinking():
    parser = create_parser()
    args = parser.parse_args(["--model", "  gemini-4-argon  ", "--thinking-level", "  low  "])
    assert args.model == "gemini-4-argon"
    assert args.thinking_level == "LOW"

    with pytest.raises(SystemExit):
        parser.parse_args(["--thinking-level", "invalid"])

    with pytest.raises(SystemExit):
        parser.parse_args(["--model", "   "])


def test_resolve_thinking_level(monkeypatch: pytest.MonkeyPatch):
    fake_agy = SimpleNamespace(
        ThinkingLevel=SimpleNamespace(LOW="ENUM_LOW", MEDIUM="ENUM_MEDIUM", HIGH="ENUM_HIGH")
    )
    monkeypatch.setattr(code_review_mod, "agy", fake_agy)
    assert resolve_thinking_level("high") == "ENUM_HIGH"
    assert resolve_thinking_level("MEDIUM") == "ENUM_MEDIUM"
    assert resolve_thinking_level("  low ") == "ENUM_LOW"

    with pytest.raises(ValueError, match="Invalid thinking level"):
        resolve_thinking_level("ultra")


def test_run_review_configures_gemini_4_argon_high(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    captured: dict[str, object] = {}

    class FakeAgent:
        def __init__(self, config: object) -> None:
            captured["config"] = config

        async def __aenter__(self) -> FakeAgent:
            return self

        async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        async def chat(self, prompt: str) -> object:
            captured["prompt"] = prompt

            class _Resp:
                async def text(self) -> str:
                    return "# Mock Review Verdict"

            return _Resp()

    fake_agy = SimpleNamespace(
        ThinkingLevel=SimpleNamespace(LOW="LOW_LVL", MEDIUM="MED_LVL", HIGH="HIGH_LVL"),
        BuiltinTools=SimpleNamespace(
            READ_URL_CONTENT="read_url",
            SEARCH_WEB="search_web",
            VIEW_FILE="view_file",
        ),
        GeminiModelOptions=lambda **kw: SimpleNamespace(**kw),
        GeminiAPIEndpoint=lambda **kw: SimpleNamespace(**kw),
        CapabilitiesConfig=lambda **kw: SimpleNamespace(**kw),
        ModelTarget=lambda **kw: SimpleNamespace(**kw),
        LocalAgentConfig=lambda **kw: SimpleNamespace(**kw),
        Agent=FakeAgent,
    )
    monkeypatch.setattr(code_review_mod, "agy", fake_agy)

    output = asyncio.run(
        run_review(
            diff_text="diff --git a/foo.py b/foo.py",
            changed_files=["foo.py"],
            skills_dir=tmp_path,
        )
    )
    assert output == "# Mock Review Verdict"
    cfg = captured["config"]
    assert getattr(cfg, "model") == "gemini-4-argon"
    models = getattr(cfg, "models")
    assert len(models) == 1
    assert models[0].name == "gemini-4-argon"
    assert models[0].endpoint.options.thinking_level == "HIGH_LVL"


def test_verify_codeowners_only_cli_mode(monkeypatch: pytest.MonkeyPatch):
    # 1. Codeowner requester on codeowner PR -> exit 0
    monkeypatch.setattr(
        "sys.argv",
        [
            "code_review.py",
            "--verify-codeowners-only",
            "--pr-author",
            "ncouture",
            "--requester",
            "ncouture",
        ],
    )
    with pytest.raises(SystemExit) as exc_info_co_co:
        code_review_mod.main()
    assert exc_info_co_co.value.code == 0

    # 2. Codeowner requester on non-codeowner PR -> exit 0 (R3 core behavior)
    monkeypatch.setattr(
        "sys.argv",
        [
            "code_review.py",
            "--verify-codeowners-only",
            "--pr-author",
            "intruder",
            "--requester",
            "ncouture",
        ],
    )
    with pytest.raises(SystemExit) as exc_info_co_non:
        code_review_mod.main()
    assert exc_info_co_non.value.code == 0

    # 3. Non-codeowner requester on codeowner PR -> exit 1
    monkeypatch.setattr(
        "sys.argv",
        [
            "code_review.py",
            "--verify-codeowners-only",
            "--pr-author",
            "ncouture",
            "--requester",
            "intruder",
        ],
    )
    with pytest.raises(SystemExit) as exc_info_non_co:
        code_review_mod.main()
    assert exc_info_non_co.value.code == 1

    # 4. Non-codeowner requester on non-codeowner PR -> exit 1
    monkeypatch.setattr(
        "sys.argv",
        [
            "code_review.py",
            "--verify-codeowners-only",
            "--pr-author",
            "intruder",
            "--requester",
            "intruder",
        ],
    )
    with pytest.raises(SystemExit) as exc_info_non_non:
        code_review_mod.main()
    assert exc_info_non_non.value.code == 1


def test_code_review_workflow_configuration(tmp_path: Path):
    import re
    import subprocess
    import textwrap

    repo_root = Path(__file__).resolve().parent.parent
    workflow_path = repo_root / ".github" / "workflows" / "code-review.yml"
    assert workflow_path.exists()
    content = workflow_path.read_text(encoding="utf-8")

    assert 'name: "AirTell Code Review (Gemini 4 Argon // Antigravity SDK)"' in content
    assert "gemini-4-argon" in content
    assert "Gemma 4" not in content
    assert "timeout-minutes: 15" in content
    assert "github.actor == 'ncouture' || github.triggering_actor == 'ncouture'" in content
    assert "github.event.action == 'ready_for_review'" in content
    assert "astral-sh/setup-uv@v4" in content
    assert "retention-days: 14" in content
    assert "--model" in content
    assert "--thinking-level" in content

    resolve_pos = content.index('- name: "Resolve PR Target & Authorize Codeowners"')
    fetch_pos = content.index('- name: "Fetch and Checkout PR Head"')
    exec_pos = content.index('- name: "Execute Antigravity Code Review"')
    assert resolve_pos < fetch_pos < exec_pos
    assert "--verify-codeowners-only" in content[resolve_pos:fetch_pos]

    match = re.search(
        r'- name: "Fetch and Checkout PR Head".*?run: \|\n(.*?)\n\s+- name: "Execute Antigravity Code Review"',
        content,
        re.DOTALL,
    )
    assert match is not None
    fetch_script = textwrap.dedent(match.group(1))
    remote = tmp_path / "remote"
    subprocess.run(["git", "init", "-b", "main", str(remote)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(remote), "config", "user.email", "test@airtell.io"], check=True)
    subprocess.run(["git", "-C", str(remote), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(remote), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(remote), "config", "tag.gpgsign", "false"], check=True)

    (remote / "file.txt").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(remote), "add", "."], check=True)
    subprocess.run(["git", "-C", str(remote), "commit", "-m", "init"], check=True, capture_output=True)
    base_sha = subprocess.run(
        ["git", "-C", str(remote), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    short_sha = base_sha[:7]
    subprocess.run(["git", "-C", str(remote), "tag", "v1.0"], check=True)

    subprocess.run(["git", "-C", str(remote), "checkout", "-b", "feature"], check=True, capture_output=True)
    (remote / "file.txt").write_text("v1.5\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(remote), "commit", "-am", "feat"], check=True, capture_output=True)

    subprocess.run(["git", "-C", str(remote), "checkout", "-b", "pr-head"], check=True, capture_output=True)
    (remote / "file.txt").write_text("v2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(remote), "commit", "-am", "pr1"], check=True, capture_output=True)
    (remote / "file.txt").write_text("v3\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(remote), "commit", "-am", "pr2"], check=True, capture_output=True)
    head_sha = subprocess.run(
        ["git", "-C", str(remote), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "-C", str(remote), "update-ref", "refs/pull/42/head", head_sha], check=True)
    subprocess.run(["git", "-C", str(remote), "checkout", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(remote), "branch", "-D", "pr-head"], check=True, capture_output=True)

    for idx, base_ref in enumerate(["origin/main", "origin/feature", base_sha, short_sha, "v1.0", "feature"]):
        clone = tmp_path / f"clone_{idx}"
        subprocess.run(
            ["git", "clone", "--depth=1", "--single-branch", "--branch", "main", f"file://{remote}", str(clone)],
            check=True,
            capture_output=True,
        )
        env = {"PATH": "/usr/bin:/bin", "BASE_REF": base_ref, "HEAD_REF": head_sha, "PR_NUMBER": "42"}
        subprocess.run(["bash", "-c", fetch_script], cwd=str(clone), env=env, check=True, capture_output=True, text=True)
        diff = subprocess.run(
            ["git", "-C", str(clone), "diff", f"{base_ref}...{head_sha}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert "+v3" in diff


def test_release_please_config_and_manifest():
    """Verify release-please-config.json and .release-please-manifest.json valid JSON and config."""
    repo_root = Path(__file__).resolve().parent.parent
    config_file = repo_root / "release-please-config.json"
    manifest_file = repo_root / ".release-please-manifest.json"

    assert config_file.exists(), "release-please-config.json must exist in repository root"
    assert manifest_file.exists(), ".release-please-manifest.json must exist in repository root"

    config_data = json.loads(config_file.read_text(encoding="utf-8"))
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Validate package configuration
    assert "packages" in config_data, "release-please-config.json must contain 'packages'"
    assert "." in config_data["packages"], "packages must configure root '.'"
    pkg_config = config_data["packages"]["."]

    assert pkg_config.get("package-name") == "airtell"
    assert pkg_config.get("release-type") == "python"
    assert pkg_config.get("changelog-path") == "CHANGELOG.md"
    assert pkg_config.get("bump-minor-pre-major") is True
    assert pkg_config.get("bump-patch-for-minor-pre-major") is False
    assert pkg_config.get("draft") is False
    assert pkg_config.get("prerelease") is False

    # Validate manifest version
    assert manifest_data.get(".") == "0.2.0"

    # Validate pyproject.toml and airtell.__version__ alignment
    import airtell

    assert airtell.__version__ == "0.2.0"

    pyproject_file = repo_root / "pyproject.toml"
    assert 'version = "0.2.0"' in pyproject_file.read_text(encoding="utf-8")


def test_release_please_workflow_configuration():
    """Verify .github/workflows/release-please.yml syntax, permissions, triggers, and dual-tier codeowner gating."""
    repo_root = Path(__file__).resolve().parent.parent
    workflow_file = repo_root / ".github" / "workflows" / "release-please.yml"

    assert workflow_file.exists(), ".github/workflows/release-please.yml must exist"
    content = workflow_file.read_text(encoding="utf-8")

    # Workflow name
    assert 'name: "Release Please"' in content

    # Triggers: push to main and workflow_dispatch
    assert "push:" in content
    assert "main" in content
    assert "workflow_dispatch:" in content

    # Concurrency control
    assert "group: release-please-${{ github.ref }}" in content
    assert "cancel-in-progress: false" in content

    # Pinned Ubuntu runner (avoids ubuntu-latest migration notice)
    assert "runs-on: ubuntu-24.04" in content
    assert "ubuntu-latest" not in content

    # Permissions
    assert "contents: write" in content
    assert "issues: write" in content
    assert "pull-requests: write" in content

    # Tier 1 Job-level codeowner actor check
    assert "if: github.actor == 'ncouture' || github.triggering_actor == 'ncouture'" in content

    # Deprecated actions and Node 20 targets must not be present
    assert "google-github-actions/release-please-action" not in content
    assert "actions/checkout@v4" not in content

    # Step sequence (Node 24 actions)
    checkout_pos = content.index("uses: actions/checkout@v6")
    auth_pos = content.index('- name: "Authorize Codeowner Execution"')
    release_pos = content.index("uses: googleapis/release-please-action@v5")
    assert checkout_pos < auth_pos < release_pos

    # Release action arguments
    assert "config-file: release-please-config.json" in content
    assert "manifest-file: .release-please-manifest.json" in content


def test_release_please_tier2_codeowner_authorization_step(tmp_path: Path):
    """Verify Tier 2 runner-level CODEOWNERS verification script dynamically enforces codeowners."""
    import re
    import subprocess
    import textwrap

    repo_root = Path(__file__).resolve().parent.parent
    workflow_file = repo_root / ".github" / "workflows" / "release-please.yml"
    content = workflow_file.read_text(encoding="utf-8")

    match = re.search(
        r'- name: "Authorize Codeowner Execution".*?run: \|\n(.*?)\n\s+- name: "Run Release Please Action"',
        content,
        re.DOTALL,
    )
    assert match is not None, "Could not extract Authorize Codeowner Execution script from workflow"
    auth_script = textwrap.dedent(match.group(1))

    # Create dummy repo with .github/CODEOWNERS
    sim_repo = tmp_path / "sim_repo"
    sim_co_dir = sim_repo / ".github"
    sim_co_dir.mkdir(parents=True)
    (sim_co_dir / "CODEOWNERS").write_text("* @ncouture # owner\n", encoding="utf-8")

    # 1. Authorized codeowner
    proc_auth = subprocess.run(
        ["bash", "-c", auth_script],
        cwd=str(sim_repo),
        env={"PATH": "/usr/bin:/bin", "ACTOR": "ncouture"},
        capture_output=True,
        text=True,
    )
    assert proc_auth.returncode == 0
    assert "Authorized codeowner execution: @ncouture" in proc_auth.stdout

    # 2. Case-insensitive authorized codeowner
    proc_case = subprocess.run(
        ["bash", "-c", auth_script],
        cwd=str(sim_repo),
        env={"PATH": "/usr/bin:/bin", "ACTOR": "NCouture"},
        capture_output=True,
        text=True,
    )
    assert proc_case.returncode == 0
    assert "Authorized codeowner execution: @ncouture" in proc_case.stdout

    # 3. Unauthorized actor
    proc_unauth = subprocess.run(
        ["bash", "-c", auth_script],
        cwd=str(sim_repo),
        env={"PATH": "/usr/bin:/bin", "ACTOR": "attacker"},
        capture_output=True,
        text=True,
    )
    assert proc_unauth.returncode != 0
    assert "Unauthorized actor @attacker not recognized in CODEOWNERS" in proc_unauth.stderr

    # 4. Missing or empty actor
    proc_empty = subprocess.run(
        ["bash", "-c", auth_script],
        cwd=str(sim_repo),
        env={"PATH": "/usr/bin:/bin", "ACTOR": ""},
        capture_output=True,
        text=True,
    )
    assert proc_empty.returncode != 0

    # 5. Missing CODEOWNERS file
    (sim_co_dir / "CODEOWNERS").unlink()
    proc_missing_co = subprocess.run(
        ["bash", "-c", auth_script],
        cwd=str(sim_repo),
        env={"PATH": "/usr/bin:/bin", "ACTOR": "ncouture"},
        capture_output=True,
        text=True,
    )
    assert proc_missing_co.returncode != 0
    assert "CODEOWNERS not found" in proc_missing_co.stderr


