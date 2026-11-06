#!/usr/bin/env python3
"""AirTell Automated Code Review Runner powered by Google Antigravity SDK.

Executes in-depth architectural and adversarial code reviews for AirTell BLE
testbed changes using Gemini 4 Argon with high thinking, grounded in the
AirTell Research NotebookLM Workspace (https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6)
and the domain-specific review skill (.github/skills/code-review/SKILL.md).

Enforces codeowner authorization policy: PRs must be authored by a repository
codeowner, and the review must be explicitly requested by a repository codeowner.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import google.antigravity as agy
except ImportError:
    agy = None

DEFAULT_NOTEBOOKLM_URL = "https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6"
DEFAULT_MODEL = "gemini-4-argon"
DEFAULT_THINKING_LEVEL = "HIGH"
VALID_THINKING_LEVELS = ("LOW", "MEDIUM", "HIGH")


def get_git_diff(base: str | None = None, head: str | None = None, staged: bool = False) -> str:
    """Retrieve git diff for the target revision range or staged changes."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--cached")
    elif base and head:
        cmd.append(f"{base}...{head}")
    elif base:
        cmd.append(base)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0 and base and head and not staged:
        result = subprocess.run(["git", "diff", base, head], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"Error computing git diff: {result.stderr}", file=sys.stderr)
        return ""
    return result.stdout.strip()


def get_changed_files(base: str | None = None, head: str | None = None, staged: bool = False) -> list[str]:
    """Retrieve list of modified filenames."""
    cmd = ["git", "diff", "--name-only"]
    if staged:
        cmd.append("--cached")
    elif base and head:
        cmd.append(f"{base}...{head}")
    elif base:
        cmd.append(base)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0 and base and head and not staged:
        result = subprocess.run(
            ["git", "diff", "--name-only", base, head], capture_output=True, text=True, check=False
        )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]


def get_codeowners(codeowners_path: Path) -> set[str]:
    """Parse CODEOWNERS file and return a set of lowercased GitHub usernames."""
    if not codeowners_path.exists():
        return set()
    owners: set[str] = set()
    for line in codeowners_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        for part in parts[1:]:
            if part.startswith("#"):
                break
            if part.startswith("@"):
                # Handle @org/team or @username
                username = part.lstrip("@").split("/")[-1].lower()
                if username:
                    owners.add(username)
            elif "@" in part:
                owners.add(part.lower())
    return owners


def verify_codeowner_authorization(
    project_root: Path,
    requester: str | None,
    pr_author: str | None,
) -> tuple[bool, str]:
    """Verify that both the PR author and review requester are repository codeowners."""
    codeowners_path = project_root / ".github" / "CODEOWNERS"
    if not codeowners_path.exists():
        codeowners_path = project_root / "CODEOWNERS"

    if not codeowners_path.exists():
        return False, "Authorization error: CODEOWNERS file not found in repository."

    codeowners = get_codeowners(codeowners_path)
    if not codeowners:
        return False, "Authorization error: CODEOWNERS file does not define any codeowners."

    clean_author = (pr_author or "").strip().lstrip("@").strip().lower()
    if not clean_author:
        return False, "Authorization error: PR author must be specified when enforcing codeowner execution."

    clean_requester = (requester or "").strip().lstrip("@").strip().lower()
    if not clean_requester:
        return False, "Authorization error: Review requester must be specified when enforcing codeowner execution."

    if clean_author not in codeowners:
        return False, (
            f"PR author '@{pr_author.strip().lstrip('@').strip()}' is not a repository codeowner. "
            f"AirTell code review execution is restricted to PRs created by codeowners: {sorted(codeowners)}"
        )

    if clean_requester not in codeowners:
        return False, (
            f"Review requester '@{requester.strip().lstrip('@').strip()}' is not a repository codeowner. "
            f"AirTell code review execution must be requested by a codeowner: {sorted(codeowners)}"
        )

    return True, f"Authorized: PR author '@{clean_author}' and requester '@{clean_requester}' are verified codeowners."


def load_notebooklm_context(context_path: Path | None) -> str:
    """Load local synchronized snapshot of the NotebookLM research workspace if present."""
    if context_path and context_path.exists():
        try:
            content = context_path.read_text(encoding="utf-8")
            if len(content) > 15000:
                return content[:15000] + "\n\n[... NotebookLM context truncated for prompt budget ...]"
            return content
        except OSError as e:
            print(f"Warning: Failed to read NotebookLM context file {context_path}: {e}", file=sys.stderr)
    return ""


def resolve_thinking_level(thinking_level: str) -> object:
    """Resolve thinking level string (LOW, MEDIUM, HIGH) to Antigravity SDK enum or normalized string."""
    if not isinstance(thinking_level, str):
        raise ValueError(
            f"Invalid thinking level '{thinking_level}'. Must be one of: {', '.join(VALID_THINKING_LEVELS)}"
        )
    normalized = thinking_level.strip().upper()
    if normalized not in VALID_THINKING_LEVELS:
        raise ValueError(
            f"Invalid thinking level '{thinking_level}'. Must be one of: {', '.join(VALID_THINKING_LEVELS)}"
        )
    if agy is not None and hasattr(agy, "ThinkingLevel"):
        return getattr(agy.ThinkingLevel, normalized, normalized)
    return normalized


async def run_review(
    diff_text: str,
    changed_files: list[str],
    skills_dir: Path,
    notebooklm_url: str = DEFAULT_NOTEBOOKLM_URL,
    notebooklm_context: str = "",
    model: str = DEFAULT_MODEL,
    thinking_level: str = DEFAULT_THINKING_LEVEL,
) -> str:
    """Run code review agent using Google Antigravity SDK with NotebookLM grounding."""
    global agy
    if agy is None:
        try:
            import google.antigravity as agy
        except ImportError as e:
            raise RuntimeError(
                "The 'google-antigravity' package is required to execute code reviews. "
                "Install it via 'pip install google-antigravity'."
            ) from e

    resolved_model = (model or "").strip() or DEFAULT_MODEL
    resolved_thinking = resolve_thinking_level(thinking_level)
    endpoint = agy.GeminiAPIEndpoint(
        options=agy.GeminiModelOptions(thinking_level=resolved_thinking)
    )

    capabilities = agy.CapabilitiesConfig(
        enabled_tools=[
            agy.BuiltinTools.READ_URL_CONTENT,
            agy.BuiltinTools.SEARCH_WEB,
            agy.BuiltinTools.VIEW_FILE,
        ]
    )

    config = agy.LocalAgentConfig(
        model=resolved_model,
        models=[agy.ModelTarget(name=resolved_model, endpoint=endpoint)],
        skills_paths=[str(skills_dir)],
        capabilities=capabilities,
    )

    files_summary = "\n".join(f"- `{f}`" for f in changed_files[:50])
    if len(changed_files) > 50:
        files_summary += f"\n- ... and {len(changed_files) - 50} more files"

    notebook_section = f"""### 📚 Authoritative Research Grounding (Google NotebookLM)
- **Primary Research Workspace:** [{notebooklm_url}]({notebooklm_url})
- **Notebook Title:** *AirTell Intel - All 2026 PoPETs + 2018 to 2026 Bluetooth related PDFs* (259 sources)
- **Core Mission:** Cross-reference link-layer timing, RPA rotation tracking, side-channels, and proprietary packet dissection against peer-reviewed empirical privacy research."""

    if notebooklm_context:
        notebook_section += f"\n\n#### Synchronized NotebookLM Research Index Snapshot:\n```markdown\n{notebooklm_context}\n```"

    prompt = f"""You are the AirTell Principal Code Reviewer.
Activate your 'airtell-code-review' skill to conduct an architectural, adversarial, and empirical privacy review of the following changes.

{notebook_section}

### Changed Files:
{files_summary}

### Git Diff:
```diff
{diff_text}
```

Please execute your full review protocol:
1. Link-layer & CC2652 UART buffer safety
2. Microsecond timestamp precision & timing side-channel integrity
3. Topology orchestration (A, B, C) and VirtualRadioBus parity
4. Zero-panic parsing of untrusted over-the-air BLE packets
5. Alignment with the AirTell NotebookLM empirical privacy research specifications
6. Code quality, typing, and test fidelity

Render your response strictly using the Review Output Schema defined in your skill, and explicitly note research grounding in your Executive Architectural Summary."""

    async with agy.Agent(config=config) as agent:
        response = await agent.chat(prompt)
        return await response.text()


def post_github_pr_comment(review_text: str, repo: str, pr_number: str, token: str) -> bool:
    """Post code review as a comment on the GitHub Pull Request."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "AirTell-Code-Reviewer",
        "Content-Type": "application/json",
    }
    payload = json.dumps({"body": review_text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status in (200, 201):
                print(f"Successfully posted code review to PR #{pr_number} on {repo}")
                return True
            print(f"Failed to post comment. HTTP Status: {resp.status}", file=sys.stderr)
            return False
    except (OSError, urllib.error.URLError) as exc:
        print(f"Error posting GitHub comment: {exc}", file=sys.stderr)
        return False


def _normalize_model_arg(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise argparse.ArgumentTypeError("Model slug cannot be empty.")
    return cleaned


def _normalize_thinking_level_arg(value: str) -> str:
    return value.strip().upper()


def create_parser() -> argparse.ArgumentParser:
    """Create and return the CLI argument parser for the code review runner."""
    env_model = (os.getenv("AIRTELL_REVIEW_MODEL") or "").strip() or DEFAULT_MODEL
    env_thinking = (os.getenv("AIRTELL_THINKING_LEVEL") or "").strip().upper()
    if env_thinking not in VALID_THINKING_LEVELS:
        env_thinking = DEFAULT_THINKING_LEVEL

    parser = argparse.ArgumentParser(description="AirTell AI Code Reviewer (Google Antigravity SDK + NotebookLM)")
    parser.add_argument("--base", help="Base commit or branch (e.g. origin/main)")
    parser.add_argument("--head", help="Head commit or branch (e.g. HEAD)")
    parser.add_argument("--staged", action="store_true", help="Review staged changes only")
    parser.add_argument("--output", help="Path to write the markdown review output")
    parser.add_argument("--post-comment", action="store_true", help="Post review comment to GitHub PR")
    parser.add_argument("--pr-number", help="GitHub Pull Request number")
    parser.add_argument("--repo", help="GitHub repository (owner/repo)")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub API Token")
    parser.add_argument(
        "--model",
        default=env_model,
        type=_normalize_model_arg,
        help=f"Antigravity model slug for code review (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--thinking-level",
        default=env_thinking,
        choices=VALID_THINKING_LEVELS,
        type=_normalize_thinking_level_arg,
        help=f"Model thinking level: LOW, MEDIUM, or HIGH (default: {DEFAULT_THINKING_LEVEL})",
    )
    parser.add_argument(
        "--notebooklm-url",
        default=os.getenv("AIRTELL_NOTEBOOKLM_URL", DEFAULT_NOTEBOOKLM_URL),
        help="URL of the AirTell NotebookLM Research Workspace",
    )
    parser.add_argument(
        "--notebooklm-context",
        help="Path to local Markdown file containing exported NotebookLM context/notes",
    )
    parser.add_argument(
        "--enforce-codeowners",
        action="store_true",
        help="Enforce that PR author and requester are designated repository codeowners",
    )
    parser.add_argument(
        "--verify-codeowners-only",
        action="store_true",
        help="Verify codeowner authorization and exit without running the AI code review",
    )
    parser.add_argument(
        "--pr-author",
        default=os.getenv("PR_AUTHOR"),
        help="GitHub username of the Pull Request author",
    )
    parser.add_argument(
        "--requester",
        default=os.getenv("REQUESTER"),
        help="GitHub username of the user requesting the code review",
    )
    return parser


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent.parent.parent
    if not (project_root / ".github").exists():
        project_root = Path.cwd()

    skills_dir = project_root / ".github" / "skills"
    if not skills_dir.exists():
        print(f"Error: Skills directory not found at {skills_dir}", file=sys.stderr)
        sys.exit(1)

    # Enforce codeowner authorization if requested
    if args.enforce_codeowners or args.verify_codeowners_only:
        authorized, reason = verify_codeowner_authorization(
            project_root=project_root,
            requester=args.requester,
            pr_author=args.pr_author,
        )
        if not authorized:
            print(f"❌ Authorization Denied: {reason}", file=sys.stderr)
            if args.post_comment and args.pr_number and args.repo and args.token:
                comment = (
                    f"> ⚠️ **AirTell Code Review Policy Violation**\n"
                    f">\n"
                    f"> Automated code reviews are strictly enforced for PRs created by repository codeowners "
                    f"and must be requested by a codeowner.\n"
                    f">\n"
                    f"> **Detail**: {reason}"
                )
                post_github_pr_comment(comment, args.repo, args.pr_number, args.token)
            sys.exit(1)
        print(f"✅ Authorization Verified: {reason}")
        if args.verify_codeowners_only:
            sys.exit(0)

    diff = get_git_diff(base=args.base, head=args.head, staged=args.staged)
    if not diff:
        print("No git diff detected in the target range. Nothing to review.")
        sys.exit(0)

    changed_files = get_changed_files(base=args.base, head=args.head, staged=args.staged)
    print(f"Detected {len(changed_files)} changed file(s).")
    print(f"Connecting to AirTell Research NotebookLM: {args.notebooklm_url}")

    # Discover NotebookLM context file (CLI flag > docs/AirTell-PoPETs.md > none)
    context_file = None
    if args.notebooklm_context:
        context_file = Path(args.notebooklm_context)
    else:
        default_context = project_root / "docs" / "AirTell-PoPETs.md"
        if default_context.exists():
            context_file = default_context

    notebooklm_context_text = load_notebooklm_context(context_file)
    if context_file and notebooklm_context_text:
        print(f"Loaded local NotebookLM research index snapshot from {context_file}")

    print(f"Running Antigravity code review with Gemini 4 Argon (model={args.model}, Thinking = {args.thinking_level})...")
    review_content = asyncio.run(
        run_review(
            diff_text=diff,
            changed_files=changed_files,
            skills_dir=skills_dir,
            notebooklm_url=args.notebooklm_url,
            notebooklm_context=notebooklm_context_text,
            model=args.model,
            thinking_level=args.thinking_level,
        )
    )

    # Output to stdout
    print("\n" + "=" * 80)
    print(review_content)
    print("=" * 80 + "\n")

    # Write to output file if requested
    if args.output:
        Path(args.output).write_text(review_content, encoding="utf-8")
        print(f"Review saved to {args.output}")

    # Append to GitHub Actions step summary if available
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(review_content + "\n")

    # Post comment to PR if enabled
    if args.post_comment and args.pr_number and args.repo and args.token:
        post_github_pr_comment(review_content, args.repo, args.pr_number, args.token)


if __name__ == "__main__":
    main()
