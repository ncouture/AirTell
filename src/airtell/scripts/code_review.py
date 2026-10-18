#!/usr/bin/env python3
"""AirTell Automated Code Review Runner powered by Google Antigravity SDK.

Executes in-depth architectural and adversarial code reviews for AirTell BLE
testbed changes using Gemini 3.8 Flash with high thinking, grounded in the
AirTell Research NotebookLM Workspace (https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6)
and the domain-specific review skill (.github/skills/code-review/SKILL.md).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Optional

import google.antigravity as agy

DEFAULT_NOTEBOOKLM_URL = "https://notebook.google.com/notebook/26cd837a-4d66-4ab1-94c7-128105718ad6"


def get_git_diff(base: Optional[str] = None, head: Optional[str] = None, staged: bool = False) -> str:
    """Retrieve git diff for the target revision range or staged changes."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--cached")
    elif base and head:
        cmd.append(f"{base}...{head}")
    elif base:
        cmd.append(base)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"Error computing git diff: {result.stderr}", file=sys.stderr)
        return ""
    return result.stdout.strip()


def get_changed_files(base: Optional[str] = None, head: Optional[str] = None, staged: bool = False) -> list[str]:
    """Retrieve list of modified filenames."""
    cmd = ["git", "diff", "--name-only"]
    if staged:
        cmd.append("--cached")
    elif base and head:
        cmd.append(f"{base}...{head}")
    elif base:
        cmd.append(base)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]


def load_notebooklm_context(context_path: Optional[Path]) -> str:
    """Load local synchronized snapshot of the NotebookLM research workspace if present."""
    if context_path and context_path.exists():
        try:
            content = context_path.read_text(encoding="utf-8")
            # Truncate to a reasonable summary if excessively large
            if len(content) > 15000:
                return content[:15000] + "\n\n[... NotebookLM context truncated for prompt budget ...]"
            return content
        except Exception as e:
            print(f"Warning: Failed to read NotebookLM context file {context_path}: {e}", file=sys.stderr)
    return ""


async def run_review(
    diff_text: str,
    changed_files: list[str],
    skills_dir: Path,
    notebooklm_url: str = DEFAULT_NOTEBOOKLM_URL,
    notebooklm_context: str = "",
) -> str:
    """Run code review agent using Google Antigravity SDK with NotebookLM grounding."""
    endpoint = agy.GeminiAPIEndpoint(
        options=agy.GeminiModelOptions(thinking_level=agy.ThinkingLevel.HIGH)
    )

    capabilities = agy.CapabilitiesConfig(
        enabled_tools=[
            agy.BuiltinTools.READ_URL_CONTENT,
            agy.BuiltinTools.SEARCH_WEB,
            agy.BuiltinTools.VIEW_FILE,
        ]
    )

    config = agy.LocalAgentConfig(
        model="gemini-3.8-flash",
        models=[agy.ModelTarget(name="gemini-3.8-flash", endpoint=endpoint)],
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
    except Exception as exc:
        print(f"Error posting GitHub comment: {exc}", file=sys.stderr)
        return False


def main() -> None:
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
        "--notebooklm-url",
        default=os.getenv("AIRTELL_NOTEBOOKLM_URL", DEFAULT_NOTEBOOKLM_URL),
        help="URL of the AirTell NotebookLM Research Workspace",
    )
    parser.add_argument(
        "--notebooklm-context",
        help="Path to local Markdown file containing exported NotebookLM context/notes",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent.parent
    if not (project_root / ".github").exists():
        project_root = Path.cwd()

    skills_dir = project_root / ".github" / "skills"
    if not skills_dir.exists():
        print(f"Error: Skills directory not found at {skills_dir}", file=sys.stderr)
        sys.exit(1)

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

    print("Running Antigravity code review with Gemini 3.8 Flash (Thinking = High)...")
    review_content = asyncio.run(
        run_review(
            diff_text=diff,
            changed_files=changed_files,
            skills_dir=skills_dir,
            notebooklm_url=args.notebooklm_url,
            notebooklm_context=notebooklm_context_text,
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
