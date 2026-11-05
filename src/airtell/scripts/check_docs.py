#!/usr/bin/env python3
"""Automated documentation link and CLI snippet syntax validator.

Validates:
1. Relative markdown file links and internal header anchors across README.md and docs/*.md.
2. CLI snippet syntax against airtell.cli.create_parser().
"""

from __future__ import annotations

import contextlib
import io
import re
import shlex
import sys
from pathlib import Path


def find_repo_root() -> Path:
    """Find repository root by walking up to pyproject.toml."""
    curr = Path(__file__).resolve().parent
    for p in [curr] + list(curr.parents):
        if (p / "pyproject.toml").exists():
            return p
    return Path.cwd()


REPO_ROOT = find_repo_root()
sys.path.insert(0, str(REPO_ROOT / "src"))

try:
    from airtell.cli import create_parser
except ImportError as e:
    print(f"Error importing airtell.cli: {e}", file=sys.stderr)
    sys.exit(1)

VALID_COMMAND_PREFIXES = {
    "sidechannel",
    "side-channel",
    "analyze-sidechannel",
    "topology-a",
    "run-topology-a",
    "topology-b",
    "run-topology-b",
    "mock-simulate",
    "mock-test",
    "verify-hardware",
    "relay",
    "deanonymize",
    "rogue-inject",
    "-h",
    "--help",
    "-v",
    "--verbose",
    "--version",
}


def extract_markdown_links(file_path: Path) -> list[tuple[str, str]]:
    """Extract all markdown links [text](target) from a markdown file."""
    content = file_path.read_text(encoding="utf-8")
    pattern = r"(?<!!)\[([^\]]*)\]\(([^)]+)\)"
    return re.findall(pattern, content)


def slugify_heading(heading: str) -> set[str]:
    """Convert a markdown heading into possible GitHub-compatible anchor slugs."""
    clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading)
    clean = clean.lower().strip()
    github_chars = re.sub(r"[^\w\s-]", "", clean)
    slug_spaces = github_chars.replace(" ", "-")
    slug1 = slug_spaces.strip("-")
    slug2 = re.sub(r"-+", "-", slug1)
    return {slug1, slug2}


def extract_markdown_anchors(file_path: Path) -> set[str]:
    """Extract all heading anchor slugs from a markdown file."""
    content = file_path.read_text(encoding="utf-8")
    anchors = set()
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            heading_text = line.lstrip("#").strip()
            if heading_text:
                anchors.update(slugify_heading(heading_text))
    return anchors


def extract_cli_commands(file_path: Path) -> list[str]:
    """Extract all executable bluetooth-sniffle commands from markdown files."""
    content = file_path.read_text(encoding="utf-8")
    commands: list[str] = []

    lines = content.splitlines()
    in_code_block = False
    current_cmd: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            if not in_code_block and current_cmd:
                commands.append(" ".join(current_cmd))
                current_cmd = []
            continue

        if in_code_block:
            if stripped.startswith("$ bluetooth-sniffle "):
                stripped = stripped[2:].strip()
            elif stripped.startswith("$ airtell "):
                stripped = stripped[2:].strip()
            elif stripped.startswith("uv run bluetooth-sniffle "):
                stripped = stripped[len("uv run "):].strip()
            elif stripped.startswith("uv run airtell "):
                stripped = stripped[len("uv run "):].strip()
            elif stripped.startswith("$ uv run bluetooth-sniffle "):
                stripped = stripped[len("$ uv run "):].strip()
            elif stripped.startswith("$ uv run airtell "):
                stripped = stripped[len("$ uv run "):].strip()

            if stripped.startswith("bluetooth-sniffle ") or stripped.startswith("airtell "):
                if current_cmd:
                    commands.append(" ".join(current_cmd))
                    current_cmd = []
                cleaned = stripped.split("#")[0].rstrip()
                if cleaned.endswith("\\"):
                    current_cmd.append(cleaned[:-1].strip())
                else:
                    commands.append(cleaned)
            elif current_cmd:
                cleaned = stripped.split("#")[0].rstrip()
                if cleaned.endswith("\\"):
                    current_cmd.append(cleaned[:-1].strip())
                else:
                    current_cmd.append(cleaned)
                    commands.append(" ".join(current_cmd))
                    current_cmd = []

    if current_cmd:
        commands.append(" ".join(current_cmd))

    inline_pattern = r"`((?:bluetooth-sniffle|airtell)\s+[^`]+)`"
    for match in re.findall(inline_pattern, content):
        cleaned = match.strip()
        if cleaned not in commands:
            commands.append(cleaned)

    runnable_commands: list[str] = []
    for cmd in commands:
        if any(char in cmd for char in ["[", "<", "(", "|"]):
            continue
        if "Usage:" in cmd:
            continue
        tokens = shlex.split(cmd)
        if len(tokens) < 2:
            continue
        if tokens[1] not in VALID_COMMAND_PREFIXES:
            continue
        runnable_commands.append(cmd)

    return runnable_commands


def main() -> int:
    """Validate documentation links and CLI snippets."""
    errors = 0
    doc_files = [REPO_ROOT / "README.md"]
    if (REPO_ROOT / "CONTRIBUTE.md").exists():
        doc_files.append(REPO_ROOT / "CONTRIBUTE.md")
    doc_files.extend(sorted((REPO_ROOT / "docs").glob("*.md")))

    print(f"Validating {len(doc_files)} documentation files...")

    # Cache anchors for each doc
    anchors_map: dict[Path, set[str]] = {}
    for doc in doc_files:
        anchors_map[doc] = extract_markdown_anchors(doc)

    for doc in doc_files:
        rel_path = doc.relative_to(REPO_ROOT)
        links = extract_markdown_links(doc)

        for text, target in links:
            if target.startswith(("http://", "https://", "mailto:", "irc://", "ftp://")):
                continue

            # Internal anchor link within same document
            if target.startswith("#"):
                anchor = target.lstrip("#")
                if anchor not in anchors_map[doc]:
                    print(f"ERROR: {rel_path}: Broken internal anchor [{text}]({target})", file=sys.stderr)
                    errors += 1
                continue

            # Target is a file, possibly with #anchor
            target_parts = target.split("#", 1)
            target_file_str = target_parts[0]
            target_anchor = target_parts[1] if len(target_parts) > 1 else None

            resolved = (doc.parent / target_file_str).resolve()
            if not resolved.exists():
                print(f"ERROR: {rel_path}: Broken link [{text}]({target}) -> {resolved}", file=sys.stderr)
                errors += 1
                continue

            # If anchor is present in another markdown file
            if target_anchor and resolved.suffix == ".md":
                if resolved not in anchors_map:
                    anchors_map[resolved] = extract_markdown_anchors(resolved)
                if target_anchor not in anchors_map[resolved]:
                    print(
                        f"ERROR: {rel_path}: Broken anchor in target [{text}]({target}) in {resolved}",
                        file=sys.stderr,
                    )
                    errors += 1

    # Validate CLI snippet syntax
    parser = create_parser()
    cli_docs = [REPO_ROOT / "README.md", REPO_ROOT / "docs" / "CLI.md"]
    if (REPO_ROOT / "CONTRIBUTE.md").exists():
        cli_docs.append(REPO_ROOT / "CONTRIBUTE.md")
    for doc in cli_docs:
        rel_path = doc.relative_to(REPO_ROOT)
        commands = extract_cli_commands(doc)
        for cmd_str in commands:
            tokens = shlex.split(cmd_str)
            args = tokens[1:]
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    parser.parse_args(args)
            except SystemExit as exc:
                if exc.code == 0 and any(a in args for a in ["-h", "--help", "-v", "--verbose", "--version"]):
                    continue
                print(f"ERROR: {rel_path}: Invalid CLI syntax: '{cmd_str}' -> Exit {exc.code}", file=sys.stderr)
                errors += 1

    if errors == 0:
        print("✓ All documentation links and CLI snippets validated successfully!")
        return 0
    else:
        print(f"✗ Validation failed with {errors} errors.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
