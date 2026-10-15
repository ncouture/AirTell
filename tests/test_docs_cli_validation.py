"""Automated validation tests for repository documentation links and CLI code snippets.

This module validates:
1. Markdown Links Resolution: All local file links and anchor references in
   README.md, docs/CLI.md, and docs/index.md resolve to existing files or headings.
2. CLI Snippet Syntax: All `bluetooth-sniffle <subcommand> ...` commands extracted
   from README.md and docs/CLI.md parse cleanly against create_parser() with 0 errors.
3. Mock Execution Verification: Representative mock command examples from documentation
   execute via main() with expected exit codes.
"""

from __future__ import annotations

import csv
import re
import shlex
from pathlib import Path
from typing import List, Set, Tuple

import pytest

from airtell.cli import create_parser, main

REPO_ROOT = Path(__file__).resolve().parent.parent

VALID_DOC_PATHS = [
    "README.md",
    "docs/CLI.md",
    "docs/index.md",
]

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


def extract_markdown_links(file_path: Path) -> List[Tuple[str, str]]:
    """Extract all markdown links [text](target) from a markdown file."""
    content = file_path.read_text(encoding="utf-8")
    # Matches [anchor_text](target) while ignoring images ![alt](url)
    pattern = r"(?<!!)\[([^\]]*)\]\(([^)]+)\)"
    return re.findall(pattern, content)


def slugify_heading(heading: str) -> Set[str]:
    """Convert a markdown heading into possible GitHub-compatible anchor slugs."""
    clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading)  # strip links inside headings
    clean = clean.lower().strip()
    # Strip characters that GitHub strips (punctuation like :, +, &, (, ), etc.)
    github_chars = re.sub(r"[^\w\s-]", "", clean)
    # GitHub replaces each space with a hyphen
    slug_spaces = github_chars.replace(" ", "-")
    # Strip leading/trailing hyphens
    slug1 = slug_spaces.strip("-")
    # Also support normalized single hyphens
    slug2 = re.sub(r"-+", "-", slug1)
    return {slug1, slug2}


def extract_markdown_anchors(file_path: Path) -> Set[str]:
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


def extract_cli_commands(file_path: Path) -> List[str]:
    """Extract all executable bluetooth-sniffle commands from markdown files."""
    content = file_path.read_text(encoding="utf-8")
    commands: List[str] = []

    # 1. Extract from fenced code blocks
    lines = content.splitlines()
    in_code_block = False
    current_cmd: List[str] = []

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

    # 2. Extract from inline table backticks
    inline_pattern = r"`((?:bluetooth-sniffle|airtell)\s+[^`]+)`"
    for match in re.findall(inline_pattern, content):
        cleaned = match.strip()
        if cleaned not in commands:
            commands.append(cleaned)

    # 3. Filter for valid command snippets
    runnable_commands: List[str] = []
    for cmd in commands:
        # Skip BNF synopsis containing placeholder syntax [<|
        if any(char in cmd for char in ["[", "<", "(", "|"]):
            continue
        # Skip if starts with 'Usage:' or other labels
        if "Usage:" in cmd:
            continue

        tokens = shlex.split(cmd)
        if len(tokens) < 2:
            continue
        if tokens[1] not in VALID_COMMAND_PREFIXES:
            continue

        runnable_commands.append(cmd)

    return runnable_commands


class TestMarkdownLinks:
    """Verifies that all markdown links in documentation resolve properly."""

    @pytest.mark.parametrize("doc_rel_path", VALID_DOC_PATHS)
    def test_file_exists(self, doc_rel_path: str) -> None:
        doc_path = REPO_ROOT / doc_rel_path
        assert doc_path.exists(), f"Target documentation file does not exist: {doc_rel_path}"

    @pytest.mark.parametrize("doc_rel_path", VALID_DOC_PATHS)
    def test_local_file_links_resolve(self, doc_rel_path: str) -> None:
        doc_path = REPO_ROOT / doc_rel_path
        links = extract_markdown_links(doc_path)
        assert len(links) > 0, f"No links found in {doc_rel_path}"

        for anchor_text, target in links:
            # Skip external web URLs
            if target.startswith(("http://", "https://", "mailto:", "irc://", "ftp://")):
                continue

            # Strip internal anchor fragment if targeting another file (e.g. path/to/file#anchor)
            target_path_part = target.split("#")[0]
            if not target_path_part:
                # Pure in-page anchor link, handled in anchor test
                continue

            # Resolve relative to the markdown file's directory
            resolved_target = (doc_path.parent / target_path_part).resolve()
            assert resolved_target.exists(), (
                f"Broken link in {doc_rel_path}: [{anchor_text}]({target}) "
                f"resolves to non-existent path: {resolved_target}"
            )

    @pytest.mark.parametrize("doc_rel_path", VALID_DOC_PATHS)
    def test_internal_anchor_links_resolve(self, doc_rel_path: str) -> None:
        doc_path = REPO_ROOT / doc_rel_path
        links = extract_markdown_links(doc_path)
        valid_anchors = extract_markdown_anchors(doc_path)

        for anchor_text, target in links:
            if target.startswith("#"):
                anchor = target.lstrip("#")
                assert anchor in valid_anchors, (
                    f"Broken internal anchor in {doc_rel_path}: [{anchor_text}]({target}). "
                    f"Available anchors: {sorted(valid_anchors)}"
                )


class TestCliSnippetsSyntax:
    """Verifies that all CLI snippets in documentation parse against create_parser()."""

    @pytest.mark.parametrize("doc_rel_path", ["README.md", "docs/CLI.md"])
    def test_cli_snippets_parse_cleanly(self, doc_rel_path: str) -> None:
        doc_path = REPO_ROOT / doc_rel_path
        commands = extract_cli_commands(doc_path)
        if doc_rel_path == "README.md" and not commands:
            pytest.skip("README.md does not contain inline executable CLI commands")
        assert len(commands) > 0, f"No executable CLI commands extracted from {doc_rel_path}"

        parser = create_parser()

        for cmd_str in commands:
            tokens = shlex.split(cmd_str)
            assert tokens[0] in ("airtell", "bluetooth-sniffle"), f"Command does not start with airtell or bluetooth-sniffle: {cmd_str}"

            args = tokens[1:]
            try:
                parsed_args = parser.parse_args(args)
            except SystemExit as exc:
                pytest.fail(f"Failed to parse snippet from {doc_rel_path}: '{cmd_str}' -> Exit {exc.code}")

            assert parsed_args.command is not None or any(
                a in args for a in ["-h", "--help", "-v", "--verbose", "--version"]
            ), f"Snippet did not resolve to a subcommand or global option: '{cmd_str}'"


class TestDocsCliMockExecution:
    """Verifies that core mock-compatible CLI snippets from documentation execute cleanly."""

    def test_mock_simulate_execution(self, tmp_path: Path) -> None:
        pcap_path = str(tmp_path / "sim.pcap")
        json_path = str(tmp_path / "sim.json")
        csv_path = str(tmp_path / "sim.csv")
        code = main([
            "mock-simulate",
            "--duration-sec",
            "0.5",
            "--interval-ms",
            "50",
            "--pcap",
            pcap_path,
            "--json",
            json_path,
            "--csv",
            csv_path,
        ])
        assert code == 0
        assert Path(pcap_path).exists()
        assert Path(json_path).exists()
        assert Path(csv_path).exists()

        # 1. Verify CSV schema against expected canonical fields
        expected_fields = [
            "mac_address",
            "address_type",
            "packet_count",
            "rssi_min",
            "rssi_max",
            "rssi_avg",
            "first_seen_iso",
            "last_seen_iso",
            "duration_sec",
            "observed_names",
            "service_uuids",
            "beacon_types",
            "channels",
        ]
        with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            actual_header = next(reader)
            rows = list(reader)

        assert actual_header == expected_fields, (
            f"Generated CSV header does not match expected device telemetry schema:\n"
            f"Actual:   {actual_header}\n"
            f"Expected: {expected_fields}"
        )

        # 2. Verify CSV header strictly matches documentation in docs/CLI.md §6.3
        cli_doc_path = REPO_ROOT / "docs" / "CLI.md"
        assert cli_doc_path.exists(), "docs/CLI.md does not exist"
        doc_content = cli_doc_path.read_text(encoding="utf-8")
        match = re.search(
            r"### 6\.3 CSV Tabular Summary Schema.*?```csv\s*\n([^\n]+)",
            doc_content,
            re.DOTALL,
        )
        assert match is not None, "Could not find CSV code block under Section 6.3 in docs/CLI.md"
        doc_header = [col.strip() for col in match.group(1).split(",")]

        assert actual_header == doc_header, (
            f"CSV header in emitted artifact does not match documented schema in docs/CLI.md §6.3:\n"
            f"Emitted:    {actual_header}\n"
            f"Documented: {doc_header}"
        )

        # 3. Verify emitted CSV rows and field structure
        assert len(rows) >= 1, "Expected at least 1 device record in mock simulation CSV"
        for row in rows:
            assert len(row) == len(expected_fields), (
                f"Row column count mismatch: expected {len(expected_fields)}, got {len(row)}: {row}"
            )
            row_dict = dict(zip(actual_header, row))
            assert re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", row_dict["mac_address"]), (
                f"Malformed MAC address in CSV row: {row_dict['mac_address']}"
            )
            assert int(row_dict["packet_count"]) >= 1
            rssi_min = float(row_dict["rssi_min"])
            rssi_max = float(row_dict["rssi_max"])
            rssi_avg = float(row_dict["rssi_avg"])
            assert rssi_min <= rssi_max
            assert rssi_min <= rssi_avg <= rssi_max or abs(rssi_avg - rssi_min) < 1e-4
            assert float(row_dict["duration_sec"]) >= 0.0
            channels = row_dict["channels"].split(";")
            assert any(ch in ["37", "38", "39"] for ch in channels)

    def test_docs_csv_schema_matches_telemetry_fields(self) -> None:
        """Verify docs/CLI.md Section 6.3 CSV header strictly matches TelemetrySession device fields."""
        cli_doc_path = REPO_ROOT / "docs" / "CLI.md"
        doc_content = cli_doc_path.read_text(encoding="utf-8")
        match = re.search(
            r"### 6\.3 CSV Tabular Summary Schema.*?```csv\s*\n([^\n]+)",
            doc_content,
            re.DOTALL,
        )
        assert match is not None, "Could not find CSV code block under Section 6.3 in docs/CLI.md"
        doc_header = [col.strip() for col in match.group(1).split(",")]

        expected_fields = [
            "mac_address",
            "address_type",
            "packet_count",
            "rssi_min",
            "rssi_max",
            "rssi_avg",
            "first_seen_iso",
            "last_seen_iso",
            "duration_sec",
            "observed_names",
            "service_uuids",
            "beacon_types",
            "channels",
        ]
        assert doc_header == expected_fields, (
            f"Documented CSV header in docs/CLI.md §6.3 does not match TelemetrySession device fields:\n"
            f"Documented: {doc_header}\n"
            f"Expected:   {expected_fields}"
        )

    def test_sidechannel_mock_execution(self) -> None:
        # Returns 0 or 1 depending on whether side-channel findings were detected
        code = main(["sidechannel", "--mock", "--analyzer", "all"])
        assert code in (0, 1)

    def test_deanonymize_mock_execution(self) -> None:
        code = main(["deanonymize", "--mock", "--max-gap", "30.0", "--max-rssi-delta", "15.0"])
        assert code == 0

    def test_rogue_inject_mock_execution(self) -> None:
        code = main(["rogue-inject", "--mock", "--network", "Apple Find My", "--count", "2"])
        assert code == 0

    def test_relay_mock_execution(self) -> None:
        code = main(["relay", "--mock", "--duration-sec", "0.2"])
        assert code == 0

    def test_verify_hardware_mock_execution(self) -> None:
        code = main(["verify-hardware", "--mock", "--burst-duration-sec", "0.1", "--interval-ms", "50"])
        assert code == 0

    def test_topology_a_mock_execution(self) -> None:
        code = main(["topology-a", "--mock", "--burst-type", "ibeacon", "--duration-sec", "0.1"])
        assert code == 0

    def test_topology_b_mock_execution(self) -> None:
        code = main(["topology-b", "--mock", "--chan1", "37", "--chan2", "38", "--duration-sec", "0.1"])
        assert code == 0
