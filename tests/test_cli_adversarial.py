"""CLI and dashboard view tests for adversarial relay, deanonymization, and rogue beacon injection."""

from __future__ import annotations

import pytest

from bluetooth_sniffle.cli import main


def test_cli_relay_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify relay subcommand exists in CLI parser."""
    rc = main(["relay", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "relay" in captured.out.lower()
    assert "--port1" in captured.out
    assert "--port2" in captured.out


def test_cli_deanonymize_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify deanonymize subcommand exists in CLI parser."""
    rc = main(["deanonymize", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "deanonymize" in captured.out.lower()


def test_cli_rogue_inject_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify rogue-inject subcommand exists in CLI parser."""
    rc = main(["rogue-inject", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "rogue-inject" in captured.out.lower()
    assert "--network" in captured.out


def test_cli_rogue_inject_mock_execution(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify mock execution of rogue beacon injection burst."""
    rc = main(["rogue-inject", "--mock", "--count", "3", "--network", "Apple Find My"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Injected 3" in captured.out or "Generated 3" in captured.out


def test_cli_deanonymize_mock_execution(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify mock execution of deanonymization analysis on synthetic traces."""
    rc = main(["deanonymize", "--mock"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Deanonymization" in captured.out or "Linkability" in captured.out
