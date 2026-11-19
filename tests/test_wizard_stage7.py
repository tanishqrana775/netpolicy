"""Unit tests for Stage 7: CLI wiring, wizard subcommand, graphs, transcript, and replay."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from netpolicy.cli import app

runner = CliRunner()


def test_cli_help_shows_wizard_and_no_wizard() -> None:
    """Verify netpolicy --help includes the wizard subcommand and --no-wizard option."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "wizard" in result.output
    assert "--no-wizard" in result.output


def test_wizard_subcommand_help() -> None:
    """Verify netpolicy wizard --help displays description and options."""
    result = runner.invoke(app, ["wizard", "--help"])
    assert result.exit_code == 0
    assert "--graph" in result.output
    assert "--transcript" in result.output


def test_wizard_graph_mermaid() -> None:
    """Verify netpolicy wizard --graph mermaid emits stateDiagram-v2."""
    result = runner.invoke(app, ["wizard", "--graph", "mermaid"])
    assert result.exit_code == 0
    assert "stateDiagram-v2" in result.stdout
    assert "MAIN_MENU --> ASK_NETWORK_ENV" in result.stdout
    assert "ASK_NETWORK_ENV --> TARGET" in result.stdout


def test_wizard_graph_dot() -> None:
    """Verify netpolicy wizard --graph dot emits valid dot digraph."""
    result = runner.invoke(app, ["wizard", "--graph", "dot"])
    assert result.exit_code == 0
    assert "digraph WizardFSM {" in result.stdout
    assert "MAIN_MENU -> ASK_NETWORK_ENV" in result.stdout
    assert "ASK_NETWORK_ENV -> TARGET" in result.stdout


def test_wizard_graph_invalid_format() -> None:
    """Verify netpolicy wizard --graph unknown exits with code 2."""
    result = runner.invoke(app, ["wizard", "--graph", "xml"])
    assert result.exit_code == 2
    assert "Unknown graph format" in result.stderr or "Unknown graph format" in result.output


def test_wizard_subcommand_non_interactive_exits_2() -> None:
    """Verify netpolicy wizard fails with exit code 2 when run without an interactive TTY."""
    with (
        patch("sys.stdin.isatty", return_value=False),
        patch("sys.stderr.isatty", return_value=False),
    ):
        result = runner.invoke(app, ["wizard"])
        assert result.exit_code == 2
        err_msg = "requires an interactive terminal"
        assert err_msg in result.stderr or err_msg in result.output


def test_bare_netpolicy_non_interactive_prints_help() -> None:
    """Verify bare netpolicy in non-interactive environment prints help and exits 0."""
    with (
        patch("sys.stdin.isatty", return_value=False),
        patch("sys.stderr.isatty", return_value=False),
    ):
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Usage: " in result.output or "netpolicy" in result.output


def test_bare_netpolicy_interactive_suppressed_by_flag() -> None:
    """Verify bare netpolicy with --no-wizard prints help even if interactive."""
    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("sys.stderr.isatty", return_value=True),
    ):
        result = runner.invoke(app, ["--no-wizard", "--no-banner"])
        assert result.exit_code == 0
        assert "Usage: " in result.output or "netpolicy" in result.output


def test_bare_netpolicy_interactive_suppressed_by_env() -> None:
    """Verify bare netpolicy with NETPOLICY_NO_WIZARD=1 prints help."""
    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("sys.stderr.isatty", return_value=True),
    ):
        result = runner.invoke(app, ["--no-banner"], env={"NETPOLICY_NO_WIZARD": "1"})
        assert result.exit_code == 0
        assert "Usage: " in result.output or "netpolicy" in result.output
