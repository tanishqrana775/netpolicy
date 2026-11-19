"""Tests for netpolicy CLI interface."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from netpolicy import __version__
from netpolicy.cli import app
from netpolicy.engine.runner import RunnerResult
from netpolicy.models import Observation, Target

runner = CliRunner()


def test_cli_help() -> None:
    """Verify root command returns help text and exit code 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "CLI network policy auditor" in result.output
    assert "audit" in result.output
    assert "ports" in result.output
    assert "dns" in result.output
    assert "http" in result.output
    assert "compare" in result.output
    assert "lab" in result.output
    assert "reclassify" in result.output


def test_cli_version() -> None:
    """Verify global --version flag prints the current package version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"netpolicy version {__version__}" in result.output


def test_audit_help() -> None:
    """Verify audit subcommand --help output."""
    result = runner.invoke(app, ["audit", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output
    assert "--ports" in result.output
    assert "--runs" in result.output
    assert "--timeout" in result.output
    assert "--retries" in result.output
    assert "--mode" in result.output
    assert "--demo" in result.output


def test_ports_help() -> None:
    """Verify ports subcommand --help output."""
    result = runner.invoke(app, ["ports", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output
    assert "--mode" in result.output


def test_dns_help() -> None:
    """Verify dns subcommand --help output."""
    result = runner.invoke(app, ["dns", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output


def test_http_help() -> None:
    """Verify http subcommand --help output."""
    result = runner.invoke(app, ["http", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output


def test_compare_help() -> None:
    """Verify compare subcommand --help output."""
    result = runner.invoke(app, ["compare", "--help"])
    assert result.exit_code == 0
    assert "Usage: netpolicy compare" in result.output


def test_lab_stub() -> None:
    """Verify lab subcommand prints the expected stub text."""
    result = runner.invoke(app, ["lab"])
    assert result.exit_code == 0
    assert "not implemented yet" in result.output


def test_compare_missing_file_exits_2() -> None:
    """Verify compare subcommand with non-existent files exits with code 2."""
    result = runner.invoke(app, ["compare", "nonexistent_a.json", "nonexistent_b.json"])
    assert result.exit_code == 2
    assert "File Error:" in result.output


@patch("netpolicy.cli.Runner.run")
def test_ports_table_output(mock_run: MagicMock) -> None:
    """Verify ports command parses options and outputs a Rich configuration table."""
    mock_run.return_value = RunnerResult(
        all_observations=[],
        control_healthy=True,
        run_id="test-run-123",
    )
    result = runner.invoke(
        app,
        ["ports", "--target", "probe.example.com", "--runs", "3", "--timeout", "2.0"],
    )
    assert result.exit_code == 0
    assert "netpolicy: PORTS configuration" in result.output
    assert "probe.example.com" in result.output
    assert "Runs" in result.output
    assert "3" in result.output


def test_audit_demo_mode() -> None:
    """Verify audit in --demo mode renders the terminal audit report and exits 1 on findings."""
    result = runner.invoke(app, ["audit", "--demo", "--no-color"])
    assert result.exit_code == 1
    assert "RESTRICTED" in result.output
    assert "WHAT WE FOUND" in result.output
    assert "WHAT YOU CAN DO" in result.output


def test_ports_missing_target_exits_2() -> None:
    """Verify ports command without target or demo exits with code 2."""
    result = runner.invoke(app, ["ports"])
    assert result.exit_code == 2
    assert "Error:" in result.output


def test_reclassify_help() -> None:
    """Verify reclassify subcommand --help output."""
    result = runner.invoke(app, ["reclassify", "--help"])
    assert result.exit_code == 0
    assert "reclassify" in result.output
    assert "run_id" in result.output.lower()


def test_reclassify_missing_file_exits_2() -> None:
    """Verify reclassify on missing file exits with code 2."""
    result = runner.invoke(app, ["reclassify", "nonexistent_9999.jsonl"])
    assert result.exit_code == 2
    assert "Error:" in result.output


def test_reclassify_success(tmp_path: Path) -> None:
    """Verify reclassify loads .jsonl, executes classifiers, and produces clean report."""
    run_file = tmp_path / "test_run.jsonl"
    obs = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=True,
        raw={"outcome": "connected", "errno_name": None, "elapsed_ms": 12.0},
    )
    record = {
        "run_id": "test_run",
        "timestamp": 1700000000.0,
        "probe_name": "tcp_connect",
        "observation": obs.model_dump(mode="json"),
    }
    run_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["reclassify", str(run_file), "--no-color"])
    assert result.exit_code == 0
    assert "CLEAN" in result.output
    assert "No unexpected blocks" in result.output


def test_reclassify_findings(tmp_path: Path) -> None:
    """Verify reclassify detects findings and exits with code 1."""
    run_file = tmp_path / "blocked_run.jsonl"
    obs = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=25, service="SMTP"),
        success=False,
        raw={"outcome": "refused", "errno_name": "ECONNREFUSED"},
    )
    record = {
        "run_id": "blocked_run",
        "timestamp": 1700000000.0,
        "probe_name": "tcp_connect",
        "observation": obs.model_dump(mode="json"),
    }
    run_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["reclassify", str(run_file), "--no-color"])
    assert result.exit_code == 1
    assert "25" in result.output and "mail" in result.output.lower()


def test_python_m_netpolicy_version() -> None:
    """Verify sys.executable -m netpolicy --version works via subprocess."""
    proc = subprocess.run(
        [sys.executable, "-m", "netpolicy", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "netpolicy version" in proc.stdout


def test_compare_with_jsonl_runs(tmp_path: Path) -> None:
    """Verify compare subcommand accepts .jsonl runs and reclassifies on the fly."""
    run_a = tmp_path / "run_a.jsonl"
    run_b = tmp_path / "run_b.jsonl"
    run_c = tmp_path / "run_c.jsonl"

    obs_open = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=True,
        raw={"outcome": "connected", "elapsed_ms": 15.0},
    )
    rec_open = {
        "run_id": "run_a",
        "timestamp": 1700000000.0,
        "probe_name": "tcp_connect",
        "observation": obs_open.model_dump(mode="json"),
    }
    run_a.write_text(json.dumps(rec_open) + "\n", encoding="utf-8")
    run_b.write_text(json.dumps(rec_open) + "\n", encoding="utf-8")

    # Identical runs should exit 0
    res_identical = runner.invoke(app, ["compare", str(run_a), str(run_b)])
    assert res_identical.exit_code == 0
    assert "No policy changes detected" in res_identical.output

    # Different run should exit 1
    obs_blocked = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=False,
        raw={"outcome": "timeout", "elapsed_ms": 3000.0},
    )
    rec_blocked = {
        "run_id": "run_c",
        "timestamp": 1700000000.0,
        "probe_name": "tcp_connect",
        "observation": obs_blocked.model_dump(mode="json"),
    }
    run_c.write_text(json.dumps(rec_blocked) + "\n", encoding="utf-8")

    res_diff = runner.invoke(app, ["compare", str(run_a), str(run_c)])
    assert res_diff.exit_code == 1
    assert "POLICY CHANGES DETECTED" in res_diff.output


def test_compare_mixed_json_and_jsonl(tmp_path: Path) -> None:
    """Verify compare works with mixed .json report and .jsonl run."""
    from netpolicy.demo import build_demo_report
    from netpolicy.report.jsonout import generate_json_report

    rep = build_demo_report()
    json_path = tmp_path / "baseline.json"
    generate_json_report(rep, output_path=json_path)

    run_path = tmp_path / "run.jsonl"
    obs = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=True,
        raw={"outcome": "connected", "elapsed_ms": 10.0},
    )
    record = {
        "run_id": "mixed_test",
        "timestamp": 1700000000.0,
        "probe_name": "tcp_connect",
        "observation": obs.model_dump(mode="json"),
    }
    run_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    res = runner.invoke(app, ["compare", str(json_path), str(run_path)])
    # The reports differ in port results, so exit code should be 1
    assert res.exit_code == 1
    assert "POLICY CHANGES DETECTED" in res.output


def test_compare_invalid_file_helpful_error(tmp_path: Path) -> None:
    """Verify compare with invalid or unparseable files shows helpful guidance and exits 2."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("this is completely invalid json and not jsonl either\n", encoding="utf-8")

    valid_run = tmp_path / "valid.jsonl"
    obs = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=True,
        raw={"outcome": "connected"},
    )
    valid_run.write_text(
        json.dumps(
            {
                "run_id": "v",
                "timestamp": 1.0,
                "probe_name": "tcp_connect",
                "observation": obs.model_dump(mode="json"),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["compare", str(bad_file), str(valid_run)])
    assert res.exit_code == 2
    assert "Invalid or unparseable report file" in res.output
    assert "netpolicy audit --output baseline.json" in res.output
    assert "netpolicy audit --json > baseline.json" in res.output
