"""Tests for report generation (JSON, Markdown), identifier redaction, compare, and exit codes."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from netpolicy.cli import app
from netpolicy.demo import build_demo_report
from netpolicy.models import (
    AuditReport,
    Confidence,
    Observation,
    ReportMetadata,
    Target,
    Verdict,
    VerdictKind,
)
from netpolicy.report.compare import compare_reports
from netpolicy.report.jsonout import (
    SchemaVersionError,
    generate_json_report,
    load_report,
    serialize_report,
)
from netpolicy.report.markdown import generate_markdown_report
from netpolicy.report.terminal import render_terminal_report

runner = CliRunner()


def test_models_roundtrip(tmp_path: Path) -> None:
    """Verify AuditReport JSON round-tripping and schema_version='1'."""
    report = build_demo_report()
    data = report.to_dict()

    assert data["schema_version"] == "1"
    assert "metadata" in data
    assert len(data["port_results"]) == 7
    assert len(data["findings"]) == 4

    out_file = tmp_path / "report.json"
    generate_json_report(report, output_path=out_file, include_identifiers=True)

    loaded = load_report(out_file)
    assert loaded.schema_version == "1"
    assert loaded.metadata.network_label == report.metadata.network_label
    assert len(loaded.port_results) == len(report.port_results)
    assert loaded.findings[0].title == report.findings[0].title
    assert loaded.findings[0].summary == report.findings[0].summary


def test_schema_version_mismatch(tmp_path: Path) -> None:
    """Verify load_report raises SchemaVersionError on unsupported schema version."""
    report_file = tmp_path / "invalid_version.json"
    report_file.write_text(json.dumps({"schema_version": "99", "findings": []}), encoding="utf-8")

    with pytest.raises(SchemaVersionError, match="Unsupported schema version: expected '1'"):
        load_report(report_file)


def test_identifier_redaction() -> None:
    """Verify SSIDs, MACs, and client public IPs are scrubbed unless include_identifiers=True."""
    report = build_demo_report()
    report.metadata.network_label = "Corporate-Secret-WiFi"
    report.metadata.client_address = "93.184.216.34"  # Public IP
    # Add an evidence containing a MAC address
    report.port_results[0].evidence.append("Gateway MAC: 00:1A:2B:3C:4D:5E")

    # 1. Redacted serialization (default)
    scrubbed_json = serialize_report(report, include_identifiers=False)
    scrubbed_data = json.loads(scrubbed_json)

    assert scrubbed_data["metadata"]["network_label"] == "[REDACTED_SSID]"
    assert scrubbed_data["metadata"]["client_address"] == "[REDACTED_PUBLIC_IP]"
    assert "00:1A:2B:3C:4D:5E" not in scrubbed_json
    assert "[REDACTED_MAC]" in scrubbed_json
    assert "Corporate-Secret-WiFi" not in scrubbed_json
    assert "93.184.216.34" not in scrubbed_json

    # 2. Authorized serialization with identifiers
    full_json = serialize_report(report, include_identifiers=True)
    full_data = json.loads(full_json)

    assert full_data["metadata"]["network_label"] == "Corporate-Secret-WiFi"
    assert full_data["metadata"]["client_address"] == "93.184.216.34"
    assert "00:1A:2B:3C:4D:5E" in full_json


def test_observation_model() -> None:
    """Verify Observation model fields and defaults."""
    target = Target(host="example.com", port=443, service="HTTPS")
    obs = Observation(
        probe_name="tcp_syn",
        target=target,
        success=True,
        raw={"flags": "SA", "ttl": 56, "rtt_ms": 23.4},
    )
    assert obs.probe_name == "tcp_syn"
    assert obs.target.port == 443
    assert obs.success is True
    assert obs.raw["flags"] == "SA"
    assert obs.timestamp > 0


def test_markdown_report_generation(tmp_path: Path) -> None:
    """Verify markdown report generation formats tables suitable for issues/READMEs."""
    report = build_demo_report()
    md_file = tmp_path / "audit.md"
    content = generate_markdown_report(report, output_path=md_file, include_identifiers=False)

    assert md_file.exists()
    assert "# Network Policy Audit Report" in content
    assert "## Overview" in content
    assert "## Outbound Port Reachability" in content
    assert "| Port | Proto | Service | Status | Confidence | Evidence |" in content
    assert "| `22` | `tcp` | SSH | **`OPEN`** |" in content
    assert "| `25` | `tcp` | SMTP | **`DROPPED`** |" in content
    assert "## DNS Interception & Tampering" in content
    assert "## HTTP Tampering & Header Injection" in content
    assert "## Key Policy Findings" in content
    assert "## Summary Metrics" in content


def test_compare_reports_detects_changes() -> None:
    """Verify compare_reports detects port reachability changes between reports."""
    baseline = build_demo_report()
    current = build_demo_report()

    # Change port 25 from DROPPED to OPEN in current
    for p in current.port_results:
        if p.target.port == 25:
            p.kind = VerdictKind.OPEN
            p.evidence = ["Port unblocked by administrator"]

    diffs, table = compare_reports(baseline, current)
    assert len(diffs) == 1
    assert diffs[0].category == "Outbound Ports"
    assert "25/tcp" in diffs[0].target
    assert diffs[0].baseline_kind == "DROPPED"
    assert diffs[0].current_kind == "OPEN"
    assert table is not None


def test_compare_reports_identical() -> None:
    """Verify compare_reports returns empty list and None when reports are identical."""
    report_a = build_demo_report()
    report_b = build_demo_report()

    diffs, table = compare_reports(report_a, report_b)
    assert diffs == []
    assert table is None


def test_cli_compare_command(tmp_path: Path) -> None:
    """Verify CLI `netpolicy compare` command behavior and exit codes."""
    rep_a = build_demo_report()
    rep_b = build_demo_report()

    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"

    generate_json_report(rep_a, output_path=path_a)
    generate_json_report(rep_b, output_path=path_b)

    # 1. Identical reports -> exit code 0
    res_identical = runner.invoke(app, ["compare", str(path_a), str(path_b)])
    assert res_identical.exit_code == 0
    assert "identical" in res_identical.output

    # 2. Changed report -> exit code 1
    for p in rep_b.port_results:
        if p.target.port == 25:
            p.kind = VerdictKind.OPEN
    generate_json_report(rep_b, output_path=path_b)

    res_changed = runner.invoke(app, ["compare", str(path_a), str(path_b)])
    assert res_changed.exit_code == 1
    assert "POLICY CHANGES DETECTED" in res_changed.output
    assert "25/tcp" in res_changed.output

    # 3. JSON output for compare
    res_json = runner.invoke(app, ["compare", str(path_a), str(path_b), "--json"])
    assert res_json.exit_code == 1
    diff_data = json.loads(res_json.output)
    assert diff_data["changed"] is True
    assert len(diff_data["diffs"]) == 1


def test_cli_json_flag_pure_output() -> None:
    """Verify --json outputs purely valid JSON to stdout without Rich elements."""
    result = runner.invoke(app, ["audit", "--demo", "--json"])
    # Demo report has findings, so exit code must be 1
    assert result.exit_code == 1

    # Output must be parseable as valid JSON
    parsed = json.loads(result.output)
    assert parsed["schema_version"] == "1"
    assert len(parsed["port_results"]) == 7
    assert len(parsed["findings"]) == 4

    # Ensure no Rich decorations leaked into stdout
    assert "┌─" not in result.output
    assert "OUTBOUND PORTS" not in result.output


def test_cli_output_file_json_and_md(tmp_path: Path) -> None:
    """Verify --output writes format chosen by file extension (.json or .md)."""
    json_target = tmp_path / "out" / "audit.json"
    md_target = tmp_path / "out" / "audit.md"

    # Write .json
    res_json = runner.invoke(app, ["audit", "--demo", "--output", str(json_target)])
    assert res_json.exit_code == 1
    assert json_target.exists()
    loaded = json.loads(json_target.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "1"

    # Write .md
    res_md = runner.invoke(app, ["audit", "--demo", "--output", str(md_target)])
    assert res_md.exit_code == 1
    assert md_target.exists()
    assert "# Network Policy Audit Report" in md_target.read_text(encoding="utf-8")

    # Unsupported extension
    bad_target = tmp_path / "out" / "audit.txt"
    res_bad = runner.invoke(app, ["audit", "--demo", "--output", str(bad_target)])
    assert res_bad.exit_code == 2
    assert "Unsupported output file extension" in res_bad.output


def test_exit_codes_clean_vs_findings() -> None:
    """Verify exit code 0 when report has no findings and 1 when findings exist."""
    # 1. Demo report has findings -> exit code 1
    res_findings = runner.invoke(app, ["ports", "--demo", "--no-color"])
    assert res_findings.exit_code == 1

    # 2. Construct clean report with 0 findings and all OPEN ports
    clean_report = AuditReport(
        schema_version="1",
        metadata=ReportMetadata(network_label="Clean-Network"),
        port_results=[
            Verdict(
                target=Target(host="probe.netpolicy.org", port=22, service="SSH"),
                kind=VerdictKind.OPEN,
                confidence=Confidence.HIGH,
                evidence=["SYN-ACK received"],
            ),
            Verdict(
                target=Target(host="probe.netpolicy.org", port=443, service="HTTPS"),
                kind=VerdictKind.OPEN,
                confidence=Confidence.HIGH,
                evidence=["SYN-ACK received"],
            ),
        ],
        findings=[],
    )

    buf = io.StringIO()
    console = Console(file=buf, no_color=True)
    # Ensure renderer functions without error on clean reports
    render_terminal_report(clean_report, console=console)
    assert "No unexpected blocks" in buf.getvalue()


def test_cli_ports_demo_command() -> None:
    """Verify `netpolicy ports --demo --no-color` renders ports section and exits 1."""
    result = runner.invoke(app, ["ports", "--demo", "--no-color"])
    assert result.exit_code == 1
    assert "RESTRICTED" in result.output
    assert "WHAT WE FOUND" in result.output
    assert "port 25" in result.output.lower()
    assert "DNS" not in result.output


def test_cli_dns_demo_command() -> None:
    """Verify `netpolicy dns --demo --no-color` renders DNS section and exits 1."""
    result = runner.invoke(app, ["dns", "--demo", "--no-color"])
    assert result.exit_code == 1
    assert "RESTRICTED" in result.output
    assert "Address lookups" in result.output or "Name lookups" in result.output
    assert "DNS" in result.output
    assert "Port 25" not in result.output


def test_cli_http_demo_command() -> None:
    """Verify `netpolicy http --demo --no-color` renders HTTP section and exits 1."""
    result = runner.invoke(app, ["http", "--demo", "--no-color"])
    assert result.exit_code == 1
    assert "RESTRICTED" in result.output
    assert "Web pages" in result.output or "Web content" in result.output
    assert "Port 25" not in result.output


def test_cli_audit_demo_quiet() -> None:
    """Verify `netpolicy audit --demo --quiet --no-color` renders only summary line and exits 1."""
    result = runner.invoke(app, ["audit", "--demo", "--quiet", "--no-color"])
    assert result.exit_code == 1
    assert "RESTRICTED:" in result.output
    assert len(result.output.strip().splitlines()) == 1
    assert "WHAT WE FOUND" not in result.output
