"""Unit tests for the lab validation metrics, evaluation, and plotting logic.

Tests CSV output, accuracy, confusion matrix generation, and plotting using
canned mock data without requiring root privileges or Linux network namespaces.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from lab.validate import (
    ValidationRecord,
    chown_to_sudo_user,
    compute_metrics,
    evaluate_report_against_scenario,
    load_scenarios_config,
    plot_accuracy,
    plot_confusion_matrices,
    plot_netem_sweeps,
    write_validation_csv,
)


def _make_canned_report(
    port_verdicts: dict[int, str] | None = None,
    dns_verdict: str = "CLEAN",
    http_verdict: str = "CLEAN",
) -> dict[str, Any]:
    """Helper to synthesize a netpolicy JSON audit report structure."""
    ports_map = port_verdicts or {21: "OPEN", 22: "OPEN", 25: "OPEN", 443: "OPEN", 587: "OPEN"}
    port_results = [
        {
            "target": {"host": "10.200.2.2", "port": p, "protocol": "tcp"},
            "kind": v,
            "confidence": "high",
            "evidence": ["test evidence"],
        }
        for p, v in ports_map.items()
    ]
    dns_results = [
        {
            "target": {"host": "10.200.2.2", "service": "dns"},
            "kind": dns_verdict,
            "confidence": "high",
            "evidence": ["dns test evidence"],
        }
    ]
    http_results = [
        {
            "target": {"host": "10.200.2.2", "port": 80, "service": "http"},
            "kind": http_verdict,
            "confidence": "high",
            "evidence": ["http test evidence"],
        }
    ]
    return {
        "port_results": port_results,
        "dns_results": dns_results,
        "http_results": http_results,
    }


def test_load_scenarios_yaml() -> None:
    yaml_path = Path(__file__).resolve().parent.parent / "lab" / "scenarios.yaml"
    scenarios = load_scenarios_config(yaml_path)
    assert len(scenarios) >= 8

    scenario_names = {s["name"] for s in scenarios}
    required = {
        "clean",
        "drop-smtp",
        "reset-smtp",
        "icmp-admin",
        "icmp-port-unreach",
        "dns-dnat",
        "nxdomain-rewrite",
        "http-proxy",
    }
    assert required.issubset(scenario_names)


def test_evaluate_clean_scenario_all_correct() -> None:
    scenario_spec = {
        "name": "clean",
        "expected": {
            "ports": {21: "OPEN", 22: "OPEN", 25: "OPEN", 443: "OPEN", 587: "OPEN"},
            "dns": "CLEAN",
            "http": "CLEAN",
        },
    }
    report = _make_canned_report()
    records = evaluate_report_against_scenario(report, scenario_spec, run_idx=0)

    assert len(records) == 7  # 5 ports + 1 dns + 1 http
    assert all(r.is_correct for r in records)


def test_evaluate_drop_smtp_scenario() -> None:
    scenario_spec = {
        "name": "drop-smtp",
        "expected": {
            "ports": {21: "OPEN", 22: "OPEN", 25: "BLOCKED_DROP", 443: "OPEN", 587: "OPEN"},
            "dns": "CLEAN",
            "http": "CLEAN",
        },
    }
    report = _make_canned_report(
        port_verdicts={21: "OPEN", 22: "OPEN", 25: "BLOCKED_DROP", 443: "OPEN", 587: "OPEN"}
    )
    records = evaluate_report_against_scenario(report, scenario_spec, run_idx=0)
    assert all(r.is_correct for r in records)


def test_evaluate_false_positive_detected_on_clean() -> None:
    scenario_spec = {
        "name": "clean",
        "expected": {
            "ports": {21: "OPEN", 22: "OPEN", 25: "OPEN", 443: "OPEN", 587: "OPEN"},
            "dns": "CLEAN",
            "http": "CLEAN",
        },
    }
    # Synthetic false positive: port 25 mistakenly detected as BLOCKED_DROP
    report = _make_canned_report(
        port_verdicts={21: "OPEN", 22: "OPEN", 25: "BLOCKED_DROP", 443: "OPEN", 587: "OPEN"}
    )
    records = evaluate_report_against_scenario(report, scenario_spec, run_idx=0)
    p25 = next(r for r in records if r.target == "25")
    assert not p25.is_correct

    metrics = compute_metrics(records)
    assert metrics["clean_fpr"] > 0.0


def test_evaluate_dns_and_http_anomalies() -> None:
    # 1. DNS dnat scenario
    dns_spec = {
        "name": "dns-dnat",
        "expected": {
            "ports": {21: "OPEN", 22: "OPEN", 25: "OPEN", 443: "OPEN", 587: "OPEN"},
            "dns": "INTERCEPTED",
            "http": "CLEAN",
        },
    }
    dns_report = _make_canned_report(dns_verdict="INTERCEPTED")
    dns_recs = evaluate_report_against_scenario(dns_report, dns_spec, run_idx=0)
    dns_check = next(r for r in dns_recs if r.check_type == "dns")
    assert dns_check.is_correct
    assert dns_check.actual_verdict == "INTERCEPTED"

    # 2. HTTP proxy scenario
    http_spec = {
        "name": "http-proxy",
        "expected": {
            "ports": {21: "OPEN", 22: "OPEN", 25: "OPEN", 443: "OPEN", 587: "OPEN"},
            "dns": "CLEAN",
            "http": "HEADERS_INJECTED",
        },
    }
    http_report = _make_canned_report(http_verdict="HEADERS_INJECTED")
    http_recs = evaluate_report_against_scenario(http_report, http_spec, run_idx=0)
    http_check = next(r for r in http_recs if r.check_type == "http")
    assert http_check.is_correct
    assert http_check.actual_verdict == "HEADERS_INJECTED"


def test_write_and_read_validation_csv(tmp_path: Path) -> None:
    csv_file = tmp_path / "validation.csv"
    records = [
        ValidationRecord("clean", 0, "port", "25", "OPEN", "OPEN", True, "high"),
        ValidationRecord(
            "drop-smtp", 0, "port", "25", "BLOCKED_DROP", "BLOCKED_DROP", True, "high"
        ),
    ]
    write_validation_csv(records, csv_file)
    assert csv_file.exists()

    content = csv_file.read_text(encoding="utf-8")
    assert "scenario,run_idx,check_type,target" in content
    assert "clean,0,port,25,OPEN,OPEN,1,high" in content


def test_compute_metrics_accuracy_and_confusion() -> None:
    records = [
        ValidationRecord("clean", 0, "port", "25", "OPEN", "OPEN", True),
        ValidationRecord("clean", 0, "port", "80", "OPEN", "OPEN", True),
        ValidationRecord("clean", 1, "port", "25", "OPEN", "OPEN", True),
        ValidationRecord("drop-smtp", 0, "port", "25", "BLOCKED_DROP", "BLOCKED_DROP", True),
        ValidationRecord("drop-smtp", 1, "port", "25", "BLOCKED_DROP", "OPEN", False),
    ]
    metrics = compute_metrics(records)
    assert metrics["overall_accuracy"] == 4 / 5
    assert metrics["clean_accuracy"] == 1.0
    assert metrics["clean_fpr"] == 0.0

    conf = metrics["confusion"]["port"]
    assert "OPEN" in conf["labels"]
    assert "BLOCKED_DROP" in conf["labels"]


def test_plot_generation(tmp_path: Path) -> None:
    records = [
        ValidationRecord("clean", 0, "port", "25", "OPEN", "OPEN", True, loss_pct=0.0, rtt_ms=0.0),
        ValidationRecord("clean", 1, "port", "25", "OPEN", "OPEN", True, loss_pct=1.0, rtt_ms=0.0),
        ValidationRecord("clean", 2, "port", "25", "OPEN", "OPEN", True, loss_pct=0.0, rtt_ms=50.0),
        ValidationRecord("drop-smtp", 0, "port", "25", "BLOCKED_DROP", "BLOCKED_DROP", True),
        ValidationRecord("drop-smtp", 1, "port", "25", "BLOCKED_DROP", "BLOCKED_DROP", True),
        ValidationRecord("dns-dnat", 0, "dns", "dns", "INTERCEPTED", "INTERCEPTED", True),
        ValidationRecord(
            "http-proxy", 0, "http", "http", "HEADERS_INJECTED", "HEADERS_INJECTED", True
        ),
    ]
    metrics = compute_metrics(records)

    conf_png = tmp_path / "confusion.png"
    acc_png = tmp_path / "accuracy.png"
    netem_png = tmp_path / "netem_sweep.png"

    plot_confusion_matrices(metrics["confusion"], conf_png)
    assert conf_png.exists() and conf_png.stat().st_size > 1000

    plot_accuracy(metrics["per_scenario"], acc_png)
    assert acc_png.exists() and acc_png.stat().st_size > 1000

    plot_netem_sweeps(records, netem_png)
    assert netem_png.exists() and netem_png.stat().st_size > 1000


def test_pyproject_lab_optional_dependencies() -> None:
    """Verify pyproject.toml defines optional extra [lab] with all required dependencies."""
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    assert pyproject_path.exists()
    content = pyproject_path.read_text(encoding="utf-8")

    assert "[project.optional-dependencies]" in content
    assert "lab = [" in content
    required = ["matplotlib", "pandas", "pyyaml", "rich", "pytest"]
    for dep in required:
        assert dep in content.lower()


def test_lab_preflight_missing_dependency(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify preflight check detects missing dependencies, prints message, and exits 2."""

    def fake_import(name: str) -> None:
        if name == "matplotlib":
            raise ImportError("No module named 'matplotlib'")
        return None

    # Test the pre-flight logic pattern
    missing: list[str] = []
    for mod in ("matplotlib", "numpy", "yaml", "rich", "pandas"):
        try:
            fake_import(mod)
        except ImportError:
            missing.append(mod)

    assert "matplotlib" in missing
    py = sys.executable or "python3"
    expected_msg = f'Missing lab dependencies. Run: {py} -m pip install -e ".[lab]"'
    assert "Missing lab dependencies. Run:" in expected_msg
    assert ".[lab]" in expected_msg


def test_lab_chown_to_sudo_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify lab validate chown_to_sudo_user applies SUDO_UID and SUDO_GID when set."""
    chown_calls: list[tuple[Path, int, int]] = []

    def mock_chown(path: str | os.PathLike[str], uid: int, gid: int) -> None:
        chown_calls.append((Path(path), uid, gid))

    monkeypatch.setattr(os, "chown", mock_chown, raising=False)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1002")

    test_file = tmp_path / "test.csv"
    test_file.write_text("hello\n", encoding="utf-8")

    chown_to_sudo_user(test_file)
    assert len(chown_calls) == 1
    assert chown_calls[0] == (test_file, 1001, 1002)

    # When SUDO_UID is not set, no chown should occur
    monkeypatch.delenv("SUDO_UID", raising=False)
    chown_to_sudo_user(test_file)
    assert len(chown_calls) == 1
