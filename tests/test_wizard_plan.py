"""Tests for Wizard plan builders, input validators, and ScriptedIO (Stage 3)."""

from __future__ import annotations

import pytest

from netpolicy.wizard.plan import (
    build_audit_plan,
    build_compare_plan,
    build_dns_plan,
    build_http_plan,
    build_lab_plan,
    build_ports_plan,
    build_reclassify_plan,
    validate_ports,
    validate_runs,
    validate_target,
    validate_timeout,
)

# ==============================================================================
# Plan Builder Argv Tests
# ==============================================================================


def test_build_audit_plan_argv() -> None:
    plan = build_audit_plan(
        target="127.0.0.1", ports="80,443", runs=5, timeout=3.0, retries=2, mode="auto"
    )
    assert plan.kind == "traffic"
    assert plan.argv == [
        "audit",
        "--target",
        "127.0.0.1",
        "--runs",
        "5",
        "--timeout",
        "3.0",
        "--retries",
        "2",
        "--mode",
        "auto",
        "--ports",
        "80,443",
    ]
    expected_cmd = (
        "netpolicy audit --target 127.0.0.1 --runs 5 --timeout 3.0 "
        "--retries 2 --mode auto --ports 80,443"
    )
    assert plan.cli_equivalent == expected_cmd
    assert "network traffic" in plan.impacts
    assert plan.writes is True


def test_build_ports_plan_argv() -> None:
    plan = build_ports_plan(
        target="probe.test", ports="25,587", runs=3, timeout=2.0, retries=1, mode="socket"
    )
    assert plan.kind == "traffic"
    assert plan.argv == [
        "ports",
        "--target",
        "probe.test",
        "--ports",
        "25,587",
        "--runs",
        "3",
        "--timeout",
        "2.0",
        "--retries",
        "1",
        "--mode",
        "socket",
    ]
    assert plan.needs_root is False


def test_build_dns_plan_argv() -> None:
    plan = build_dns_plan(target="1.1.1.1", runs=2, timeout=1.5, retries=1, mode="auto")
    assert plan.kind == "traffic"
    assert plan.argv == [
        "dns",
        "--runs",
        "2",
        "--timeout",
        "1.5",
        "--retries",
        "1",
        "--mode",
        "auto",
        "--target",
        "1.1.1.1",
    ]


def test_build_http_plan_argv() -> None:
    plan = build_http_plan(target="canary.test", runs=1, timeout=5.0, retries=0, mode="auto")
    assert plan.kind == "traffic"
    assert plan.argv == [
        "http",
        "--target",
        "canary.test",
        "--runs",
        "1",
        "--timeout",
        "5.0",
        "--retries",
        "0",
        "--mode",
        "auto",
    ]


def test_build_compare_plan_argv() -> None:
    plan = build_compare_plan("reports/run1.jsonl", "reports/run2.jsonl")
    assert plan.kind == "offline"
    assert plan.argv == ["compare", "reports/run1.jsonl", "reports/run2.jsonl"]
    assert "offline" in plan.impacts
    assert plan.needs_root is False


def test_build_reclassify_plan_argv() -> None:
    plan = build_reclassify_plan("reports/old_run.jsonl")
    assert plan.kind == "offline"
    assert plan.argv == ["reclassify", "reports/old_run.jsonl"]
    assert plan.writes is False


def test_build_lab_plan_argv() -> None:
    plan = build_lab_plan(action="status")
    assert plan.kind == "lab"
    assert plan.argv == ["lab"]
    assert "changes lab namespaces" in plan.impacts
    assert plan.needs_root is True


# ==============================================================================
# Input Validation Allow-list Tests
# ==============================================================================


@pytest.mark.parametrize(
    ("bad_target", "expected_err"),
    [
        ("", "Target cannot be empty"),
        ("10.0.0.0/24", "CIDR notation"),
        ("192.168.1.1,192.168.1.2", "Comma-separated"),
        ("a,b", "Comma-separated"),
        ("host name", "Spaces"),
        ("probe*.test", "Wildcards"),
        ("probe;rm", "Wildcards"),
        ("224.0.0.1", "Multicast"),
        ("0.0.0.0", "Unspecified"),
        ("255.255.255.255", "Broadcast"),
    ],
)
def test_target_validation_rejects_invalid(bad_target: str, expected_err: str) -> None:
    valid, msg = validate_target(bad_target)
    assert not valid
    assert expected_err.lower() in msg.lower()


@pytest.mark.parametrize(
    "good_target",
    ["127.0.0.1", "10.200.2.2", "probe.example.com", "localhost", "my-server.internal"],
)
def test_target_validation_accepts_valid(good_target: str) -> None:
    valid, msg = validate_target(good_target)
    assert valid
    assert msg == ""


def test_port_validation() -> None:
    # Valid
    valid, _, ports = validate_ports("25, 465, 587")
    assert valid
    assert ports == [25, 465, 587]

    # Port out of range (99999)
    valid, msg, _ = validate_ports("99999")
    assert not valid
    assert "out of range" in msg.lower()

    # Port 0
    valid, msg, _ = validate_ports("0")
    assert not valid

    # Non-integer
    valid, msg, _ = validate_ports("http")
    assert not valid
    assert "integer" in msg.lower()

    # Exceeding 20 ports
    too_many = ",".join(str(i) for i in range(1, 25))
    valid, msg, _ = validate_ports(too_many)
    assert not valid
    assert "maximum" in msg.lower()


def test_runs_and_timeout_validation() -> None:
    # Runs (1-20)
    assert validate_runs("5")[0] is True
    assert validate_runs("0")[0] is False
    assert validate_runs("25")[0] is False
    assert validate_runs("abc")[0] is False

    # Timeout (0.5 - 30.0)
    assert validate_timeout("3.0")[0] is True
    assert validate_timeout("0.1")[0] is False
    assert validate_timeout("35.0")[0] is False
    assert validate_timeout("xyz")[0] is False
