"""Parametrized and unit tests for TCP reachability classification and fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netpolicy.classify.tcp import (
    ICMP_TYPE_3_CODES,
    classify_tcp_reachability,
    classify_tcp_run,
)
from netpolicy.models import Confidence, Observation, Target, VerdictKind

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "tcp"
FIXTURE_FILES = sorted(FIXTURES_DIR.glob("*.json"))


def load_fixture_data(
    path: Path,
) -> tuple[list[Observation], dict[str, Any], bool, int | None]:
    """Parse fixture file returning observations, expected outcomes, and control parameters."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    raw_obs = data.get("observations", data if isinstance(data, list) else [])
    observations = [Observation.model_validate(o) for o in raw_obs]
    expected = data.get("expected", {})
    control_reachable = data.get("control_reachable", True)
    control_syn_ack_ttl = data.get("control_syn_ack_ttl")
    return observations, expected, control_reachable, control_syn_ack_ttl


@pytest.mark.parametrize(
    "fixture_path",
    FIXTURE_FILES,
    ids=[f.stem for f in FIXTURE_FILES],
)
def test_tcp_classifier_fixtures(fixture_path: Path) -> None:
    """Parametrized test executing classify_tcp_reachability on each JSON fixture."""
    observations, expected, control_reachable, control_syn_ack_ttl = load_fixture_data(fixture_path)
    assert len(observations) > 0, f"Fixture {fixture_path.name} must have observations"

    verdict = classify_tcp_reachability(
        observations=observations,
        control_reachable=control_reachable,
        control_syn_ack_ttl=control_syn_ack_ttl,
    )

    expected_kind = expected.get("kind")
    assert expected_kind is not None
    assert verdict.kind.value == expected_kind, (
        f"Fixture {fixture_path.name} expected kind {expected_kind}, got {verdict.kind.value}. "
        f"Evidence: {verdict.evidence}"
    )

    expected_confidence = expected.get("confidence")
    if expected_confidence:
        assert verdict.confidence.value == expected_confidence, (
            f"Fixture {fixture_path.name} expected confidence {expected_confidence}, "
            f"got {verdict.confidence.value}. Evidence: {verdict.evidence}"
        )

    expected_evidence_items = expected.get("evidence_contains", [])
    combined_evidence = " | ".join(verdict.evidence)
    for expected_str in expected_evidence_items:
        assert expected_str.lower() in combined_evidence.lower(), (
            f"Fixture {fixture_path.name} expected substring '{expected_str}' "
            f"in evidence: {verdict.evidence}"
        )


def test_empty_observations_returns_unknown() -> None:
    """Verify empty observation list returns UNKNOWN verdict with low confidence."""
    verdict = classify_tcp_reachability([])
    assert verdict.kind == VerdictKind.UNKNOWN
    assert verdict.confidence == Confidence.LOW
    assert "No observations provided" in verdict.evidence[0]


def test_classify_via_control_observations_list() -> None:
    """Verify control_observations argument supplies control_reachable and control_syn_ack_ttl."""
    target_obs = [
        Observation(
            probe_name="tcp_syn",
            target=Target(host="192.0.2.1", port=443, expect_open=True),
            success=False,
            raw={
                "attempt": 1,
                "reply_type": "RST",
                "reply_received": True,
                "ip_ttl": 61,
            },
        )
    ]
    control_obs = [
        Observation(
            probe_name="tcp_syn",
            target=Target(host="1.1.1.1", port=443, expect_open=True),
            success=True,
            raw={
                "attempt": 1,
                "reply_type": "SYN-ACK",
                "reply_received": True,
                "ip_ttl": 52,
            },
        )
    ]

    verdict = classify_tcp_reachability(
        observations=target_obs,
        control_observations=control_obs,
    )
    assert verdict.kind == VerdictKind.BLOCKED_RESET
    assert verdict.confidence == Confidence.HIGH
    assert "RST TTL 61 vs SYN-ACK TTL 52" in verdict.evidence[0]


def test_control_failed_overrides_drop_to_unknown() -> None:
    """Verify that when control fails, all-timeouts verdict is UNKNOWN, never BLOCKED_DROP."""
    target_obs = [
        Observation(
            probe_name="tcp_syn",
            target=Target(host="192.0.2.1", port=80),
            success=False,
            raw={"attempt": 1, "reply_type": "none", "reply_received": False},
        )
    ]
    # Control failed
    verdict = classify_tcp_run(target_obs, control_reachable=False)
    assert verdict.kind == VerdictKind.UNKNOWN
    assert "control failed" in verdict.evidence[0]

    # Control OK
    verdict_ok = classify_tcp_run(target_obs, control_reachable=True)
    assert verdict_ok.kind == VerdictKind.BLOCKED_DROP
    assert "control OK" in verdict_ok.evidence[0]


def test_icmp_codes_table() -> None:
    """Verify ICMP Type 3 code definitions for administrative prohibited vs unreachable."""
    assert ICMP_TYPE_3_CODES[13]["prohibited"] is True
    assert ICMP_TYPE_3_CODES[13]["raw_confidence"] == Confidence.HIGH
    assert ICMP_TYPE_3_CODES[9]["prohibited"] is True
    assert ICMP_TYPE_3_CODES[10]["prohibited"] is True
    assert ICMP_TYPE_3_CODES[3]["prohibited"] is False
    assert ICMP_TYPE_3_CODES[1]["prohibited"] is False
    assert ICMP_TYPE_3_CODES[0]["prohibited"] is False


def test_socket_mode_econnrefused_evidence_note() -> None:
    """Verify socket mode includes note that RST and ICMP cannot be told apart from ECONNREFUSED."""
    obs = [
        Observation(
            probe_name="tcp_connect",
            target=Target(host="127.0.0.1", port=9000, expect_open=False),
            success=False,
            raw={"attempt": 1, "outcome": "refused", "errno_name": "ECONNREFUSED"},
        )
    ]
    verdict = classify_tcp_reachability(obs)
    assert verdict.kind == VerdictKind.CLOSED_OR_RESET
    assert verdict.confidence == Confidence.LOW
    combined_ev = " ".join(verdict.evidence)
    assert "cannot be told apart from ECONNREFUSED" in combined_ev
