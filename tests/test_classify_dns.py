"""Parametrized and unit tests for DNS observation classification and fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netpolicy.classify.dns import (
    answers_overlap_loosely,
    classify_dns,
    classify_dns_checks,
)
from netpolicy.models import Confidence, Observation, Target, VerdictKind

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "dns"
FIXTURE_FILES = sorted(FIXTURES_DIR.glob("*.json"))


def load_dns_fixture(path: Path) -> tuple[list[Observation], str, str | None, bool]:
    """Parse DNS fixture file returning observations and expectations."""
    with path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    raw_obs = data.get("observations", [])
    observations = [Observation.model_validate(o) for o in raw_obs]
    expected_verdict = str(data.get("expected_verdict", data.get("expected", {}).get("kind", "")))
    expected_confidence = data.get(
        "expected_confidence", data.get("expected", {}).get("confidence")
    )
    control_reachable = bool(data.get("control_reachable", True))
    return observations, expected_verdict, expected_confidence, control_reachable


@pytest.mark.parametrize(
    "fixture_path",
    FIXTURE_FILES,
    ids=[f.stem for f in FIXTURE_FILES],
)
def test_dns_classifier_fixtures(fixture_path: Path) -> None:
    """Parametrized test executing classify_dns on all DNS fixtures."""
    observations, expected_verdict, expected_confidence, control_reachable = load_dns_fixture(
        fixture_path
    )
    assert len(observations) > 0, f"Fixture {fixture_path.name} must have observations"

    verdict = classify_dns(
        observations=observations,
        control_reachable=control_reachable,
    )

    assert verdict.kind.value == expected_verdict, (
        f"Fixture {fixture_path.name} expected {expected_verdict}, got {verdict.kind.value}. "
        f"Evidence: {verdict.evidence}"
    )

    if expected_confidence:
        assert verdict.confidence.value == expected_confidence, (
            f"Fixture {fixture_path.name} expected confidence {expected_confidence}, "
            f"got {verdict.confidence.value}."
        )

    assert len(verdict.evidence) > 0, (
        f"Verdict for {fixture_path.name} must contain evidence strings"
    )


def test_classify_dns_empty_observations() -> None:
    """Empty observation list must produce UNKNOWN with LOW confidence."""
    verdict = classify_dns([])
    assert verdict.kind == VerdictKind.UNKNOWN
    assert verdict.confidence == Confidence.LOW
    assert "No DNS observations" in verdict.evidence[0]


def test_answers_overlap_loosely_exact_match() -> None:
    """Exact identical answers should overlap."""
    assert answers_overlap_loosely(["93.184.216.34"], ["93.184.216.34"]) is True


def test_answers_overlap_loosely_slash16_cdn_variation() -> None:
    """Different IPs within the same /16 should loosely overlap (CDN variation)."""
    assert answers_overlap_loosely(["104.21.50.1"], ["104.21.90.2"]) is True


def test_answers_overlap_loosely_different_subnets() -> None:
    """IPs in distinct /16 subnets must not overlap."""
    assert answers_overlap_loosely(["93.184.216.34"], ["198.51.100.5"]) is False


def test_answers_overlap_loosely_empty() -> None:
    """Empty answer sets must return False."""
    assert answers_overlap_loosely([], ["1.1.1.1"]) is False
    assert answers_overlap_loosely(["1.1.1.1"], []) is False


def test_classify_dns_custom_expected_whoami_ranges() -> None:
    """Configuring expected Whoami ranges allows custom lab egress subnets."""
    obs = Observation(
        probe_name="dns_whoami",
        target=Target(host="custom-resolver.lab", port=53, service="DNS-Whoami"),
        success=True,
        raw={
            "protocol": "udp",
            "qname": "whoami.lab",
            "queried_address": "10.0.0.1",
            "source_address": "10.0.0.1",
            "reply_received": True,
            "rcode": 0,
            "txt_answers": ["198.51.100.77"],
            "rtt_ms": 15.0,
        },
    )

    # When expected range does NOT match -> INTERCEPTED
    verdict_bad = classify_dns([obs], expected_whoami_ranges=["10.0.0.0/8"])
    assert verdict_bad.kind == VerdictKind.INTERCEPTED

    # When expected range matches -> CLEAN
    verdict_good = classify_dns([obs], expected_whoami_ranges=["198.51.100.0/24"])
    assert verdict_good.kind == VerdictKind.CLEAN


def test_classify_dns_checks_returns_breakdown() -> None:
    """classify_dns_checks must return distinct verdicts per evaluated capability."""
    bh_obs = Observation(
        probe_name="dns_blackhole",
        target=Target(host="192.0.2.1", port=53, service="DNS-Blackhole-UDP"),
        success=False,
        raw={"protocol": "udp", "reply_received": False, "queried_address": "192.0.2.1"},
    )
    nx_obs = Observation(
        probe_name="dns_nxdomain",
        target=Target(host="8.8.8.8", port=53, service="DNS-NXDOMAIN-Public"),
        success=True,
        raw={"qname": "test.invalid", "reply_received": True, "rcode": 3, "a_records": []},
    )

    verdicts = classify_dns_checks([bh_obs, nx_obs])
    assert len(verdicts) == 2
    assert all(v.kind == VerdictKind.CLEAN for v in verdicts)
