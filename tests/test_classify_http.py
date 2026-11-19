"""Parametrized and unit tests for HTTP canary observation classification and fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netpolicy.classify.http import (
    CanaryManifest,
    classify_http,
    classify_http_checks,
)
from netpolicy.models import Confidence, Observation, Target, VerdictKind

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "http"
FIXTURE_FILES = sorted(FIXTURES_DIR.glob("*.json"))


def load_http_fixture(path: Path) -> tuple[list[Observation], str, str | None, bool]:
    """Parse HTTP fixture file returning observations and expectations."""
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
def test_http_classifier_fixtures(fixture_path: Path) -> None:
    """Parametrized test executing classify_http on all HTTP fixtures."""
    observations, expected_verdict, expected_confidence, control_reachable = load_http_fixture(
        fixture_path
    )
    assert len(observations) > 0, f"Fixture {fixture_path.name} must have observations"

    verdict = classify_http(
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


def test_classify_http_empty_observations() -> None:
    """Empty observation list must produce UNKNOWN with LOW confidence."""
    verdict = classify_http([])
    assert verdict.kind == VerdictKind.UNKNOWN
    assert verdict.confidence == Confidence.LOW
    assert "No HTTP observations" in verdict.evidence[0]


def test_classify_http_fetch_failure_returns_unknown_not_tampering() -> None:
    """When canary fetch fails, classifier must return UNKNOWN and never report tampering."""
    obs = Observation(
        probe_name="http_canary",
        target=Target(host="unreachable.test", port=80, service="HTTP-HTTP"),
        success=False,
        raw={
            "scheme": "http",
            "path": "/canary.txt",
            "status": None,
            "error": "Connection refused",
            "body_sha256": None,
        },
    )

    verdict = classify_http([obs])
    assert verdict.kind == VerdictKind.UNKNOWN
    assert verdict.confidence == Confidence.HIGH
    assert "fetch failure, not tampering" in verdict.evidence[0]


def test_classify_http_custom_manifest() -> None:
    """Custom canary manifest can override expected hash and disallowed headers."""
    obs = Observation(
        probe_name="http_canary",
        target=Target(host="127.0.0.1", port=8080, service="HTTP-HTTP"),
        success=True,
        raw={
            "scheme": "http",
            "path": "/canary.txt",
            "status": 200,
            "headers": [["Content-Type", "text/plain"]],
            "body_sha256": "custom_known_hash_12345",
        },
    )

    # With default manifest -> mismatch (BODY_MODIFIED)
    verdict_default = classify_http([obs])
    assert verdict_default.kind == VerdictKind.BODY_MODIFIED

    # With custom manifest -> matches (CLEAN)
    custom_manifest = CanaryManifest(expected_sha256="custom_known_hash_12345")
    verdict_custom = classify_http([obs], manifest=custom_manifest)
    assert verdict_custom.kind == VerdictKind.CLEAN


def test_classify_http_checks_returns_breakdown() -> None:
    """classify_http_checks must evaluate individual endpoints and return separate verdicts."""
    obs_txt = Observation(
        probe_name="http_canary",
        target=Target(host="127.0.0.1", port=8080, service="HTTP-HTTP"),
        success=True,
        raw={
            "scheme": "http",
            "path": "/canary.txt",
            "status": 200,
            "headers": [["Via", "1.1 proxy"]],
            "body_sha256": "cb78ffc9eaad165cc788a103fe5e422670cc3dbd50c3eb93d20e9c5aca43c8a8",
        },
    )
    obs_echo = Observation(
        probe_name="http_canary",
        target=Target(host="127.0.0.1", port=8080, service="HTTP-HTTP"),
        success=True,
        raw={
            "scheme": "http",
            "path": "/echo",
            "status": 200,
            "headers": [],
            "nonce_sent": "test_nonce",
            "nonce_echoed": "test_nonce",
        },
    )

    verdicts = classify_http_checks([obs_txt, obs_echo])
    assert len(verdicts) == 2
    assert verdicts[0].kind == VerdictKind.HEADERS_INJECTED
    assert verdicts[1].kind == VerdictKind.CLEAN
