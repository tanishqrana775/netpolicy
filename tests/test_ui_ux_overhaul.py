"""Tests for the UI/UX overhaul across all 5 phases."""

from __future__ import annotations

import io

from rich.console import Console

from netpolicy.models import (
    AuditReport,
    Confidence,
    ReportMetadata,
    Target,
    Verdict,
    VerdictKind,
)
from netpolicy.report.summary import Issue, VerdictSummary
from netpolicy.report.terminal import _render_scorecards
from netpolicy.wizard.keys import flush_stdin
from netpolicy.wizard.recommend import solutions_for


def test_solutions_for_home_ssh() -> None:
    """Verify home Wi-Fi port 22 block advises router / ISP port 22 settings."""
    issues = [
        Issue(
            area="ports",
            subject="Port 22 (SSH)",
            kind="BLOCKED_DROP",
            confidence=Confidence.HIGH,
            attempts=1,
            runs_seen=1,
            runs_total=1,
            plain="No reply on port 22 (remote login)",
        )
    ]
    verdict = VerdictSummary(
        level="RESTRICTED",
        sentence="Your connection is restricted.",
        confidence=Confidence.HIGH,
        tested_summary="1 port tested",
    )
    sols = solutions_for(issues, verdict, network_kind="home")
    assert any("router" in s.steps[0].lower() or "isp" in s.steps[0].lower() for s in sols)


def test_solutions_for_corporate_ssh() -> None:
    """Verify corporate/campus port 22 block advises IT team check."""
    issues = [
        Issue(
            area="ports",
            subject="Port 22 (SSH)",
            kind="BLOCKED_DROP",
            confidence=Confidence.HIGH,
            attempts=1,
            runs_seen=1,
            runs_total=1,
            plain="No reply on port 22 (remote login)",
        )
    ]
    verdict = VerdictSummary(
        level="RESTRICTED",
        sentence="Your connection is restricted.",
        confidence=Confidence.HIGH,
        tested_summary="1 port tested",
    )
    sols = solutions_for(issues, verdict, network_kind="corporate")
    assert any("it team" in s.steps[0].lower() for s in sols)


def test_solutions_for_public_wifi_captive() -> None:
    """Verify public hotspot captive portal advises opening browser terms."""
    issues = [
        Issue(
            area="web",
            subject="http://probe.test",
            kind="REDIRECTED",
            confidence=Confidence.HIGH,
            attempts=1,
            runs_seen=1,
            runs_total=1,
            plain="Redirected to login page",
        )
    ]
    verdict = VerdictSummary(
        level="ACTION_REQUIRED",
        sentence="Sign-in required.",
        confidence=Confidence.HIGH,
        tested_summary="Web check",
    )
    sols = solutions_for(issues, verdict, network_kind="public_wifi")
    assert any("browser" in s.steps[0].lower() and "terms" in s.steps[0].lower() for s in sols)


def test_flush_stdin_safe_execution() -> None:
    """Verify flush_stdin runs safely without exceptions."""
    flush_stdin()


def test_scorecards_render_clean_titles_and_no_banned_dns() -> None:
    """Verify scorecards display clean titles without DNS jargon."""
    meta = ReportMetadata(tool_version="0.1.0", network_label="test")
    report = AuditReport(
        metadata=meta,
        port_results=[
            Verdict(
                kind=VerdictKind.OPEN,
                confidence=Confidence.HIGH,
                target=Target(host="probe.test", port=80, service="HTTP"),
                evidence=["open"],
            ),
            Verdict(
                kind=VerdictKind.OPEN,
                confidence=Confidence.HIGH,
                target=Target(host="probe.test", port=22, service="SSH"),
                evidence=["open"],
            ),
        ],
        dns_results=[
            Verdict(
                kind=VerdictKind.OK,
                confidence=Confidence.HIGH,
                target=Target(host="probe.test", port=53, service="DNS"),
                evidence=["clean"],
            )
        ],
        http_results=[
            Verdict(
                kind=VerdictKind.OK,
                confidence=Confidence.HIGH,
                target=Target(host="probe.test", port=80, service="HTTP"),
                evidence=["clean"],
            )
        ],
    )
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=False, width=100)
    _render_scorecards(report, [], con)
    output = buf.getvalue()

    assert "Websites" in output
    assert "Address lookups" in output
    assert "Web pages" in output
    assert "Remote login" in output
    assert "Lookups working" in output
    assert "Clean content" in output
