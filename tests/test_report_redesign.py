# ruff: noqa: E501
"""Comprehensive tests for netpolicy terminal report redesign, summary aggregation, and reliability gates."""

import io
import json
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from netpolicy.cli import app
from netpolicy.models import (
    AuditReport,
    Confidence,
    ReportMetadata,
    Target,
    Verdict,
    VerdictKind,
)
from netpolicy.report.humanize import confidence_verb
from netpolicy.report.summary import (
    Caveat,
    Issue,
    aggregate,
    apply_reliability_gates,
    compute_verdict,
)
from netpolicy.report.terminal import render_terminal_report

runner = CliRunner()


# =============================================================================
# Synthetic Fixture 1: 20 REDIRECTED observations (301 to canary.txt + 404)
# =============================================================================
@pytest.fixture
def fixture_1_unverified_canary() -> AuditReport:
    """Fixture 1: 20 REDIRECTED observations to same-host canary returning 404.

    Should fire G1 (unverified canary) and G3 (benign same-host upgrade).
    Must NOT declare a captive portal; verdict should be INCONCLUSIVE.
    """
    http_verdicts = [
        Verdict(
            target=Target(host="1.1.1.1", port=443, protocol="https", service="canary"),
            kind=VerdictKind.REDIRECTED,
            confidence=Confidence.HIGH,
            evidence=[
                "Unexpected HTTP status code 404 on /canary.txt (expected 200) - possible captive portal or block page.",
                "HTTP redirects: [{'status': 301, 'location': 'https://1.1.1.1/canary.txt'}]",
            ],
        )
        for _ in range(20)
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-1",
            target="1.1.1.1",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=[],
        dns_results=[],
        http_results=http_verdicts,
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 2: 10 "documentation address 1.1.1.1" lines
# =============================================================================
@pytest.fixture
def fixture_2_blackhole_querying_target() -> AuditReport:
    """Fixture 2: Blackhole probe queried the audit target instead of doc IP.

    Should fire G2 (blackhole probe validity) and mark issue invalid.
    """
    dns_verdicts = [
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Blackhole-UDP"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.HIGH,
            evidence=["Documentation address 1.1.1.1 answered over udp/53"],
        )
        for _ in range(10)
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-2",
            target="1.1.1.1",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=[],
        dns_results=dns_verdicts,
        http_results=[],
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 3: IPv6 whoami mismatch
# =============================================================================
@pytest.fixture
def fixture_3_whoami_ipv6_mismatch() -> AuditReport:
    """Fixture 3: Resolver whoami query returns IPv6 egress not in IPv4 CIDRs.

    Should fire G4 (address-family mismatch) and downgrade to INCONCLUSIVE.
    """
    dns_verdicts = [
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.HIGH,
            evidence=[
                "DNS whoami egress IP '2400:cb00:1007:1024::6816:306e' not in expected provider range(s): ['1.1.1.0/24', '1.0.0.0/24']"
            ],
        )
        for _ in range(5)
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-3",
            target="1.1.1.1",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=[],
        dns_results=dns_verdicts,
        http_results=[],
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 4: 10 SSL WRONG_VERSION_NUMBER errors
# =============================================================================
@pytest.fixture
def fixture_4_ssl_wrong_version() -> AuditReport:
    """Fixture 4: TLS ClientHello sent to plain-HTTP port 80.

    Should fire G5 and categorize as a test execution problem, not network block.
    """
    http_verdicts = [
        Verdict(
            target=Target(host="1.1.1.1", port=80, protocol="https", service="HTTP"),
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=[
                "HTTPS probe error: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1127)"
            ],
        )
        for _ in range(10)
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-4",
            target="1.1.1.1",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=[],
        dns_results=[],
        http_results=http_verdicts,
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 5: Conflicting outcomes across runs (CLEAN + INTERCEPTED)
# =============================================================================
@pytest.fixture
def fixture_5_inconsistent_runs() -> AuditReport:
    """Fixture 5: Same probe returns CLEAN in 2 runs and INTERCEPTED in 3 runs.

    Should reconcile into a single INCONSISTENT issue rather than conflicting rows.
    """
    dns_verdicts = [
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.CLEAN,
            confidence=Confidence.HIGH,
            evidence=["Egress IP 172.69.202.51 verified in range 172.64.0.0/13"],
        ),
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.CLEAN,
            confidence=Confidence.HIGH,
            evidence=["Egress IP 172.69.202.51 verified in range 172.64.0.0/13"],
        ),
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.MEDIUM,
            evidence=["Egress IP 198.51.100.99 outside expected range"],
        ),
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.MEDIUM,
            evidence=["Egress IP 198.51.100.99 outside expected range"],
        ),
        Verdict(
            target=Target(host="1.1.1.1", port=53, protocol="udp", service="DNS-Whoami"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.MEDIUM,
            evidence=["Egress IP 198.51.100.99 outside expected range"],
        ),
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-5",
            target="1.1.1.1",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=[],
        dns_results=dns_verdicts,
        http_results=[],
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 6: Real Captive Portal
# =============================================================================
@pytest.fixture
def fixture_6_real_captive_portal() -> AuditReport:
    """Fixture 6: Genuine captive portal redirecting HTTP requests to external login page.

    Must classify as ACTION_REQUIRED and show a single aggregated row with x20 multiplier.
    """
    http_verdicts = [
        Verdict(
            target=Target(
                host="connectivitycheck.gstatic.com",
                port=80,
                protocol="http",
                service="HTTP",
            ),
            kind=VerdictKind.REDIRECTED,
            confidence=Confidence.HIGH,
            evidence=[
                "Unexpected HTTP redirect: [{'status': 302, 'location': 'https://login.campus.example/guest/portal.php'}]"
            ],
        )
        for _ in range(20)
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Test-Network-6",
            target="connectivitycheck.gstatic.com",
            client_address="192.168.1.10",
            mode="auto",
            runs_per_check=1,
        ),
        port_results=[],
        dns_results=[],
        http_results=http_verdicts,
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 7: Clean Lab Baseline with Verified Canary
# =============================================================================
@pytest.fixture
def fixture_7_clean_lab_baseline() -> AuditReport:
    """Fixture 7: Clean network with verified canary manifest and open ports.

    Must classify as CLEAN with zero findings.
    """
    ports = [
        Verdict(
            target=Target(host="canary.lab", port=p, service=s, expect_open=True),
            kind=VerdictKind.OPEN,
            confidence=Confidence.HIGH,
            evidence=["SYN-ACK received in 5ms"],
        )
        for p, s in [(22, "SSH"), (80, "HTTP"), (443, "HTTPS")]
    ]
    dns = [
        Verdict(
            target=Target(host="10.0.0.1", port=53, protocol="udp", service="DNS"),
            kind=VerdictKind.CLEAN,
            confidence=Confidence.HIGH,
            evidence=["Authentic resolver response"],
        )
    ]
    http = [
        Verdict(
            target=Target(host="canary.lab", port=443, protocol="https", service="canary"),
            kind=VerdictKind.OK,
            confidence=Confidence.HIGH,
            evidence=["SHA-256 verified against expected manifest", "HTTP 200 OK"],
        )
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Clean-Lab",
            target="canary.lab",
            client_address="10.0.0.2",
            mode="auto",
            runs_per_check=1,
        ),
        port_results=ports,
        dns_results=dns,
        http_results=http,
        findings=[],
    )


# =============================================================================
# Synthetic Fixture 8: Campus-like Network (RST 587, DNS DNAT, Header Injection)
# =============================================================================
@pytest.fixture
def fixture_8_campus_restricted() -> AuditReport:
    """Fixture 8: Campus network with middlebox RST on 587, DNS interception, and header injection.

    Must classify as RESTRICTED.
    """
    ports = [
        Verdict(
            target=Target(host="probe.campus", port=587, service="Submission", expect_open=True),
            kind=VerdictKind.BLOCKED_RESET,
            confidence=Confidence.HIGH,
            evidence=[
                "TCP RST received in 3ms",
                "Inbound TTL=64 indicates local gateway RST injection",
            ],
        ),
        Verdict(
            target=Target(host="probe.campus", port=25, service="SMTP", expect_open=True),
            kind=VerdictKind.BLOCKED_DROP,
            confidence=Confidence.HIGH,
            evidence=["0/5 replies received, timed out after 3.0s per run"],
        ),
    ]
    dns = [
        Verdict(
            target=Target(host="8.8.8.8", port=53, protocol="udp", service="DNS"),
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.HIGH,
            evidence=["Queries to 8.8.8.8 intercepted by local gateway (TTL=64 instead of 115)"],
        )
    ]
    http = [
        Verdict(
            target=Target(host="probe.campus", port=80, protocol="http", service="HTTP"),
            kind=VerdictKind.TAMPERED,
            confidence=Confidence.HIGH,
            evidence=["Injected proxy headers detected: 'Via: 1.1 squid-proxy'"],
        )
    ]
    return AuditReport(
        schema_version="1",
        metadata=ReportMetadata(
            tool_version="0.1.0",
            network_label="Campus-WiFi",
            target="probe.campus",
            client_address="192.168.10.50",
            mode="auto",
            runs_per_check=5,
        ),
        port_results=ports,
        dns_results=dns,
        http_results=http,
        findings=[],
    )


# =============================================================================
# Fixture Test Cases
# =============================================================================


def test_fixture_1_unverified_canary_gates_and_rendering(
    fixture_1_unverified_canary: AuditReport,
) -> None:
    """Verify Fixture 1 triggers G1 and G3, produces INCONCLUSIVE, and renders cleanly."""
    issues = aggregate(fixture_1_unverified_canary)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_1_unverified_canary)
    summary = compute_verdict(adj_issues, caveats, fixture_1_unverified_canary)

    assert summary.level == "INCONCLUSIVE"
    assert any(c.code == "G1" for c in caveats)
    assert any(c.code == "G3" for c in caveats)
    # The HTTP redirect issue must be marked invalid (not a captive portal)
    assert all(not i.valid for i in adj_issues)

    # Render terminal report
    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_1_unverified_canary, console=console)
    output = buf.getvalue()

    # Must render in fewer than 25 lines
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) < 25

    # Hygiene: Must not leak raw Python dicts, tracebacks, or internal fields
    for forbidden in ["{'status'", "_ssl.c", "range(s)", "Fingerprint", "TTL", "RTT", "Traceback"]:
        assert forbidden not in output


def test_fixture_2_blackhole_probe_invalidation(
    fixture_2_blackhole_querying_target: AuditReport,
) -> None:
    """Verify Fixture 2 invalidates blackhole query targeting non-doc IP (Gate G2)."""
    issues = aggregate(fixture_2_blackhole_querying_target)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_2_blackhole_querying_target)
    assert any(c.code == "G2" for c in caveats)
    assert all(not i.valid for i in adj_issues)


def test_fixture_3_whoami_ipv6_mismatch(fixture_3_whoami_ipv6_mismatch: AuditReport) -> None:
    """Verify Fixture 3 catches IPv6 address family mismatch (Gate G4)."""
    issues = aggregate(fixture_3_whoami_ipv6_mismatch)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_3_whoami_ipv6_mismatch)
    summary = compute_verdict(adj_issues, caveats, fixture_3_whoami_ipv6_mismatch)

    assert summary.level == "INCONCLUSIVE"
    assert any(c.code == "G4" for c in caveats)
    assert any(i.kind == "INCONCLUSIVE" for i in adj_issues)


def test_fixture_4_ssl_wrong_version_error(fixture_4_ssl_wrong_version: AuditReport) -> None:
    """Verify Fixture 4 flags SSL WRONG_VERSION_NUMBER as probe error (Gate G5)."""
    issues = aggregate(fixture_4_ssl_wrong_version)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_4_ssl_wrong_version)

    assert any(c.code == "G5" for c in caveats)
    assert all(not i.valid for i in adj_issues)

    # In verbose mode it should appear under 'Checks that could not run'
    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_4_ssl_wrong_version, console=console, verbose=True)
    assert "checks that could not run" in buf.getvalue().lower()


def test_fixture_5_inconsistent_outcomes_reconciliation(
    fixture_5_inconsistent_runs: AuditReport,
) -> None:
    """Verify Fixture 5 aggregates mixed CLEAN/INTERCEPTED runs into INCONSISTENT."""
    issues = aggregate(fixture_5_inconsistent_runs)
    assert len(issues) == 1
    assert issues[0].kind == "INCONSISTENT"
    assert "Inconsistent DNS responses across runs" in issues[0].plain
    assert issues[0].runs_seen == 3
    assert issues[0].runs_total == 5


def test_fixture_6_real_captive_portal(fixture_6_real_captive_portal: AuditReport) -> None:
    """Verify Fixture 6 identifies genuine captive portal as ACTION_REQUIRED."""
    issues = aggregate(fixture_6_real_captive_portal)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_6_real_captive_portal)
    summary = compute_verdict(adj_issues, caveats, fixture_6_real_captive_portal)

    assert summary.level == "ACTION_REQUIRED"
    assert "captive portal" in summary.sentence.lower()

    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_6_real_captive_portal, console=console)
    output = buf.getvalue()

    assert "ACTION_REQUIRED" in output
    assert "x20" in output
    assert "WHAT YOU CAN DO" in output


def test_fixture_7_clean_lab_baseline(fixture_7_clean_lab_baseline: AuditReport) -> None:
    """Verify Fixture 7 produces CLEAN verdict and no findings table."""
    issues = aggregate(fixture_7_clean_lab_baseline)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_7_clean_lab_baseline)
    summary = compute_verdict(adj_issues, caveats, fixture_7_clean_lab_baseline)

    assert summary.level == "CLEAN"
    assert "passed cleanly" in summary.sentence.lower()

    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_7_clean_lab_baseline, console=console)
    output = buf.getvalue()

    assert "CLEAN" in output
    assert "WHAT WE FOUND" not in output


def test_fixture_8_campus_restricted(fixture_8_campus_restricted: AuditReport) -> None:
    """Verify Fixture 8 produces RESTRICTED verdict with actionable findings."""
    issues = aggregate(fixture_8_campus_restricted)
    adj_issues, caveats = apply_reliability_gates(issues, fixture_8_campus_restricted)
    summary = compute_verdict(adj_issues, caveats, fixture_8_campus_restricted)

    assert summary.level == "RESTRICTED"
    assert "restricting or altering" in summary.sentence.lower()

    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_8_campus_restricted, console=console)
    output = buf.getvalue()

    assert "RESTRICTED" in output
    assert "WHAT WE FOUND" in output
    assert "WHAT YOU CAN DO" in output


# =============================================================================
# Behavioral & Contract Assertions
# =============================================================================


def test_confidence_honesty_rule() -> None:
    """Verify wording strictly reflects confidence level."""
    assert confidence_verb(Confidence.HIGH) == "is"
    assert confidence_verb(Confidence.MEDIUM) == "appears to be"
    assert confidence_verb(Confidence.LOW) == "may be"


def test_verdict_precedence_truth_table() -> None:
    """Verify verdict precedence: INCONCLUSIVE > ACTION_REQUIRED > RESTRICTED > LIMITED > CLEAN."""
    portal_issue = Issue(
        area="web",
        subject="http://portal.test",
        kind=VerdictKind.REDIRECTED.value,
        confidence=Confidence.HIGH,
        attempts=1,
        runs_seen=1,
        runs_total=1,
        plain="Redirected to portal.test",
        valid=True,
    )
    tamper_issue = Issue(
        area="dns",
        subject="DNS (8.8.8.8)",
        kind=VerdictKind.INTERCEPTED.value,
        confidence=Confidence.HIGH,
        attempts=1,
        runs_seen=1,
        runs_total=1,
        plain="DNS intercepted",
        valid=True,
    )
    block_issue = Issue(
        area="ports",
        subject="Port 25 (SMTP)",
        kind=VerdictKind.BLOCKED_DROP.value,
        confidence=Confidence.HIGH,
        attempts=1,
        runs_seen=1,
        runs_total=1,
        plain="Blocked port 25",
        valid=True,
    )
    g1_caveat = Caveat(code="G1", plain="Unverified canary", technical="no canary")

    # 1. Clean when zero issues
    assert compute_verdict([], []).level == "CLEAN"

    # 2. Limited when single block issue
    assert compute_verdict([block_issue], []).level == "LIMITED"

    # 3. Restricted when tampering present
    assert compute_verdict([tamper_issue], []).level == "RESTRICTED"
    assert compute_verdict([tamper_issue, block_issue], []).level == "RESTRICTED"

    # 4. Action Required when portal present (beats Restricted)
    assert compute_verdict([portal_issue, tamper_issue], []).level == "ACTION_REQUIRED"

    # 5. Inconclusive when G1 fired and no confirmed problem
    assert compute_verdict([], [g1_caveat]).level == "INCONCLUSIVE"


def test_quiet_mode_single_line(fixture_8_campus_restricted: AuditReport) -> None:
    """Verify --quiet produces exactly one line with symbol, LEVEL, and sentence."""
    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_8_campus_restricted, console=console, quiet=True)
    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 1
    assert "RESTRICTED:" in lines[0]


def test_zero_consecutive_duplicate_lines(fixture_8_campus_restricted: AuditReport) -> None:
    """Verify terminal output has zero duplicate consecutive lines."""
    buf = io.StringIO()
    console = Console(file=buf, width=80, no_color=True)
    render_terminal_report(fixture_8_campus_restricted, console=console)
    lines = [line.strip() for line in buf.getvalue().splitlines() if line.strip()]
    for i in range(len(lines) - 1):
        assert lines[i] != lines[i + 1]


def test_terminal_width_wrapping(fixture_8_campus_restricted: AuditReport) -> None:
    """Verify terminal report renders cleanly without exception at various widths."""
    for width in (60, 80, 120):
        buf = io.StringIO()
        console = Console(file=buf, width=width, no_color=True)
        render_terminal_report(fixture_8_campus_restricted, console=console)
        output = buf.getvalue()
        assert "RESTRICTED" in output
        assert "WHAT WE FOUND" in output


def test_reclassify_json_matches_baseline(tmp_path: Path) -> None:
    """Verify `netpolicy reclassify --json` output matches baseline byte-for-byte ignoring timestamp."""
    before_path = Path("/tmp/before.json")
    if not before_path.exists():
        pytest.skip("/tmp/before.json not found in test environment")

    result = runner.invoke(app, ["reclassify", "20261115_150345_86c3aca1", "--json"])
    assert result.exit_code in (0, 1)

    curr_data = json.loads(result.output)
    before_data = json.loads(before_path.read_text(encoding="utf-8"))

    # Ignore dynamic runtime / timestamp field if present
    curr_data.get("metadata", {}).pop("run_time", None)
    before_data.get("metadata", {}).pop("run_time", None)

    assert curr_data == before_data
