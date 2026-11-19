"""Unit tests for rule-based policy finding synthesis in netpolicy.findings."""

from __future__ import annotations

from netpolicy.findings import generate_findings
from netpolicy.models import Confidence, Severity, Target, Verdict, VerdictKind


def test_mail_submission_blocked_all() -> None:
    """When ports 25, 465, and 587 are all blocked, produce mail submission blocked finding."""
    v25 = Verdict(
        target=Target(host="probe.test", port=25, service="SMTP"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
        evidence=["Dropped"],
    )
    v465 = Verdict(
        target=Target(host="probe.test", port=465, service="SMTPS"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
        evidence=["Dropped"],
    )
    v587 = Verdict(
        target=Target(host="probe.test", port=587, service="Submission"),
        kind=VerdictKind.BLOCKED_RESET,
        confidence=Confidence.HIGH,
        evidence=["Reset"],
    )

    findings = generate_findings(port_results=[v25, v465, v587])
    mail_findings = [f for f in findings if f.title == "Outbound Mail Submission Blocked"]
    assert len(mail_findings) == 1
    f = mail_findings[0]
    assert f.severity == Severity.WARN
    assert "Mail submission is blocked on this network" in f.summary
    assert len(f.verdicts) == 3


def test_direct_smtp_blocked_submission_open() -> None:
    """When port 25 is blocked but submission 587 is open, produce INFO finding."""
    v25 = Verdict(
        target=Target(host="probe.test", port=25, service="SMTP"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
        evidence=["Dropped"],
    )
    v587 = Verdict(
        target=Target(host="probe.test", port=587, service="Submission"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
        evidence=["Connected"],
    )

    findings = generate_findings(port_results=[v25, v587])
    smtp_findings = [f for f in findings if f.title == "Direct SMTP (Port 25) Blocked"]
    assert len(smtp_findings) == 1
    assert smtp_findings[0].severity == Severity.INFO


def test_ssh_blocked() -> None:
    """When port 22 is blocked, report SSH administration blocked."""
    v22 = Verdict(
        target=Target(host="probe.test", port=22, service="SSH"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
        evidence=["Dropped"],
    )

    findings = generate_findings(port_results=[v22])
    ssh_findings = [f for f in findings if f.title == "Outbound SSH (Port 22) Blocked"]
    assert len(ssh_findings) == 1
    assert ssh_findings[0].severity == Severity.WARN


def test_web_access_blocked_both_80_and_443() -> None:
    """When both 80 and 443 are blocked, report CRITICAL web access blocked."""
    v80 = Verdict(
        target=Target(host="probe.test", port=80, service="HTTP"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
    )
    v443 = Verdict(
        target=Target(host="probe.test", port=443, service="HTTPS"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(port_results=[v80, v443])
    web_findings = [f for f in findings if f.title == "Web Access Blocked"]
    assert len(web_findings) == 1
    assert web_findings[0].severity == Severity.CRITICAL


def test_plain_http_blocked_https_open() -> None:
    """When port 80 is blocked and 443 is open, report INFO finding."""
    v80 = Verdict(
        target=Target(host="probe.test", port=80, service="HTTP"),
        kind=VerdictKind.BLOCKED_DROP,
        confidence=Confidence.HIGH,
    )
    v443 = Verdict(
        target=Target(host="probe.test", port=443, service="HTTPS"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(port_results=[v80, v443])
    http_findings = [f for f in findings if f.title == "Plain HTTP (Port 80) Blocked"]
    assert len(http_findings) == 1
    assert http_findings[0].severity == Severity.INFO


def test_firewall_reset_and_icmp_prohibition() -> None:
    """Detect firewall TCP reset injection and ICMP prohibition behaviors."""
    v_rst = Verdict(
        target=Target(host="probe.test", port=3306, service="MySQL"),
        kind=VerdictKind.BLOCKED_RESET,
        confidence=Confidence.HIGH,
    )
    v_icmp = Verdict(
        target=Target(host="probe.test", port=21, service="FTP"),
        kind=VerdictKind.BLOCKED_ICMP,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(port_results=[v_rst, v_icmp])
    titles = [f.title for f in findings]
    assert "Firewall TCP Reset Injection" in titles
    assert "Firewall ICMP Administrative Prohibition" in titles


def test_dns_intercepted_with_doh_bypass() -> None:
    """When plain DNS is intercepted and DoH works, report DNS redirected but bypassed by DoH."""
    v_udp = Verdict(
        target=Target(host="8.8.8.8", port=53, service="DNS-UDP"),
        kind=VerdictKind.INTERCEPTED,
        confidence=Confidence.HIGH,
        evidence=["Blackhole replied"],
    )
    v_doh = Verdict(
        target=Target(host="cloudflare-dns.com", port=443, protocol="https", service="DoH"),
        kind=VerdictKind.CLEAN,
        confidence=Confidence.HIGH,
        evidence=["Authenticated DoH OK"],
    )

    findings = generate_findings(dns_results=[v_udp, v_doh])
    dns_findings = [f for f in findings if f.title == "DNS Interception Bypassed by DoH"]
    assert len(dns_findings) == 1
    f = dns_findings[0]
    assert f.severity == Severity.CRITICAL
    assert "DNS is redirected, but encrypted DNS bypasses it" in f.summary


def test_dns_nxdomain_hijacking() -> None:
    """When DNS returns A records for .invalid, report NXDOMAIN hijacking."""
    v_nx = Verdict(
        target=Target(host="8.8.8.8", port=53, service="DNS-NXDOMAIN"),
        kind=VerdictKind.REWRITTEN,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(dns_results=[v_nx])
    nx_findings = [f for f in findings if f.title == "NXDOMAIN Hijacking Active"]
    assert len(nx_findings) == 1
    assert nx_findings[0].severity == Severity.WARN


def test_http_payload_tampering() -> None:
    """When canary body SHA-256 changes, report CRITICAL payload tampering."""
    v_body = Verdict(
        target=Target(host="canary.test", port=80, service="HTTP"),
        kind=VerdictKind.BODY_MODIFIED,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(http_results=[v_body])
    body_findings = [f for f in findings if f.title == "HTTP Payload Tampered in Transit"]
    assert len(body_findings) == 1
    assert body_findings[0].severity == Severity.CRITICAL


def test_http_proxy_headers_and_rewriting_nonce() -> None:
    """Detect proxy header injection and rewriting proxy nonces."""
    v_hdr = Verdict(
        target=Target(host="canary.test", port=80, service="HTTP"),
        kind=VerdictKind.HEADERS_INJECTED,
        confidence=Confidence.HIGH,
    )
    v_nonce = Verdict(
        target=Target(host="canary.test", port=80, service="HTTP"),
        kind=VerdictKind.PROXIED,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(http_results=[v_hdr, v_nonce])
    titles = [f.title for f in findings]
    assert "HTTP Proxy Header Injection" in titles
    assert "HTTP Traffic Intercepted by Rewriting Proxy" in titles


def test_clean_audit_generates_zero_findings() -> None:
    """Clean audit with open ports, authentic DNS, and intact HTTP produces no findings."""
    v_port = Verdict(
        target=Target(host="probe.test", port=443, service="HTTPS"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
    )
    v_dns = Verdict(
        target=Target(host="1.1.1.1", port=53, service="DNS"),
        kind=VerdictKind.CLEAN,
        confidence=Confidence.HIGH,
    )
    v_http = Verdict(
        target=Target(host="canary.test", port=80, service="HTTP"),
        kind=VerdictKind.CLEAN,
        confidence=Confidence.HIGH,
    )

    findings = generate_findings(
        port_results=[v_port],
        dns_results=[v_dns],
        http_results=[v_http],
    )
    assert findings == []
