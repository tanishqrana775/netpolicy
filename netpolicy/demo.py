"""Mock data generator producing realistic network audit reports for testing and demonstrations."""

from __future__ import annotations

from netpolicy.models import (
    AuditReport,
    Confidence,
    Finding,
    ReportMetadata,
    Severity,
    Target,
    Verdict,
    VerdictKind,
)


def build_demo_report() -> AuditReport:
    """Build a realistic mock AuditReport demonstrating various network policy findings.

    Scenario:
    - Outbound ports: 22/443 open, 25/465 dropped, 587 reset, 21 ICMP-rejected, 443/udp open.
    - DNS: Interception on UDP/53 with NXDOMAIN search portal rewriting.
    - HTTP: Transparent caching proxy injecting 'Via' and 'X-Cache' headers.
    """
    metadata = ReportMetadata(
        tool_version="0.1.0",
        network_label="Guest-WiFi (Campus / Hotspot)",
        client_address="192.168.44.120",
        mode="raw",
        runs_per_check=5,
        target="probe.netpolicy.org",
        network_fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        include_identifiers=False,
    )

    # Port reachability verdicts
    v_ssh = Verdict(
        target=Target(host="probe.netpolicy.org", port=22, service="SSH"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
        evidence=["SYN-ACK received in 24ms across 5/5 runs", "Inbound TTL=56 matches direct path"],
    )
    v_https = Verdict(
        target=Target(host="probe.netpolicy.org", port=443, service="HTTPS"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
        evidence=["SYN-ACK received in 21ms across 5/5 runs", "TCP handshake completed"],
    )
    v_smtp = Verdict(
        target=Target(host="probe.netpolicy.org", port=25, service="SMTP"),
        kind=VerdictKind.DROPPED,
        confidence=Confidence.HIGH,
        evidence=[
            "0/5 replies received, timed out after 3.0s per run",
            "Silent egress packet drop at perimeter firewall",
        ],
    )
    v_smtps = Verdict(
        target=Target(host="probe.netpolicy.org", port=465, service="SMTPS"),
        kind=VerdictKind.DROPPED,
        confidence=Confidence.HIGH,
        evidence=[
            "0/5 replies received, timed out after 3.0s per run",
            "Silent egress packet drop at perimeter firewall",
        ],
    )
    v_submission = Verdict(
        target=Target(host="probe.netpolicy.org", port=587, service="Submission"),
        kind=VerdictKind.RESET,
        confidence=Confidence.HIGH,
        evidence=[
            "TCP RST received in 3ms",
            "Inbound TTL=64 indicates local gateway RST injection",
        ],
    )
    v_ftp = Verdict(
        target=Target(host="probe.netpolicy.org", port=21, service="FTP"),
        kind=VerdictKind.REJECTED,
        confidence=Confidence.HIGH,
        evidence=[
            "ICMP Type 3 Code 10 (Host Administratively Prohibited) from 192.168.44.1 in 2ms"
        ],
    )
    v_quic = Verdict(
        target=Target(host="probe.netpolicy.org", port=443, protocol="udp", service="QUIC"),
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
        evidence=[
            "UDP reply received from probe server in 23ms",
            "QUIC initial packet handshake accepted",
        ],
    )

    port_results = [v_ssh, v_https, v_smtp, v_smtps, v_submission, v_ftp, v_quic]

    # DNS verdicts
    v_dns_udp = Verdict(
        target=Target(host="8.8.8.8", port=53, protocol="udp", service="DNS"),
        kind=VerdictKind.INTERCEPTED,
        confidence=Confidence.HIGH,
        evidence=[
            "Queries to 8.8.8.8 intercepted by local gateway (TTL=64 instead of 115)",
            "NXDOMAIN query for 'test-nxdomain.invalid' redirected to 198.51.100.25 (ISP portal)",
        ],
    )
    v_dns_doh = Verdict(
        target=Target(host="cloudflare-dns.com", port=443, protocol="https", service="DoH"),
        kind=VerdictKind.OK,
        confidence=Confidence.HIGH,
        evidence=[
            "Encrypted DoH queries to https://cloudflare-dns.com/dns-query "
            "returned authentic NXDOMAIN"
        ],
    )
    dns_results = [v_dns_udp, v_dns_doh]

    # HTTP verdicts
    v_http_clear = Verdict(
        target=Target(host="probe.netpolicy.org", port=80, protocol="http", service="HTTP"),
        kind=VerdictKind.TAMPERED,
        confidence=Confidence.HIGH,
        evidence=[
            "Injected proxy headers detected: 'Via: 1.1 squid-proxy', "
            "'X-Cache: HIT from local-cache'",
            "Server header modified from 'nginx' to 'squid/5.7'",
        ],
    )
    v_http_tls = Verdict(
        target=Target(host="probe.netpolicy.org", port=443, protocol="https", service="HTTPS"),
        kind=VerdictKind.OK,
        confidence=Confidence.HIGH,
        evidence=[
            "End-to-end TLS certificate chain verified against public CA root (no MITM bump)"
        ],
    )
    http_results = [v_http_clear, v_http_tls]

    # High-level findings
    f_mail = Finding(
        title="Outbound Email Ports Blocked (Ports 25, 465, 587)",
        severity=Severity.HIGH,
        verdicts=[v_smtp, v_smtps, v_submission],
        summary=(
            "Outbound SMTP is blocked via silent packet drops on ports 25 and 465, "
            "and local gateway RST injection on port 587."
        ),
    )
    f_ftp = Finding(
        title="FTP Egress Prohibited (Port 21)",
        severity=Severity.MEDIUM,
        verdicts=[v_ftp],
        summary=(
            "FTP outbound traffic is actively rejected by the local gateway with ICMP "
            "Administratively Prohibited (Type 3, Code 10)."
        ),
    )
    f_dns = Finding(
        title="Transparent DNS Interception & NXDOMAIN Rewriting",
        severity=Severity.HIGH,
        verdicts=[v_dns_udp],
        summary=(
            "Unencrypted port 53 DNS queries are intercepted by the local network, "
            "and non-existent domains are rewritten to an ISP advertising portal."
        ),
    )
    f_http = Finding(
        title="HTTP Traffic Interception and Header Injection",
        severity=Severity.MEDIUM,
        verdicts=[v_http_clear],
        summary=(
            "Cleartext HTTP requests are intercepted by a transparent proxy that "
            "injects 'Via' and 'X-Cache' headers."
        ),
    )
    findings = [f_mail, f_ftp, f_dns, f_http]

    return AuditReport(
        schema_version="1",
        metadata=metadata,
        port_results=port_results,
        dns_results=dns_results,
        http_results=http_results,
        findings=findings,
    )
