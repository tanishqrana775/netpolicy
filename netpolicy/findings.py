"""Rule-based policy finding synthesis for netpolicy audit verdicts.

Adheres strictly to GEMINI.md design rules:
1. Rule-based only: deterministic synthesis of verdicts into plain-English findings (no AI).
2. Findings carry title, severity (info, warn, critical), associated verdicts, and summary.
3. Pure functions: list[Verdict] -> list[Finding]. Zero I/O.
"""

from __future__ import annotations

from netpolicy.models import Finding, Severity, Verdict, VerdictKind

__all__ = ["generate_findings"]

_BLOCKED_KINDS = frozenset(
    {
        VerdictKind.BLOCKED_DROP,
        VerdictKind.BLOCKED_RESET,
        VerdictKind.BLOCKED_ICMP,
        VerdictKind.CLOSED_OR_RESET,
        VerdictKind.DROPPED,
        VerdictKind.RESET,
        VerdictKind.REJECTED,
    }
)

_OPEN_KINDS = frozenset(
    {
        VerdictKind.OPEN,
        VerdictKind.OK,
        VerdictKind.CLEAN,
    }
)


def _is_blocked(v: Verdict) -> bool:
    """Return True if a verdict represents an unreachable or blocked port."""
    return v.kind in _BLOCKED_KINDS


def _is_open(v: Verdict) -> bool:
    """Return True if a verdict represents an open/reachable port."""
    return v.kind in _OPEN_KINDS


def generate_findings(
    port_results: list[Verdict] | None = None,
    dns_results: list[Verdict] | None = None,
    http_results: list[Verdict] | None = None,
) -> list[Finding]:
    """Synthesize audit verdicts across ports, DNS, and HTTP into high-level policy findings.

    Args:
        port_results: List of classified port reachability verdicts.
        dns_results: List of classified DNS audit verdicts.
        http_results: List of classified HTTP integrity verdicts.

    Returns:
        List of structured Finding objects with rule-based severity and plain-English summaries.
    """
    ports = port_results or []
    dns = dns_results or []
    http = http_results or []
    findings: list[Finding] = []

    port_map: dict[int, Verdict] = {v.target.port: v for v in ports if v.target.port is not None}

    # ------------------------------------------------------------------
    # Rule 1: Mail submission (Ports 25, 465, 587)
    # ------------------------------------------------------------------
    mail_ports = [25, 465, 587]
    audited_mail_ports = [p for p in mail_ports if p in port_map]
    if audited_mail_ports:
        all_mail_blocked = all(_is_blocked(port_map[p]) for p in audited_mail_ports)
        if len(audited_mail_ports) >= 2 and all_mail_blocked:
            findings.append(
                Finding(
                    title="Outbound Mail Submission Blocked",
                    severity=Severity.WARN,
                    verdicts=[port_map[p] for p in audited_mail_ports],
                    summary=(
                        "Mail submission is blocked on this network "
                        "(ports 25, 465, and 587 are unreachable)."
                    ),
                )
            )
        elif 25 in port_map and _is_blocked(port_map[25]):
            any_submission_open = any(p in port_map and _is_open(port_map[p]) for p in (465, 587))
            if any_submission_open:
                findings.append(
                    Finding(
                        title="Direct SMTP (Port 25) Blocked",
                        severity=Severity.INFO,
                        verdicts=[port_map[25]],
                        summary=(
                            "Direct SMTP port 25 is blocked (standard ISP anti-abuse policy); "
                            "submission ports 465/587 remain accessible."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Rule 2: SSH / Server Administration (Port 22)
    # ------------------------------------------------------------------
    if 22 in port_map and _is_blocked(port_map[22]):
        findings.append(
            Finding(
                title="Outbound SSH (Port 22) Blocked",
                severity=Severity.WARN,
                verdicts=[port_map[22]],
                summary=(
                    "Outbound SSH is blocked on this network, "
                    "preventing command-line server administration."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 3: Web Egress (Ports 80, 443)
    # ------------------------------------------------------------------
    if 80 in port_map and 443 in port_map:
        if _is_blocked(port_map[80]) and _is_blocked(port_map[443]):
            findings.append(
                Finding(
                    title="Web Access Blocked",
                    severity=Severity.CRITICAL,
                    verdicts=[port_map[80], port_map[443]],
                    summary="Web browsing ports (80 and 443) are completely unreachable.",
                )
            )
        elif _is_blocked(port_map[80]) and _is_open(port_map[443]):
            findings.append(
                Finding(
                    title="Plain HTTP (Port 80) Blocked",
                    severity=Severity.INFO,
                    verdicts=[port_map[80]],
                    summary=(
                        "Plain HTTP (port 80) is blocked; secure HTTPS (port 443) remains open."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Rule 4: Firewall TCP Reset Injection
    # ------------------------------------------------------------------
    reset_verdicts = [v for v in ports if v.kind == VerdictKind.BLOCKED_RESET]
    if reset_verdicts:
        findings.append(
            Finding(
                title="Firewall TCP Reset Injection",
                severity=Severity.WARN,
                verdicts=reset_verdicts,
                summary=(
                    "The network firewall actively injects TCP RST packets "
                    "to terminate unauthorized outbound connections."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 5: Firewall ICMP Administrative Prohibition
    # ------------------------------------------------------------------
    icmp_verdicts = [v for v in ports if v.kind == VerdictKind.BLOCKED_ICMP]
    if icmp_verdicts:
        findings.append(
            Finding(
                title="Firewall ICMP Administrative Prohibition",
                severity=Severity.WARN,
                verdicts=icmp_verdicts,
                summary=(
                    "Intermediate gateway or firewall actively returns "
                    "ICMP unreachable messages for filtered ports."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 6: Strict Outbound Port Filtering
    # ------------------------------------------------------------------
    if len(ports) >= 4:
        blocked_count = sum(1 for v in ports if _is_blocked(v))
        if blocked_count / len(ports) >= 0.7 and not any(
            f.title == "Web Access Blocked" for f in findings
        ):
            findings.append(
                Finding(
                    title="Strict Outbound Port Filtering",
                    severity=Severity.WARN,
                    verdicts=[v for v in ports if _is_blocked(v)],
                    summary=(
                        f"Strict egress filtering active: {blocked_count}/{len(ports)} "
                        "audited outbound ports are blocked."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Rule 7: DNS Interception with DoH Bypass
    # ------------------------------------------------------------------
    intercepted_dns = [v for v in dns if v.kind == VerdictKind.INTERCEPTED]
    doh_verdicts = [
        v for v in dns if "doh" in (v.target.service or "").lower() or v.target.protocol == "https"
    ]
    doh_working = any(v.kind in _OPEN_KINDS for v in doh_verdicts)

    if intercepted_dns and doh_working:
        findings.append(
            Finding(
                title="DNS Interception Bypassed by DoH",
                severity=Severity.CRITICAL,
                verdicts=intercepted_dns + [v for v in doh_verdicts if v.kind in _OPEN_KINDS],
                summary="DNS is redirected, but encrypted DNS bypasses it.",
            )
        )
    elif intercepted_dns:
        findings.append(
            Finding(
                title="DNS Queries Intercepted",
                severity=Severity.CRITICAL,
                verdicts=intercepted_dns,
                summary=(
                    "In-path middlebox or gateway intercepts and alters unencrypted DNS queries."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 8: NXDOMAIN Hijacking
    # ------------------------------------------------------------------
    rewritten_dns = [v for v in dns if v.kind == VerdictKind.REWRITTEN]
    if rewritten_dns:
        findings.append(
            Finding(
                title="NXDOMAIN Hijacking Active",
                severity=Severity.WARN,
                verdicts=rewritten_dns,
                summary=(
                    "Nonexistent domains (.invalid) return IP addresses instead of "
                    "NXDOMAIN (ISP search portal or ad injection)."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 9: DNS Resolution Discrepancy
    # ------------------------------------------------------------------
    mismatch_dns = [v for v in dns if v.kind == VerdictKind.MISMATCH]
    if mismatch_dns and not intercepted_dns:
        findings.append(
            Finding(
                title="DNS Resolution Discrepancy",
                severity=Severity.WARN,
                verdicts=mismatch_dns,
                summary=(
                    "Plain DNS resolution answers do not match secure DoH baseline "
                    "outside normal CDN subnets."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 10: HTTP Payload Tampering (BODY_MODIFIED)
    # ------------------------------------------------------------------
    tampered_http = [v for v in http if v.kind == VerdictKind.BODY_MODIFIED]
    if tampered_http:
        findings.append(
            Finding(
                title="HTTP Payload Tampered in Transit",
                severity=Severity.CRITICAL,
                verdicts=tampered_http,
                summary=(
                    "Canary payload SHA-256 mismatch detected; HTTP body content was "
                    "modified in transit by an intermediary."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 11: HTTP Proxy Header Injection (HEADERS_INJECTED)
    # ------------------------------------------------------------------
    injected_http = [v for v in http if v.kind == VerdictKind.HEADERS_INJECTED]
    if injected_http:
        findings.append(
            Finding(
                title="HTTP Proxy Header Injection",
                severity=Severity.WARN,
                verdicts=injected_http,
                summary=(
                    "Intermediary proxy injected caching or tracking headers "
                    "(e.g. Via, X-Cache) into HTTP responses."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 12: HTTP Rewriting Proxy (PROXIED)
    # ------------------------------------------------------------------
    proxied_http = [v for v in http if v.kind == VerdictKind.PROXIED]
    if proxied_http:
        findings.append(
            Finding(
                title="HTTP Traffic Intercepted by Rewriting Proxy",
                severity=Severity.CRITICAL,
                verdicts=proxied_http,
                summary=(
                    "Canary nonce was stripped or altered in transit, "
                    "confirming request header rewriting."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 13: HTTP Captive Portal / Redirection (REDIRECTED)
    # ------------------------------------------------------------------
    redirected_http = [v for v in http if v.kind == VerdictKind.REDIRECTED]
    if redirected_http:
        findings.append(
            Finding(
                title="Captive Portal or HTTP Redirection Detected",
                severity=Severity.WARN,
                verdicts=redirected_http,
                summary=(
                    "HTTP requests were intercepted and redirected to an "
                    "authentication landing page or captive portal."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Rule 14: Network Packet Loss
    # ------------------------------------------------------------------
    lossy_ports = [v for v in ports if v.kind == VerdictKind.LOSSY]
    if lossy_ports:
        findings.append(
            Finding(
                title="Network Packet Loss Detected",
                severity=Severity.INFO,
                verdicts=lossy_ports,
                summary="Unstable network connection: packet loss observed across probe attempts.",
            )
        )

    return findings
