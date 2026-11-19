# ruff: noqa: E501
"""Pure data models, aggregation logic, reliability gates, and verdict computation for terminal reports."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from netpolicy.models import AuditReport, Confidence, Verdict, VerdictKind
from netpolicy.report.humanize import (
    extract_redirects_from_evidence,
    format_redirect_plain,
    humanize_verdict_kind,
    is_canary_404_error,
    is_documentation_address_answered,
    is_ssl_wrong_version_error,
    is_whoami_out_of_range,
    service_group,
)

# RFC 5737 and RFC 3849 documentation networks
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),  # IPv6 documentation
)


@dataclass
class Issue:
    """Aggregated network finding or anomaly for report presentation."""

    area: str  # "ports", "dns", "web", "canary"
    subject: str
    kind: str
    confidence: Confidence
    attempts: int
    runs_seen: int
    runs_total: int
    plain: str
    technical: list[str] = field(default_factory=list)
    valid: bool = True
    invalid_reason: str | None = None
    expect_open: bool = False

    @property
    def display_area(self) -> str:
        """User-facing area column name."""
        if self.area == "dns":
            return "Name lookups"
        if self.area == "ports":
            if "port 80" in self.subject.lower() or "port 443" in self.subject.lower():
                return "Websites"
            return "Remote services"
        if self.area in ("web", "canary"):
            if "redirect" in self.plain.lower() or "website" in self.subject.lower():
                return "Websites"
            return "Web content"
        return "Remote services"

    @property
    def multiplier_str(self) -> str:
        """Formatted multiplier string for presentation (e.g. 'x20' or '5 of 5 runs')."""
        if self.runs_total > 1:
            return f"{self.runs_seen} of {self.runs_total} runs"
        if self.attempts > 1:
            return f"x{self.attempts}"
        return ""


@dataclass
class Caveat:
    """Reliability note emitted when a gate adjusts or invalidates an issue."""

    code: str
    plain: str
    technical: str


@dataclass
class VerdictSummary:
    """Overall audit verdict synthesizing findings, reliability gates, and confidence."""

    level: str  # "CLEAN", "LIMITED", "ACTION_REQUIRED", "RESTRICTED", "INCONCLUSIVE"
    sentence: str
    confidence: Confidence
    tested_summary: str


def _is_documentation_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to official documentation networks."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in DOCUMENTATION_NETWORKS)
    except ValueError:
        return False


def _is_same_host_upgrade(request_host: str, location_url: str) -> bool:
    """Check if redirect is a benign scheme/port upgrade on the same host."""
    parsed = urlparse(location_url)
    loc_host = parsed.hostname or ""
    req_host = request_host.split(":")[0].strip()
    return loc_host.lower() == req_host.lower()


def aggregate(report: AuditReport) -> list[Issue]:
    """Aggregate raw verdicts from an AuditReport into distinct, deduplicated Issues."""
    issues: list[Issue] = []
    runs_total = max(1, report.metadata.runs_per_check)

    # 1. Aggregate Port Results
    for verdict in report.port_results:
        if verdict.kind in (VerdictKind.OPEN, VerdictKind.OK, VerdictKind.CLEAN):
            continue

        subj = f"Port {verdict.target.port} ({verdict.target.service or 'TCP'})"
        grp = service_group(verdict.target.port)

        runs_seen = runs_total
        attempts = 1
        for ev in verdict.evidence:
            m_runs = re.search(r"(\d+)/(\d+)\s+runs", ev)
            if m_runs:
                runs_seen = int(m_runs.group(1))
                runs_total = int(m_runs.group(2))
            m_att = re.search(r"(\d+)/(\d+)\s+replies", ev)
            if m_att:
                attempts = int(m_att.group(2))

        plain_verb = humanize_verdict_kind(verdict.kind)
        plain = f"{plain_verb} on port {verdict.target.port} ({grp})"

        issues.append(
            Issue(
                area="ports",
                subject=subj,
                kind=verdict.kind.value,
                confidence=verdict.confidence,
                attempts=attempts,
                runs_seen=runs_seen,
                runs_total=runs_total,
                plain=plain,
                technical=list(verdict.evidence),
                expect_open=verdict.target.expect_open,
            )
        )

    # 2. Aggregate DNS Results
    # Group dns results by target / service
    dns_by_probe: dict[str, list[Verdict]] = {}
    for verdict in report.dns_results:
        key = f"{verdict.target.service or 'DNS'} ({verdict.target.host})"
        dns_by_probe.setdefault(key, []).append(verdict)

    for probe_key, v_list in dns_by_probe.items():
        kinds = {v.kind for v in v_list}
        non_clean = [v for v in v_list if v.kind not in (VerdictKind.CLEAN, VerdictKind.OK)]

        if not non_clean:
            # 100% clean
            continue

        # Check for inconsistent outcomes across runs
        has_clean = any(v.kind in (VerdictKind.CLEAN, VerdictKind.OK) for v in v_list)
        total_runs = max(len(v_list), runs_total)
        runs_seen = len(non_clean)

        first_nc = non_clean[0]
        all_ev: list[str] = []
        for v in non_clean:
            for e in v.evidence:
                if e not in all_ev:
                    all_ev.append(e)

        if has_clean and len(kinds) > 1:
            plain = f"Inconsistent DNS responses across runs ({runs_seen} of {total_runs} runs showed anomalies)"
            issues.append(
                Issue(
                    area="dns",
                    subject=probe_key,
                    kind="INCONSISTENT",
                    confidence=Confidence.MEDIUM,
                    attempts=len(all_ev) or runs_seen,
                    runs_seen=runs_seen,
                    runs_total=total_runs,
                    plain=plain,
                    technical=all_ev,
                )
            )
        else:
            # Consistent non-clean verdict
            if first_nc.kind == VerdictKind.INTERCEPTED:
                if any(is_documentation_address_answered(e) for e in all_ev):
                    plain = "A device answered an address lookup sent to an unused address"
                elif any(is_whoami_out_of_range(e) for e in all_ev):
                    plain = "Lookup service identity could not be verified"
                else:
                    plain = "Address lookups intercepted by the local network filter"
            elif first_nc.kind == VerdictKind.REWRITTEN:
                plain = "Address lookups altered or redirected by network"
            else:
                plain = f"Address lookup anomaly: {humanize_verdict_kind(first_nc.kind)}"

            issues.append(
                Issue(
                    area="dns",
                    subject=probe_key,
                    kind=first_nc.kind.value,
                    confidence=first_nc.confidence,
                    attempts=len(all_ev) or runs_seen,
                    runs_seen=runs_seen,
                    runs_total=total_runs,
                    plain=plain,
                    technical=all_ev,
                )
            )

    # 3. Aggregate HTTP Results
    http_by_group: dict[tuple[str, str], list[Verdict]] = {}
    for verdict in report.http_results:
        if verdict.kind in (VerdictKind.CLEAN, VerdictKind.OK):
            continue
        key = (verdict.target.host, verdict.kind.value)
        http_by_group.setdefault(key, []).append(verdict)

    for (host, kind_val), v_list in http_by_group.items():
        all_ev: list[str] = []
        for v in v_list:
            for e in v.evidence:
                if e not in all_ev:
                    all_ev.append(e)

        port = v_list[0].target.port or 80
        subj = f"http://{host}:{port}" if port != 443 else f"https://{host}"
        attempts = len(v_list)

        if kind_val == VerdictKind.REDIRECTED.value:
            # Check if evidence contains redirect
            plain = "Web requests redirected"
            for e in all_ev:
                if "unexpected http redirect" in e.lower():
                    plain = format_redirect_plain(e)
                    break
                if is_canary_404_error(e):
                    plain = "The test server does not host the netpolicy canary file"
        elif kind_val == VerdictKind.UNKNOWN.value:
            if any(is_ssl_wrong_version_error(e) for e in all_ev):
                plain = "Secure connection attempt failed on a plain-HTTP port (a test problem, not a network block)"
            else:
                plain = "Web check could not complete"
        elif kind_val in (VerdictKind.BODY_MODIFIED.value, VerdictKind.TAMPERED.value):
            plain = "Web content modified in transit"
        elif kind_val in (VerdictKind.HEADERS_INJECTED.value, VerdictKind.PROXIED.value):
            plain = "Network proxy injected intermediate headers"
        else:
            plain = f"Web page anomaly: {humanize_verdict_kind(kind_val)}"

        issues.append(
            Issue(
                area="web",
                subject=subj,
                kind=kind_val,
                confidence=v_list[0].confidence,
                attempts=attempts,
                runs_seen=max(1, attempts // 4 or 1),
                runs_total=runs_total,
                plain=plain,
                technical=all_ev,
            )
        )

    return issues


def apply_reliability_gates(
    issues: list[Issue],
    report: AuditReport,
) -> tuple[list[Issue], list[Caveat]]:
    """Apply reliability gates G1-G5 to calibrate, invalidate, or adjust findings."""
    caveats: list[Caveat] = []
    target_host = report.metadata.target or ""

    # Check G1 condition: Did any HTTP observation test and/or verify the canary manifest?
    canary_tested = any(
        (v.target.service and "canary" in v.target.service.lower())
        or any(is_canary_404_error(e) or "canary" in e.lower() for e in v.evidence)
        for v in report.http_results
    )
    has_verified_canary = any(
        v.kind in (VerdictKind.CLEAN, VerdictKind.OK)
        and any(
            "sha-256 verified" in e.lower() or "matches expected" in e.lower() for e in v.evidence
        )
        for v in report.http_results
    )

    g1_fired = bool(canary_tested and not has_verified_canary)
    g2_fired = False
    g3_fired = False
    g4_fired = False
    g5_fired = False

    for issue in issues:
        # ---------------------------------------------------------------------
        # Gate G5: Probe errors (SSL wrong version, probe-side connection drops)
        # ---------------------------------------------------------------------
        if any(is_ssl_wrong_version_error(t) for t in issue.technical):
            issue.valid = False
            issue.invalid_reason = "probe error: SSL wrong version on plain HTTP port"
            g5_fired = True
            continue

        # ---------------------------------------------------------------------
        # Gate G2: Blackhole probe validity
        # ---------------------------------------------------------------------
        if issue.area == "dns" and (
            "blackhole" in issue.subject.lower()
            or any(is_documentation_address_answered(t) for t in issue.technical)
        ):
            # Check queried address
            queried_ip = target_host
            for t in issue.technical:
                m = re.search(r"Documentation address\s+([0-9a-fA-F.:]+)", t)
                if m:
                    queried_ip = m.group(1)
                    break
            if not _is_documentation_ip(queried_ip):
                issue.valid = False
                issue.invalid_reason = (
                    f"queried address {queried_ip} is not an RFC 5737/3849 documentation IP"
                )
                g2_fired = True
                continue

        # ---------------------------------------------------------------------
        # Gate G3: Benign scheme/port upgrade
        # ---------------------------------------------------------------------
        if issue.area == "web" and issue.kind == VerdictKind.REDIRECTED.value:
            is_benign = False
            for t in issue.technical:
                redirects = extract_redirects_from_evidence(t)
                for r in redirects:
                    loc = r.get("location", "")
                    if _is_same_host_upgrade(target_host, loc):
                        is_benign = True
                        break
            if is_benign:
                issue.valid = False
                issue.invalid_reason = "benign same-host HTTP-to-HTTPS upgrade"
                g3_fired = True
                continue

        # ---------------------------------------------------------------------
        # Gate G4: Address-family mismatch (IPv6 egress vs IPv4 CIDRs)
        # ---------------------------------------------------------------------
        if issue.area == "dns" and (
            "whoami" in issue.subject.lower()
            or any(is_whoami_out_of_range(t) for t in issue.technical)
        ):
            has_ipv6_egress = False
            for t in issue.technical:
                m_ip = re.search(r"egress IP '([0-9a-fA-F:]+)'", t)
                if m_ip and ":" in m_ip.group(1):
                    has_ipv6_egress = True
                    break
            if has_ipv6_egress:
                issue.kind = "INCONCLUSIVE"
                issue.confidence = Confidence.LOW
                issue.plain = (
                    "Resolver identity could not be verified (IPv6 egress address vs IPv4 ranges)"
                )
                issue.valid = False
                issue.invalid_reason = (
                    "address-family mismatch: IPv6 egress address compared against IPv4 ranges"
                )
                g4_fired = True
                continue

        # ---------------------------------------------------------------------
        # Gate G1: Unverified canary
        # ---------------------------------------------------------------------
        if canary_tested and not has_verified_canary:
            # Invalidate HTTP status/redirect checks
            if issue.area in ("web", "canary") and (
                issue.kind in (VerdictKind.REDIRECTED.value, "REDIRECTED")
                or any(is_canary_404_error(t) for t in issue.technical)
            ):
                issue.valid = False
                issue.invalid_reason = "this server is not a netpolicy canary"
                g1_fired = True
            # Downgrade port drop/reset results if not expect_open
            elif (
                issue.area == "ports"
                and not issue.expect_open
                and issue.kind
                in (
                    VerdictKind.BLOCKED_DROP.value,
                    VerdictKind.DROPPED.value,
                    VerdictKind.BLOCKED_RESET.value,
                    VerdictKind.RESET.value,
                )
            ):
                issue.kind = "NO_REPLY"
                issue.confidence = Confidence.LOW
                issue.plain = f"No reply on {issue.subject} (server may be closed)"
                issue.invalid_reason = (
                    "cannot tell whether the network or the server is responsible"
                )
                g1_fired = True

    # Assemble Caveats based on fired gates
    if g1_fired:
        caveats.append(
            Caveat(
                code="G1",
                plain="The test target does not host a netpolicy canary; server silence cannot be distinguished from network blocks.",
                technical="No HTTP response matched the expected canary SHA-256 manifest; port drop/reset verdicts downgraded to LOW confidence NO_REPLY.",
            )
        )
    if g2_fired:
        caveats.append(
            Caveat(
                code="G2",
                plain="DNS blackhole check queried a live server instead of a documentation IP address.",
                technical="Queried address is outside documentation networks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32); result marked invalid.",
            )
        )
    if g3_fired:
        caveats.append(
            Caveat(
                code="G3",
                plain="Same-host HTTP-to-HTTPS redirect was recognized as a standard security upgrade.",
                technical="Redirect differs only by scheme/port; dropped from tampering findings.",
            )
        )
    if g4_fired:
        caveats.append(
            Caveat(
                code="G4",
                plain="DNS resolver egressed over IPv6 while only IPv4 provider ranges were configured.",
                technical="Whoami check evaluated IPv6 address against IPv4 CIDRs; classified as INCONCLUSIVE rather than INTERCEPTED.",
            )
        )
    if g5_fired:
        caveats.append(
            Caveat(
                code="G5",
                plain="Some checks could not complete due to protocol or connection errors.",
                technical="SSL WRONG_VERSION_NUMBER on port 80 moved to checks that could not run; not classified as tampering.",
            )
        )

    return issues, caveats


def compute_verdict(
    issues: list[Issue],
    caveats: list[Caveat],
    report: AuditReport | None = None,
) -> VerdictSummary:
    """Compute overall verdict level, plain sentence, confidence, and tested summary."""
    valid_issues = [i for i in issues if i.valid]

    # Generate tested summary
    port_count = len(report.port_results) if report else 0
    dns_count = len({v.target.host for v in report.dns_results}) if report else 0
    http_count = len({v.target.host for v in report.http_results}) if report else 0
    tested_parts = []
    if port_count:
        tested_parts.append(f"{port_count} ports")
    if dns_count:
        tested_parts.append(f"{dns_count} DNS resolvers")
    if http_count:
        tested_parts.append(f"{http_count} web endpoints")
    tested_summary = (
        f"Tested: {', '.join(tested_parts)}" if tested_parts else "Tested: standard suite"
    )

    # Precedence:
    # 1. INCONCLUSIVE (control probe failed, or no verified canary and no confirmed problem)
    g1_fired = any(c.code == "G1" for c in caveats)
    g4_fired = any(c.code == "G4" for c in caveats)
    has_inconclusive_issues = any(i.kind == "INCONCLUSIVE" for i in issues)
    has_tampering = any(
        i.kind
        in (
            VerdictKind.INTERCEPTED.value,
            VerdictKind.TAMPERED.value,
            VerdictKind.REWRITTEN.value,
            VerdictKind.HEADERS_INJECTED.value,
            VerdictKind.BODY_MODIFIED.value,
            VerdictKind.PROXIED.value,
        )
        for i in valid_issues
    )
    block_kinds = (
        VerdictKind.BLOCKED_DROP.value,
        VerdictKind.BLOCKED_RESET.value,
        VerdictKind.BLOCKED_ICMP.value,
        VerdictKind.DROPPED.value,
        VerdictKind.RESET.value,
        VerdictKind.REJECTED.value,
        VerdictKind.CLOSED_OR_RESET.value,
        "BLOCKED_DROP",
        "BLOCKED_RESET",
        "BLOCKED_ICMP",
        "DROPPED",
        "RESET",
        "REJECTED",
        "CLOSED_OR_RESET",
    )
    has_blocks = any(i.kind in block_kinds for i in valid_issues)
    has_captive_portal = any(
        i.kind == VerdictKind.REDIRECTED.value and "redirected" in i.plain.lower()
        for i in valid_issues
    )

    if (g1_fired or g4_fired or has_inconclusive_issues) and not (
        has_tampering or has_blocks or has_captive_portal
    ):
        if g4_fired or has_inconclusive_issues:
            sentence = (
                "Audit is inconclusive because resolver identity could not be verified "
                "(IPv6 egress address vs IPv4 ranges), but no network tampering was detected."
            )
        else:
            sentence = (
                "Audit is inconclusive because the target is not a netpolicy canary, "
                "but no network tampering was detected."
            )
        return VerdictSummary(
            level="INCONCLUSIVE",
            sentence=sentence,
            confidence=Confidence.LOW,
            tested_summary=tested_summary,
        )

    # 2. ACTION_REQUIRED (captive portal: redirect to a different host, valid and not benign)
    if has_captive_portal:
        portal_issue = next(i for i in valid_issues if i.kind == VerdictKind.REDIRECTED.value)
        return VerdictSummary(
            level="ACTION_REQUIRED",
            sentence=f"A captive portal is blocking internet access ({portal_issue.plain}).",
            confidence=Confidence.HIGH,
            tested_summary=tested_summary,
        )

    # 3. RESTRICTED (confirmed DNS interception/rewriting, content modification, or 2+ service groups blocked)
    blocked_groups = {
        service_group(int(m.group(1)))
        for i in valid_issues
        if i.area == "ports" and i.kind in block_kinds
        for m in [re.search(r"Port\s+(\d+)", i.subject)]
        if m
    }

    if has_tampering or len(blocked_groups) >= 2:
        return VerdictSummary(
            level="RESTRICTED",
            sentence="Your network is restricting or altering network traffic.",
            confidence=Confidence.HIGH,
            tested_summary=tested_summary,
        )

    # 4. LIMITED (some services blocked, nothing tampered)
    if has_blocks or len(blocked_groups) == 1:
        grp_name = next(iter(blocked_groups)) if blocked_groups else "outbound services"
        return VerdictSummary(
            level="LIMITED",
            sentence=f"Some outbound services ({grp_name}) are blocked, but no network tampering was detected.",
            confidence=Confidence.HIGH,
            tested_summary=tested_summary,
        )

    # 5. CLEAN (verified canary, control OK, nothing found)
    return VerdictSummary(
        level="CLEAN",
        sentence="All network policy checks passed cleanly. No unexpected blocks, tampering, or interceptions detected.",
        confidence=Confidence.HIGH,
        tested_summary=tested_summary,
    )


def recommendations(issues: list[Issue], verdict: VerdictSummary) -> list[str]:
    """Generate at most 3 prioritized, rule-based recommendations for valid findings."""
    valid_issues = [i for i in issues if i.valid]
    recs: list[str] = []

    # 1. Captive portal
    if any(i.kind == VerdictKind.REDIRECTED.value for i in valid_issues):
        recs.append(
            "Sign in via your web browser to complete captive portal authentication, then re-run the audit."
        )

    # 2. DNS interception
    if any(
        "dns" in i.area and i.kind in (VerdictKind.INTERCEPTED.value, VerdictKind.REWRITTEN.value)
        for i in valid_issues
    ):
        recs.append(
            "Configure encrypted DNS (DNS-over-HTTPS or DNS-over-TLS) or use a trusted VPN."
        )

    # 3. Remote login / SSH blocked
    if any(
        "22" in i.subject
        and i.kind
        in (
            VerdictKind.BLOCKED_DROP.value,
            VerdictKind.BLOCKED_RESET.value,
            VerdictKind.BLOCKED_ICMP.value,
        )
        for i in valid_issues
    ):
        recs.append("Try connecting to SSH over port 443 or use a VPN to reach remote servers.")

    # 4. Mail sending blocked
    if any(
        any(p in i.subject for p in ("25", "465", "587"))
        and i.kind in (VerdictKind.BLOCKED_DROP.value, VerdictKind.BLOCKED_RESET.value)
        for i in valid_issues
    ):
        recs.append(
            "Use your email provider's web interface or authenticated REST API instead of direct SMTP ports."
        )

    # 5. Content tampering
    if any(
        i.kind
        in (
            VerdictKind.BODY_MODIFIED.value,
            VerdictKind.HEADERS_INJECTED.value,
            VerdictKind.TAMPERED.value,
        )
        for i in valid_issues
    ):
        recs.append(
            "Prefer HTTPS sites and consider a VPN to protect against in-transit network modification."
        )

    # 6. Inconclusive public target
    if verdict.level == "INCONCLUSIVE" and len(recs) < 3:
        recs.append(
            "Run netpolicy against your own dedicated control server using --target for definitive policy results."
        )

    return recs[:3]
