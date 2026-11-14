"""Pure classification functions and decision rules for DNS observations.

Adheres strictly to GEMINI.md design rules:
1. Pure functions: list[Observation] -> Verdict. No I/O.
2. If control probe fails, verdicts must become UNKNOWN.
3. Every verdict carries a confidence level (HIGH/MEDIUM/LOW) and human-readable evidence strings.

DNS Verdict Kinds:
- CLEAN: No interception, rewriting, or unexpected mismatches detected.
- INTERCEPTED: Reply from a documentation (blackhole) address, UDP/53 source IP mismatch,
  or whoami resolver identity outside expected provider IP range (high confidence).
- REWRITTEN: Nonexistent .invalid name returned an A record instead of NXDOMAIN (high confidence).
- MISMATCH: Plain-DNS and DoH answers do not overlap (compared loosely by same /16
  or exact set overlap) because CDN geo-variation is normal. Confidence is lowered
  when only a few domains differ.
- UNKNOWN: Control probe failed, empty observations, or all DNS queries timed out without replies.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from netpolicy.models import Confidence, Observation, Target, Verdict, VerdictKind

__all__ = [
    "classify_dns",
    "classify_dns_checks",
    "answers_overlap_loosely",
    "DEFAULT_PROVIDER_WHOAMI_RANGES",
    "BLACKHOLE_NETWORKS",
]

# RFC 5737 IPv4 documentation blocks that must never be answered on the Internet
BLACKHOLE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),  # TEST-NET-3
]

# Known public resolver egress subnets used as defaults for Whoami checks
DEFAULT_PROVIDER_WHOAMI_RANGES: dict[str, list[str]] = {
    # Google Public DNS (8.8.8.8, 8.8.4.4)
    "8.8.8.8": [
        "8.8.8.0/24",
        "8.8.4.0/24",
        "172.217.0.0/16",
        "216.58.192.0/19",
        "74.125.0.0/16",
        "142.250.0.0/15",
    ],
    "8.8.4.4": [
        "8.8.8.0/24",
        "8.8.4.0/24",
        "172.217.0.0/16",
        "216.58.192.0/19",
        "74.125.0.0/16",
        "142.250.0.0/15",
    ],
    # Cloudflare (1.1.1.1, 1.0.0.1)
    "1.1.1.1": [
        "1.1.1.0/24",
        "1.0.0.0/24",
        "172.64.0.0/13",
        "162.158.0.0/15",
        "108.162.192.0/18",
        "198.41.128.0/17",
    ],
    "1.0.0.1": [
        "1.1.1.0/24",
        "1.0.0.0/24",
        "172.64.0.0/13",
        "162.158.0.0/15",
        "108.162.192.0/18",
        "198.41.128.0/17",
    ],
    # Quad9 (9.9.9.9)
    "9.9.9.9": [
        "9.9.9.0/24",
        "149.112.112.0/24",
    ],
}


def _is_blackhole_ip(address_str: str | None) -> bool:
    """Return True if the IP address belongs to RFC 5737 documentation networks."""
    if not address_str:
        return False
    try:
        ip = ipaddress.ip_address(address_str.strip())
        return any(ip in net for net in BLACKHOLE_NETWORKS)
    except ValueError:
        return False


def _is_ip_in_ranges(ip_str: str, ranges: list[str]) -> bool:
    """Check if an IP address string falls inside any of the specified CIDR ranges."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    for r in ranges:
        try:
            net = ipaddress.ip_network(r.strip(), strict=False)
            if ip in net:
                return True
        except ValueError:
            continue
    return False


def answers_overlap_loosely(plain_answers: list[str], doh_answers: list[str]) -> bool:
    """Check if two DNS answer sets overlap either exactly or within a loose /16 IPv4 subnet.

    Accommodates legitimate CDN geo-variation (e.g. Cloudflare, Fastly, Akamai) while detecting
    complete redirection/hijacking.
    """
    p_set = set(plain_answers)
    d_set = set(doh_answers)
    if not p_set or not d_set:
        return False

    # 1. Exact answer record overlap
    if bool(p_set & d_set):
        return True

    # 2. Loose IPv4 /16 prefix match
    for p_str in plain_answers:
        try:
            p_ip = ipaddress.ip_address(p_str.strip())
        except ValueError:
            continue
        if p_ip.version != 4:
            continue

        p_net = ipaddress.ip_network(f"{p_ip}/16", strict=False)
        for d_str in doh_answers:
            try:
                d_ip = ipaddress.ip_address(d_str.strip())
            except ValueError:
                continue
            if d_ip.version == 4 and d_ip in p_net:
                return True

    return False


def classify_dns_checks(
    observations: list[Observation],
    control_reachable: bool = True,
    expected_whoami_ranges: list[str] | None = None,
) -> list[Verdict]:
    """Classify DNS observations, producing per-check verdicts for each audited capability.

    Returns verdicts for:
    - Blackhole interception check
    - Source IP mismatch check
    - Whoami resolver identity check
    - NXDOMAIN hijacking check
    - DoH cross-check consistency
    """
    if not observations:
        return [
            Verdict(
                target=Target(host="unknown", service="DNS"),
                kind=VerdictKind.UNKNOWN,
                confidence=Confidence.LOW,
                evidence=["No DNS observations provided."],
            )
        ]

    first_target = observations[0].target
    if not control_reachable:
        return [
            Verdict(
                target=first_target,
                kind=VerdictKind.UNKNOWN,
                confidence=Confidence.HIGH,
                evidence=["Control probe failed; cannot verify DNS baseline."],
            )
        ]

    verdicts: list[Verdict] = []

    # 1. Evaluate Blackhole Probes
    bh_obs = [
        o
        for o in observations
        if o.probe_name == "dns_blackhole"
        or "blackhole" in (o.target.service or "").lower()
        or _is_blackhole_ip(o.raw.get("queried_address"))
        or _is_blackhole_ip(o.target.host)
    ]
    if bh_obs:
        replies = [o for o in bh_obs if o.raw.get("reply_received") or o.success]
        if replies:
            evidences = [
                f"Documentation address {r.raw.get('queried_address') or r.target.host} answered "
                f"over {r.raw.get('protocol', 'udp').upper()}/53 (answers: {r.raw.get('answers')}) "
                f"- in-path middlebox intercepted documentation IP."
                for r in replies
            ]
            verdicts.append(
                Verdict(
                    target=replies[0].target,
                    kind=VerdictKind.INTERCEPTED,
                    confidence=Confidence.HIGH,
                    evidence=evidences,
                )
            )
        else:
            verdicts.append(
                Verdict(
                    target=bh_obs[0].target,
                    kind=VerdictKind.CLEAN,
                    confidence=Confidence.HIGH,
                    evidence=[
                        "Documentation addresses (192.0.2.1, 198.51.100.1) "
                        "correctly did not answer."
                    ],
                )
            )

    # 2. Evaluate Source Mismatch Probes
    src_obs = [
        o
        for o in observations
        if o.probe_name in ("dns_source_mismatch", "source_mismatch")
        or "sourcemismatch" in (o.target.service or "").lower()
        or o.raw.get("source_differs") is not None
    ]
    if src_obs:
        mismatched = [
            o
            for o in src_obs
            if o.raw.get("source_differs") is True
            or (
                o.raw.get("source_address")
                and o.raw.get("queried_address")
                and o.raw.get("source_address") != o.raw.get("queried_address")
            )
        ]
        if mismatched:
            evidences = [
                f"DNS reply source address {m.raw.get('source_address')} differs from queried "
                f"resolver {m.raw.get('queried_address')} over UDP/53."
                for m in mismatched
            ]
            verdicts.append(
                Verdict(
                    target=mismatched[0].target,
                    kind=VerdictKind.INTERCEPTED,
                    confidence=Confidence.HIGH,
                    evidence=evidences,
                )
            )
        elif any(o.raw.get("reply_received") for o in src_obs):
            verdicts.append(
                Verdict(
                    target=src_obs[0].target,
                    kind=VerdictKind.CLEAN,
                    confidence=Confidence.HIGH,
                    evidence=["DNS reply source addresses matched queried resolvers."],
                )
            )

    # 3. Evaluate Whoami Probes
    whoami_obs = [
        o
        for o in observations
        if o.probe_name == "dns_whoami" or "whoami" in (o.target.service or "").lower()
    ]
    if whoami_obs:
        answered_whoami = [
            o for o in whoami_obs if o.raw.get("reply_received") and o.raw.get("rcode") == 0
        ]
        if answered_whoami:
            for obs in answered_whoami:
                queried_res = obs.raw.get("queried_address") or obs.target.host
                ranges = (
                    expected_whoami_ranges
                    if expected_whoami_ranges is not None
                    else DEFAULT_PROVIDER_WHOAMI_RANGES.get(queried_res)
                )
                txt_ans = obs.raw.get("txt_answers") or [
                    a.strip('"') for a in obs.raw.get("answers", [])
                ]
                out_of_range_ips: list[str] = []

                if ranges:
                    for ans in txt_ans:
                        if not _is_ip_in_ranges(ans, ranges):
                            out_of_range_ips.append(ans)

                if out_of_range_ips:
                    verdicts.append(
                        Verdict(
                            target=obs.target,
                            kind=VerdictKind.INTERCEPTED,
                            confidence=Confidence.HIGH,
                            evidence=[
                                f"Whoami resolver egress IP '{ip}' is outside expected "
                                f"provider range(s) {ranges} for resolver {queried_res}."
                                for ip in out_of_range_ips
                            ],
                        )
                    )
                else:
                    ans_list = ", ".join(txt_ans)
                    verdicts.append(
                        Verdict(
                            target=obs.target,
                            kind=VerdictKind.CLEAN,
                            confidence=Confidence.HIGH,
                            evidence=[
                                f"Whoami resolver egress IP ({ans_list}) "
                                "verified within expected provider bounds."
                            ],
                        )
                    )

    # 4. Evaluate NXDOMAIN Hijacking Probes
    nx_obs = [
        o
        for o in observations
        if o.probe_name == "dns_nxdomain"
        or "nxdomain" in (o.target.service or "").lower()
        or str(o.raw.get("qname", "")).endswith(".invalid")
    ]
    if nx_obs:
        hijacked = [
            o
            for o in nx_obs
            if (o.raw.get("a_records") or (o.raw.get("rcode") == 0 and o.raw.get("answers")))
        ]
        if hijacked:
            evidences = [
                f"Nonexistent '{h.raw.get('qname')}' returned A record(s) "
                f"{h.raw.get('a_records') or h.raw.get('answers')} "
                f"(rcode: {h.raw.get('rcode_name', h.raw.get('rcode'))}) "
                "instead of NXDOMAIN (NXDOMAIN hijacking)."
                for h in hijacked
            ]
            verdicts.append(
                Verdict(
                    target=hijacked[0].target,
                    kind=VerdictKind.REWRITTEN,
                    confidence=Confidence.HIGH,
                    evidence=evidences,
                )
            )
        elif any(o.raw.get("reply_received") for o in nx_obs):
            verdicts.append(
                Verdict(
                    target=nx_obs[0].target,
                    kind=VerdictKind.CLEAN,
                    confidence=Confidence.HIGH,
                    evidence=[
                        "All .invalid test domains returned expected NXDOMAIN "
                        "without injected A records."
                    ],
                )
            )

    # 5. Evaluate DoH Cross-Check Probes
    doh_obs = [
        o
        for o in observations
        if o.probe_name == "dns_doh_crosscheck"
        or "doh" in (o.target.service or "").lower()
        or o.raw.get("method") in ("plain", "doh")
    ]
    if doh_obs:
        # Group by qname
        domain_groups: dict[str, dict[str, Observation]] = defaultdict(dict)
        for o in doh_obs:
            qname = str(o.raw.get("qname", ""))
            method = str(
                o.raw.get("method", "plain" if o.raw.get("protocol") == "udp" else "doh")
            ).lower()
            if qname:
                domain_groups[qname][method] = o

        evaluated_count = 0
        mismatched_domains: list[tuple[str, list[str], list[str]]] = []

        for domain, methods in domain_groups.items():
            obs_plain = methods.get("plain")
            obs_doh = methods.get("doh")

            # DoH is only supporting evidence: if either probe failed to receive a response, skip
            if not obs_plain or not obs_doh:
                continue
            if not obs_plain.raw.get("reply_received") or not obs_doh.raw.get("reply_received"):
                continue
            if obs_plain.raw.get("error") or obs_doh.raw.get("error"):
                continue

            plain_answers = list(obs_plain.raw.get("answers", []))
            doh_answers = list(obs_doh.raw.get("answers", []))
            evaluated_count += 1

            if not answers_overlap_loosely(plain_answers, doh_answers):
                mismatched_domains.append((domain, plain_answers, doh_answers))

        if mismatched_domains:
            ratio = len(mismatched_domains) / evaluated_count if evaluated_count > 0 else 1.0
            # Lower confidence when only a few domains differ
            confidence = Confidence.MEDIUM if ratio >= 0.5 else Confidence.LOW
            evidences = [
                f"Plain DNS and DoH answers for '{d}' do not overlap (plain: {p}, DoH: {doh})"
                for d, p, doh in mismatched_domains
            ]
            evidences.append(
                f"DoH cross-check mismatch on {len(mismatched_domains)}/{evaluated_count} "
                "tested domain(s) (loose /16 subnet comparison)."
            )
            verdicts.append(
                Verdict(
                    target=doh_obs[0].target,
                    kind=VerdictKind.MISMATCH,
                    confidence=confidence,
                    evidence=evidences,
                )
            )
        elif evaluated_count > 0:
            verdicts.append(
                Verdict(
                    target=doh_obs[0].target,
                    kind=VerdictKind.CLEAN,
                    confidence=Confidence.HIGH,
                    evidence=[
                        "Plain DNS and DoH answers matched or showed normal CDN /16 overlap "
                        f"across {evaluated_count} domain(s)."
                    ],
                )
            )

    return verdicts


def classify_dns(
    observations: list[Observation],
    control_reachable: bool = True,
    expected_whoami_ranges: list[str] | None = None,
) -> Verdict:
    """Classify a collection of DNS observations into an aggregate Verdict.

    Follows priority:
    1. INTERCEPTED (high confidence): blackhole reply, source IP mismatch, whoami out-of-range.
    2. REWRITTEN (high confidence): NXDOMAIN hijacking returning A records.
    3. MISMATCH (medium or low confidence): Plain-DNS vs DoH answers disjoint outside /16.
    4. CLEAN: all performed checks passed cleanly.
    5. UNKNOWN: control probe failed or no replies received.
    """
    if not observations:
        return Verdict(
            target=Target(host="unknown", service="DNS"),
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No DNS observations provided for classification."],
        )

    target = observations[0].target
    if not control_reachable:
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.HIGH,
            evidence=["Control probe failed; cannot verify DNS baseline."],
        )

    # Check if any non-blackhole probe got a reply, or if DNS is completely unreachable
    non_bh_obs = [
        o
        for o in observations
        if o.probe_name != "dns_blackhole"
        and not _is_blackhole_ip(o.raw.get("queried_address"))
        and not _is_blackhole_ip(o.target.host)
        and "blackhole" not in (o.target.service or "").lower()
    ]
    if non_bh_obs and not any(o.raw.get("reply_received") or o.success for o in non_bh_obs):
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.HIGH,
            evidence=[
                "No DNS replies received across all active queries; DNS service is unreachable."
            ],
        )

    check_verdicts = classify_dns_checks(
        observations=observations,
        control_reachable=control_reachable,
        expected_whoami_ranges=expected_whoami_ranges,
    )

    if not check_verdicts:
        return Verdict(
            target=target,
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No interpretable DNS checks found in observations."],
        )

    # Precedence hierarchy: INTERCEPTED > REWRITTEN > MISMATCH > CLEAN > UNKNOWN
    intercepted = [v for v in check_verdicts if v.kind == VerdictKind.INTERCEPTED]
    if intercepted:
        all_evidence: list[str] = []
        for v in intercepted:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.INTERCEPTED,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    rewritten = [v for v in check_verdicts if v.kind == VerdictKind.REWRITTEN]
    if rewritten:
        all_evidence = []
        for v in rewritten:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.REWRITTEN,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    mismatches = [v for v in check_verdicts if v.kind == VerdictKind.MISMATCH]
    if mismatches:
        all_evidence = []
        # Use lowest or highest confidence? Use the confidence from the mismatch check
        confidence = mismatches[0].confidence
        for v in mismatches:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.MISMATCH,
            confidence=confidence,
            evidence=all_evidence,
        )

    clean_checks = [v for v in check_verdicts if v.kind == VerdictKind.CLEAN]
    if clean_checks:
        all_evidence = []
        for v in clean_checks:
            all_evidence.extend(v.evidence)
        return Verdict(
            target=target,
            kind=VerdictKind.CLEAN,
            confidence=Confidence.HIGH,
            evidence=all_evidence,
        )

    return check_verdicts[0]
