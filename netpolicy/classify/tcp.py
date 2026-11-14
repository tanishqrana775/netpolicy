"""Pure classification functions and decision tables for TCP reachability observations.

Adheres strictly to GEMINI.md design rules:
1. Pure functions: list[Observation] -> Verdict. No I/O.
2. If control probe fails, verdicts must become UNKNOWN, never BLOCKED.
3. Every verdict carries a confidence level (HIGH/MEDIUM/LOW) and human-readable evidence strings.
4. Single missing reply is packet loss (LOSSY), not a block.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from netpolicy.models import Confidence, Observation, Target, Verdict, VerdictKind

__all__ = [
    "classify_tcp_reachability",
    "classify_tcp_run",
    "ICMP_TYPE_3_CODES",
]

# Standard ICMP Type 3 (Destination Unreachable) Code Mapping (RFC 792, RFC 1812)
ICMP_TYPE_3_CODES: dict[int, dict[str, Any]] = {
    0: {
        "name": "network unreachable",
        "prohibited": False,
        "raw_confidence": Confidence.MEDIUM,
    },
    1: {
        "name": "host unreachable",
        "prohibited": False,
        "raw_confidence": Confidence.MEDIUM,
    },
    2: {
        "name": "protocol unreachable",
        "prohibited": False,
        "raw_confidence": Confidence.MEDIUM,
    },
    3: {
        "name": "port unreachable",
        "prohibited": False,
        "raw_confidence": Confidence.MEDIUM,
    },
    9: {
        "name": "network administratively prohibited",
        "prohibited": True,
        "raw_confidence": Confidence.HIGH,
    },
    10: {
        "name": "host administratively prohibited",
        "prohibited": True,
        "raw_confidence": Confidence.HIGH,
    },
    13: {
        "name": "communication administratively prohibited",
        "prohibited": True,
        "raw_confidence": Confidence.HIGH,
    },
}


@dataclass(frozen=True)
class _ParsedAttempt:
    """Normalized representation of a single probe attempt."""

    category: str  # "OPEN", "RESET", "ICMP", "TIMEOUT", "OTHER"
    is_socket: bool
    reply_received: bool
    ip_ttl: int | None
    rtt_ms: float | None
    icmp_type: int | None
    icmp_code: int | None
    icmp_src: str | None
    icmp_src_differs: bool | None
    errno_name: str | None
    raw: dict[str, Any]


def _parse_attempt(obs: Observation) -> _ParsedAttempt:
    """Normalize raw observation dictionary into standardized probe attempt fields."""
    raw = obs.raw or {}
    is_socket = obs.probe_name == "tcp_connect" or "outcome" in raw or "errno_name" in raw

    if is_socket:
        outcome = raw.get("outcome", "")
        errno_name = raw.get("errno_name")
        icmp_type = raw.get("icmp_type")
        icmp_code = raw.get("icmp_code")
        icmp_src = raw.get("icmp_src")
        rtt_ms = raw.get("rtt_ms", raw.get("elapsed_ms"))

        if outcome == "connected" or obs.success:
            category = "OPEN"
            reply_received = True
        elif icmp_type == 3:
            category = "ICMP"
            reply_received = True
        elif outcome == "refused" or errno_name == "ECONNREFUSED":
            category = "RESET"
            reply_received = True
        elif outcome == "timeout" or errno_name == "ETIMEDOUT":
            category = "TIMEOUT"
            reply_received = False
        elif outcome == "unreachable":
            category = "ICMP"
            reply_received = True
        else:
            category = "OTHER"
            reply_received = False

        return _ParsedAttempt(
            category=category,
            is_socket=True,
            reply_received=reply_received,
            ip_ttl=None,
            rtt_ms=rtt_ms,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_src=icmp_src,
            icmp_src_differs=None,
            errno_name=errno_name,
            raw=raw,
        )

    # Raw mode (Scapy tcp_syn probe)
    reply_type = str(raw.get("reply_type", "")).upper()
    reply_received = raw.get("reply_received", False)
    tcp_flags = str(raw.get("tcp_flags", ""))
    ip_ttl = raw.get("ip_ttl")
    rtt_ms = raw.get("rtt_ms")
    icmp_type = raw.get("icmp_type")
    icmp_code = raw.get("icmp_code")
    icmp_src = raw.get("icmp_src")
    icmp_src_differs = raw.get("icmp_src_differs")

    if reply_type == "SYN-ACK" or obs.success or ("S" in tcp_flags and "A" in tcp_flags):
        category = "OPEN"
        reply_received = True
    elif reply_type in ("RST", "RST-ACK") or "R" in tcp_flags:
        category = "RESET"
        reply_received = True
    elif reply_type == "ICMP" or icmp_type == 3:
        category = "ICMP"
        reply_received = True
    elif reply_type in ("NONE", "TIMEOUT") or not reply_received:
        category = "TIMEOUT"
        reply_received = False
    else:
        category = "OTHER"

    return _ParsedAttempt(
        category=category,
        is_socket=False,
        reply_received=reply_received,
        ip_ttl=ip_ttl,
        rtt_ms=rtt_ms,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_src=icmp_src,
        icmp_src_differs=icmp_src_differs,
        errno_name=None,
        raw=raw,
    )


def classify_tcp_run(
    observations: list[Observation],
    control_reachable: bool = True,
    control_syn_ack_ttl: int | None = None,
) -> Verdict:
    """Classify TCP reachability for a single run attempt series.

    Pure table-driven classifier evaluating:
    1. Control reachability guard: if all attempts timeout and control fails -> UNKNOWN.
    2. OPEN: SYN-ACK or connect in at least one attempt.
    3. BLOCKED_DROP: 0 replies in all attempts with control OK.
    4. LOSSY: mixed replies and timeouts across attempts; reports loss rate, never blocked.
    5. BLOCKED_ICMP: ICMP type 3 received; records code name and gateway vs target source.
    6. BLOCKED_RESET: RST on expect_open=True (evaluating TTL diff vs control SYN-ACK TTL).
    7. CLOSED_OR_RESET: RST on expect_open=False (low confidence due to closed/reset ambiguity).
    """
    if not observations:
        return Verdict(
            target=Target(host="unknown"),
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No observations provided for classification."],
        )

    target = observations[0].target
    attempts = [_parse_attempt(o) for o in observations]
    n = len(attempts)
    is_socket_run = any(a.is_socket for a in attempts)

    open_attempts = [a for a in attempts if a.category == "OPEN"]
    timeout_attempts = [a for a in attempts if a.category == "TIMEOUT"]
    reset_attempts = [a for a in attempts if a.category == "RESET"]
    icmp_attempts = [a for a in attempts if a.category == "ICMP"]
    reply_count = sum(1 for a in attempts if a.reply_received)
    timeout_count = len(timeout_attempts)

    # Resolve control_syn_ack_ttl from observations if not explicitly passed
    if control_syn_ack_ttl is None:
        for a in attempts:
            candidate = a.raw.get("control_syn_ack_ttl", a.raw.get("syn_ack_ttl"))
            if candidate is not None:
                control_syn_ack_ttl = int(candidate)
                break

    # -------------------------------------------------------------------------
    # Rule 1: All timeouts (no replies)
    # -------------------------------------------------------------------------
    if timeout_count == n and reply_count == 0:
        if not control_reachable:
            return Verdict(
                target=target,
                kind=VerdictKind.UNKNOWN,
                confidence=Confidence.HIGH,
                evidence=[
                    f"0/{n} replies, control failed; cannot distinguish "
                    "egress network failure from target blocking",
                ],
            )

        # Control OK -> BLOCKED_DROP
        conf = Confidence.MEDIUM if is_socket_run else Confidence.HIGH
        ev = [f"0/{n} replies, control OK"]
        if is_socket_run:
            ev.append("Socket-mode: timeout confirms outbound packets dropped or unrouted")
        return Verdict(
            target=target,
            kind=VerdictKind.BLOCKED_DROP,
            confidence=conf,
            evidence=ev,
        )

    # -------------------------------------------------------------------------
    # Rule 2: OPEN (SYN-ACK or connect in at least one attempt)
    # -------------------------------------------------------------------------
    if open_attempts:
        first_open = open_attempts[0]
        rtt_str = f", RTT {first_open.rtt_ms:.1f}ms" if first_open.rtt_ms is not None else ""
        ttl_str = f", TTL {first_open.ip_ttl}" if first_open.ip_ttl is not None else ""

        if len(open_attempts) == n:
            # Succeeded in all attempts
            conf = Confidence.MEDIUM if is_socket_run else Confidence.HIGH
            if is_socket_run:
                ev = [f"{n}/{n} TCP connects succeeded{rtt_str}"]
            else:
                ev = [f"{n}/{n} attempts received SYN-ACK{ttl_str}{rtt_str}"]
        else:
            # Succeeded in some attempts, some timed out/failed
            loss_pct = (timeout_count / n) * 100.0
            conf = Confidence.LOW if is_socket_run else Confidence.MEDIUM
            if is_socket_run:
                ev = [
                    f"TCP connect succeeded in {len(open_attempts)}/{n} attempts "
                    f"({timeout_count}/{n} lost, loss rate: {loss_pct:.1f}%){rtt_str}"
                ]
            else:
                ev = [
                    f"SYN-ACK received in {len(open_attempts)}/{n} attempts "
                    f"({timeout_count}/{n} lost, loss rate: {loss_pct:.1f}%){ttl_str}{rtt_str}"
                ]

        if is_socket_run:
            ev.append("Socket-mode observation: reachability verified")
        return Verdict(
            target=target,
            kind=VerdictKind.OPEN,
            confidence=conf,
            evidence=ev,
        )

    # -------------------------------------------------------------------------
    # Rule 3: LOSSY (mixed replies and timeouts across attempts; never blocked)
    # -------------------------------------------------------------------------
    if timeout_count > 0 and reply_count > 0:
        loss_rate = timeout_count / n
        loss_pct = loss_rate * 100.0
        conf = Confidence.LOW if is_socket_run else Confidence.MEDIUM
        reply_summary = []
        if reset_attempts:
            reply_summary.append(f"{len(reset_attempts)} RST")
        if icmp_attempts:
            reply_summary.append(f"{len(icmp_attempts)} ICMP")

        rep_str = f" ({', '.join(reply_summary)})" if reply_summary else ""
        ev = [
            f"{reply_count}/{n} replies{rep_str}, {timeout_count}/{n} timeouts "
            f"(loss rate: {loss_pct:.1f}%); packet loss detected, never called blocked",
        ]
        if is_socket_run:
            ev.append(
                "Socket-mode: a RST and an ICMP port-unreachable cannot be told apart "
                "from ECONNREFUSED"
            )
        return Verdict(
            target=target,
            kind=VerdictKind.LOSSY,
            confidence=conf,
            evidence=ev,
        )

    # -------------------------------------------------------------------------
    # Rule 4: BLOCKED_ICMP (ICMP type 3 Destination Unreachable)
    # -------------------------------------------------------------------------
    if icmp_attempts:
        first_icmp = icmp_attempts[0]
        code = first_icmp.icmp_code if first_icmp.icmp_code is not None else 3
        code_meta = ICMP_TYPE_3_CODES.get(
            code,
            {
                "name": f"code {code}",
                "prohibited": False,
                "raw_confidence": Confidence.MEDIUM,
            },
        )
        code_name = code_meta["name"]
        is_prohibited = code_meta["prohibited"]

        # Check if source is target or intermediate device (gateway)
        src = first_icmp.icmp_src
        target_host = target.host
        if first_icmp.icmp_src_differs is True or (src and src != target_host):
            source_desc = f"intermediate device ({src})"
        elif src:
            source_desc = f"target ({src})"
        else:
            source_desc = "target or gateway (source unspecified)"

        if is_socket_run:
            conf = Confidence.MEDIUM if is_prohibited else Confidence.LOW
        else:
            conf = Confidence.HIGH if is_prohibited else Confidence.MEDIUM

        ev = [f"ICMP type 3 code {code} ({code_name}) from {source_desc}"]
        if is_prohibited:
            ev.append("Administratively prohibited by in-path network policy")
        if is_socket_run:
            ev.append(
                "Socket-mode: a RST and an ICMP port-unreachable cannot be told apart "
                "from ECONNREFUSED"
            )

        return Verdict(
            target=target,
            kind=VerdictKind.BLOCKED_ICMP,
            confidence=conf,
            evidence=ev,
        )

    # -------------------------------------------------------------------------
    # Rule 5 & 6: BLOCKED_RESET & CLOSED_OR_RESET
    # -------------------------------------------------------------------------
    if reset_attempts:
        first_reset = reset_attempts[0]
        rst_ttl = first_reset.ip_ttl

        # Subcase 5A: expect_open is True (server is listening on this port)
        if target.expect_open:
            if is_socket_run:
                conf = Confidence.MEDIUM
                ev = [
                    "ECONNREFUSED received on expect_open=True port; middlebox reset inferred",
                    "Socket-mode: a RST and an ICMP port-unreachable cannot be told apart "
                    "from ECONNREFUSED",
                ]
            else:
                # Compare RST TTL against control SYN-ACK TTL
                if rst_ttl is not None and control_syn_ack_ttl is not None:
                    ttl_diff = abs(rst_ttl - control_syn_ack_ttl)
                    if ttl_diff > 2:
                        conf = Confidence.HIGH
                        ev = [
                            f"RST TTL {rst_ttl} vs SYN-ACK TTL {control_syn_ack_ttl} "
                            f"(diff {ttl_diff} > 2); expect_open=True indicates "
                            "middlebox injection"
                        ]
                    else:
                        conf = Confidence.MEDIUM
                        ev = [
                            f"RST TTL {rst_ttl} vs SYN-ACK TTL {control_syn_ack_ttl} "
                            f"(diff {ttl_diff} <= 2); expect_open=True indicates "
                            "middlebox injection"
                        ]
                else:
                    ttl_msg = f" (TTL {rst_ttl})" if rst_ttl is not None else ""
                    conf = Confidence.MEDIUM
                    ev = [
                        f"TCP RST received{ttl_msg}; expect_open=True indicates middlebox injection"
                    ]

            return Verdict(
                target=target,
                kind=VerdictKind.BLOCKED_RESET,
                confidence=conf,
                evidence=ev,
            )

        # Subcase 5B: expect_open is False
        # A closed port and an injected reset look the same -> CLOSED_OR_RESET with low confidence
        if is_socket_run:
            ev = [
                "ECONNREFUSED received with expect_open=False; closed port and injected reset "
                "or ICMP port-unreachable cannot be distinguished",
                "Socket-mode: a RST and an ICMP port-unreachable cannot be told apart "
                "from ECONNREFUSED",
            ]
        else:
            ttl_msg = f" (TTL {rst_ttl})" if rst_ttl is not None else ""
            ev = [
                f"TCP RST received{ttl_msg}; expect_open=False means closed port "
                "and injected reset look identical",
            ]

        return Verdict(
            target=target,
            kind=VerdictKind.CLOSED_OR_RESET,
            confidence=Confidence.LOW,
            evidence=ev,
        )

    # -------------------------------------------------------------------------
    # Fallback / Unrecognized
    # -------------------------------------------------------------------------
    return Verdict(
        target=target,
        kind=VerdictKind.UNKNOWN,
        confidence=Confidence.LOW,
        evidence=["No conclusive classification criteria met."],
    )


def classify_tcp_reachability(
    observations: list[Observation],
    control_reachable: bool = True,
    control_syn_ack_ttl: int | None = None,
    control_observations: list[Observation] | None = None,
) -> Verdict:
    """Classify TCP reachability from raw observations, aggregating multiple runs.

    Pure function: list[Observation] -> Verdict.
    If control fails, verdicts must become UNKNOWN, never BLOCKED.
    """
    if not observations:
        return Verdict(
            target=Target(host="unknown"),
            kind=VerdictKind.UNKNOWN,
            confidence=Confidence.LOW,
            evidence=["No observations provided for classification."],
        )

    # 1. Resolve control parameters if control_observations is provided
    if control_observations:
        control_reachable = any(
            c.success or c.raw.get("reply_received", False) for c in control_observations
        )
        if control_syn_ack_ttl is None:
            for c in control_observations:
                val = c.raw.get("ip_ttl", c.raw.get("syn_ack_ttl"))
                if val is not None:
                    control_syn_ack_ttl = int(val)
                    break

    target = observations[0].target

    # 2. Group observations by run_index (or 0 if not present)
    runs_map: dict[int, list[Observation]] = {}
    for obs in observations:
        idx = obs.raw.get("run_index", 0)
        runs_map.setdefault(idx, []).append(obs)

    # 3. Single run: evaluate directly
    if len(runs_map) <= 1:
        return classify_tcp_run(
            observations,
            control_reachable=control_reachable,
            control_syn_ack_ttl=control_syn_ack_ttl,
        )

    # 4. Multiple runs: classify each run and aggregate
    run_verdicts: list[Verdict] = []
    for _idx, run_obs in runs_map.items():
        v = classify_tcp_run(
            run_obs,
            control_reachable=control_reachable,
            control_syn_ack_ttl=control_syn_ack_ttl,
        )
        run_verdicts.append(v)

    # Compute majority verdict kind
    kind_counts = Counter(v.kind for v in run_verdicts)
    majority_kind, count = kind_counts.most_common(1)[0]
    total_runs = len(run_verdicts)
    consistency_score = count / total_runs

    # Filter verdicts matching the majority
    majority_verdicts = [v for v in run_verdicts if v.kind == majority_kind]
    conf_counts = Counter(v.confidence for v in majority_verdicts)
    base_confidence = conf_counts.most_common(1)[0][0]

    # Mixed results across runs lower confidence
    if consistency_score < 1.0:
        if base_confidence == Confidence.HIGH:
            final_confidence = Confidence.MEDIUM
        else:
            final_confidence = Confidence.LOW
    else:
        final_confidence = base_confidence

    evidence: list[str] = [
        f"Multi-run consistency: {count}/{total_runs} runs "
        f"({consistency_score * 100:.1f}%) agreed on {majority_kind.value}"
    ]
    for v in majority_verdicts:
        for ev in v.evidence:
            if ev not in evidence:
                evidence.append(ev)

    return Verdict(
        target=target,
        kind=majority_kind,
        confidence=final_confidence,
        evidence=evidence,
    )
