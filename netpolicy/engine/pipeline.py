"""Observation aggregation and classification pipeline.

Transforms raw observations produced by probes into categorized verdicts and policy findings:
raw observations -> group by (probe, target) -> classifiers -> Verdicts -> findings -> AuditReport.
Strictly zero network I/O; pure data transformation pipeline.
"""

from __future__ import annotations

from collections import defaultdict

from netpolicy.classify.dns import classify_dns_checks
from netpolicy.classify.http import classify_http_checks
from netpolicy.classify.tcp import classify_tcp_reachability
from netpolicy.findings import generate_findings
from netpolicy.models import (
    AuditReport,
    Observation,
    ReportMetadata,
    Verdict,
)

__all__ = [
    "group_observations",
    "classify_observations",
    "build_audit_report",
    "process_observations",
]


def _is_dns_observation(obs: Observation) -> bool:
    """Return True if observation was produced by a DNS inspection probe."""
    name = obs.probe_name.lower()
    return name.startswith("dns")


def _is_http_observation(obs: Observation) -> bool:
    """Return True if observation was produced by an HTTP canary probe."""
    name = obs.probe_name.lower()
    return name.startswith("http")


def group_observations(
    observations: list[Observation],
) -> tuple[dict[tuple[str, int | None], list[Observation]], list[Observation], list[Observation]]:
    """Partition raw observations into port groups, DNS observations, and HTTP observations.

    Returns:
        (port_groups, dns_observations, http_observations)
    """
    port_groups: dict[tuple[str, int | None], list[Observation]] = defaultdict(list)
    dns_obs: list[Observation] = []
    http_obs: list[Observation] = []

    for obs in observations:
        if _is_dns_observation(obs):
            dns_obs.append(obs)
        elif _is_http_observation(obs):
            http_obs.append(obs)
        else:
            # TCP / Port reachability probe
            key = (obs.target.host, obs.target.port)
            port_groups[key].append(obs)

    return port_groups, dns_obs, http_obs


def classify_observations(
    observations: list[Observation],
    control_healthy: bool = True,
    control_syn_ack_ttl: int | None = None,
) -> tuple[list[Verdict], list[Verdict], list[Verdict]]:
    """Run pure classifiers over partitioned observation groups.

    Returns:
        (port_verdicts, dns_verdicts, http_verdicts)
    """
    port_groups, dns_obs, http_obs = group_observations(observations)

    # 1. Classify TCP Outbound Ports (grouped per target host + port)
    port_verdicts: list[Verdict] = []
    for _key, group in port_groups.items():
        v = classify_tcp_reachability(
            observations=group,
            control_reachable=control_healthy,
            control_syn_ack_ttl=control_syn_ack_ttl,
        )
        port_verdicts.append(v)

    # Sort port verdicts by port number ascending if available
    port_verdicts.sort(key=lambda v: (v.target.port or 0, v.target.host))

    # 2. Classify DNS Probes
    dns_verdicts: list[Verdict] = []
    if dns_obs:
        dns_verdicts = classify_dns_checks(
            observations=dns_obs,
            control_reachable=control_healthy,
        )

    # 3. Classify HTTP Canary Probes
    http_verdicts: list[Verdict] = []
    if http_obs:
        http_verdicts = classify_http_checks(
            observations=http_obs,
            control_reachable=control_healthy,
        )

    return port_verdicts, dns_verdicts, http_verdicts


def build_audit_report(
    observations: list[Observation],
    control_healthy: bool = True,
    metadata: ReportMetadata | None = None,
    control_syn_ack_ttl: int | None = None,
) -> AuditReport:
    """Build an AuditReport from raw observations via classifiers and findings synthesis."""
    meta = metadata or ReportMetadata()
    port_results, dns_results, http_results = classify_observations(
        observations=observations,
        control_healthy=control_healthy,
        control_syn_ack_ttl=control_syn_ack_ttl,
    )

    findings = generate_findings(
        port_results=port_results,
        dns_results=dns_results,
        http_results=http_results,
    )

    return AuditReport(
        schema_version="1",
        metadata=meta,
        port_results=port_results,
        dns_results=dns_results,
        http_results=http_results,
        findings=findings,
    )


# Alias
process_observations = build_audit_report
