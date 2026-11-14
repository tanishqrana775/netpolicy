"""Comparison utilities to detect differences between two audit reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rich.table import Table

from netpolicy.models import AuditReport, VerdictKind
from netpolicy.report.terminal import _get_verdict_badge


@dataclass
class ReportDiff:
    """Represents a single policy or reachability difference between reports."""

    category: str
    target: str
    baseline_kind: str
    current_kind: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        """Convert diff to a dictionary representation."""
        return {
            "category": self.category,
            "target": self.target,
            "baseline": self.baseline_kind,
            "current": self.current_kind,
            "details": self.details,
        }


def _format_status(kind_str: str) -> str:
    """Format status with appropriate symbol and color badge."""
    try:
        kind = VerdictKind(kind_str)
        symbol, color = _get_verdict_badge(kind)
        return f"[{color}]{symbol} {kind.value}[/{color}]"
    except ValueError:
        return kind_str


def compare_reports(
    baseline: AuditReport,
    current: AuditReport,
) -> tuple[list[ReportDiff], Table | None]:
    """Compare two AuditReports and detect changes in port reachability, DNS, and HTTP.

    Args:
        baseline: The earlier/baseline AuditReport (A).
        current: The comparison/current AuditReport (B).

    Returns:
        Tuple of (list of ReportDiff items, Rich Table representation or None if identical).
    """
    diffs: list[ReportDiff] = []

    # 1. Compare Port Reachability
    baseline_ports = {f"{p.target.port}/{p.target.protocol}": p for p in baseline.port_results}
    current_ports = {f"{p.target.port}/{p.target.protocol}": p for p in current.port_results}

    all_port_keys = sorted(set(baseline_ports.keys()) | set(current_ports.keys()))
    for key in all_port_keys:
        p_base = baseline_ports.get(key)
        p_curr = current_ports.get(key)

        if p_base is None and p_curr is not None:
            svc = p_curr.target.service or "-"
            diffs.append(
                ReportDiff(
                    category="Outbound Ports",
                    target=f"{key} ({svc})",
                    baseline_kind="(not audited)",
                    current_kind=p_curr.kind.value,
                    details=f"Port added to audit (status: {p_curr.kind.value})",
                )
            )
        elif p_curr is None and p_base is not None:
            svc = p_base.target.service or "-"
            diffs.append(
                ReportDiff(
                    category="Outbound Ports",
                    target=f"{key} ({svc})",
                    baseline_kind=p_base.kind.value,
                    current_kind="(removed)",
                    details="Port removed from audit",
                )
            )
        elif p_base is not None and p_curr is not None and p_base.kind != p_curr.kind:
            svc = p_curr.target.service or p_base.target.service or "-"
            diffs.append(
                ReportDiff(
                    category="Outbound Ports",
                    target=f"{key} ({svc})",
                    baseline_kind=p_base.kind.value,
                    current_kind=p_curr.kind.value,
                    details=(
                        f"Port status changed from {p_base.kind.value} to {p_curr.kind.value}"
                    ),
                )
            )

    # 2. Compare DNS checks
    base_dns = {
        f"{d.target.host}:{d.target.port or 53}/{d.target.protocol}": d
        for d in baseline.dns_results
    }
    curr_dns = {
        f"{d.target.host}:{d.target.port or 53}/{d.target.protocol}": d for d in current.dns_results
    }
    all_dns_keys = sorted(set(base_dns.keys()) | set(curr_dns.keys()))
    for key in all_dns_keys:
        d_base = base_dns.get(key)
        d_curr = curr_dns.get(key)
        if d_base is not None and d_curr is not None and d_base.kind != d_curr.kind:
            diffs.append(
                ReportDiff(
                    category="DNS Integrity",
                    target=key,
                    baseline_kind=d_base.kind.value,
                    current_kind=d_curr.kind.value,
                    details=(
                        f"DNS resolution status changed from {d_base.kind.value} "
                        f"to {d_curr.kind.value}"
                    ),
                )
            )

    # 3. Compare HTTP checks
    base_http = {
        f"{h.target.host}:{h.target.port or 80}/{h.target.protocol}": h
        for h in baseline.http_results
    }
    curr_http = {
        f"{h.target.host}:{h.target.port or 80}/{h.target.protocol}": h
        for h in current.http_results
    }
    all_http_keys = sorted(set(base_http.keys()) | set(curr_http.keys()))
    for key in all_http_keys:
        h_base = base_http.get(key)
        h_curr = curr_http.get(key)
        if h_base is not None and h_curr is not None and h_base.kind != h_curr.kind:
            diffs.append(
                ReportDiff(
                    category="HTTP Integrity",
                    target=key,
                    baseline_kind=h_base.kind.value,
                    current_kind=h_curr.kind.value,
                    details=f"HTTP status changed from {h_base.kind.value} to {h_curr.kind.value}",
                )
            )

    if not diffs:
        return [], None

    # Render table of changes
    table = Table(
        title="POLICY CHANGES DETECTED",
        title_style="bold white on red",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Category", style="bold cyan", width=16)
    table.add_column("Target", style="bold", width=22)
    table.add_column("Baseline (A)", width=16)
    table.add_column("Current (B)", width=16)
    table.add_column("Change Details", style="dim", ratio=2)

    for item in diffs:
        base_display = _format_status(item.baseline_kind)
        curr_display = _format_status(item.current_kind)
        table.add_row(
            item.category,
            item.target,
            base_display,
            curr_display,
            item.details,
        )

    return diffs, table
