"""Markdown report generator for audit documentation, GitHub issues, and READMEs."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from netpolicy.models import AuditReport, VerdictKind
from netpolicy.store.raw import chown_to_sudo_user


def _mask_client_ip(client_addr: str) -> str:
    """Mask client IP if not authorized to display identifiers."""
    if not client_addr or client_addr == "127.0.0.1":
        return client_addr
    try:
        ip = ipaddress.ip_address(client_addr)
        if not (ip.is_private or ip.is_loopback):
            return "[REDACTED_PUBLIC_IP]"
    except ValueError:
        pass

    octets = client_addr.split(".")
    if len(octets) == 4:
        return f"{octets[0]}.{octets[1]}.*.*"
    return "[REDACTED_IP]"


def generate_markdown_report(
    report: AuditReport,
    output_path: Path | str | None = None,
    include_identifiers: bool = False,
) -> str:
    """Format the audit report as Markdown tables suitable for GitHub issues or READMEs.

    Args:
        report: AuditReport to format.
        output_path: Optional file path to write Markdown.
        include_identifiers: If True, include SSIDs and client IPs.

    Returns:
        Formatted Markdown text.
    """
    net_label = report.metadata.network_label if include_identifiers else "[REDACTED_SSID]"
    client_ip = (
        report.metadata.client_address
        if include_identifiers
        else _mask_client_ip(report.metadata.client_address)
    )

    lines: list[str] = [
        f"# Network Policy Audit Report - {net_label}",
        "",
        "## Overview",
        "",
        "| Attribute | Value |",
        "| :--- | :--- |",
        f"| **Network Label** | `{net_label}` |",
        f"| **Audit Timestamp** | `{report.metadata.run_time}` |",
        f"| **Tool Version** | `netpolicy v{report.metadata.tool_version}` |",
        f"| **Probe Mode** | `{report.metadata.mode.upper()}` |",
        f"| **Runs per Check** | `{report.metadata.runs_per_check}` |",
        f"| **Client Address** | `{client_ip}` |",
        f"| **Target Host** | `{report.metadata.target or '(default)'}` |",
        "",
    ]

    # Outbound Port Reachability Table
    if report.port_results:
        lines.extend(
            [
                "## Outbound Port Reachability",
                "",
                "| Port | Proto | Service | Status | Confidence | Evidence |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for p in report.port_results:
            ev = "<br>".join(p.evidence) if p.evidence else "-"
            svc = p.target.service or "-"
            port_num = p.target.port if p.target.port is not None else "-"
            conf = p.confidence.value.capitalize()
            lines.append(
                f"| `{port_num}` | `{p.target.protocol}` | {svc} | "
                f"**`{p.kind.value}`** | {conf} | {ev} |"
            )
        lines.append("")

    # DNS Interception & Tampering Table
    if report.dns_results:
        lines.extend(
            [
                "## DNS Interception & Tampering",
                "",
                "| Resolver / Target | Protocol | Status | Confidence | Evidence |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for d in report.dns_results:
            ev = "<br>".join(d.evidence) if d.evidence else "-"
            port_str = f":{d.target.port}" if d.target.port else ""
            target_str = f"{d.target.host}{port_str}"
            conf = d.confidence.value.capitalize()
            lines.append(
                f"| `{target_str}` | `{d.target.protocol}` | **`{d.kind.value}`** | {conf} | {ev} |"
            )
        lines.append("")

    # HTTP Tampering Table
    if report.http_results:
        lines.extend(
            [
                "## HTTP Tampering & Header Injection",
                "",
                "| Target | Protocol | Status | Confidence | Evidence |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for h in report.http_results:
            ev = "<br>".join(h.evidence) if h.evidence else "-"
            port_str = f":{h.target.port}" if h.target.port else ""
            target_str = f"{h.target.host}{port_str}"
            conf = h.confidence.value.capitalize()
            lines.append(
                f"| `{target_str}` | `{h.target.protocol}` | **`{h.kind.value}`** | {conf} | {ev} |"
            )
        lines.append("")

    # Policy Findings Table
    lines.extend(
        [
            "## Key Policy Findings",
            "",
            "| Severity | Finding | Summary |",
            "| :--- | :--- | :--- |",
        ]
    )
    if report.findings:
        for f in report.findings:
            sev = f.severity.value.upper()
            lines.append(f"| **`{sev}`** | {f.title} | {f.summary} |")
    else:
        lines.append(
            "| `INFO` | Clean Network | No unexpected blocks, tampering, or "
            "interceptions detected. |"
        )
    lines.append("")

    # Summary Metrics Table
    total_ports = len(report.port_results)
    open_ports = sum(1 for p in report.port_results if p.kind in (VerdictKind.OPEN, VerdictKind.OK))
    blocked_ports = total_ports - open_ports
    dns_anomalies = sum(
        1
        for d in report.dns_results
        if d.kind in (VerdictKind.INTERCEPTED, VerdictKind.TAMPERED, VerdictKind.DROPPED)
    )
    http_anomalies = sum(
        1
        for h in report.http_results
        if h.kind in (VerdictKind.TAMPERED, VerdictKind.INTERCEPTED, VerdictKind.DROPPED)
    )

    lines.extend(
        [
            "## Summary Metrics",
            "",
            "| Metric | Count |",
            "| :--- | :--- |",
            f"| Total Outbound Ports Audited | {total_ports} |",
            f"| Open Ports | {open_ports} |",
            f"| Blocked / Filtered Ports | {blocked_ports} |",
            f"| DNS Anomalies Detected | {dns_anomalies} |",
            f"| HTTP Anomalies Detected | {http_anomalies} |",
            f"| Total High-Level Findings | {len(report.findings)} |",
            "",
        ]
    )

    content = "\n".join(lines)
    if output_path is not None:
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(path.parent)
        path.write_text(content, encoding="utf-8")
        chown_to_sudo_user(path)

    return content
