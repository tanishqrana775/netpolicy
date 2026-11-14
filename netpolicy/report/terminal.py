"""Rich terminal renderer for netpolicy findings and audit reports."""

from __future__ import annotations

import time

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from netpolicy.models import (
    AuditReport,
    Finding,
    Observation,
    Verdict,
    VerdictKind,
)


def _get_verdict_badge(kind: VerdictKind) -> tuple[str, str]:
    """Return the symbol and color style for a verdict kind."""
    match kind:
        case VerdictKind.OPEN | VerdictKind.OK | VerdictKind.CLEAN:
            return ("✓", "green")
        case (
            VerdictKind.DROPPED
            | VerdictKind.BLOCKED_DROP
            | VerdictKind.RESET
            | VerdictKind.BLOCKED_RESET
            | VerdictKind.INTERCEPTED
            | VerdictKind.TAMPERED
            | VerdictKind.REWRITTEN
            | VerdictKind.HEADERS_INJECTED
            | VerdictKind.BODY_MODIFIED
        ):
            return ("✗", "red")
        case (
            VerdictKind.REJECTED
            | VerdictKind.BLOCKED_ICMP
            | VerdictKind.CLOSED_OR_RESET
            | VerdictKind.LOSSY
            | VerdictKind.MISMATCH
            | VerdictKind.PROXIED
            | VerdictKind.REDIRECTED
        ):
            return ("⚠", "yellow")
        case _:
            return ("?", "magenta")


def _render_header_panel(report: AuditReport, console: Console) -> None:
    """Render metadata header panel."""
    client_ip = report.metadata.client_address
    if not report.metadata.include_identifiers and client_ip != "127.0.0.1":
        # Privacy protection per GEMINI.md safety rules
        octets = client_ip.split(".")
        if len(octets) == 4:
            client_ip = f"{octets[0]}.{octets[1]}.*.* [dim](redacted)[/dim]"

    content = Text()
    content.append("Tool Version:     ", style="bold")
    content.append(f"{report.metadata.tool_version}\n")
    content.append("Network Label:    ", style="bold")
    content.append(f"{report.metadata.network_label}\n")
    content.append("Client Address:   ", style="bold")
    content.append(f"{client_ip}\n")
    content.append("Audit Run Time:   ", style="bold")
    content.append(f"{report.metadata.run_time}\n")
    content.append("Probe Mode:       ", style="bold")
    content.append(f"{report.metadata.mode.upper()}\n")
    content.append("Runs per Check:   ", style="bold")
    content.append(f"{report.metadata.runs_per_check}\n")
    content.append("Target Host:      ", style="bold")
    content.append(f"{report.metadata.target or '(default resolvers)'}")
    if report.metadata.network_fingerprint:
        content.append("\nNetwork Fingerprint: ", style="bold")
        content.append(f"{report.metadata.network_fingerprint}")

    panel = Panel(
        content,
        title="[bold cyan]netpolicy: Network Policy & Tampering Audit[/bold cyan]",
        border_style="cyan",
        expand=False,
    )
    console.print(panel)


def _render_ports_table(port_results: list[Verdict], console: Console) -> None:
    """Render the OUTBOUND PORTS table."""
    table = Table(
        title="OUTBOUND PORTS",
        title_style="bold white on blue",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Port", style="bold", width=12)
    table.add_column("Service", width=14)
    table.add_column("Result", width=16)
    table.add_column("Evidence", style="dim", ratio=3)
    table.add_column("Confidence", width=12)

    for item in port_results:
        symbol, color = _get_verdict_badge(item.kind)
        proto = f"/{item.target.protocol}" if item.target.protocol != "tcp" else ""
        port_label = f"{item.target.port}{proto}"
        service_label = item.target.service or "-"
        result_label = f"[{color}]{symbol} {item.kind.value}[/{color}]"
        evidence_label = "\n".join(f"• {e}" for e in item.evidence)
        confidence_label = f"[{color}]{item.confidence.value.upper()}[/{color}]"

        table.add_row(
            port_label,
            service_label,
            result_label,
            evidence_label,
            confidence_label,
        )

    console.print(table)


def _render_dns_section(dns_results: list[Verdict], console: Console) -> None:
    """Render DNS audit checks as bullet lines."""
    console.print("\n[bold cyan]DNS CHECKS[/bold cyan]")
    for item in dns_results:
        symbol, color = _get_verdict_badge(item.kind)
        headline = (
            f"  [{color}]{symbol} {item.kind.value}[/{color}] "
            f"[bold]{item.target.service or 'DNS'}[/bold] ({item.target.host}) "
            f"- Confidence: [{color}]{item.confidence.value.upper()}[/{color}]"
        )
        console.print(headline)
        for e in item.evidence:
            console.print(f"      [dim]• {e}[/dim]")


def _render_http_section(http_results: list[Verdict], console: Console) -> None:
    """Render HTTP integrity audit checks as bullet lines."""
    console.print("\n[bold cyan]HTTP INTEGRITY CHECKS[/bold cyan]")
    for item in http_results:
        symbol, color = _get_verdict_badge(item.kind)
        port_str = f":{item.target.port}" if item.target.port else ""
        headline = (
            f"  [{color}]{symbol} {item.kind.value}[/{color}] "
            f"[bold]{item.target.protocol.upper()}[/bold] ({item.target.host}{port_str}) "
            f"- Confidence: [{color}]{item.confidence.value.upper()}[/{color}]"
        )
        console.print(headline)
        for e in item.evidence:
            console.print(f"      [dim]• {e}[/dim]")


def _render_summary_panel(
    report: AuditReport,
    active_findings: list[Finding],
    console: Console,
) -> None:
    """Render summary panel with metrics and plain-English findings."""
    total_ports = len(report.port_results)
    open_ports = sum(1 for p in report.port_results if p.kind in (VerdictKind.OPEN, VerdictKind.OK))
    blocked_ports = total_ports - open_ports

    dns_issues = sum(
        1
        for d in report.dns_results
        if d.kind
        in (
            VerdictKind.INTERCEPTED,
            VerdictKind.TAMPERED,
            VerdictKind.REWRITTEN,
            VerdictKind.MISMATCH,
            VerdictKind.DROPPED,
        )
    )
    http_issues = sum(
        1
        for h in report.http_results
        if h.kind
        in (
            VerdictKind.TAMPERED,
            VerdictKind.INTERCEPTED,
            VerdictKind.HEADERS_INJECTED,
            VerdictKind.BODY_MODIFIED,
            VerdictKind.PROXIED,
            VerdictKind.REDIRECTED,
            VerdictKind.DROPPED,
        )
    )

    metrics_text = Text()
    metrics_text.append("Audit Metrics: ", style="bold")
    metrics_text.append(f"{total_ports} Ports Audited (")
    metrics_text.append(f"{open_ports} Open", style="green bold")
    metrics_text.append(", ")
    metrics_text.append(f"{blocked_ports} Blocked/Filtered", style="red bold")
    metrics_text.append(f") | DNS Anomalies: {dns_issues} | HTTP Anomalies: {http_issues}\n\n")

    findings_elements = []
    if active_findings:
        findings_header = Text("Key Policy Findings:\n", style="bold underline")
        findings_elements.append(findings_header)
        for f in active_findings:
            f_text = Text()
            severity_color = "red" if f.severity.value in ("high", "critical") else "yellow"
            f_text.append("• ", style="bold")
            f_text.append(f"[{f.severity.value.upper()}] ", style=f"bold {severity_color}")
            f_text.append(f"{f.title}: ", style="bold")
            f_text.append(f"{f.summary}\n")
            findings_elements.append(f_text)
    else:
        findings_elements.append(
            Text("• No unexpected blocks, tampering, or interceptions detected.", style="green")
        )

    panel_content = Group(metrics_text, *findings_elements)
    summary_panel = Panel(
        panel_content,
        title="[bold yellow]AUDIT SUMMARY & FINDINGS[/bold yellow]",
        border_style="yellow",
        expand=True,
    )
    console.print("\n")
    console.print(summary_panel)


def simulate_progress(
    report: AuditReport,
    console: Console,
    sections: list[str],
) -> None:
    """Display simulated progress bars in demo mode."""
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        tasks = []
        if "ports" in sections and report.port_results:
            tasks.append(
                (
                    progress.add_task(
                        "[cyan]Auditing outbound ports...",
                        total=len(report.port_results),
                    ),
                    len(report.port_results),
                )
            )
        if "dns" in sections and report.dns_results:
            tasks.append(
                (
                    progress.add_task(
                        "[magenta]Testing DNS resolvers...",
                        total=len(report.dns_results),
                    ),
                    len(report.dns_results),
                )
            )
        if "http" in sections and report.http_results:
            tasks.append(
                (
                    progress.add_task(
                        "[yellow]Inspecting HTTP integrity...",
                        total=len(report.http_results),
                    ),
                    len(report.http_results),
                )
            )

        for task_id, total in tasks:
            for _ in range(total):
                progress.advance(task_id, 1)
                time.sleep(0.005)


def render_terminal_report(
    report: AuditReport,
    console: Console | None = None,
    section: str = "all",
    show_progress: bool = False,
    quiet: bool = False,
    no_color: bool = False,
) -> None:
    """Render findings and audit summary report to the terminal.

    Args:
        report: The AuditReport containing results and findings.
        console: Optional existing Rich console instance.
        section: Section filter ('all', 'ports', 'dns', 'http').
        show_progress: Whether to simulate interactive progress bars.
        quiet: If True, only render the summary panel.
        no_color: If True, disable ANSI color codes while preserving symbols.
    """
    if console is None:
        console = Console(no_color=no_color)

    # Filter findings based on active section
    if section == "ports":
        active_findings = [
            f for f in report.findings if any(v in report.port_results for v in f.verdicts)
        ]
        target_sections = ["ports"]
    elif section == "dns":
        active_findings = [
            f for f in report.findings if any(v in report.dns_results for v in f.verdicts)
        ]
        target_sections = ["dns"]
    elif section == "http":
        active_findings = [
            f for f in report.findings if any(v in report.http_results for v in f.verdicts)
        ]
        target_sections = ["http"]
    else:
        active_findings = report.findings
        target_sections = ["ports", "dns", "http"]

    # When quiet mode is active, only output the summary panel
    if quiet:
        _render_summary_panel(report, active_findings, console)
        return

    # Render header panel
    _render_header_panel(report, console)

    # Render simulated progress in demo mode
    if show_progress:
        simulate_progress(report, console, target_sections)

    # Render selected sections
    if "ports" in target_sections and report.port_results:
        _render_ports_table(report.port_results, console)

    if "dns" in target_sections and report.dns_results:
        _render_dns_section(report.dns_results, console)

    if "http" in target_sections and report.http_results:
        _render_http_section(report.http_results, console)

    # Render summary panel
    _render_summary_panel(report, active_findings, console)


def render_raw_observations_table(
    observations: list[Observation],
    console: Console | None = None,
    title: str = "RAW OBSERVATIONS",
) -> None:
    """Render a plain Rich table of raw observations before classification."""
    if console is None:
        console = Console()
    table = Table(
        title=title,
        title_style="bold cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Probe", style="bold cyan")
    table.add_column("Target", style="green")
    table.add_column("Key Fields", style="white")
    table.add_column("Verdict", style="yellow")

    if not observations:
        table.add_row("-", "-", "No observations recorded", "unclassified")
    else:
        for obs in observations:
            target_str = obs.target.host
            if obs.target.port is not None:
                target_str = f"{target_str}:{obs.target.port}"
            table.add_row(
                obs.probe_name,
                target_str,
                str(obs.raw),
                "unclassified",
            )
    console.print(table)
