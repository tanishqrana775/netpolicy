# ruff: noqa: E501
"""Redesigned Rich terminal renderer for plain-English verdicts and progressive disclosure (Stage 5)."""

from __future__ import annotations

import time

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from netpolicy.models import (
    AuditReport,
    Observation,
    VerdictKind,
)
from netpolicy.report.humanize import (
    get_verdict_description,
    get_verdict_headline,
    humanize_verdict_kind,
    service_group,
)
from netpolicy.report.summary import (
    Caveat,
    Issue,
    VerdictSummary,
    aggregate,
    apply_reliability_gates,
    compute_verdict,
)
from netpolicy.wizard.recommend import solutions_for


def _is_utf8(console: Console) -> bool:
    """Check if the console stream supports UTF-8 character encoding."""
    enc = getattr(console, "encoding", None) or getattr(
        getattr(console, "file", None), "encoding", None
    )
    if enc:
        clean = enc.lower().replace("-", "").replace("_", "")
        return clean in ("utf8", "utf")
    return True


def _get_symbols(console: Console) -> dict[str, str]:
    """Return UTF-8 symbols or ASCII fallbacks based on console capabilities."""
    legacy = getattr(console, "legacy_windows", False)
    utf8 = _is_utf8(console) and not legacy
    if utf8:
        return {
            "diamond": "◆",
            "diamond_empty": "◇",
            "check": "✔",
            "cross": "✖",
            "chevron": "❯",
            "rail": "│",
            "corner": "└",
            "dot": "●",
            "dot_empty": "○",
            "bar": "━",
            "dash": "─",
            "prompt": "›",
        }
    return {
        "diamond": "*",
        "diamond_empty": "o",
        "check": "v",
        "cross": "x",
        "chevron": ">",
        "rail": "|",
        "corner": "+",
        "dot": "*",
        "dot_empty": "o",
        "bar": "=",
        "dash": "-",
        "prompt": ">",
    }


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


def _get_level_badge(level: str, console: Console) -> tuple[str, str]:
    """Return symbol and color for a verdict level respecting UTF-8/ASCII fallback."""
    colors = {
        "CLEAN": "#5ee89a",
        "LIMITED": "#ffd166",
        "ACTION_REQUIRED": "#ff9f43",
        "RESTRICTED": "#ff6b6b",
        "INCONCLUSIVE": "#7a7a8c",
    }
    hex_color = colors.get(level, "#7a7a8c")
    sym = _get_symbols(console)
    return sym["dot"], hex_color


def _render_hero_panel(
    verdict: VerdictSummary,
    console: Console,
) -> None:
    """Render the top-level plain-English Hero Panel with segmented confidence bar."""
    colors = {
        "CLEAN": "#5ee89a",
        "LIMITED": "#ffd166",
        "ACTION_REQUIRED": "#ff9f43",
        "RESTRICTED": "#ff6b6b",
        "INCONCLUSIVE": "#7a7a8c",
    }
    border_color = colors.get(verdict.level, "#7a7a8c")
    sym = _get_symbols(console)
    dot = sym["dot"]

    headline = get_verdict_headline(verdict.level)
    description = get_verdict_description(verdict.level)

    # Segmented bar: High (10 filled), Medium (6 filled, 4 light), Low (3 filled, 7 light)
    conf_val = (
        verdict.confidence.value.lower()
        if hasattr(verdict.confidence, "value")
        else str(verdict.confidence).lower()
    )
    bar_char = sym["bar"]
    dash_char = sym["dash"]
    if conf_val == "high":
        bar_str = bar_char * 10
        conf_label = "High"
    elif conf_val == "medium":
        bar_str = bar_char * 6 + dash_char * 4
        conf_label = "Medium"
    else:
        bar_str = bar_char * 3 + dash_char * 7
        conf_label = "Low"

    panel_width = min(console.width, 90)

    content = Text()
    content.append(f"  {dot} {headline} ({verdict.level})\n", style=f"bold {border_color}")
    content.append(f"  {description}\n", style="white" if not console.no_color else "")
    content.append("  How sure we are  ", style="dim")
    content.append(f"{bar_str}  ", style=border_color if not console.no_color else "dim")
    content.append(conf_label, style="bold")

    panel = Panel(
        content,
        box=box.ROUNDED,
        padding=(0, 2),
        border_style=border_color if not console.no_color else "none",
        width=panel_width,
        expand=False,
    )
    console.print(panel)


def _render_scorecards(
    report: AuditReport,
    issues: list[Issue],
    console: Console,
    section: str = "all",
) -> None:
    """Render up to four small rounded scorecards in a row."""
    sym = _get_symbols(console)
    dot = sym["dot"]
    dot_empty = sym["dot_empty"]

    cards: list[Panel] = []
    card_width = 20 if console.width >= 85 else (min(console.width - 4, 24))

    # 1. Websites (Ports 80 / 443)
    if section in ("all", "ports"):
        web_ports = [p for p in report.port_results if p.target.port in (80, 443)]
        if not web_ports and not report.port_results:
            web_status = f"{dot_empty} Not checked"
            web_style = "dim"
            web_detail = "Skipped"
        elif any(
            p.kind not in (VerdictKind.OPEN, VerdictKind.OK, VerdictKind.CLEAN) for p in web_ports
        ):
            web_status = f"{dot} Blocked"
            web_style = "#ff6b6b"
            web_detail = "Filtered"
        else:
            web_status = f"{dot} Working"
            web_style = "#5ee89a"
            web_detail = "Reachable"

        t_web = Text()
        t_web.append(f"{web_status}\n", style=f"bold {web_style}")
        t_web.append(web_detail, style="dim")
        cards.append(
            Panel(
                t_web,
                title="[bold]Websites[/bold]",
                box=box.ROUNDED,
                width=card_width,
                padding=(0, 1),
            )
        )

    # 2. Name lookups (DNS)
    if section in ("all", "dns"):
        if not report.dns_results:
            dns_status = f"{dot_empty} Not checked"
            dns_style = "dim"
            dns_detail = "Skipped"
        elif any(
            d.kind
            in (
                VerdictKind.INTERCEPTED,
                VerdictKind.TAMPERED,
                VerdictKind.REWRITTEN,
            )
            for d in report.dns_results
        ):
            dns_status = f"{dot} Redirected"
            dns_style = "#ffd166"
            dns_detail = "Lookups altered"
        elif any(
            d.kind in (VerdictKind.DROPPED, VerdictKind.BLOCKED_DROP) for d in report.dns_results
        ):
            dns_status = f"{dot} Blocked"
            dns_style = "#ff6b6b"
            dns_detail = "No reply"
        else:
            dns_status = f"{dot} Working"
            dns_style = "#5ee89a"
            dns_detail = "Lookups working"

        t_dns = Text()
        t_dns.append(f"{dns_status}\n", style=f"bold {dns_style}")
        t_dns.append(dns_detail, style="dim")
        cards.append(
            Panel(
                t_dns,
                title="[bold]Address lookups[/bold]",
                box=box.ROUNDED,
                width=card_width,
                padding=(0, 1),
            )
        )

    # 3. Web content (HTTP)
    if section in ("all", "http"):
        if not report.http_results:
            http_status = f"{dot_empty} Not checked"
            http_style = "dim"
            http_detail = "Skipped"
        elif any(h.kind == VerdictKind.REDIRECTED for h in report.http_results):
            http_status = f"{dot} Login page"
            http_style = "#ff9f43"
            http_detail = "Sign-in required"
        elif any(
            h.kind
            in (
                VerdictKind.HEADERS_INJECTED,
                VerdictKind.BODY_MODIFIED,
                VerdictKind.PROXIED,
            )
            for h in report.http_results
        ):
            http_status = f"{dot} Altered"
            http_style = "#ff6b6b"
            http_detail = "Headers injected"
        else:
            http_status = f"{dot} Working"
            http_style = "#5ee89a"
            http_detail = "Clean content"

        t_http = Text()
        t_http.append(f"{http_status}\n", style=f"bold {http_style}")
        t_http.append(http_detail, style="dim")
        cards.append(
            Panel(
                t_http,
                title="[bold]Web pages[/bold]",
                box=box.ROUNDED,
                width=card_width,
                padding=(0, 1),
            )
        )

    # 4. Remote login (SSH / Port 22)
    if section in ("all", "ports"):
        ssh_ports = [p for p in report.port_results if p.target.port == 22]
        if not ssh_ports:
            ssh_status = f"{dot_empty} Not checked"
            ssh_style = "dim"
            ssh_detail = "Skipped"
        elif any(
            p.kind not in (VerdictKind.OPEN, VerdictKind.OK, VerdictKind.CLEAN) for p in ssh_ports
        ):
            ssh_status = f"{dot} Blocked"
            ssh_style = "#ff6b6b"
            ssh_detail = "Port 22 filtered"
        else:
            ssh_status = f"{dot} Working"
            ssh_style = "#5ee89a"
            ssh_detail = "Port 22 open"

        t_ssh = Text()
        t_ssh.append(f"{ssh_status}\n", style=f"bold {ssh_style}")
        t_ssh.append(ssh_detail, style="dim")
        cards.append(
            Panel(
                t_ssh,
                title="[bold]Remote login[/bold]",
                box=box.ROUNDED,
                width=card_width,
                padding=(0, 1),
            )
        )

    if cards:
        console.print(Columns(cards, padding=(0, 1), equal=True))


def _render_what_happened(
    issues: list[Issue],
    verdict: VerdictSummary,
    console: Console,
) -> None:
    """Render 'WHAT WE FOUND' section with plain sentences and counts."""
    valid_issues = [i for i in issues if getattr(i, "valid", True)]
    if not valid_issues:
        return

    console.print("\n[bold]WHAT WE FOUND[/bold]")
    lines: list[str] = []
    for iss in valid_issues[:3]:
        mult = iss.multiplier_str
        count_str = f"({mult})" if mult else ""
        lines.append(f"  • {iss.plain} {count_str}".strip())
    console.print("\n".join(lines))


def _render_what_you_can_do(
    issues: list[Issue],
    verdict: VerdictSummary,
    console: Console,
    network_kind: str = "unknown",
) -> None:
    """Render 'WHAT YOU CAN DO' rounded Panel with numbered solutions."""
    sols = solutions_for(issues, verdict, network_kind=network_kind)
    if not sols:
        return

    pcontent = Text()
    for idx, sol in enumerate(sols[:3], start=1):
        pcontent.append(f"{idx}. ", style="bold")
        pcontent.append(f"{sol.steps[0]}", style="bold white")
        pcontent.append(f"  ({sol.effort})", style="dim")
        for step in sol.steps[1:]:
            pcontent.append(f"\n   {step}", style="dim")
        if idx < len(sols[:3]):
            pcontent.append("\n\n")

    panel = Panel(
        pcontent,
        title="[bold]WHAT YOU CAN DO[/bold]",
        box=box.ROUNDED,
        padding=(1, 2),
        border_style="#7b61ff",
    )
    console.print(panel)


def _render_caveat_notes(
    caveats: list[Caveat],
    console: Console,
) -> None:
    """Render at most 2 dim-yellow Note: lines when reliability gates fired."""
    if not caveats:
        return

    console.print("")
    for c in caveats[:2]:
        style = "dim yellow" if not console.no_color else "dim"
        console.print(f"Note: {c.plain}", style=style)


def _render_footer(
    report: AuditReport,
    console: Console,
) -> None:
    """Render dim footer line."""
    console.print("")
    run_label = getattr(report.metadata, "run_id", None) or report.metadata.network_label or "audit"
    console.print(
        f"[dim]Report: {run_label} · Want the technical details? Run again with --verbose.[/dim]"
    )


def _render_verbose_sections(
    report: AuditReport,
    issues: list[Issue],
    caveats: list[Caveat],
    console: Console,
) -> None:
    """Render extended technical tables and diagnostic details for --verbose mode."""
    console.print("\n" + "=" * min(console.width, 80))
    console.print("[bold cyan]TECHNICAL EVIDENCE & DETAILED AUDIT DIAGNOSTICS[/bold cyan]")
    console.print("=" * min(console.width, 80))

    # 1. Parameters Table (non-default values only)
    param_table = Table(
        title="Audit Parameters",
        title_style="bold cyan",
        show_header=True,
        header_style="bold magenta",
        expand=False,
    )
    param_table.add_column("Parameter", style="bold", width=22)
    param_table.add_column("Configured Value", style="green")

    meta = report.metadata
    if meta.target:
        param_table.add_row("Target Host", str(meta.target))
    if meta.mode and meta.mode.lower() != "auto":
        param_table.add_row("Probe Mode", str(meta.mode))
    if meta.runs_per_check and meta.runs_per_check != 5:
        param_table.add_row("Runs Per Check", str(meta.runs_per_check))
    if meta.network_label and meta.network_label != "Guest-WiFi":
        param_table.add_row("Network Label", str(meta.network_label))

    if param_table.row_count > 0:
        console.print(param_table)

    # 2. Aggregated Ports Table
    if report.port_results:
        ports_table = Table(
            title="Outbound Ports Inspection",
            title_style="bold cyan",
            show_header=True,
            header_style="bold magenta",
            expand=False,
        )
        ports_table.add_column("Port", style="bold", width=12)
        ports_table.add_column("Service", width=16)
        ports_table.add_column("Result", width=18)
        ports_table.add_column("Technical Evidence", ratio=1)
        ports_table.add_column("Confidence", width=12)

        seen_ports: set[int | None] = set()
        for p in report.port_results:
            if p.target.port in seen_ports:
                continue
            seen_ports.add(p.target.port)

            proto = f"/{p.target.protocol}" if p.target.protocol != "tcp" else ""
            port_label = f"{p.target.port}{proto}"
            serv_label = p.target.service or service_group(p.target.port)
            res_label = humanize_verdict_kind(p.kind)

            short_ev = " ; ".join(p.evidence[:2]) if p.evidence else "Direct socket connect"
            ports_table.add_row(
                port_label,
                serv_label,
                res_label,
                short_ev,
                p.confidence.value.upper(),
            )
        console.print("\n")
        console.print(ports_table)

    # 3. DNS Checks Table
    if report.dns_results:
        console.print("\n[bold cyan]DNS RESOLUTION CHECKS[/bold cyan]")
        seen_dns: set[str] = set()
        for d in report.dns_results:
            key = f"{d.target.host}_{d.kind}"
            if key in seen_dns:
                continue
            seen_dns.add(key)
            console.print(
                f"  • {d.target.host}: {humanize_verdict_kind(d.kind)} ({d.confidence.value})"
            )
            for ev in d.evidence:
                console.print(f"      [dim]{ev}[/dim]")

    # 4. HTTP Checks Table
    if report.http_results:
        console.print("\n[bold cyan]HTTP INTEGRITY CHECKS[/bold cyan]")
        seen_http: set[str] = set()
        for h in report.http_results:
            key = f"{h.target.host}_{h.kind}"
            if key in seen_http:
                continue
            seen_http.add(key)
            console.print(
                f"  • {h.target.host}: {humanize_verdict_kind(h.kind)} ({h.confidence.value})"
            )
            for ev in h.evidence:
                console.print(f"      [dim]{ev}[/dim]")

    # 5. Invalid / Discarded Checks
    invalid_issues = [i for i in issues if not i.valid]
    if invalid_issues:
        console.print("\n[bold yellow]CHECKS THAT COULD NOT RUN OR WERE INVALID[/bold yellow]")
        for inv in invalid_issues:
            reason = inv.invalid_reason or "Target or configuration error"
            console.print(f"  • {inv.subject}: [dim]{reason}[/dim]")

    # 6. Reliability Notes
    if caveats:
        console.print("\n[bold yellow]RELIABILITY GATE EVALUATION[/bold yellow]")
        for c in caveats:
            console.print(f"  • [{c.code}] {c.technical}")

    # 7. Network Fingerprint & Run ID
    console.print("\n[bold cyan]AUDIT TELEMETRY[/bold cyan]")
    if report.metadata.network_fingerprint:
        console.print(f"  • Network Fingerprint: [dim]{report.metadata.network_fingerprint}[/dim]")
    run_time = getattr(report.metadata, "run_time", None)
    if run_time:
        console.print(f"  • Audit Timestamp:     [dim]{run_time}[/dim]")


def simulate_progress(
    console: Console,
    sections: list[str],
) -> None:
    """Display a single transient progress spinner on stderr."""
    err_console = Console(stderr=True)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=err_console,
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Auditing network policies...", total=100)
        for _ in range(20):
            progress.advance(task, 5)
            time.sleep(0.01)


def render_terminal_report(
    report: AuditReport,
    console: Console | None = None,
    section: str = "all",
    show_progress: bool = False,
    quiet: bool = False,
    verbose: bool = False,
    no_color: bool = False,
    network_kind: str = "unknown",
) -> None:
    """Render findings and audit summary report to the terminal."""
    if console is None:
        console = Console(no_color=no_color)

    # Filter by section if a specific section command was invoked
    if section == "ports":
        report = report.model_copy(update={"dns_results": [], "http_results": []})
    elif section == "dns":
        report = report.model_copy(update={"port_results": [], "http_results": []})
    elif section == "http":
        report = report.model_copy(update={"port_results": [], "dns_results": []})

    # 1. Aggregate and apply reliability gates
    raw_issues = aggregate(report)
    issues, caveats = apply_reliability_gates(raw_issues, report)
    verdict = compute_verdict(issues, caveats, report)

    # 2. Quiet Mode: Exactly one line
    if quiet:
        sym = _get_symbols(console)
        dot = sym["dot"]
        console.print(f"{dot} {verdict.level}: {verdict.sentence}")
        return

    # 3. Simulated progress in demo mode (stderr only, transient)
    if show_progress:
        simulate_progress(console, ["all"])

    # 4. Default Presentation
    # Hero Panel
    _render_hero_panel(verdict, console)

    # Scorecards
    _render_scorecards(report, issues, console, section=section)

    # What Happened
    _render_what_happened(issues, verdict, console)

    # What You Can Do
    _render_what_you_can_do(issues, verdict, console, network_kind=network_kind)

    # Reliability Note: lines (at most 2)
    _render_caveat_notes(caveats, console)

    # Dim Footer Line
    _render_footer(report, console)

    # 5. Verbose Technical Details (if requested)
    if verbose:
        _render_verbose_sections(report, issues, caveats, console)


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
