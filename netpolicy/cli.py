"""Command-line interface for netpolicy."""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from netpolicy import __version__
from netpolicy.config import (
    AppConfig,
    PortDefinition,
    load_config,
    parse_ports_arg,
)
from netpolicy.demo import build_demo_report
from netpolicy.engine.context import Context
from netpolicy.engine.pipeline import build_audit_report
from netpolicy.engine.runner import Runner, RunnerResult
from netpolicy.models import (
    AuditReport,
    Observation,
    ReportMetadata,
    Target,
    VerdictKind,
)
from netpolicy.probes.base import Probe
from netpolicy.probes.dns import (
    BlackholeProbe,
    DohCrossCheckProbe,
    NxdomainProbe,
    SourceMismatchProbe,
    WhoamiProbe,
)
from netpolicy.probes.http import HttpCanaryProbe
from netpolicy.probes.tcp_connect import TcpConnectProbe
from netpolicy.probes.tcp_syn import TcpSynProbe
from netpolicy.report.compare import compare_reports
from netpolicy.report.jsonout import (
    generate_json_report,
    load_report,
    serialize_report,
)
from netpolicy.report.markdown import generate_markdown_report
from netpolicy.report.terminal import render_terminal_report
from netpolicy.store.raw import RawObservationStore, chown_to_sudo_user, read_run
from netpolicy.ui import (
    get_ui_console,
    maybe_launch_wsl,
    print_welcome,
    set_global_no_banner,
    should_show_banner,
    ui_session,
)

app = typer.Typer(
    name="netpolicy",
    help="CLI network policy auditor to detect silent blocking, interception, and tampering.",
    no_args_is_help=False,
    add_completion=False,
)


class ProbeMode(str, Enum):
    """Execution mode for network probes."""

    AUTO = "auto"
    RAW = "raw"
    SOCKET = "socket"


def version_callback(value: bool) -> None:
    """Print netpolicy version and exit."""
    if value:
        console = Console()
        console.print(f"netpolicy version {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show netpolicy version and exit.",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Disable gradient welcome banner and compact headers.",
    ),
    no_wizard: bool = typer.Option(
        False,
        "--no-wizard",
        help="Disable interactive wizard and print standard help.",
    ),
) -> None:
    """Audit network policies, egress filtering, and traffic interception."""
    if no_banner:
        set_global_no_banner(True)

    if ctx.invoked_subcommand is None:
        ui_console = get_ui_console()
        is_interactive = sys.stdin.isatty() and sys.stderr.isatty()
        is_handoff = os.environ.get("NETPOLICY_HANDOFF") == "1"
        banner_allowed = (
            should_show_banner(no_banner_flag=no_banner, stream=ui_console.file) and not is_handoff
        )

        # 1. If session is interactive and animation is not suppressed, call print_welcome()
        if is_interactive and banner_allowed:
            print_welcome(ui_console)

        # 2. If session is interactive and banner flags not set and NETPOLICY_NO_WSL_PROMPT not set:
        no_wsl_prompt = os.environ.get("NETPOLICY_NO_WSL_PROMPT")
        skip_wsl = is_handoff or (
            no_wsl_prompt is not None
            and no_wsl_prompt != ""
            and no_wsl_prompt.lower() not in ("0", "false", "no")
        )

        if is_interactive and not skip_wsl and not no_banner:
            wsl_code = maybe_launch_wsl(ui_console)
            if wsl_code is not None:
                raise typer.Exit(code=wsl_code)

        # 3. If session is interactive and wizard is not suppressed, launch the guided wizard
        env_no_wizard = os.environ.get("NETPOLICY_NO_WIZARD", "")
        wizard_suppressed = no_wizard or (
            env_no_wizard is not None
            and env_no_wizard != ""
            and env_no_wizard.lower() not in ("0", "false", "no")
        )

        if is_interactive and not wizard_suppressed:
            from netpolicy.wizard.ui import run_wizard

            code, _ = run_wizard()
            raise typer.Exit(code=code)

        # 4. Otherwise print standard Typer help exactly as "netpolicy --help" renders it
        console = Console()
        console.print(ctx.get_help())
        raise typer.Exit(code=0)


def _render_config_table(
    command_name: str,
    cfg: AppConfig,
    active_ports: list[PortDefinition],
    console: Console,
) -> None:
    """Print the parsed configuration and options as a formatted Rich table."""
    table = Table(
        title=f"netpolicy: {command_name.upper()} configuration",
        title_style="bold cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Parameter", style="bold", width=22)
    table.add_column("Value", style="green")

    table.add_row("Command", command_name)
    table.add_row("Target", str(cfg.general.target or "(none)"))
    table.add_row("Control Target", cfg.general.control_target)
    table.add_row("Control Port", str(cfg.ports.control_port))
    table.add_row("Probe Mode", cfg.ports.mode)
    table.add_row("Runs", str(cfg.ports.runs))
    table.add_row("Timeout", f"{cfg.ports.timeout}s")
    table.add_row("Retries", str(cfg.ports.retries))

    ports_summary = ", ".join(f"{p.port} ({p.service})" for p in active_ports)
    table.add_row("Audited Ports", ports_summary or "(none)")

    if command_name in ("audit", "dns"):
        table.add_row("DNS Resolvers", ", ".join(cfg.dns.servers))
        table.add_row("DoH Endpoints", ", ".join(cfg.dns.doh_servers))
        table.add_row("Test Domains", ", ".join(cfg.dns.domains))

    if command_name in ("audit", "http"):
        table.add_row("HTTP Ports", ", ".join(str(p) for p in cfg.http.ports))
        table.add_row("HTTP Paths", ", ".join(cfg.http.paths))

    table.add_row("Output File", str(cfg.general.output or "(stdout)"))
    table.add_row("JSON Output", str(cfg.general.json_output))
    table.add_row("Quiet Mode", str(cfg.general.quiet))
    table.add_row("Verbose Mode", str(cfg.general.verbose))
    table.add_row("No Color", str(cfg.general.no_color))
    table.add_row("Include Identifiers", str(cfg.general.include_identifiers))
    table.add_row("Demo Mode", str(cfg.general.demo))

    console.print(table)


def _format_key_fields(obs: Observation) -> str:
    """Extract and format key metrics from raw observation for summary display."""
    raw = obs.raw or {}
    parts: list[str] = []

    # 1. TCP Connect probe fields
    if "outcome" in raw:
        outcome = raw.get("outcome", "")
        errno_name = raw.get("errno_name")
        if errno_name and outcome != "connected":
            parts.append(f"outcome={outcome} ({errno_name})")
        else:
            parts.append(f"outcome={outcome}")
        if raw.get("attempt", 1) > 1:
            parts.append(f"attempt={raw['attempt']}")
        if raw.get("icmp_type") is not None:
            parts.append(f"icmp={raw.get('icmp_type')}/{raw.get('icmp_code')}")

    # 2. TCP SYN probe fields
    elif "reply_type" in raw:
        rep = raw.get("reply_type", "")
        flags = raw.get("tcp_flags")
        if flags:
            parts.append(f"reply={rep} [{flags}]")
        else:
            parts.append(f"reply={rep}")
        if raw.get("ip_ttl") is not None:
            parts.append(f"ttl={raw['ip_ttl']}")
        if raw.get("syn_ack_ttl") is not None:
            parts.append(f"ctrl_ttl={raw['syn_ack_ttl']}")
        if raw.get("icmp_type") is not None:
            parts.append(f"icmp={raw.get('icmp_type')}/{raw.get('icmp_code')}")

    # 3. HTTP Canary probe fields
    elif "status" in raw:
        scheme = raw.get("scheme", "")
        path = raw.get("path", "")
        status = raw.get("status")
        if scheme or path:
            parts.append(f"{scheme} {path} -> {status}".strip())
        else:
            parts.append(f"status={status}")
        if raw.get("nonce_matches") is not None:
            parts.append(f"nonce_ok={raw['nonce_matches']}")
        if raw.get("body_sha256"):
            parts.append(f"hash={raw['body_sha256'][:8]}...")

    # 4. DNS Probes fields
    elif "rcode_name" in raw or "rcode" in raw:
        rcode = raw.get("rcode_name") or raw.get("rcode")
        parts.append(f"rcode={rcode}")
        if raw.get("protocol"):
            parts.append(f"proto={raw['protocol']}")
        if raw.get("egress_ip"):
            parts.append(f"egress_ip={raw['egress_ip']}")
        if raw.get("hijacked") is not None:
            parts.append(f"hijacked={raw['hijacked']}")
        if raw.get("answers_match") is not None:
            parts.append(f"answers_match={raw['answers_match']}")
        if raw.get("source_differs") is not None:
            parts.append(f"src_differs={raw['source_differs']}")
        if raw.get("answers"):
            ans_str = str(raw["answers"])
            if len(ans_str) > 30:
                ans_str = ans_str[:27] + "..."
            parts.append(f"answers={ans_str}")

    # Common latency / RTT
    rtt = raw.get("rtt_ms") or raw.get("elapsed_ms")
    if rtt is not None:
        parts.append(f"rtt={rtt}ms")

    # Common error string
    if raw.get("error"):
        parts.append(f"error={raw['error']}")

    # Fallback if no specific fields matched
    if not parts:
        for k, v in list(raw.items())[:3]:
            if not isinstance(v, (dict, list)):
                parts.append(f"{k}={v}")

    return ", ".join(parts) if parts else ("success" if obs.success else "failed")


def _write_markdown_observations(
    out_path: Path,
    observations: list[Observation],
    command_name: str,
) -> None:
    """Write raw observations as a GitHub-flavored Markdown table to file."""
    lines = [
        f"# NetPolicy Audit Report: {command_name.upper()}",
        "",
        "## Raw Observations (Unclassified)",
        "",
        "| Probe | Target | Key Fields | Verdict |",
        "|---|---|---|---|",
    ]
    for obs in observations:
        target_str = obs.target.host
        if obs.target.port is not None:
            target_str = f"{target_str}:{obs.target.port}"
        if obs.target.service and obs.target.service not in ("Custom", "custom"):
            target_str += f" ({obs.target.service})"
        key_fields = _format_key_fields(obs).replace("|", "\\|")
        lines.append(f"| {obs.probe_name} | {target_str} | {key_fields} | unclassified |")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    chown_to_sudo_user(out_path)


def render_raw_observations_table(
    observations: list[Observation],
    console: Console,
    title: str = "RAW OBSERVATIONS",
) -> None:
    """Render a plain Rich table of raw probe observations before classification."""
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
            if obs.target.service and obs.target.service not in ("Custom", "custom"):
                target_str += f" ({obs.target.service})"

            key_fields = _format_key_fields(obs)
            table.add_row(
                obs.probe_name,
                target_str,
                key_fields,
                "unclassified",
            )

    console.print(table)


def _execute_audit_flow(
    command_name: str,
    jobs: list[tuple[Probe, Target]],
    ctx: Context,
    cfg: AppConfig,
    console: Console,
    control_probe: Probe | None = None,
) -> None:
    """Execute probe jobs via Runner with Rich Progress and save raw table."""
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    chown_to_sudo_user(reports_dir)
    run_id = f"{time.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
    log_file = reports_dir / f"{run_id}.jsonl"
    chown_to_sudo_user(log_file)
    store = RawObservationStore(file_path=log_file, run_id=run_id)

    progress_lock = threading.Lock()
    show_progress = not cfg.general.quiet and not cfg.general.json_output

    runner = Runner(
        ctx=ctx,
        jobs=jobs,
        store=store,
        control_probe=control_probe,
    )

    if show_progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[italic dim]{task.fields[current_probe]}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        task_id = progress.add_task(
            f"Auditing ({command_name})...",
            total=runner.total_tasks,
            current_probe="Initializing...",
        )

        def on_task_start(p: Probe, t: Target, idx: int) -> None:
            t_label = f"{t.host}:{t.port}" if t.port else t.host
            probe_label = f"Current probe: {p.name} -> {t_label} (run {idx + 1}/{ctx.runs})"
            with progress_lock:
                progress.update(
                    task_id,
                    current_probe=probe_label,
                )

        def on_task_done(p: Probe, t: Target, idx: int, obs: list[Observation]) -> None:
            with progress_lock:
                progress.advance(task_id, 1)

        runner.on_task_start = on_task_start
        runner.on_task_done = on_task_done

        try:
            with progress:
                result = runner.run()
        except KeyboardInterrupt:
            result = RunnerResult(
                all_observations=store.read_run(),
                interrupted=True,
                run_id=run_id,
            )
    else:
        try:
            result = runner.run()
        except KeyboardInterrupt:
            result = RunnerResult(
                all_observations=store.read_run(),
                interrupted=True,
                run_id=run_id,
            )

    if result.interrupted:
        console.print(
            "\n[bold yellow]Audit interrupted by user (Ctrl-C). "
            f"Saved {len(result.all_observations)} partial observations "
            f"to reports/{run_id}.jsonl[/bold yellow]"
        )
    elif not cfg.general.quiet and not cfg.general.json_output:
        console.print(f"[dim]Raw observations saved to reports/{run_id}.jsonl[/dim]")

    if not result.control_healthy and not cfg.general.quiet and not cfg.general.json_output:
        console.print(
            "[bold red]WARNING: Control probe failed! "
            "Baseline reachability to target control port is broken.[/bold red]"
        )

    # Build classified report from raw observations
    meta = ReportMetadata(
        tool_version=__version__,
        network_label="Local-Network" if not cfg.general.include_identifiers else "Audited-Network",
        network_fingerprint=ctx.network_fingerprint(),
        client_address=ctx.server_address if cfg.general.include_identifiers else "127.0.0.1",
        mode=ctx.mode,
        runs_per_check=ctx.runs,
        target=cfg.general.target,
        include_identifiers=cfg.general.include_identifiers,
    )
    report = build_audit_report(
        observations=result.all_observations,
        control_healthy=result.control_healthy,
        metadata=meta,
    )
    handle_report_completion(report, cfg, command_name, console)


def handle_report_completion(
    report: AuditReport,
    cfg: AppConfig,
    command_name: str,
    console: Console,
) -> None:
    """Central output handler enforcing format choices and exit codes.

    Rules:
    - --output PATH: writes file as JSON (.json) or Markdown (.md/.markdown)
    - --json: prints pure JSON to stdout (no Rich markup mixed in)
    - Default/terminal: renders Rich terminal report
    - Exit code 0: No findings / all clean
    - Exit code 1: Policy findings detected
    - Exit code 2: Error
    """
    # 1. Handle file output if requested
    if cfg.general.output is not None:
        out_path = Path(cfg.general.output).expanduser()
        ext = out_path.suffix.lower()
        if ext == ".json":
            generate_json_report(
                report=report,
                output_path=out_path,
                include_identifiers=cfg.general.include_identifiers,
            )
        elif ext in (".md", ".markdown"):
            generate_markdown_report(
                report=report,
                output_path=out_path,
                include_identifiers=cfg.general.include_identifiers,
            )
        else:
            console.print(
                f"[bold red]Error:[/bold red] Unsupported output file extension '{ext}'. "
                "Supported formats are .json and .md."
            )
            raise typer.Exit(code=2)
        chown_to_sudo_user(out_path)
        if out_path.parent.exists():
            chown_to_sudo_user(out_path.parent)

    # 2. Determine exit code based on findings
    clean_kinds = (VerdictKind.OPEN, VerdictKind.OK, VerdictKind.CLEAN)
    section = "all" if command_name in ("audit", "reclassify") else command_name
    if section == "ports":
        active_findings = [
            f for f in report.findings if any(v in report.port_results for v in f.verdicts)
        ]
        has_anomalies = any(p.kind not in clean_kinds for p in report.port_results)
    elif section == "dns":
        active_findings = [
            f for f in report.findings if any(v in report.dns_results for v in f.verdicts)
        ]
        has_anomalies = any(d.kind not in clean_kinds for d in report.dns_results)
    elif section == "http":
        active_findings = [
            f for f in report.findings if any(v in report.http_results for v in f.verdicts)
        ]
        has_anomalies = any(h.kind not in clean_kinds for h in report.http_results)
    else:
        active_findings = report.findings
        has_anomalies = (
            any(p.kind not in clean_kinds for p in report.port_results)
            or any(d.kind not in clean_kinds for d in report.dns_results)
            or any(h.kind not in clean_kinds for h in report.http_results)
        )

    exit_code = 1 if (active_findings or has_anomalies) else 0

    # 3. Print output: JSON vs Terminal
    if cfg.general.json_output:
        json_str = serialize_report(
            report=report,
            include_identifiers=cfg.general.include_identifiers,
        )
        print(json_str)
        raise typer.Exit(code=exit_code)

    render_terminal_report(
        report=report,
        console=console,
        section=section,
        show_progress=not cfg.general.quiet,
        quiet=cfg.general.quiet,
        verbose=cfg.general.verbose,
        no_color=cfg.general.no_color,
    )
    raise typer.Exit(code=exit_code)


def _prepare_config(
    command: str,
    target: str | None,
    ports: str | None,
    runs: int,
    timeout: float,
    retries: int,
    mode: ProbeMode,
    json_output: bool,
    quiet: bool,
    verbose: bool,
    no_color: bool,
    output: Path | None,
    include_identifiers: bool,
    demo: bool,
    config: Path | None,
    require_target: bool = False,
) -> tuple[AppConfig, list[PortDefinition], Console]:
    """Merge CLI arguments with file/default configuration and validate."""
    console = Console(no_color=no_color)

    try:
        app_cfg = load_config(config)
    except Exception as exc:
        console.print(f"[bold red]Configuration Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    # Merge CLI options into configuration
    if target is not None:
        app_cfg.general.target = target
    elif demo and not app_cfg.general.target:
        app_cfg.general.target = "demo.netpolicy.local"

    if require_target and not app_cfg.general.target:
        console.print(
            "[bold red]Error:[/bold red] --target is required for this command "
            "(or configure in YAML / pass --demo)."
        )
        raise typer.Exit(code=2)

    app_cfg.ports.runs = runs
    app_cfg.ports.timeout = timeout
    app_cfg.ports.retries = retries
    app_cfg.ports.mode = mode.value

    app_cfg.general.output = output
    app_cfg.general.json_output = json_output
    app_cfg.general.quiet = quiet
    app_cfg.general.verbose = verbose
    app_cfg.general.no_color = no_color
    app_cfg.general.include_identifiers = include_identifiers
    app_cfg.general.demo = demo

    try:
        active_ports = parse_ports_arg(ports, app_cfg.ports.ports)
    except ValueError as exc:
        console.print(f"[bold red]Argument Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    return app_cfg, active_ports, console


@app.command("audit")
def audit(
    target: str | None = typer.Option(
        None, "--target", "-t", help="Probe server host or IP (required for ports/http)."
    ),
    ports: str | None = typer.Option(
        None, "--ports", "-p", help="Comma-separated port list to audit."
    ),
    runs: int = typer.Option(5, "--runs", "-r", help="Number of probe iterations."),
    timeout: float = typer.Option(3.0, "--timeout", help="Timeout per probe in seconds."),
    retries: int = typer.Option(2, "--retries", help="Retries before concluding a block."),
    mode: ProbeMode = typer.Option(ProbeMode.AUTO, "--mode", "-m", help="Probe mode."),
    control_port: int | None = typer.Option(
        None,
        "--control-port",
        help="Port known to be open on target for control probe (default 443).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal terminal output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write report."),
    include_identifiers: bool = typer.Option(
        False, "--include-identifiers", help="Include SSID/MAC/IP in output."
    ),
    demo: bool = typer.Option(False, "--demo", help="Run with mock data."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Execute full network audit (ports + DNS + HTTP)."""
    cfg, active_ports, console = _prepare_config(
        command="audit",
        target=target,
        ports=ports,
        runs=runs,
        timeout=timeout,
        retries=retries,
        mode=mode,
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
        output=output,
        include_identifiers=include_identifiers,
        demo=demo,
        config=config,
        require_target=True,
    )
    with ui_session(
        command="audit",
        target=cfg.general.target,
        mode=cfg.ports.mode,
        json_flag=json_output,
        quiet_flag=quiet,
        no_banner=no_banner,
    ):
        if control_port is not None:
            cfg.ports.control_port = control_port

        if demo:
            report = build_demo_report()
            report.metadata.mode = cfg.ports.mode
            report.metadata.runs_per_check = cfg.ports.runs
            report.metadata.include_identifiers = cfg.general.include_identifiers
            if cfg.general.target:
                report.metadata.target = cfg.general.target
            handle_report_completion(report, cfg, "audit", console)

        if not cfg.general.quiet and not cfg.general.json_output:
            _render_config_table("audit", cfg, active_ports, console)

        target_host = cfg.general.target or ""
        control_target = Target(
            host=target_host,
            port=cfg.ports.control_port,
            service="Control",
            expect_open=True,
        )
        ctx = Context(
            mode=cfg.ports.mode,
            timeout=cfg.ports.timeout,
            retries=cfg.ports.retries,
            runs=cfg.ports.runs,
            control_target=control_target,
        )

        probe_cls: type[Probe] = TcpSynProbe if ctx.mode == "raw" else TcpConnectProbe

        try:
            ports_probe = probe_cls()
            control_probe = probe_cls()
        except PermissionError as exc:
            console.print(f"[bold red]Permission Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

        # 1. Ports jobs
        port_jobs: list[tuple[Probe, Target]] = []
        for p in active_ports:
            is_ctrl = p.port == cfg.ports.control_port
            port_jobs.append(
                (
                    ports_probe,
                    Target(
                        host=target_host,
                        port=p.port,
                        service=p.service,
                        expect_open=is_ctrl,
                    ),
                )
            )

        # 2. DNS jobs
        dns_jobs: list[tuple[Probe, Target]] = [
            (
                BlackholeProbe(cfg.dns.blackhole_servers),
                Target(host=target_host, port=53, service="DNS-Blackhole"),
            ),
            (
                WhoamiProbe(cfg.dns.whoami_name, cfg.dns.whoami_resolver),
                Target(host=target_host, port=53, service="DNS-Whoami"),
            ),
            (
                NxdomainProbe(cfg.dns.nxdomain_count, cfg.dns.nxdomain_resolver),
                Target(host=target_host, port=53, service="DNS-Nxdomain"),
            ),
            (
                DohCrossCheckProbe(
                    cfg.dns.doh_crosscheck_domains,
                    cfg.dns.doh_crosscheck_resolver,
                    cfg.dns.doh_crosscheck_url,
                ),
                Target(host=target_host, port=53, service="DNS-DoH"),
            ),
            (
                SourceMismatchProbe(cfg.dns.source_mismatch_resolvers),
                Target(host=target_host, port=53, service="DNS-SourceMismatch"),
            ),
        ]

        # 3. HTTP jobs
        http_probe = HttpCanaryProbe(
            http_port=80,
            https_port=443,
            user_agent=cfg.http.user_agent,
        )
        http_jobs: list[tuple[Probe, Target]] = [
            (
                http_probe,
                Target(
                    host=target_host,
                    port=p,
                    service="HTTP" if p == 80 else ("HTTPS" if p == 443 else f"HTTP-{p}"),
                ),
            )
            for p in cfg.http.ports
        ]

        all_jobs = port_jobs + dns_jobs + http_jobs

        _execute_audit_flow(
            command_name="audit",
            jobs=all_jobs,
            ctx=ctx,
            cfg=cfg,
            console=console,
            control_probe=control_probe,
        )


@app.command("ports")
def ports(
    target: str | None = typer.Option(
        None, "--target", "-t", help="Probe server host or IP (required)."
    ),
    ports: str | None = typer.Option(
        None, "--ports", "-p", help="Comma-separated port list to audit."
    ),
    runs: int = typer.Option(5, "--runs", "-r", help="Number of probe iterations."),
    timeout: float = typer.Option(3.0, "--timeout", help="Timeout per probe in seconds."),
    retries: int = typer.Option(2, "--retries", help="Retries before concluding a block."),
    mode: ProbeMode = typer.Option(ProbeMode.AUTO, "--mode", "-m", help="Probe mode."),
    control_port: int | None = typer.Option(
        None,
        "--control-port",
        help="Port known to be open on target for control probe (default 443).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal terminal output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write report."),
    include_identifiers: bool = typer.Option(
        False, "--include-identifiers", help="Include SSID/MAC/IP in output."
    ),
    demo: bool = typer.Option(False, "--demo", help="Run with mock data."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Audit outbound port reachability and firewall behavior."""
    cfg, active_ports, console = _prepare_config(
        command="ports",
        target=target,
        ports=ports,
        runs=runs,
        timeout=timeout,
        retries=retries,
        mode=mode,
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
        output=output,
        include_identifiers=include_identifiers,
        demo=demo,
        config=config,
        require_target=True,
    )
    with ui_session(
        command="ports",
        target=cfg.general.target,
        mode=cfg.ports.mode,
        json_flag=json_output,
        quiet_flag=quiet,
        no_banner=no_banner,
    ):
        if control_port is not None:
            cfg.ports.control_port = control_port

        if demo:
            report = build_demo_report()
            report.metadata.mode = cfg.ports.mode
            report.metadata.runs_per_check = cfg.ports.runs
            report.metadata.include_identifiers = cfg.general.include_identifiers
            if cfg.general.target:
                report.metadata.target = cfg.general.target
            handle_report_completion(report, cfg, "ports", console)

        if not cfg.general.quiet and not cfg.general.json_output:
            _render_config_table("ports", cfg, active_ports, console)

        target_host = cfg.general.target or ""
        control_target = Target(
            host=target_host,
            port=cfg.ports.control_port,
            service="Control",
            expect_open=True,
        )
        ctx = Context(
            mode=cfg.ports.mode,
            timeout=cfg.ports.timeout,
            retries=cfg.ports.retries,
            runs=cfg.ports.runs,
            control_target=control_target,
        )

        probe_cls: type[Probe] = TcpSynProbe if ctx.mode == "raw" else TcpConnectProbe

        try:
            probe_instance = probe_cls()
            control_probe = probe_cls()
        except PermissionError as exc:
            console.print(f"[bold red]Permission Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

        jobs: list[tuple[Probe, Target]] = []
        for p in active_ports:
            is_ctrl = p.port == cfg.ports.control_port
            jobs.append(
                (
                    probe_instance,
                    Target(
                        host=target_host,
                        port=p.port,
                        service=p.service,
                        expect_open=is_ctrl,
                    ),
                )
            )

        _execute_audit_flow(
            command_name="ports",
            jobs=jobs,
            ctx=ctx,
            cfg=cfg,
            console=console,
            control_probe=control_probe,
        )


@app.command("dns")
def dns(
    target: str | None = typer.Option(
        None, "--target", "-t", help="Optional specific DNS target server."
    ),
    ports: str | None = typer.Option(
        None, "--ports", "-p", help="Comma-separated port list to audit."
    ),
    runs: int = typer.Option(5, "--runs", "-r", help="Number of probe iterations."),
    timeout: float = typer.Option(3.0, "--timeout", help="Timeout per probe in seconds."),
    retries: int = typer.Option(2, "--retries", help="Retries before concluding a block."),
    mode: ProbeMode = typer.Option(ProbeMode.AUTO, "--mode", "-m", help="Probe mode."),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal terminal output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write report."),
    include_identifiers: bool = typer.Option(
        False, "--include-identifiers", help="Include SSID/MAC/IP in output."
    ),
    demo: bool = typer.Option(False, "--demo", help="Run with mock data."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Audit DNS interception, redirection, and tampering."""
    cfg, active_ports, console = _prepare_config(
        command="dns",
        target=target,
        ports=ports,
        runs=runs,
        timeout=timeout,
        retries=retries,
        mode=mode,
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
        output=output,
        include_identifiers=include_identifiers,
        demo=demo,
        config=config,
        require_target=False,
    )
    with ui_session(
        command="dns",
        target=cfg.general.target or "auto",
        mode=cfg.ports.mode,
        json_flag=json_output,
        quiet_flag=quiet,
        no_banner=no_banner,
    ):
        if demo:
            report = build_demo_report()
            report.metadata.mode = cfg.ports.mode
            report.metadata.runs_per_check = cfg.ports.runs
            report.metadata.include_identifiers = cfg.general.include_identifiers
            if cfg.general.target:
                report.metadata.target = cfg.general.target
            handle_report_completion(report, cfg, "dns", console)

        if not cfg.general.quiet and not cfg.general.json_output:
            _render_config_table("dns", cfg, active_ports, console)

        ctx = Context(
            mode=cfg.ports.mode,
            timeout=cfg.dns.timeout,
            retries=cfg.dns.retries,
            runs=cfg.ports.runs,
            control_target=Target(
                host=cfg.general.control_target,
                port=53,
                service="Control-DNS",
            ),
        )

        target_host = cfg.general.target or "auto"
        jobs: list[tuple[Probe, Target]] = [
            (
                BlackholeProbe(cfg.dns.blackhole_servers),
                Target(host=target_host, port=53, service="DNS-Blackhole"),
            ),
            (
                WhoamiProbe(cfg.dns.whoami_name, cfg.dns.whoami_resolver),
                Target(host=target_host, port=53, service="DNS-Whoami"),
            ),
            (
                NxdomainProbe(cfg.dns.nxdomain_count, cfg.dns.nxdomain_resolver),
                Target(host=target_host, port=53, service="DNS-Nxdomain"),
            ),
            (
                DohCrossCheckProbe(
                    cfg.dns.doh_crosscheck_domains,
                    cfg.dns.doh_crosscheck_resolver,
                    cfg.dns.doh_crosscheck_url,
                ),
                Target(host=target_host, port=53, service="DNS-DoH"),
            ),
            (
                SourceMismatchProbe(cfg.dns.source_mismatch_resolvers),
                Target(host=target_host, port=53, service="DNS-SourceMismatch"),
            ),
        ]

        _execute_audit_flow(
            command_name="dns",
            jobs=jobs,
            ctx=ctx,
            cfg=cfg,
            console=console,
        )


@app.command("http")
def http(
    target: str | None = typer.Option(
        None, "--target", "-t", help="Probe server host or IP (required)."
    ),
    ports: str | None = typer.Option(
        None, "--ports", "-p", help="Comma-separated port list to audit."
    ),
    runs: int = typer.Option(5, "--runs", "-r", help="Number of probe iterations."),
    timeout: float = typer.Option(3.0, "--timeout", help="Timeout per probe in seconds."),
    retries: int = typer.Option(2, "--retries", help="Retries before concluding a block."),
    mode: ProbeMode = typer.Option(ProbeMode.AUTO, "--mode", "-m", help="Probe mode."),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal terminal output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write report."),
    include_identifiers: bool = typer.Option(
        False, "--include-identifiers", help="Include SSID/MAC/IP in output."
    ),
    demo: bool = typer.Option(False, "--demo", help="Run with mock data."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Audit HTTP tampering, header injection, and captive portal interception."""
    cfg, active_ports, console = _prepare_config(
        command="http",
        target=target,
        ports=ports,
        runs=runs,
        timeout=timeout,
        retries=retries,
        mode=mode,
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
        output=output,
        include_identifiers=include_identifiers,
        demo=demo,
        config=config,
        require_target=True,
    )
    with ui_session(
        command="http",
        target=cfg.general.target,
        mode=cfg.ports.mode,
        json_flag=json_output,
        quiet_flag=quiet,
        no_banner=no_banner,
    ):
        if demo:
            report = build_demo_report()
            report.metadata.mode = cfg.ports.mode
            report.metadata.runs_per_check = cfg.ports.runs
            report.metadata.include_identifiers = cfg.general.include_identifiers
            if cfg.general.target:
                report.metadata.target = cfg.general.target
            handle_report_completion(report, cfg, "http", console)

        if not cfg.general.quiet and not cfg.general.json_output:
            _render_config_table("http", cfg, active_ports, console)

        target_host = cfg.general.target or ""
        http_ports = [p.port for p in active_ports] if ports is not None else cfg.http.ports

        ctx = Context(
            mode=cfg.ports.mode,
            timeout=cfg.http.timeout,
            retries=cfg.http.retries,
            runs=cfg.ports.runs,
            control_target=Target(
                host=target_host,
                port=cfg.ports.control_port,
                service="Control",
                expect_open=True,
            ),
        )

        probe = HttpCanaryProbe(
            http_port=80,
            https_port=443,
            user_agent=cfg.http.user_agent,
        )

        jobs: list[tuple[Probe, Target]] = []
        for p in http_ports:
            service_name = "HTTP" if p == 80 else ("HTTPS" if p == 443 else f"HTTP-{p}")
            jobs.append((probe, Target(host=target_host, port=p, service=service_name)))

        _execute_audit_flow(
            command_name="http",
            jobs=jobs,
            ctx=ctx,
            cfg=cfg,
            console=console,
        )


def _print_invalid_report_help(
    path: Path | str,
    console: Console,
    detail: str | None = None,
) -> None:
    """Print a helpful message explaining what compare expects and how to generate a baseline."""
    console.print(f"[bold red]Error:[/bold red] Invalid or unparseable report file '{path}'.")
    if detail:
        console.print(f"[dim]Detail: {detail}[/dim]")
    console.print(
        "\nExpected either:\n"
        "  1. A classified AuditReport JSON file (.json)\n"
        "  2. A raw telemetry observations run file (.jsonl)\n\n"
        "To generate a valid baseline JSON report, run:\n"
        "  [cyan]netpolicy audit --output baseline.json[/cyan]\n"
        "or:\n"
        "  [cyan]netpolicy audit --json > baseline.json[/cyan]\n"
    )


def _load_or_reclassify_report(path: Path | str, console: Console) -> AuditReport:
    """Load an AuditReport from a .json file or reclassify on the fly from a .jsonl run."""
    report_path = Path(path).expanduser()
    if not report_path.is_file():
        # Check if it exists under reports/
        candidate = Path("reports") / report_path.name
        if candidate.is_file():
            report_path = candidate
        else:
            console.print(f"[bold red]File Error:[/bold red] Report file not found: {path}")
            raise typer.Exit(code=2)

    report_path = report_path.resolve()

    # 1. If explicitly .jsonl, reclassify from raw observations
    if report_path.suffix.lower() == ".jsonl":
        try:
            observations = read_run(report_path)
            if not observations:
                _print_invalid_report_help(
                    report_path, console, "File contains no valid observations."
                )
                raise typer.Exit(code=2)
            meta = ReportMetadata(
                tool_version=__version__,
                network_label=f"Run-{report_path.stem}",
                network_fingerprint=Context.compute_network_fingerprint(),
                client_address="127.0.0.1",
                mode="auto",
                runs_per_check=1,
                include_identifiers=False,
            )
            return build_audit_report(
                observations=observations,
                control_healthy=True,
                metadata=meta,
            )
        except typer.Exit:
            raise
        except Exception as exc:
            _print_invalid_report_help(report_path, console, str(exc))
            raise typer.Exit(code=2) from exc

    # 2. Try loading as a classified AuditReport JSON
    try:
        return load_report(report_path)
    except Exception as exc_json:
        # 3. If loading as JSON failed, test if it's a JSONL observation file with another extension
        try:
            observations = read_run(report_path)
            if observations:
                meta = ReportMetadata(
                    tool_version=__version__,
                    network_label=f"Run-{report_path.stem}",
                    network_fingerprint=Context.compute_network_fingerprint(),
                    client_address="127.0.0.1",
                    mode="auto",
                    runs_per_check=1,
                    include_identifiers=False,
                )
                return build_audit_report(
                    observations=observations,
                    control_healthy=True,
                    metadata=meta,
                )
        except Exception:
            pass

        _print_invalid_report_help(report_path, console, str(exc_json))
        raise typer.Exit(code=2) from exc_json


@app.command("compare")
def compare(
    report_a: Path = typer.Argument(
        ...,
        help="Path to baseline report (.json or .jsonl).",
    ),
    report_b: Path = typer.Argument(
        ...,
        help="Path to comparison report (.json or .jsonl).",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Compare two audit reports (.json or .jsonl) to highlight differences in network policies."""
    with ui_session(
        command="compare",
        target=f"{report_a.name} vs {report_b.name}",
        mode="diff",
        json_flag=json_output,
        quiet_flag=False,
        no_banner=no_banner,
    ):
        console = Console(no_color=no_color)
        a = _load_or_reclassify_report(report_a, console)
        b = _load_or_reclassify_report(report_b, console)

        diffs, table = compare_reports(a, b)
        if diffs:
            if json_output:
                diff_dicts = [d.to_dict() for d in diffs]
                print(json.dumps({"changed": True, "diffs": diff_dicts}, indent=2))
            else:
                console.print(table)
            raise typer.Exit(code=1)

        if json_output:
            print(json.dumps({"changed": False, "diffs": []}, indent=2))
        else:
            console.print(
                "[bold green]✓ No policy changes detected. "
                "Both audit reports are identical.[/bold green]"
            )
        raise typer.Exit(code=0)


@app.command("lab")
def lab() -> None:
    """Manage and inspect reproducible Linux network namespace test labs."""
    console = Console()
    console.print("not implemented yet")


@app.command("reclassify")
def reclassify(
    run_id: str = typer.Argument(
        ...,
        help="Run ID or path to .jsonl file to reclassify.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Format output as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal terminal output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color formatting."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Path to write report."),
    include_identifiers: bool = typer.Option(
        False, "--include-identifiers", help="Include SSID/MAC/IP in output."
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Disable gradient header and footer."
    ),
) -> None:
    """Reclassify raw observations from a saved .jsonl file through updated classifier rules."""
    with ui_session(
        command="reclassify",
        target=Path(run_id).name,
        mode="offline",
        json_flag=json_output,
        quiet_flag=quiet,
        no_banner=no_banner,
    ):
        console = Console(no_color=no_color)
        cfg, _, _ = _prepare_config(
            command="reclassify",
            target=None,
            ports=None,
            runs=1,
            timeout=3.0,
            retries=2,
            mode=ProbeMode.AUTO,
            json_output=json_output,
            quiet=quiet,
            verbose=verbose,
            no_color=no_color,
            output=output,
            include_identifiers=include_identifiers,
            demo=False,
            config=config,
            require_target=False,
        )

        # Locate the .jsonl file
        target_path = Path(run_id)
        candidates = [
            target_path,
            Path("reports") / run_id,
            Path("reports") / f"{run_id}.jsonl",
            Path("reports") / f"{target_path.stem}.jsonl",
        ]
        resolved_path: Path | None = None
        for cand in candidates:
            if cand.is_file():
                resolved_path = cand
                break

        if resolved_path is None:
            console.print(
                f"[bold red]Error:[/bold red] Could not find audit run file '{run_id}'. "
                "Searched in current working directory and ./reports/."
            )
            raise typer.Exit(code=2)

        try:
            observations = read_run(resolved_path)
        except Exception as exc:
            console.print(f"[bold red]Error reading run file:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

        if not observations:
            console.print(
                f"[bold red]Error:[/bold red] No valid observations found in '{resolved_path}'."
            )
            raise typer.Exit(code=2)

        meta = ReportMetadata(
            tool_version=__version__,
            network_label="Reclassified-Run",
            network_fingerprint=Context.compute_network_fingerprint(),
            client_address="127.0.0.1",
            mode="auto",
            runs_per_check=1,
            include_identifiers=include_identifiers,
        )

        report = build_audit_report(
            observations=observations,
            control_healthy=True,
            metadata=meta,
        )

        handle_report_completion(report, cfg, "audit", console)


@app.command(
    "wizard",
    help="Interactive guided wizard to configure and run network policy audits.",
)
def wizard(
    graph: str | None = typer.Option(
        None,
        "--graph",
        help="Export finite-state machine graph and exit (mermaid | dot).",
    ),
    transcript: Path | None = typer.Option(
        None,
        "--transcript",
        help="Custom file path to save the session JSON transcript.",
    ),
    replay: Path | None = typer.Option(
        None,
        "--replay",
        hidden=True,
        help="Replay a previously saved session transcript file.",
    ),
) -> None:
    """Run the interactive guided wizard or inspect its state machine."""
    from netpolicy.wizard.fsm import to_dot, to_mermaid

    if graph:
        fmt = graph.lower().strip()
        if fmt == "mermaid":
            sys.stdout.write(to_mermaid() + "\n")
            raise typer.Exit(code=0)
        elif fmt == "dot":
            sys.stdout.write(to_dot() + "\n")
            raise typer.Exit(code=0)
        else:
            console = Console(stderr=True)
            console.print(
                f"[bold red]Error:[/bold red] Unknown graph format '{graph}'. "
                "Supported formats: mermaid, dot."
            )
            raise typer.Exit(code=2)

    if replay:
        from netpolicy.wizard.ui import run_replay

        code = run_replay(replay)
        raise typer.Exit(code=code)

    is_interactive = sys.stdin.isatty() and sys.stderr.isatty()
    if not is_interactive:
        console = Console(stderr=True)
        console.print(
            "[bold red]Error:[/bold red] 'netpolicy wizard' requires an interactive terminal. "
            "Use --help for subcommands."
        )
        raise typer.Exit(code=2)

    from netpolicy.wizard.ui import run_wizard

    code, _ = run_wizard(transcript_path=transcript)
    raise typer.Exit(code=code)


if __name__ == "__main__":
    app()
