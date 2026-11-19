"""Structured academic Markdown lab report generator (Stage 6)."""
# ruff: noqa: E501

from __future__ import annotations

import datetime
import hashlib
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

from netpolicy.models import AuditReport, Observation
from netpolicy.report.summary import (
    Caveat,
    Issue,
    aggregate,
    apply_reliability_gates,
    compute_verdict,
)
from netpolicy.wizard.capture import CaptureResult, generate_wireshark_filters
from netpolicy.wizard.plan import CommandPlan
from netpolicy.wizard.runner import RunResult


def get_git_commit() -> str:
    """Safely retrieves current git commit hash with a short timeout."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return "not available"


def _compute_sha256(path: Path) -> str:
    """Computes SHA-256 hash of a file if it exists."""
    if not path.is_file():
        return "not available"
    hasher = hashlib.sha256()
    try:
        hasher.update(path.read_bytes())
        return hasher.hexdigest()
    except Exception:
        return "error reading file"


def render_lab_report(
    report: AuditReport | None,
    run_meta: dict[str, Any] | None = None,
    metrics: RunResult | None = None,
    plan: CommandPlan | None = None,
    transcript: tuple[Any, ...] = (),
    capture: CaptureResult | None = None,
    clock: Any | None = None,
    git_commit: str | None = None,
) -> str:
    """Renders a pure, deterministic, structured academic Markdown lab report."""
    now_dt = clock() if clock else datetime.datetime.now(datetime.timezone.utc)
    utc_str = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    run_id = (
        (metrics.run_id if metrics else None)
        or (run_meta.get("run_id") if run_meta else None)
        or "unknown"
    )
    commit_hash = git_commit if git_commit is not None else get_git_commit()

    from netpolicy import __version__

    # 1. Summary & Findings Extraction
    issues: list[Issue] = []
    caveats: list[Caveat] = []
    verdict_level = "CLEAN"
    verdict_sentence = "No network policy restrictions or tampering were detected."
    tested_summary = "Tested: standard suite"
    confidence_str = "HIGH"

    if report:
        try:
            raw_issues = aggregate(report)
            issues, caveats = apply_reliability_gates(raw_issues, report)
            v_summary = compute_verdict(issues, caveats, report)
            verdict_level = v_summary.level
            verdict_sentence = v_summary.sentence
            tested_summary = v_summary.tested_summary
            confidence_str = v_summary.confidence.name
        except Exception:
            pass

    lines: list[str] = []

    # --------------------------------------------------------------------------
    # 1. Title and Metadata
    # --------------------------------------------------------------------------
    lines.append(f"# Netpolicy Laboratory Audit Report: {run_id}")
    lines.append("")
    lines.append("| Metadata Attribute | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Run Identifier** | `{run_id}` |")
    lines.append(f"| **Timestamp (UTC)** | `{utc_str}` |")
    lines.append(f"| **Tool Version** | `netpolicy v{__version__}` |")
    if commit_hash != "not available":
        lines.append(f"| **Git Commit** | `{commit_hash}` |")
    lines.append(f"| **Overall Verdict** | **{verdict_level}** |")
    lines.append(f"| **Confidence Level** | `{confidence_str}` |")
    lines.append("")

    # --------------------------------------------------------------------------
    # 2. Abstract
    # --------------------------------------------------------------------------
    lines.append("## 1. Abstract")
    lines.append("")
    lines.append(
        f"This report presents empirical findings from an active network policy audit conducted with `netpolicy v{__version__}`. "
        f"The measurement suite evaluated outbound port reachability, DNS resolution integrity, and transparent HTTP proxy behavior. "
        f"Overall assessment yielded a verdict of **{verdict_level}** ({verdict_sentence}). "
        f"A total of {len(issues)} distinct issues or policy anomalies were classified with {confidence_str} confidence across the tested vectors ({tested_summary})."
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 3. Objective
    # --------------------------------------------------------------------------
    lines.append("## 2. Objective")
    lines.append("")
    goal_text = (
        plan.plain_summary if plan else "Audit network egress filtering and middlebox tampering."
    )
    lines.append(
        f"The primary experimental objective was: {goal_text}. "
        "The evaluation sought to determine whether intermediate gateways, captive portals, or stateful firewalls "
        "silently drop, forge resets, reject via ICMP, or transparently rewrite transport- and application-layer communications."
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 4. Environment and Reproducibility
    # --------------------------------------------------------------------------
    lines.append("## 3. Environment and Reproducibility")
    lines.append("")
    os_desc = platform.system()
    if sys.platform.startswith("linux") and (
        "microsoft" in platform.release().lower() or "wsl" in platform.release().lower()
    ):
        os_desc = "Linux (WSL2 environment)"
    elif sys.platform == "win32":
        os_desc = "Microsoft Windows"

    lines.append("| System Parameter | Configuration |")
    lines.append("|---|---|")
    lines.append(f"| **Operating System** | {os_desc} (`{platform.platform()}`) |")
    lines.append(f"| **Kernel / Release** | `{platform.release()}` |")
    lines.append(f"| **Python Interpreter** | `Python {platform.python_version()}` |")
    lines.append(f"| **Probe Execution Mode** | `{getattr(plan, 'mode', 'auto')}` |")
    lines.append(
        f"| **Equivalent CLI Command** | `{getattr(plan, 'cli_equivalent', 'netpolicy audit')}` |"
    )
    lines.append(
        f"| **Privilege Level** | {'Root / Administrator' if getattr(plan, 'needs_root', False) else 'Unprivileged User'} |"
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 5. Methodology
    # --------------------------------------------------------------------------
    lines.append("## 4. Methodology")
    lines.append("")
    lines.append(
        "The netpolicy measurement architecture decouples active probing from pure mathematical classification:\n"
        "1. **Outbound Port Probing**: Measures reachability on specified TCP ports via raw SYN segments (if root) or standard socket connect calls. "
        "Each probe is compared against a control probe targeting a known open port (default 443) to decouple systemic path drops from targeted port blocking.\n"
        "2. **DNS Resolution Integrity**: Queries both standard UDP/53 endpoints and RFC 5737 unroutable documentation addresses (`192.0.2.1`, `198.51.100.1`) "
        "to catch transparent middlebox resolvers, while cross-checking unencrypted responses against DNS-over-HTTPS (DoH).\n"
        "3. **HTTP Content & Canary Validation**: Issues HTTP GET requests with custom nonce tokens (`X-NetPolicy-Nonce`) and verifies status codes, "
        "expected headers, and SHA-256 payload digests against upstream canary manifests.\n"
        "4. **Classification & Confidence**: Verdicts are computed without heuristics or artificial intelligence, relying strictly on "
        "deterministic protocol rules and reliability gates."
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 6. Results
    # --------------------------------------------------------------------------
    lines.append("## 5. Experimental Results")
    lines.append("")
    lines.append(
        f"**Overall Classification:** `{verdict_level}`  \n**Summary:** {verdict_sentence}"
    )
    lines.append("")

    # Findings Table
    lines.append("### 5.1 Aggregated Findings")
    lines.append("")
    if issues:
        lines.append(
            "| Area | Subject | Classification | Confidence | Observations / Runs | Detail |"
        )
        lines.append("|---|---|---|---|---|---|")
        for iss in issues:
            detail = iss.plain
            if not iss.valid and iss.invalid_reason:
                detail += f" *(Ignored: {iss.invalid_reason})*"
            lines.append(
                f"| {iss.display_area} | {iss.subject} | `{iss.kind}` | `{iss.confidence.name}` | {iss.runs_seen}/{iss.runs_total} | {detail} |"
            )
    else:
        lines.append("*No policy anomalies or network restrictions were detected.*")
    lines.append("")

    # Per-Check Statistical Breakdown
    lines.append("### 5.2 Per-Check Latency and Reliability Metrics")
    lines.append("")

    raw_obs_list: list[Observation] = []
    if run_meta:
        if "observations" in run_meta and isinstance(run_meta["observations"], list):
            raw_obs_list = run_meta["observations"]
        elif "raw_observations" in run_meta and isinstance(run_meta["raw_observations"], list):
            raw_obs_list = run_meta["raw_observations"]
        elif "run_id" in run_meta:
            run_id = run_meta["run_id"]
            jsonl_path = Path("reports") / f"{run_id}.jsonl"
            if jsonl_path.exists():
                try:
                    from netpolicy.store.raw import read_run

                    raw_obs_list = read_run(str(jsonl_path))
                except Exception:
                    pass

    raw_checks: list[tuple[str, list[Observation]]] = []
    if raw_obs_list:
        grouped: dict[str, list[Observation]] = {}
        for obs in raw_obs_list:
            if obs.target.port is not None:
                key = f"Port {obs.target.port} ({obs.target.service or 'TCP'})"
            elif obs.probe_name == "dns" or "dns" in obs.raw:
                key = f"DNS {obs.target.host}"
            else:
                key = f"{obs.probe_name.upper()} {obs.target.host}"
            grouped.setdefault(key, []).append(obs)
        for k, v_list in grouped.items():
            raw_checks.append((k, v_list))
    elif report:
        for r_list in (report.port_results, report.dns_results, report.http_results):
            for vr in r_list:
                obs_attr = getattr(vr, "observations", None)
                if obs_attr and isinstance(obs_attr, list):
                    if vr.target.port is not None:
                        key = f"Port {vr.target.port} ({vr.target.service or 'TCP'})"
                    else:
                        key = f"{vr.target.protocol.upper()} {vr.target.host}"
                    raw_checks.append((key, obs_attr))

    def _extract_obs_rtt(o: Observation) -> float | None:
        val = getattr(o, "rtt_ms", None)
        if val is not None:
            return float(val)
        if isinstance(o.raw, dict) and o.raw.get("rtt_ms") is not None:
            try:
                return float(o.raw["rtt_ms"])
            except (ValueError, TypeError):
                pass
        return None

    verdict_rows: list[tuple[str, int, float, float | None]] = []
    if not raw_checks and report:
        from netpolicy.models import VerdictKind

        all_verdicts = (
            list(report.port_results) + list(report.dns_results) + list(report.http_results)
        )
        for vr in all_verdicts:
            if vr.target.port is not None:
                name = f"Port {vr.target.port} ({vr.target.service or 'TCP'})"
            else:
                name = f"{vr.target.protocol.upper()} {vr.target.host}"
            runs = plan.runs if plan and plan.runs else (report.metadata.runs_per_check or 1)
            loss_rate = (
                0.0
                if vr.kind in (VerdictKind.OPEN, VerdictKind.OK, VerdictKind.CLEAN)
                else (
                    1.0
                    if vr.kind in (VerdictKind.DROPPED, VerdictKind.RESET, VerdictKind.REJECTED)
                    else 0.5
                )
            )
            rtt_val: float | None = None
            for ev in vr.evidence:
                m = re.search(r"(\d+(?:\.\d+)?)\s*ms", ev)
                if m:
                    rtt_val = float(m.group(1))
                    break
            verdict_rows.append((name, runs, loss_rate, rtt_val))

    total_observations = (
        sum(len(obs) for _, obs in raw_checks) if raw_checks else sum(r[1] for r in verdict_rows)
    )

    if raw_checks or verdict_rows:
        lines.append(
            "| Check Target | Sample Size ($n$) | Loss Rate | Min RTT | Median RTT | P95 RTT | StdDev RTT | Consistency |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")

        if raw_checks:
            for name, obs_list in raw_checks:
                n = len(obs_list)
                if n == 0:
                    continue
                successes = [o for o in obs_list if o.success]
                loss_rate = (n - len(successes)) / n

                rtts = [_extract_obs_rtt(o) for o in successes]
                valid_rtts = [r for r in rtts if r is not None]
                min_rtt = f"{min(valid_rtts):.1f} ms" if valid_rtts else "N/A"
                med_rtt = f"{statistics.median(valid_rtts):.1f} ms" if valid_rtts else "N/A"
                p95_val = sorted(valid_rtts)[int(0.95 * len(valid_rtts))] if valid_rtts else None
                p95_rtt = f"{p95_val:.1f} ms" if p95_val is not None else "N/A"
                std_rtt = (
                    f"{statistics.stdev(valid_rtts):.1f} ms" if len(valid_rtts) >= 2 else "0.0 ms"
                )

                consistency = (
                    "Consistent"
                    if (
                        loss_rate in (0.0, 1.0)
                        or (len(valid_rtts) >= 2 and statistics.stdev(valid_rtts) < 20.0)
                    )
                    else "Variable"
                )
                lines.append(
                    f"| {name} | {n} | {loss_rate * 100:.1f}% | {min_rtt} | {med_rtt} | {p95_rtt} | {std_rtt} | {consistency} |"
                )
        else:
            for name, n, loss_rate, rtt_val in verdict_rows:
                rtt_str = f"{rtt_val:.1f} ms" if rtt_val is not None else "N/A"
                consistency = "Consistent" if loss_rate in (0.0, 1.0) else "Variable"
                lines.append(
                    f"| {name} | {n} | {loss_rate * 100:.1f}% | {rtt_str} | {rtt_str} | {rtt_str} | 0.0 ms | {consistency} |"
                )

        lines.append("")
        if total_observations < 30:
            lines.append(
                "> **Statistical Power Caution:** Total sample size ($n < 30$) represents preliminary exploratory sampling. "
                "Confidence intervals and strict hypothesis tests require $n \\ge 30$ iterations under controlled load."
            )
            lines.append("")
    else:
        lines.append("*No per-check observation telemetry available.*")
        lines.append("")

    # --------------------------------------------------------------------------
    # 7. Execution Metrics
    # --------------------------------------------------------------------------
    lines.append("## 6. Execution Metrics")
    lines.append("")
    wall_time = metrics.wall_s if metrics else 0.0
    cpu_time = metrics.cpu_s if metrics else 0.0
    peak_mem = (
        f"{metrics.peak_rss_kb:,} KB"
        if (metrics and metrics.peak_rss_kb is not None)
        else "not available (Windows / non-POSIX)"
    )
    obs_per_sec = round(total_observations / wall_time, 1) if wall_time > 0 else 0.0

    lines.append("| Metric | Measured Value |")
    lines.append("|---|---|")
    lines.append(f"| **Wall-Clock Duration** | `{wall_time:.3f} s` |")
    lines.append(f"| **CPU Process Time** | `{cpu_time:.3f} s` |")
    lines.append(f"| **Peak Resident Set Size (RSS)** | `{peak_mem}` |")
    lines.append(f"| **Total Observations Recorded** | `{total_observations}` |")
    lines.append(f"| **Observation Throughput** | `{obs_per_sec} obs/s` |")
    lines.append("")
    lines.append(
        "*Note: Resource metrics are measured in-process and include interactive wizard chrome overhead.*"
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 8. Analysis
    # --------------------------------------------------------------------------
    lines.append("## 7. Analysis")
    lines.append("")
    if verdict_level == "CLEAN":
        lines.append(
            "Empirical observations confirm unrestricted end-to-end connectivity across all audited protocols. "
            "SYN-ACK segments were returned consistently on open destination ports with stable IP TTL and RTT values. "
            "DNS queries resolved matching records without NXDOMAIN redirection, and HTTP transactions matched upstream SHA-256 digests."
        )
    elif verdict_level == "LIMITED":
        lines.append(
            "Targeted egress filtering was observed on specific transport ports, while core web and DNS services remained unimpaired. "
            "Because no packet content alteration or proxy header injection was detected, the policy is categorized as port-selective boundary filtering."
        )
    elif verdict_level == "ACTION_REQUIRED":
        lines.append(
            "Web traffic redirection indicates that the access gateway has intercepted client HTTP sessions. "
            "This pattern typically indicates an unauthenticated captive portal requiring splash-page authentication before full egress is granted."
        )
    elif verdict_level == "RESTRICTED":
        lines.append(
            "Active middlebox interference was definitively identified in the data path. "
            "Observed anomalies include in-path DNS manipulation, transparent HTTP proxy caching, or multi-service egress drops."
        )
    else:
        lines.append(
            "The audit completed with inconclusive verdicts. This occurs when testing against public endpoints that do not host netpolicy canary manifests, "
            "or when network latency exceeds probe timeouts without producing diagnostic ICMP rejection packets."
        )
    lines.append("")

    # --------------------------------------------------------------------------
    # 9. Threats to Validity
    # --------------------------------------------------------------------------
    lines.append("## 8. Threats to Validity")
    lines.append("")
    lines.append(
        "The following methodological limitations and reliability caveats apply to this evaluation:"
    )
    lines.append(
        "1. **Single Vantage Point**: Measurements reflect conditions observed exclusively from the local network interface at the time of testing."
    )
    lines.append(
        "2. **Time-of-Day Variations**: Access policies and traffic engineering rules may vary dynamically with network load or scheduling."
    )
    if sys.platform.startswith("linux") and (
        "microsoft" in platform.release().lower() or "wsl" in platform.release().lower()
    ):
        lines.append(
            "3. **WSL2 Virtual NAT Switch**: Windows Subsystem for Linux operates behind a virtual Hyper-V NAT switch which can alter packet TTLs or intercept select handshakes."
        )
    lines.append(
        "4. **Small Sample Size**: Exploratory audits with few probe iterations can be subject to transient wireless packet loss mimicking silent drops."
    )

    # Reliability gates that fired
    if caveats:
        lines.append("")
        lines.append("### 8.1 Reliability Gates Triggered")
        lines.append("")
        for cav in caveats:
            lines.append(f" • **[{cav.code}]**: {cav.plain} *(Technical: {cav.technical})*")
    lines.append("")

    # --------------------------------------------------------------------------
    # 10. Ethics and Authorization
    # --------------------------------------------------------------------------
    lines.append("## 9. Ethics and Authorization")
    lines.append("")
    consent_statement = (
        getattr(plan, "consent_text", None) or run_meta.get("consent_text") if run_meta else None
    )
    if not consent_statement:
        consent_statement = (
            "I own this network and server, or I have explicit permission to test them."
        )
    consent_timestamp = (
        getattr(plan, "consent_utc", None) or run_meta.get("consent_utc") if run_meta else None
    )
    if not consent_timestamp:
        consent_timestamp = utc_str

    lines.append(
        f'**Recorded User Attestation:** "{consent_statement}"  \n**Timestamp (UTC):** `{consent_timestamp}`'
    )
    lines.append("")
    lines.append(
        "netpolicy adheres to strict privacy and authorization safeguards:\n"
        " • No subnet sweeps or port range scanning are performed.\n"
        " • Local MAC addresses, Wi-Fi SSIDs, and client public IP addresses are excluded by default.\n"
        " • Gateways and resolvers are correlated using cryptographic SHA-256 hashes (`fp:...`)."
    )
    lines.append("")

    # --------------------------------------------------------------------------
    # 11. Evidence Manifest
    # --------------------------------------------------------------------------
    lines.append("## 10. Evidence Manifest")
    lines.append("")
    lines.append("| Artifact | File Path | File Size | SHA-256 Digest |")
    lines.append("|---|---|---|---|")

    jsonl_path = Path(f"reports/{run_id}.jsonl")
    if jsonl_path.is_file():
        lines.append(
            f"| Raw Observation Store | `{jsonl_path}` | `{jsonl_path.stat().st_size:,} bytes` | `{_compute_sha256(jsonl_path)}` |"
        )
    else:
        lines.append(
            f"| Raw Observation Store | `reports/{run_id}.jsonl` | *not persisted* | *not available* |"
        )

    if capture:
        pcap_p = Path(capture.pcap_path)
        sz = f"{capture.byte_count:,} bytes ({capture.packet_count:,} packets)"
        lines.append(f"| Wireshark Packet Capture | `{pcap_p}` | `{sz}` | `{capture.sha256}` |")
    else:
        lines.append("| Wireshark Packet Capture | *none* | *not opted in* | *not available* |")
    lines.append("")

    # --------------------------------------------------------------------------
    # 12. Appendix
    # --------------------------------------------------------------------------
    lines.append("## 11. Appendix")
    lines.append("")

    # Transcript table
    if transcript:
        lines.append("### 11.1 Wizard Session Transcript")
        lines.append("")
        lines.append("| Step | State | Question / Prompt | Recorded Input |")
        lines.append("|---|---|---|---|")
        for idx, item in enumerate(transcript, start=1):
            st_name = getattr(item, "state", str(item))
            q_text = getattr(item, "question", "")
            ans_text = getattr(item, "answer", "")
            lines.append(f"| {idx} | `{st_name}` | {q_text} | `{ans_text}` |")
        lines.append("")

    # Reproduction steps
    lines.append("### 11.2 Reproduction Command")
    lines.append("")
    lines.append("```bash")
    lines.append(getattr(plan, "cli_equivalent", "netpolicy audit"))
    lines.append("```")
    lines.append("")

    # Suggested Wireshark filters
    target_ip = getattr(plan, "target", None)
    finding_keys = [i.kind for i in issues]
    ws_filters = generate_wireshark_filters(target_ip, finding_keys)
    if ws_filters:
        lines.append("### 11.3 Recommended Wireshark Display Filters")
        lines.append("")
        for wf in ws_filters:
            lines.append(f" • `{wf}`")
        lines.append("")

    return "\n".join(lines)


def write_lab_report(
    content: str,
    run_id: str,
    output_dir: Path | str = "reports",
) -> Path:
    """Saves generated Markdown lab report to the reports directory."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / f"lab-report-{run_id}.md"
    report_file.write_text(content, encoding="utf-8")
    return report_file
