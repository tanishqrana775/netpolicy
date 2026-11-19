# ruff: noqa: E501
"""Pure rule-based recommendation and practical solution engine (Stage 4)."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netpolicy.models import AuditReport
from netpolicy.report.summary import (
    Caveat,
    Issue,
    VerdictSummary,
    aggregate,
    apply_reliability_gates,
    compute_verdict,
)


@dataclass(frozen=True)
class Solution:
    """A concrete, non-technical practical solution tailored to user environment."""

    title: str
    steps: list[str]
    who: str  # "you", "your school or office", "your provider"
    effort: str  # "about 30 seconds", "about 5 minutes", "a phone call"
    note: str = ""


@dataclass(frozen=True)
class Recommendation:
    """Actionable next-step recommendation derived from audit results."""

    key: str
    label: str
    action: str  # "export", "rerun", "deep_dive", "menu", "quit", "support"
    details: dict[str, Any]


EFFORT_RANK = {
    "about 30 seconds": 1,
    "about 5 minutes": 2,
    "a phone call": 3,
}


def solutions_for(
    issues: list[Issue],
    verdict: VerdictSummary | None = None,
    network_kind: str = "unknown",
) -> list[Solution]:
    """Derive up to 3 practical solutions ordered by effort (easiest first)."""
    sols: list[Solution] = []
    level = verdict.level if verdict else "CLEAN"
    valid_issues = [i for i in issues if getattr(i, "valid", True)]

    # 1. Clean
    if level == "CLEAN" and not valid_issues:
        return [
            Solution(
                title="No network action needed",
                steps=[
                    "Nothing to fix. If something still doesn't work, the cause is probably the app or website, not your network."
                ],
                who="you",
                effort="about 30 seconds",
            )
        ]

    # 2. Inconclusive
    if level == "INCONCLUSIVE":
        return [
            Solution(
                title="Test against a server you control",
                steps=[
                    "This test used a server you don't control, so it can't judge your network. Try again with a server you own."
                ],
                who="you",
                effort="about 5 minutes",
            )
        ]

    # 3. Action Required (Captive Login Portal)
    if level == "ACTION_REQUIRED" or any(
        i.area in ("web", "canary") and "login" in i.plain.lower() for i in valid_issues
    ):
        steps = [
            "Open your web browser. The network is waiting for you to accept its Wi-Fi login terms.",
            "Check again once you're signed in.",
        ]
        if network_kind == "public_wifi":
            steps.append(
                "If a page doesn't appear, open any website that starts with http:// and it usually shows up."
            )
        sols.append(
            Solution(
                title="Sign in to network login page",
                steps=steps,
                who="you",
                effort="about 30 seconds",
            )
        )

    # 4. Address Lookups Redirected (DNS)
    dns_issues = [i for i in valid_issues if i.area == "dns"]
    if dns_issues:
        if network_kind in ("corporate", "school_or_office"):
            sols.append(
                Solution(
                    title="Ask your IT team about website filtering",
                    steps=[
                        "This is often on purpose, to filter websites. Ask your IT team before changing anything."
                    ],
                    who="your school or office",
                    effort="about 5 minutes",
                )
            )
        elif network_kind == "public_wifi":
            sols.append(
                Solution(
                    title="Avoid sensitive tasks or use a VPN",
                    steps=[
                        "Avoid signing in to banking or email on this network, or use a VPN you trust."
                    ],
                    who="you",
                    effort="about 30 seconds",
                )
            )
        else:
            sols.append(
                Solution(
                    title="Contact your internet provider or turn on secure DNS",
                    steps=[
                        "Call your internet provider's customer care and tell them your connection seems to redirect website lookups. Ask whether it can be turned off.",
                        "Turn on 'secure DNS' in your browser's privacy settings.",
                    ],
                    who="your provider",
                    effort="a phone call",
                )
            )

    # 5. Service Ports Blocked
    port_issues = [i for i in valid_issues if i.area == "ports"]
    if port_issues:
        ssh_blocked = any(i.subject and "22" in i.subject for i in port_issues)
        mail_blocked = any(
            i.subject and any(p in i.subject for p in ("25", "465", "587")) for i in port_issues
        )

        if network_kind in ("corporate", "school_or_office"):
            if ssh_blocked:
                sols.append(
                    Solution(
                        title="Check with your school or office IT team",
                        steps=[
                            "Your school/office filter is intentionally blocking this. Ask your IT team before using a VPN."
                        ],
                        who="your school or office",
                        effort="about 5 minutes",
                    )
                )
            else:
                sols.append(
                    Solution(
                        title="Check with your school or office IT team",
                        steps=[
                            "Your school or office filter is blocking this specific app. Ask your IT team to unblock it."
                        ],
                        who="your school or office",
                        effort="about 5 minutes",
                    )
                )
        elif network_kind == "home":
            if ssh_blocked:
                sols.append(
                    Solution(
                        title="Check home router or contact your provider",
                        steps=[
                            "Check your home router settings or contact your ISP to see if port 22 forwarding/outbound is allowed."
                        ],
                        who="you",
                        effort="about 5 minutes",
                    )
                )
            elif mail_blocked:
                sols.append(
                    Solution(
                        title="Use your email provider's website or alternate port",
                        steps=[
                            "Many providers block one email door on purpose to stop spam. Use your email provider's recommended settings or their website."
                        ],
                        who="you",
                        effort="about 5 minutes",
                    )
                )
            else:
                sols.append(
                    Solution(
                        title="Contact your provider about blocked services",
                        steps=["Call your provider and ask whether they block that service."],
                        who="your provider",
                        effort="a phone call",
                    )
                )
        elif network_kind == "mobile":
            sols.append(
                Solution(
                    title="Check mobile hotspot and tethering restrictions",
                    steps=[
                        "Your mobile carrier may be filtering or restricting tethered traffic. Test over regular Wi-Fi or contact your mobile provider."
                    ],
                    who="your provider",
                    effort="a phone call",
                )
            )
        elif network_kind == "server":
            sols.append(
                Solution(
                    title="Check cloud security group and firewall settings",
                    steps=[
                        "Your cloud or VPS provider may have strict outbound security group rules. Check your server's security group settings."
                    ],
                    who="you",
                    effort="about 5 minutes",
                )
            )
        else:
            if mail_blocked:
                sols.append(
                    Solution(
                        title="Use your email provider's website or alternate port",
                        steps=[
                            "Many providers block one email door on purpose to stop spam. Use your email provider's recommended settings or their website."
                        ],
                        who="you",
                        effort="about 5 minutes",
                    )
                )
            elif ssh_blocked:
                sols.append(
                    Solution(
                        title="Connect over an alternate port or VPN",
                        steps=[
                            "Try connecting over the website port (443) if your server allows it, or use a VPN."
                        ],
                        who="you",
                        effort="about 5 minutes",
                    )
                )
            else:
                sols.append(
                    Solution(
                        title="Contact your provider about blocked services",
                        steps=["Call your provider and ask whether they block that service."],
                        who="your provider",
                        effort="a phone call",
                    )
                )

    # 6. Web Content Altered
    web_issues = [
        i for i in valid_issues if i.area in ("web", "canary") and "login" not in i.plain.lower()
    ]
    if web_issues:
        sols.append(
            Solution(
                title="Stick to secure websites",
                steps=[
                    "Stick to websites that start with https://, and be careful with passwords on pages that look different than usual. A VPN can help."
                ],
                who="you",
                effort="about 30 seconds",
            )
        )

    # Deduplicate and sort by effort rank
    unique_sols: list[Solution] = []
    seen_titles: set[str] = set()
    for s in sols:
        if s.title not in seen_titles:
            seen_titles.add(s.title)
            unique_sols.append(s)

    unique_sols.sort(key=lambda s: EFFORT_RANK.get(s.effort, 99))
    return unique_sols[:3]


def support_message(
    issues: list[Issue],
    verdict: VerdictSummary | None = None,
    run_meta: dict[str, Any] | None = None,
    network_kind: str = "unknown",
) -> str:
    """Generate a polite, jargon-free support message containing only measured facts."""
    meta = run_meta or {}
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    date_val = meta.get("date") or meta.get("run_time") or now_str
    net_label = meta.get("network_label") or "My current network connection"
    report_name = meta.get("run_id") or "audit-report"

    lines: list[str] = []
    lines.append("Hello,")
    lines.append("")
    lines.append(f"I am writing regarding my internet connection ({net_label}).")
    lines.append(f"On {date_val}, I ran a connectivity audit from my computer.")
    lines.append("")

    valid_issues = [i for i in issues if getattr(i, "valid", True)]
    if not valid_issues:
        lines.append("The audit did not detect any active network filters.")
    else:
        lines.append("The test detected the following restrictions:")
        for iss in valid_issues[:4]:
            count_str = f"({iss.runs_seen} times)" if iss.runs_seen > 1 else ""
            lines.append(f" - {iss.display_area}: {iss.plain} {count_str}".strip())

    lines.append("")
    lines.append(
        "Could you please check whether these services are being filtered or redirected on this connection?"
    )
    lines.append(f"Detailed test records are saved in '{report_name}'.")
    lines.append("")
    lines.append("Thank you for your assistance.")

    msg = "\n".join(lines)

    # Save to reports/ if run_id is known
    run_id = meta.get("run_id")
    if run_id:
        out_dir = Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"support-message-{run_id}.txt").write_text(msg, encoding="utf-8")

    return msg


def load_report_for_run(run_id_or_path: str | Path) -> AuditReport | None:
    """Loads an AuditReport through the verified reclassify code path."""
    from rich.console import Console

    from netpolicy.cli import _load_or_reclassify_report

    silent_console = Console(stderr=True, quiet=True)
    try:
        return _load_or_reclassify_report(run_id_or_path, silent_console)
    except Exception:
        return None


def get_recommendations(
    report: AuditReport | None,
    current_intent: str = "audit",
    target: str | None = None,
) -> list[Recommendation]:
    """Generates at most 5 tailored next-step choices based on verdict and caveats."""
    recs: list[Recommendation] = []
    key_idx = 1

    level = "CLEAN"
    issues: list[Issue] = []
    caveats: list[Caveat] = []

    if report:
        try:
            raw_issues = aggregate(report)
            issues, caveats = apply_reliability_gates(raw_issues, report)
            summary = compute_verdict(issues, caveats, report)
            level = summary.level
        except Exception:
            level = "CLEAN"

    # Contextual recommendation based on verdict level
    if level == "INCONCLUSIVE":
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Re-run against a server you control (resolves inconclusive baseline)",
                action="rerun",
                details={"target_kind": "own"},
            )
        )
        key_idx += 1
    elif level == "ACTION_REQUIRED":
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Sign in to the network login page, then run again and compare",
                action="rerun",
                details={"intent": "compare"},
            )
        )
        key_idx += 1
    elif level in ("RESTRICTED", "LIMITED"):
        # Check specific issue domains
        dns_issues = [i for i in issues if i.area == "dns"]
        web_issues = [i for i in issues if i.area in ("web", "canary")]
        port_issues = [i for i in issues if i.area == "ports"]

        if dns_issues:
            recs.append(
                Recommendation(
                    key=str(key_idx),
                    label="Deep dive: Address lookups (investigate quiet redirection)",
                    action="deep_dive",
                    details={"intent": "dns", "target": target},
                )
            )
            key_idx += 1
        elif web_issues:
            recs.append(
                Recommendation(
                    key=str(key_idx),
                    label="Deep dive: Web pages (inspect altered content)",
                    action="deep_dive",
                    details={"intent": "http", "target": target},
                )
            )
            key_idx += 1
        elif port_issues:
            blocked_ports: list[str] = []
            for pi in port_issues:
                m = re.search(r"Port\s+(\d+)", pi.subject)
                if m:
                    blocked_ports.append(m.group(1))
            ports_str = ",".join(blocked_ports) if blocked_ports else "80,443"
            recs.append(
                Recommendation(
                    key=str(key_idx),
                    label=f"Deep dive: Blocked services (focus on {ports_str})",
                    action="deep_dive",
                    details={"intent": "ports", "target": target, "ports": ports_str},
                )
            )
            key_idx += 1

    # Option to write support message if findings exist
    if issues and key_idx <= 4:
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Write a message to my provider or IT team",
                action="support",
                details={},
            )
        )
        key_idx += 1

    # Standard choices to reach up to 5 options
    if key_idx <= 4:
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Export the report (structured Markdown format)",
                action="export",
                details={},
            )
        )
        key_idx += 1

    if key_idx <= 4:
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Run again with the same choices",
                action="rerun",
                details={},
            )
        )
        key_idx += 1

    if key_idx <= 4:
        recs.append(
            Recommendation(
                key=str(key_idx),
                label="Return to Main Menu",
                action="menu",
                details={},
            )
        )
        key_idx += 1

    recs.append(
        Recommendation(
            key=str(key_idx),
            label="Done for now",
            action="quit",
            details={},
        )
    )

    # Cap at 5 choices
    return recs[:5]
