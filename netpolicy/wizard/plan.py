"""Command plan generation, input validation, and plain-English intent mapping (Stage 3)."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

# ==============================================================================
# Input Validators
# ==============================================================================

HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$"
)


def validate_target(target: str) -> tuple[bool, str]:
    """Validates target host or IP according to strict allow-list rules."""
    cleaned = target.strip()
    if not cleaned:
        return False, "Target cannot be empty."

    # Reject CIDR notation, comma-separated lists, and spaces
    if "/" in cleaned:
        return False, "CIDR notation (e.g. /24) is not allowed; specify a single host or IP."
    if "," in cleaned:
        return False, "Comma-separated target lists are not allowed; specify a single host or IP."
    if " " in cleaned or "\t" in cleaned:
        return False, "Spaces are not allowed in target address."
    if any(ch in cleaned for ch in "*?;&|<>`$'\""):
        return False, "Wildcards and shell metacharacters are not allowed."

    # Check if IP address
    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_multicast:
            return False, f"Multicast IP '{cleaned}' is not allowed."
        if ip.is_unspecified:
            return False, f"Unspecified IP '{cleaned}' is not allowed."
        if str(ip) == "255.255.255.255":
            return False, "Broadcast IP '255.255.255.255' is not allowed."
        return True, ""
    except ValueError:
        pass

    # Validate as hostname
    if len(cleaned) > 253:
        return False, "Hostname exceeds maximum length of 253 characters."
    if not HOSTNAME_REGEX.match(cleaned):
        return False, f"'{cleaned}' is not a valid hostname or IP address."

    return True, ""


def validate_ports(ports_str: str) -> tuple[bool, str, list[int]]:
    """Validates comma-separated port list: 1-65535, at most 20 ports."""
    cleaned = ports_str.strip()
    if not cleaned:
        return False, "Port list cannot be empty.", []

    parts = [p.strip() for p in cleaned.split(",") if p.strip()]
    if not parts:
        return False, "No valid ports provided.", []

    parsed_ports: list[int] = []
    seen: set[int] = set()

    for item in parts:
        try:
            val = int(item)
        except ValueError:
            return False, f"Invalid port number '{item}': must be an integer.", []

        if not (1 <= val <= 65535):
            return False, f"Port {val} out of range (allowed: 1-65535).", []

        if val not in seen:
            seen.add(val)
            parsed_ports.append(val)

    if len(parsed_ports) > 20:
        return False, f"Too many ports ({len(parsed_ports)}). Maximum allowed is 20.", []

    return True, "", parsed_ports


def validate_runs(runs_str: str) -> tuple[bool, str, int]:
    """Validates runs count: integer between 1 and 20."""
    try:
        val = int(runs_str.strip())
        if 1 <= val <= 20:
            return True, "", val
        return False, "Runs must be between 1 and 20.", val
    except ValueError:
        return False, f"Invalid integer '{runs_str}'.", 0


def validate_timeout(timeout_str: str) -> tuple[bool, str, float]:
    """Validates timeout in seconds: float between 0.5 and 30.0."""
    try:
        val = float(timeout_str.strip())
        if 0.5 <= val <= 30.0:
            return True, "", val
        return False, "Timeout must be between 0.5 and 30.0 seconds.", val
    except ValueError:
        return False, f"Invalid number '{timeout_str}'.", 0.0


# ==============================================================================
# Port Presets
# ==============================================================================

PORT_PRESETS: dict[str, str] = {
    "Email sending (25, 465, 587)": "25,465,587",
    "Remote login (22)": "22",
    "File transfer (21)": "21",
    "Websites (80, 443)": "80,443",
    "Everything common": "21,22,25,53,80,110,143,443,465,587,993,995,8080",
}


# ==============================================================================
# Command Plan Model
# ==============================================================================


@dataclass(frozen=True)
class CommandPlan:
    """Rigorous plan describing the command to execute and its operational profile."""

    kind: str  # "traffic", "offline", "lab"
    argv: list[str]  # Arguments excluding the program name
    plain_summary: str
    cli_equivalent: str
    impacts: list[str]
    needs_root: bool
    writes: bool
    upper_bound_seconds: float
    capture: bool = False
    details: dict[str, str] = field(default_factory=dict)


# ==============================================================================
# Plan Builders (One Per Intent)
# ==============================================================================


def build_audit_plan(
    target: str,
    ports: str | None = None,
    runs: int = 5,
    timeout: float = 3.0,
    retries: int = 2,
    mode: str = "auto",
    capture: bool = False,
) -> CommandPlan:
    """Builds plan for 'audit' intent."""
    argv: list[str] = [
        "audit",
        "--target",
        target,
        "--runs",
        str(runs),
        "--timeout",
        str(timeout),
        "--retries",
        str(retries),
        "--mode",
        mode,
    ]
    if ports:
        argv.extend(["--ports", ports])

    cli_eq = shlex.join(["netpolicy"] + argv)
    port_count = len(ports.split(",")) if ports else 12
    # Rough estimate formula: runs * (timeout * checks_factor)
    est = float(runs) * (float(timeout) * 1.5 + float(retries) * 1.0) + (port_count * 0.2)

    impacts = ["network traffic", "writes files"]
    if mode == "raw":
        impacts.append("needs root")

    return CommandPlan(
        kind="traffic",
        argv=argv,
        plain_summary=f"Full network policy audit (ports + DNS + HTTP) against '{target}'",
        cli_equivalent=cli_eq,
        impacts=impacts,
        needs_root=(mode == "raw"),
        writes=True,
        upper_bound_seconds=round(est, 1),
        capture=capture,
    )


def build_ports_plan(
    target: str,
    ports: str,
    runs: int = 5,
    timeout: float = 3.0,
    retries: int = 2,
    mode: str = "auto",
    capture: bool = False,
) -> CommandPlan:
    """Builds plan for 'ports' intent."""
    argv: list[str] = [
        "ports",
        "--target",
        target,
        "--ports",
        ports,
        "--runs",
        str(runs),
        "--timeout",
        str(timeout),
        "--retries",
        str(retries),
        "--mode",
        mode,
    ]
    cli_eq = shlex.join(["netpolicy"] + argv)
    port_count = len(ports.split(","))
    est = float(runs) * float(port_count) * (float(timeout) + float(retries) * 0.5)

    impacts = ["network traffic", "writes files"]
    if mode == "raw":
        impacts.append("needs root")

    return CommandPlan(
        kind="traffic",
        argv=argv,
        plain_summary=f"Outbound reachability audit on ports [{ports}] against '{target}'",
        cli_equivalent=cli_eq,
        impacts=impacts,
        needs_root=(mode == "raw"),
        writes=True,
        upper_bound_seconds=round(est, 1),
        capture=capture,
    )


def build_dns_plan(
    target: str | None = None,
    runs: int = 5,
    timeout: float = 3.0,
    retries: int = 2,
    mode: str = "auto",
    capture: bool = False,
) -> CommandPlan:
    """Builds plan for 'dns' intent."""
    argv: list[str] = [
        "dns",
        "--runs",
        str(runs),
        "--timeout",
        str(timeout),
        "--retries",
        str(retries),
        "--mode",
        mode,
    ]
    if target:
        argv.extend(["--target", target])

    cli_eq = shlex.join(["netpolicy"] + argv)
    est = float(runs) * 4.0 * (float(timeout) + 0.5)

    impacts = ["network traffic", "writes files"]
    if mode == "raw":
        impacts.append("needs root")

    summary = "Audit DNS interception, redirection, and NXDOMAIN tampering"
    if target:
        summary += f" targeting resolver '{target}'"

    return CommandPlan(
        kind="traffic",
        argv=argv,
        plain_summary=summary,
        cli_equivalent=cli_eq,
        impacts=impacts,
        needs_root=(mode == "raw"),
        writes=True,
        upper_bound_seconds=round(est, 1),
        capture=capture,
    )


def build_http_plan(
    target: str,
    runs: int = 5,
    timeout: float = 3.0,
    retries: int = 2,
    mode: str = "auto",
    capture: bool = False,
) -> CommandPlan:
    """Builds plan for 'http' intent."""
    argv: list[str] = [
        "http",
        "--target",
        target,
        "--runs",
        str(runs),
        "--timeout",
        str(timeout),
        "--retries",
        str(retries),
        "--mode",
        mode,
    ]
    cli_eq = shlex.join(["netpolicy"] + argv)
    est = float(runs) * 2.0 * (float(timeout) + 1.0)

    impacts = ["network traffic", "writes files"]
    if mode == "raw":
        impacts.append("needs root")

    return CommandPlan(
        kind="traffic",
        argv=argv,
        plain_summary=(
            f"Audit HTTP proxy interception and captive portal tampering against '{target}'"
        ),
        cli_equivalent=cli_eq,
        impacts=impacts,
        needs_root=(mode == "raw"),
        writes=True,
        upper_bound_seconds=round(est, 1),
        capture=capture,
    )


def build_compare_plan(run_a: str, run_b: str) -> CommandPlan:
    """Builds plan for 'compare' intent."""
    argv: list[str] = ["compare", str(run_a), str(run_b)]
    cli_eq = shlex.join(["netpolicy"] + argv)

    return CommandPlan(
        kind="offline",
        argv=argv,
        plain_summary=f"Compare audit runs: '{Path(run_a).name}' vs '{Path(run_b).name}'",
        cli_equivalent=cli_eq,
        impacts=["offline"],
        needs_root=False,
        writes=False,
        upper_bound_seconds=3.0,
        capture=False,
    )


def build_reclassify_plan(run_id: str) -> CommandPlan:
    """Builds plan for 'reclassify' intent."""
    argv: list[str] = ["reclassify", str(run_id)]
    cli_eq = shlex.join(["netpolicy"] + argv)

    return CommandPlan(
        kind="offline",
        argv=argv,
        plain_summary=f"Reclassify saved raw observations from '{Path(run_id).name}'",
        cli_equivalent=cli_eq,
        impacts=["offline"],
        needs_root=False,
        writes=False,
        upper_bound_seconds=3.0,
        capture=False,
    )


def build_lab_plan(action: str = "status") -> CommandPlan:
    """Builds plan for 'lab' intent."""
    argv: list[str] = ["lab"]
    cli_eq = shlex.join(["netpolicy"] + argv)

    return CommandPlan(
        kind="lab",
        argv=argv,
        plain_summary=f"Inspect reproducible Linux network namespace testbed (action: {action})",
        cli_equivalent=cli_eq,
        impacts=["changes lab namespaces", "needs root"],
        needs_root=True,
        writes=False,
        upper_bound_seconds=5.0,
        capture=False,
        details={"lab_action": action},
    )
