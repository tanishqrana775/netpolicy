# ruff: noqa: E501
"""Human-friendly translations, formatting helpers, and safe parsing for report presentation."""

from __future__ import annotations

import ast
import re
from typing import Any
from urllib.parse import urlparse

from netpolicy.models import Confidence, VerdictKind

# Standard service groupings based on common ports and protocols
SERVICE_GROUPS: dict[int, str] = {
    21: "file transfer",
    22: "remote login",
    25: "sending mail",
    53: "address lookups",
    80: "websites",
    110: "reading mail",
    143: "reading mail",
    443: "websites",
    465: "sending mail",
    587: "sending mail",
    993: "reading mail",
    995: "reading mail",
}

# Plain English translations for classifier VerdictKind outcomes
VERDICT_KIND_LABELS: dict[VerdictKind | str, str] = {
    VerdictKind.OPEN: "Reachable",
    VerdictKind.OK: "Reachable",
    VerdictKind.CLEAN: "Clean",
    VerdictKind.BLOCKED_DROP: "No reply",
    VerdictKind.DROPPED: "No reply",
    VerdictKind.BLOCKED_RESET: "Connection actively refused",
    VerdictKind.RESET: "Connection actively refused",
    VerdictKind.CLOSED_OR_RESET: "Connection actively refused",
    VerdictKind.BLOCKED_ICMP: "Rejected by a network filter",
    VerdictKind.REJECTED: "Rejected by a network filter",
    VerdictKind.INTERCEPTED: "Traffic redirected",
    VerdictKind.REDIRECTED: "Redirected",
    VerdictKind.TAMPERED: "Content altered",
    VerdictKind.REWRITTEN: "Traffic altered",
    VerdictKind.HEADERS_INJECTED: "Headers injected",
    VerdictKind.BODY_MODIFIED: "Content modified",
    VerdictKind.PROXIED: "Proxy detected",
    VerdictKind.LOSSY: "Intermittent connection loss",
    VerdictKind.MISMATCH: "Response mismatch",
    VerdictKind.UNKNOWN: "Check inconclusive",
}

# ==============================================================================
# Central Voice & Plain-Language Copy Store (Stage 1)
# ==============================================================================
# Voice Rules:
# - Warm, short, second person, like a helpful friend.
# - Sentences of 18 words or fewer.
# - No blame; reassure where appropriate; start with good news.
# - No banned words in default view: DNS, RST, ICMP, SYN, TTL, middlebox,
#   interception, canary, namespace, probe, resolver, firewall, captive portal,
#   packet, BLOCKED_DROP, confidence.

STRINGS: dict[str, Any] = {
    "main_menu": {
        "title": "What would you like to do?",
        "step": "Goal",
        "question": "What would you like to do?",
        "options": [
            ("1", "Check my Wi-Fi for anything that's getting in the way"),
            (
                "2",
                "See if something I use is being blocked (email, remote login, file sharing, websites)",
            ),
            ("3", "See if my internet is being quietly redirected"),
            ("4", "Check if the network wants me to log in, or is filtering websites"),
            ("5", "Compare two earlier checks"),
            ("6", "Look at a past check"),
            ("7", "Try it in a safe practice network"),
            ("8", "Show the classic command list"),
            ("9", "Done for now"),
        ],
        "brackets": [
            "Runs an automated background sweep",
            "Requires you to type a specific port or app name",
            "Checks for DNS tampering & hijacking",
            "Checks for HTTP tampering & captive portals",
            "Requires 2 saved JSON reports",
            "Requires 1 saved JSON report",
            "Practice network cyber-range",
            "Standard CLI subcommands",
            "Exit",
        ],
        "help": "Choose what you want to check on your current internet connection.",
    },
    "network_env": {
        "title": "Network environment",
        "step": "Environment",
        "question": "What type of network or device environment are you currently testing?",
        "options": [
            ("1", "Home Wi-Fi / Personal Router", "You have full admin access"),
            (
                "2",
                "Public Hotspot (Hotel, Cafe, Airport)",
                "Prone to captive portals & interception",
            ),
            (
                "3",
                "Corporate / Campus Network",
                "Likely has strict intentional firewalls",
            ),
            ("4", "Mobile Data / Tethering", "Testing cellular carrier restrictions"),
            ("5", "Remote Company Server", "Testing cloud/VPS egress filtering"),
        ],
        "help": "Choose the environment you are currently testing so we can tailor our recommendations.",
    },
    "preflight": {
        "title": "Your computer",
        "step": "Check",
        "header": "Checking what your computer can do",
        "ready_summary": "Ready for everyday checks.",
        "admin_note": "Three extras are off because they need admin access.",
        "saved_checks": "saved checks",
        "chips": {
            "linux_wsl": "Linux (WSL)",
            "windows": "Windows",
            "linux": "Linux",
            "advanced": "Advanced tests",
            "record": "Record the traffic",
            "practice": "Practice network",
        },
        "help": (
            "Everyday checks work on any computer without extra setup. "
            "Advanced tests need administrator access inside Linux."
        ),
    },
    "target": {
        "title": "Choose target",
        "step": "Target",
        "question": "What should I connect to for the test?",
        "options": [
            ("1", "A server I own or manage (best results)"),
            ("2", "The practice network"),
            ("3", "A public website or service (results will be limited)"),
        ],
        "address_question": "Type its address, like 203.0.113.10 or myserver.example.com",
        "warning_public": (
            "Testing against a public server gives limited results. "
            "We cannot tell if its own filters are blocking us."
        ),
        "warning_confirm": "Continue anyway with limited results?",
        "help": (
            "Connecting to your own server gives the clearest answers. "
            "Public websites may block tests on their own side."
        ),
    },
    "ports": {
        "title": "Services to check",
        "step": "Services",
        "question": "Which services would you like to test?",
        "options": [
            ("1", "Sending email (25, 465, 587)"),
            ("2", "Remote login (22)"),
            ("3", "File transfer (21)"),
            ("4", "Websites (80, 443)"),
            ("5", "Everything common"),
            ("6", "Custom list"),
        ],
        "custom_prompt": "Type port numbers separated by commas (like 80, 443, 8080)",
        "help": (
            "Networks often block email sending to stop spam. "
            "Schools and offices sometimes block remote login."
        ),
    },
    "options": {
        "title": "Test options",
        "step": "Options",
        "runs_question": "How thorough should this test be?",
        "runs_options": [
            ("1", "Quick (1 check)"),
            ("2", "Standard (5 checks, recommended)"),
            ("3", "Thorough (10 checks)"),
        ],
        "mode_question": "Which testing method should we use?",
        "mode_options": [
            ("1", "Standard (works on all computers)"),
            ("2", "Standard socket"),
            ("3", "Advanced tests (needs admin access)"),
        ],
        "capture_question": "Record the traffic (for Wireshark)?",
        "help": (
            "Running multiple checks separates network hiccups from real blocks. "
            "Recording traffic helps technical experts inspect details."
        ),
    },
    "authorize": {
        "title": "Safety check",
        "step": "Permission",
        "question": (
            "Quick check before we start: do you have permission to test this network and server? "
            "Only say yes if it's yours or you've been given the OK."
        ),
        "decline_note": "No problem. We stopped here and sent no test traffic.",
        "help": "Testing networks without permission is against network terms.",
    },
    "review": {
        "title": "Review check",
        "step": "Review",
        "ready_question": "Ready to run this check?",
        "ready_options": [
            ("1", "Run now"),
            ("2", "Just show me the command"),
        ],
        "what_will_happen": "We will run a safe connectivity check against your chosen server.",
        "what_this_does": {
            "traffic": "sends test traffic",
            "admin": "needs admin access",
            "report": "saves a report",
            "capture": "records traffic",
        },
        "duration_label": "about",
        "equivalent_label": "Equivalent command",
        "help": "Check your choices before any test traffic is sent.",
    },
    "results": {
        "title": "Test outcome",
        "step": "Results",
        "clean": "Everything looks normal",
        "clean_msg": "Your internet connection is open with no filters in the way.",
        "findings": "Some things are being blocked",
        "findings_msg": "We found network filters or blocks getting in your way.",
        "error": "The test could not finish",
    },
    "next_steps": {
        "title": "Recommended next steps",
        "step": "Next steps",
        "question": "What would you like to do next?",
    },
    "wsl": {
        "question": "Raw packet tests need Linux. Open Kali Linux and continue there?",
        "options": [
            ("1", "Yes, with full power (recommended)"),
            ("2", "Yes, standard"),
            ("3", "Not now"),
        ],
        "help": (
            "Full power runs as an admin inside your Kali Linux. "
            "This unlocks advanced tests, traffic recording, and the practice network."
        ),
        "not_now_note": "Continuing on Windows in everyday mode.",
        "opening": "Opening Kali Linux...",
        "back_note": "Back in Windows. Run netpolicy any time.",
        "missing_distro": "Kali Linux is not installed in WSL. Install it with: wsl --install -d kali-linux",
        "missing_wsl": "Hint: WSL (Windows Subsystem for Linux) is not available on this computer.",
        "missing_venv_title": "Setup needed in Linux",
        "missing_venv_body": (
            "The Linux setup is not finished yet. "
            "Open Kali Linux and run:\n\n"
            "  bash scripts/bootstrap-python.sh\n\n"
            "Continuing on Windows in everyday mode."
        ),
    },
    "errors": {
        "target_invalid": "That doesn't look like an address. Try something like 203.0.113.10.",
        "ports_invalid": "Enter numbers between 1 and 65535, separated by commas.",
        "runs_invalid": "Enter a number between 1 and 20.",
        "timeout_invalid": "Enter a time between 0.5 and 30 seconds.",
    },
    "verdict_headlines": {
        "CLEAN": "Everything looks normal",
        "LIMITED": "Some things are being blocked",
        "ACTION_REQUIRED": "Your Wi-Fi is asking you to sign in",
        "RESTRICTED": "Your connection is being changed on the way",
        "INCONCLUSIVE": "We couldn't tell this time",
    },
    "verdict_descriptions": {
        "CLEAN": "No unexpected blocks or filters were found. Your connection is working normally.",
        "LIMITED": "Some services you use appear to be blocked by this network.",
        "ACTION_REQUIRED": "The network wants you to open a web browser and sign in.",
        "RESTRICTED": "Something between you and your server is altering your traffic.",
        "INCONCLUSIVE": "We could not reach your test server to confirm your network policy.",
    },
}


def get_string(category: str, key: str | None = None, default: str = "") -> Any:
    """Retrieve user-facing copy string or dictionary from STRINGS store."""
    cat = STRINGS.get(category, {})
    if key is None:
        return cat
    return cat.get(key, default)


def get_verdict_headline(level: str) -> str:
    """Return plain-English headline for an overall audit verdict."""
    return STRINGS["verdict_headlines"].get(level, "We couldn't tell this time")


def get_verdict_description(level: str) -> str:
    """Return plain-English description for an overall audit verdict."""
    return STRINGS["verdict_descriptions"].get(
        level, "We could not reach your test server to confirm your network policy."
    )


def service_group(port: int | None) -> str:
    """Map a TCP/UDP port number to its human-readable service group name."""
    if port is None:
        return "remote services"
    return SERVICE_GROUPS.get(port, "remote services")


def humanize_verdict_kind(kind: VerdictKind | str) -> str:
    """Return plain English label for a verdict kind."""
    if isinstance(kind, VerdictKind):
        return VERDICT_KIND_LABELS.get(kind, kind.value)
    return VERDICT_KIND_LABELS.get(kind, str(kind))


def safe_parse_python_literal(text: str) -> Any:
    """Safely parse Python-literal strings (e.g. lists, dicts) without using eval."""
    try:
        return ast.literal_eval(text.strip())
    except (ValueError, SyntaxError, MemoryError):
        return None


def extract_redirects_from_evidence(evidence_line: str) -> list[dict[str, Any]]:
    """Extract list of redirect dicts from evidence strings using safe literal_eval."""
    match = re.search(r"(\[\s*\{.*?\}\s*\])", evidence_line)
    if not match:
        return []
    parsed = safe_parse_python_literal(match.group(1))
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def format_redirect_plain(evidence_line: str) -> str:
    """Translate raw redirect evidence dict into plain English 'Redirected to <host> (HTTP <status>)'."""
    redirects = extract_redirects_from_evidence(evidence_line)
    if not redirects:
        return "Redirected to unknown destination"

    first = redirects[0]
    status = first.get("status", 301)
    location = first.get("location", "")
    host = urlparse(location).hostname or location or "unknown host"
    return f"Redirected to {host} (HTTP {status})"


def format_redirect_technical(evidence_line: str) -> str:
    """Format redirect evidence into compact technical notation '301 -> https://host/path'."""
    redirects = extract_redirects_from_evidence(evidence_line)
    if not redirects:
        return evidence_line

    steps = []
    for r in redirects:
        status = r.get("status", 301)
        location = r.get("location", "")
        steps.append(f"{status} -> {location}")
    return " ; ".join(steps)


def is_ssl_wrong_version_error(text: str) -> bool:
    """Check if the text represents an SSL WRONG_VERSION_NUMBER handshake failure."""
    return "WRONG_VERSION_NUMBER" in text or "wrong version number" in text


def is_canary_404_error(text: str) -> bool:
    """Check if the text indicates a 404 response on the canary path."""
    return "404" in text and ("canary" in text.lower() or "expected 200" in text)


def is_whoami_out_of_range(text: str) -> bool:
    """Check if text indicates whoami resolver egress IP outside expected range."""
    return "outside expected" in text and "provider range" in text


def is_documentation_address_answered(text: str) -> bool:
    """Check if text indicates an answered documentation/blackhole probe."""
    return "documentation address" in text.lower() and "answered" in text.lower()


def humanize_technical_evidence(text: str) -> str:
    """Translate raw classifier evidence strings into clean, human-readable explanations."""
    clean_text = text.strip()

    if is_ssl_wrong_version_error(clean_text):
        return "Secure connection attempt failed on a plain-HTTP port (a test problem, not a network block)"

    if is_canary_404_error(clean_text):
        return "The test server does not host the netpolicy canary file"

    if is_whoami_out_of_range(clean_text):
        return "Address lookup service identity could not be verified"

    if is_documentation_address_answered(clean_text):
        return "A device answered a query sent to an address that should never reply"

    if "unexpected http redirect" in clean_text.lower():
        return format_redirect_plain(clean_text)

    if "0/" in clean_text and "replies" in clean_text:
        return "No reply received from target server"

    if "actively refused" in clean_text.lower() or "connection refused" in clean_text.lower():
        return "Connection actively refused by host or gateway"

    if "injected proxy header detected" in clean_text.lower():
        match = re.search(r"injected proxy header detected:\s*'([^']+)'", clean_text, re.IGNORECASE)
        if match:
            return f"Network filter injected header: {match.group(1)}"
        return "Network filter injected intermediate headers"

    # Fallback for unrecognized raw/technical strings
    if any(tok in clean_text for tok in ("{'", "{", "_ssl.c", "range(s)", "TTL", "RTT", "SHA-256")):
        return "Technical detail hidden. Use --verbose."

    return clean_text


def confidence_verb(confidence: Confidence | str) -> str:
    """Honesty rule: wording strictly matching confidence level."""
    val = confidence.value if isinstance(confidence, Confidence) else str(confidence).lower()
    if val == "high":
        return "is"
    if val == "medium":
        return "appears to be"
    return "may be"
