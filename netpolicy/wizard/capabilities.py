"""System capabilities detection with injectable inputs (Stage 4)."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Capabilities:
    """Detected environment capabilities and system profile."""

    os_family: str  # "windows", "linux", "wsl", "macos"
    is_root: bool
    has_scapy: bool
    can_raw: bool
    can_capture: bool
    lab_capable: bool
    saved_runs: tuple[str, ...] = field(default_factory=tuple)
    versions: dict[str, str] = field(default_factory=dict)
    advice: list[str] = field(default_factory=list)


def detect_os(platform_str: str | None = None, os_release: str | None = None) -> str:
    """Detects OS family: 'windows', 'wsl', 'linux', or 'macos'."""
    plat = (platform_str or sys.platform).lower()
    if plat == "win32":
        return "windows"
    if plat == "darwin":
        return "macos"
    if plat.startswith("linux"):
        # Check if running under WSL
        rel = os_release or platform.release().lower()
        if "microsoft" in rel or "wsl" in rel:
            return "wsl"
        # Check WSL_DISTRO_NAME environment variable
        if "WSL_DISTRO_NAME" in os.environ or "WSL_INTEROP" in os.environ:
            return "wsl"
        return "linux"
    return "linux"


def check_is_root() -> bool:
    """Check if current process has root/administrator privileges."""
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        # Windows
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def get_installed_version(pkg_name: str) -> str:
    """Safely retrieves installed version string for a package."""
    try:
        return importlib.metadata.version(pkg_name)
    except Exception:
        return "not installed"


def scan_saved_runs(reports_dir: Path | str | None = None) -> tuple[str, ...]:
    """Finds all saved raw runs (.jsonl) in the reports directory."""
    rep_path = Path(reports_dir or "reports")
    if not rep_path.is_dir():
        return ()

    runs: list[str] = []
    try:
        for f in rep_path.glob("*.jsonl"):
            if f.is_file() and f.stat().st_size > 0:
                runs.append(f.name)
        # Sort newest first by name / mtime
        runs.sort(reverse=True)
    except Exception:
        return ()
    return tuple(runs)


def detect_capabilities(
    os_family: str | None = None,
    is_root: bool | None = None,
    has_scapy: bool | None = None,
    has_ip: bool | None = None,
    lab_scripts_dir: Path | str | None = None,
    reports_dir: Path | str | None = None,
) -> Capabilities:
    """Pure capability detection with injectable parameters for testability."""
    # 1. OS Family
    os_name = os_family or detect_os()

    # 2. Root Privilege
    root = check_is_root() if is_root is None else is_root

    # 3. Scapy availability
    if has_scapy is None:
        try:
            import scapy  # noqa: F401

            scapy_avail = True
        except ImportError:
            scapy_avail = False
    else:
        scapy_avail = has_scapy

    # 4. Raw socket capability
    can_raw = (os_name in ("linux", "wsl")) and root and scapy_avail

    # 5. Packet capture capability
    can_capture = root and scapy_avail

    # 6. Lab capability (Linux/WSL, root, 'ip' utility on PATH, lab scripts present)
    ip_on_path = bool(shutil.which("ip")) if has_ip is None else has_ip

    lab_dir = Path(lab_scripts_dir or "lab")
    lab_scripts_exist = lab_dir.is_dir() and (lab_dir / "setup.sh").exists()
    lab_cap = (os_name in ("linux", "wsl")) and root and ip_on_path and lab_scripts_exist

    # 7. Saved runs
    saved = scan_saved_runs(reports_dir)

    # 8. Dependency versions
    from netpolicy import __version__

    versions = {
        "netpolicy": __version__,
        "python": platform.python_version(),
        "typer": get_installed_version("typer"),
        "rich": get_installed_version("rich"),
        "scapy": get_installed_version("scapy"),
        "dnspython": get_installed_version("dnspython"),
        "httpx": get_installed_version("httpx"),
    }

    # 9. One sentence of advice per missing capability
    advice: list[str] = []
    if not root:
        if os_name == "windows":
            advice.append("Administrator rights required for raw SYN packets and packet capture.")
        else:
            advice.append(
                "Raw mode needs root: run 'sudo netpolicy' or 'sudo .linux-venv/bin/netpolicy'."
            )
    if not scapy_avail:
        advice.append(
            "Scapy is not installed: install with 'pip install scapy' to enable raw probes."
        )
    if not can_capture and root and not scapy_avail:
        advice.append("Packet capture requires scapy.")
    if os_name == "windows":
        advice.append(
            "Namespace lab is unavailable on native Windows; use WSL2 or a Linux virtual machine."
        )
    elif not lab_cap:
        if not root:
            advice.append("Namespace lab requires root privileges to configure network namespaces.")
        elif not ip_on_path:
            advice.append("The 'ip' utility was not found on PATH; install 'iproute2'.")
        elif not lab_scripts_exist:
            advice.append("Lab scripts directory 'lab/' was not found.")

    return Capabilities(
        os_family=os_name,
        is_root=root,
        has_scapy=scapy_avail,
        can_raw=can_raw,
        can_capture=can_capture,
        lab_capable=lab_cap,
        saved_runs=saved,
        versions=versions,
        advice=advice,
    )
