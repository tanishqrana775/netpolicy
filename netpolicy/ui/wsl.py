# ruff: noqa: E501
"""WSL detection and zero-touch interactive launcher helpers for netpolicy on Windows (Stage 6)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel

from netpolicy.report.humanize import STRINGS
from netpolicy.wizard.ui import Option, RichIO


def is_native_windows() -> bool:
    """Return True if running directly on native Windows (not inside WSL or Linux)."""
    return platform.system() == "Windows"


def is_wsl() -> bool:
    """Return True if running inside Windows Subsystem for Linux (WSL)."""
    return platform.system() == "Linux" and "microsoft" in platform.uname().release.lower()


def distro_name() -> str:
    """Return target WSL distribution name (default 'kali-linux', overridable via NETPOLICY_WSL_DISTRO)."""
    return os.environ.get("NETPOLICY_WSL_DISTRO", "kali-linux")


def wsl_available() -> bool:
    """Return True if wsl executable is available on PATH."""
    return shutil.which("wsl") is not None


def distro_installed(name: str) -> bool | None:
    """Check if the given distro name is installed via 'wsl -l -q'."""
    try:
        res = subprocess.run(
            ["wsl", "-l", "-q"],
            capture_output=True,
            timeout=5,
        )
        if res.returncode != 0:
            return None

        raw = res.stdout
        try:
            decoded = raw.decode("utf-16-le")
        except Exception:
            decoded = raw.decode("utf-8", errors="replace")

        cleaned = decoded.replace("\x00", "").replace("\ufeff", "")
        distros = [line.strip().lower() for line in cleaned.splitlines() if line.strip()]
        return name.lower() in distros
    except Exception:
        return None


def _check_cd_support() -> bool:
    """Check whether 'wsl --help' supports the '--cd' argument."""
    try:
        res = subprocess.run(["wsl", "--help"], capture_output=True, timeout=3)
        raw = res.stdout or res.stderr
        try:
            text = raw.decode("utf-16-le")
        except Exception:
            text = raw.decode("utf-8", errors="replace")
        return "--cd" in text
    except Exception:
        return False


def _windows_to_wsl_path(win_path: Path, distro: str) -> str:
    """Convert a Windows Path to its WSL path using wslpath, with /mnt/c fallback."""
    try:
        res = subprocess.run(
            ["wsl", "-d", distro, "-e", "wslpath", "-a", str(win_path)],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    # Standard fallback: C:\path -> /mnt/c/path
    parts = win_path.resolve().parts
    if parts and ":" in parts[0]:
        drive = parts[0][0].lower()
        sub = "/".join(parts[1:])
        return f"/mnt/{drive}/{sub}"
    return str(win_path).replace("\\", "/")


def maybe_launch_wsl(err_console: Console) -> int | None:
    """Zero-touch interactive launcher handoff into WSL when running on native Windows."""
    if not is_native_windows():
        return None

    if not wsl_available():
        err_console.print(f"[dim]{STRINGS['wsl']['missing_wsl']}[/dim]")
        return None

    target_distro = distro_name()
    installed = distro_installed(target_distro)

    if installed is False:
        err_console.print(STRINGS["wsl"]["missing_distro"])
        return None

    # Resolve project root from installed package location (editable install)
    project_root = Path(__file__).resolve().parent.parent.parent
    linux_venv_python = project_root / ".linux-venv" / "bin" / "python"
    linux_venv_activate = project_root / ".linux-venv" / "bin" / "activate"

    # In WSL mounted paths on Windows, python is a symlink to /usr/bin/python3
    # which does not resolve on native Windows, but lexists is True and activate is a file.
    if not (os.path.lexists(linux_venv_python) or linux_venv_activate.is_file()):
        err_console.print()
        err_console.print(
            Panel(
                STRINGS["wsl"]["missing_venv_body"],
                title=f"[bold yellow]{STRINGS['wsl']['missing_venv_title']}[/bold yellow]",
                box=box.ROUNDED,
                padding=(1, 2),
                border_style="#ffd166",
            )
        )
        return None

    # Prompt user with ask_choice
    io = RichIO(console=err_console)
    options = [
        Option("1", STRINGS["wsl"]["options"][0][1]),
        Option("2", STRINGS["wsl"]["options"][1][1]),
        Option("3", STRINGS["wsl"]["options"][2][1]),
    ]
    try:
        ans = io.ask_choice(
            STRINGS["wsl"]["question"],
            options,
            help_text=STRINGS["wsl"]["help"],
            allow_back=False,
            default="1",
        )
    except (EOFError, KeyboardInterrupt):
        err_console.print(f"[dim]{STRINGS['wsl']['not_now_note']}[/dim]")
        return None

    if ans in ("3", "q", "b"):
        err_console.print(f"[dim]{STRINGS['wsl']['not_now_note']}[/dim]")
        return None

    full_power = ans == "1"

    # Convert Windows root path to WSL path
    wsl_root_path = _windows_to_wsl_path(project_root, target_distro)

    # Get default user's UID and GID if full power (for chown logic)
    sudo_uid: str | None = None
    sudo_gid: str | None = None
    if full_power:
        try:
            uid_res = subprocess.run(
                ["wsl", "-d", target_distro, "-e", "id", "-u"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            gid_res = subprocess.run(
                ["wsl", "-d", target_distro, "-e", "id", "-g"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if uid_res.returncode == 0:
                sudo_uid = uid_res.stdout.strip()
            if gid_res.returncode == 0:
                sudo_gid = gid_res.stdout.strip()
        except Exception:
            pass

    # Build argv list
    cmd = ["wsl", "-d", target_distro]
    if full_power:
        cmd.extend(["-u", "root"])

    supports_cd = _check_cd_support()
    if supports_cd:
        cmd.extend(["--cd", wsl_root_path, "-e", "env", "NETPOLICY_HANDOFF=1"])
    else:
        cmd.extend(
            [
                "-e",
                "bash",
                "-c",
                'cd -- "$1" && shift && exec "$@"',
                "_",
                wsl_root_path,
                "env",
                "NETPOLICY_HANDOFF=1",
            ]
        )

    if err_console.color_system == "truecolor":
        cmd.append("COLORTERM=truecolor")

    if full_power and sudo_uid and sudo_gid:
        cmd.extend([f"SUDO_UID={sudo_uid}", f"SUDO_GID={sudo_gid}"])

    cmd.extend([".linux-venv/bin/python", "-m", "netpolicy"])

    # Do NOT clear screen on Windows (user override).
    err_console.print(f"[dim]{STRINGS['wsl']['opening']}[/dim]")

    try:
        proc = subprocess.run(cmd)
        ret = proc.returncode
    except KeyboardInterrupt:
        ret = 130

    err_console.print(f"[dim]{STRINGS['wsl']['back_note']}[/dim]")
    return ret
