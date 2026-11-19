# ruff: noqa: E501
"""Tests for netpolicy WSL launcher helpers on Windows."""

from __future__ import annotations

import io
import subprocess
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from netpolicy.ui.wsl import (
    distro_installed,
    distro_name,
    is_native_windows,
    is_wsl,
    maybe_launch_wsl,
    wsl_available,
)


def test_is_native_windows_and_is_wsl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify is_native_windows and is_wsl detect platforms properly."""
    monkeypatch.setattr("platform.system", lambda: "Windows")
    assert is_native_windows() is True
    assert is_wsl() is False

    monkeypatch.setattr("platform.system", lambda: "Linux")
    fake_uname = MagicMock()
    fake_uname.release = "5.15.153.1-microsoft-standard-WSL2"
    monkeypatch.setattr("platform.uname", lambda: fake_uname)
    assert is_native_windows() is False
    assert is_wsl() is True

    fake_uname.release = "6.1.0-generic"
    assert is_wsl() is False


def test_distro_name_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify distro_name defaults to kali-linux and respects environment override."""
    monkeypatch.delenv("NETPOLICY_WSL_DISTRO", raising=False)
    assert distro_name() == "kali-linux"

    monkeypatch.setenv("NETPOLICY_WSL_DISTRO", "custom-distro")
    assert distro_name() == "custom-distro"


def test_wsl_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify wsl_available checks for wsl on PATH."""
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/wsl" if cmd == "wsl" else None)
    assert wsl_available() is True

    monkeypatch.setattr("shutil.which", lambda cmd: None)
    assert wsl_available() is False


def test_distro_installed_utf16le_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify distro_installed decodes UTF-16-LE with NUL bytes and BOM."""
    raw_text = "kali-linux\r\nUbuntu-22.04\r\ndocker-desktop\r\n"
    # Encode with BOM and embedded NUL bytes (standard UTF-16-LE output on Windows)
    utf16_bytes = b"\xff\xfe" + raw_text.encode("utf-16-le")

    def mock_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=utf16_bytes)

    monkeypatch.setattr("subprocess.run", mock_run)

    # Case-insensitive checks
    assert distro_installed("kali-linux") is True
    assert distro_installed("Kali-Linux") is True
    assert distro_installed("ubuntu-22.04") is True
    assert distro_installed("debian") is False


def test_distro_installed_failure_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify distro_installed returns None when subprocess fails or times out."""

    def mock_run_fail(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout=b"")

    monkeypatch.setattr("subprocess.run", mock_run_fail)
    assert distro_installed("kali-linux") is None

    def mock_run_timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="wsl -l -q", timeout=5)

    monkeypatch.setattr("subprocess.run", mock_run_timeout)
    assert distro_installed("kali-linux") is None


def test_maybe_launch_wsl_non_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify maybe_launch_wsl returns None immediately on non-Windows platforms."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: False)
    console = Console(file=io.StringIO())
    assert maybe_launch_wsl(console) is None


def test_maybe_launch_wsl_missing_wsl_exe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify missing wsl prints hint and returns None."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: False)

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=120)
    res = maybe_launch_wsl(console)

    assert res is None
    assert "Hint: WSL (Windows Subsystem for Linux) is not available" in buf.getvalue()


def test_maybe_launch_wsl_distro_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify uninstalled distro prints install instruction and returns None without installing."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.distro_installed", lambda d: False)

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=120)
    res = maybe_launch_wsl(console)

    assert res is None
    assert (
        "Kali Linux is not installed in WSL. Install it with: wsl --install -d kali-linux"
        in buf.getvalue()
    )


def test_maybe_launch_wsl_confirmed_launches_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify choice 1 (full power) calls subprocess.run with root and env handoff."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.distro_installed", lambda d: True)
    monkeypatch.setattr("netpolicy.wizard.ui.RichIO.ask_choice", lambda self, *args, **kwargs: "1")

    executed_cmds: list[list[str]] = []

    def mock_subprocess_run(
        cmd: list[str], *args: Any, **kwargs: Any
    ) -> subprocess.CompletedProcess[Any]:
        if "wslpath" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="/home/user/netpolicy\n"
            )
        if "id" in cmd and "-u" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="1000\n")
        if "id" in cmd and "-g" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="1000\n")
        if "--help" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="--cd <dir>\n")
        executed_cmds.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=42)

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    buf = io.StringIO()
    console = Console(file=buf)
    res = maybe_launch_wsl(console)

    assert res == 42
    assert len(executed_cmds) == 1
    launch_cmd = executed_cmds[0]
    assert launch_cmd[:3] == ["wsl", "-d", "kali-linux"]
    assert "-u" in launch_cmd and "root" in launch_cmd
    assert "NETPOLICY_HANDOFF=1" in launch_cmd
    assert ".linux-venv/bin/python" in launch_cmd
    assert "-m" in launch_cmd
    assert "netpolicy" in launch_cmd


def test_maybe_launch_wsl_custom_distro_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify NETPOLICY_WSL_DISTRO is passed to subprocess.run."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.distro_installed", lambda d: True)
    monkeypatch.setenv("NETPOLICY_WSL_DISTRO", "my-distro")
    monkeypatch.setattr("netpolicy.wizard.ui.RichIO.ask_choice", lambda self, *args, **kwargs: "2")

    executed_cmds: list[list[str]] = []

    def mock_subprocess_run(
        cmd: list[str], *args: Any, **kwargs: Any
    ) -> subprocess.CompletedProcess[Any]:
        if "wslpath" in cmd:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="/home/user/netpolicy\n"
            )
        if "--help" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="--cd <dir>\n")
        executed_cmds.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    console = Console(file=io.StringIO())
    res = maybe_launch_wsl(console)

    assert res == 0
    assert len(executed_cmds) == 1
    launch_cmd = executed_cmds[0]
    assert launch_cmd[:3] == ["wsl", "-d", "my-distro"]
    # Option 2 (standard) does not use -u root
    assert "-u" not in launch_cmd
    assert "NETPOLICY_HANDOFF=1" in launch_cmd


def test_maybe_launch_wsl_declined_or_aborted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Choice 3 or EOFError/KeyboardInterrupt returns None without launching."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.distro_installed", lambda d: True)

    launch_called = False

    def mock_run(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        nonlocal launch_called
        launch_called = True
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr("subprocess.run", mock_run)

    console = Console(file=io.StringIO())

    # User picks 3 (Not now)
    monkeypatch.setattr("netpolicy.wizard.ui.RichIO.ask_choice", lambda self, *args, **kwargs: "3")
    assert maybe_launch_wsl(console) is None
    assert launch_called is False

    # EOFError (e.g. Ctrl-D) treated as No
    def raise_eof(*args: Any, **kwargs: Any) -> str:
        raise EOFError()

    monkeypatch.setattr("netpolicy.wizard.ui.RichIO.ask_choice", raise_eof)
    assert maybe_launch_wsl(console) is None
    assert launch_called is False

    # KeyboardInterrupt treated as No
    def raise_sigint(*args: Any, **kwargs: Any) -> str:
        raise KeyboardInterrupt()

    monkeypatch.setattr("netpolicy.wizard.ui.RichIO.ask_choice", raise_sigint)
    assert maybe_launch_wsl(console) is None
    assert launch_called is False


def test_maybe_launch_wsl_missing_venv_shows_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify missing .linux-venv shows instructions and returns None without launching."""
    monkeypatch.setattr("netpolicy.ui.wsl.is_native_windows", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.wsl_available", lambda: True)
    monkeypatch.setattr("netpolicy.ui.wsl.distro_installed", lambda d: True)
    monkeypatch.setattr("os.path.lexists", lambda p: False)
    monkeypatch.setattr("pathlib.Path.is_file", lambda self: False)

    buf = io.StringIO()
    console = Console(file=buf)
    res = maybe_launch_wsl(console)

    assert res is None
    assert "Setup needed in Linux" in buf.getvalue()
    assert "bootstrap-python.sh" in buf.getvalue()
