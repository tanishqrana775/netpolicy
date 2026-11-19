"""Tests for wizard back-tracking and clean screen redraw (BUG 2 fix) & WSL handoff guard."""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from netpolicy.wizard.ui import RichIO


def test_non_tty_console_clear_emits_no_escape_codes() -> None:
    """Assert that with a non-TTY console, clear() is a no-op and emits no escape codes."""
    console = Console(record=True, force_terminal=False, width=80)
    assert not console.is_terminal

    ui = RichIO(console=console)
    ui.clear()

    # Must not emit any control sequences into the record buffer
    assert len(console._record_buffer) == 0
    assert ui.clear_count == 0


def test_wsl_handoff_command_construction_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard test: verify WSL handoff command construction in netpolicy.ui.wsl is unchanged."""
    import netpolicy.ui.wsl as wsl_mod

    monkeypatch.setattr(wsl_mod, "is_native_windows", lambda: True)
    monkeypatch.setattr(wsl_mod, "wsl_available", lambda: True)
    monkeypatch.setattr(wsl_mod, "distro_installed", lambda d: True)
    monkeypatch.setattr(wsl_mod, "_check_cd_support", lambda: True)
    monkeypatch.setattr(wsl_mod, "_windows_to_wsl_path", lambda p, d: "/mnt/c/test/netpolicy")

    captured_cmds: list[list[str]] = []

    def mock_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", mock_run)

    console = Console(record=True, force_terminal=True, width=80)
    # User selects option 1 (Launch inside Kali WSL)
    fake_io = MagicMock()
    fake_io.ask_choice.return_value = "1"
    monkeypatch.setattr(wsl_mod, "RichIO", lambda *args, **kwargs: fake_io)

    code = wsl_mod.maybe_launch_wsl(console)
    assert code == 0
    assert len(captured_cmds) == 3

    # Command 1: id -u
    assert captured_cmds[0] == ["wsl", "-d", "kali-linux", "-e", "id", "-u"]
    # Command 2: id -g
    assert captured_cmds[1] == ["wsl", "-d", "kali-linux", "-e", "id", "-g"]
    # Command 3: launch inside WSL
    expected_prefix = [
        "wsl", "-d", "kali-linux", "-u", "root", "--cd", "/mnt/c/test/netpolicy", "-e"
    ]
    assert captured_cmds[2][: len(expected_prefix)] == expected_prefix
    assert "NETPOLICY_HANDOFF=1" in captured_cmds[2]
    assert "netpolicy" in captured_cmds[2]
