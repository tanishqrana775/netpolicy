# ruff: noqa: E501, N806, SIM117, SIM102
"""Tests for netpolicy UI banner, header, footer, packet sweep animation, and styling."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from unittest.mock import patch

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from netpolicy import __version__
from netpolicy.cli import app
from netpolicy.ui.banner import (
    GLYPHS,
    GRADIENT_STOPS,
    TIPS,
    build_logo,
    detect_environment,
    detect_privilege,
    interpolate_gradient,
    print_compact_header,
    print_footer,
    print_welcome,
    render_static_banner,
    should_show_banner,
    sweep_frames,
    ui_session,
)

runner = CliRunner()


class DummyStream:
    """Mock stream to simulate TTY or non-TTY behaviour."""

    def __init__(self, tty: bool = True, encoding: str = "utf-8") -> None:
        self._tty = tty
        self.encoding = encoding

    def isatty(self) -> bool:
        return self._tty


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text for reliable content assertion."""
    ansi_regex = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    return ansi_regex.sub("", text)


# 1. audit --demo --json via CliRunner: assert stdout parses with json.loads and has NO banner text
def test_audit_demo_json_clean_stdout() -> None:
    """Verify that --json output contains purely parseable JSON and no banner/footer text."""
    result = runner.invoke(app, ["audit", "--demo", "--json"])
    assert result.exit_code == 1  # Demo audit contains intentional anomalies/findings

    # Standard output must parse cleanly as JSON
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
    assert data["metadata"]["tool_version"] == __version__
    assert "findings" in data
    assert "port_results" in data

    # Verify stdout has absolutely no UI banner text
    assert "NETPOLICY" not in result.stdout
    assert "Network Policy Auditor" not in result.stdout
    assert "exit codes:" not in result.stdout
    assert "Tip:" not in result.stdout


# 2. subprocess with stderr redirected: verify no banner/header/footer text appears
def test_subprocess_stderr_redirected_no_banner() -> None:
    """Verify non-interactive subprocess has no banner, compact header, or footer."""
    proc = subprocess.run(
        [sys.executable, "-m", "netpolicy", "audit", "--demo", "--no-color"],
        capture_output=True,
        text=True,
    )
    # Stderr was a pipe (non-TTY), so should_show_banner evaluated to False
    assert "NETPOLICY" not in proc.stderr
    assert "silently blocks" not in proc.stderr
    assert "exit codes:" not in proc.stderr
    assert "target demo.netpolicy.local" not in proc.stderr


# 3. --version prints exactly one line: "netpolicy version 0.1.0"
def test_version_single_line_no_banner() -> None:
    """Verify --version prints exactly one line without any welcome banner."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.strip().splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0] == f"netpolicy version {__version__}"


# 4. Glyph definitions: every row of every glyph has the same width as the other rows of that glyph
def test_glyph_definitions_uniform_width() -> None:
    """Verify every glyph has 5 rows and all rows in each glyph have identical length."""
    expected_letters = set("NETPOLICY")
    assert set(GLYPHS.keys()) == expected_letters

    for char, rows in GLYPHS.items():
        assert len(rows) == 5, f"Glyph '{char}' does not have 5 rows"
        expected_len = len(rows[0])
        assert expected_len > 0, f"Glyph '{char}' row 0 is empty"
        for idx, row in enumerate(rows):
            assert len(row) == expected_len, (
                f"Glyph '{char}' row {idx} length {len(row)} != row 0 length {expected_len}"
            )


# 5. Gradient: all interpolated colors are valid 6-character hex strings, and ends match stops
def test_gradient_interpolation_hex_and_stops() -> None:
    """Verify gradient colors are valid hex colors and first/last match stops."""
    hex_pattern = re.compile(r"^#[0-9a-f]{6}$")

    # First and last endpoints
    first_col = interpolate_gradient(GRADIENT_STOPS, 0.0)
    last_col = interpolate_gradient(GRADIENT_STOPS, 1.0)
    assert first_col.lower() == GRADIENT_STOPS[0].lower()
    assert last_col.lower() == GRADIENT_STOPS[-1].lower()

    # Step through intermediate points
    for i in range(101):
        t = i / 100.0
        col = interpolate_gradient(GRADIENT_STOPS, t)
        assert hex_pattern.match(col), f"Color '{col}' at t={t} is not a valid 6-digit hex"


# 6. Fallback: on a narrow terminal (width < 64) or NO_COLOR set, build_logo returns plain text / single style
def test_build_logo_fallbacks() -> None:
    """Verify logo fallbacks for narrow width, non-UTF8 encoding, NO_COLOR, and standard colors."""
    # Narrow terminal (< 64 cols)
    narrow_console = Console(width=60, color_system="truecolor", file=io.StringIO())
    logo_narrow = build_logo(narrow_console)
    assert logo_narrow.plain == "NETPOLICY"

    # Non-UTF-8 encoding uses # substitute
    ascii_stream = DummyStream(tty=True, encoding="ascii")
    ascii_console = Console(width=80, file=ascii_stream)
    logo_ascii = build_logo(ascii_console)
    assert "#" in logo_ascii.plain

    # NO_COLOR / color_system is None
    nocolor_console = Console(width=80, color_system=None, file=io.StringIO())
    logo_nocolor = build_logo(nocolor_console)
    assert "█" in logo_nocolor.plain
    for span in logo_nocolor.spans:
        assert span.style == "bold"

    # Standard 16-color terminal
    std_console = Console(width=80, color_system="standard", file=io.StringIO())
    logo_std = build_logo(std_console)
    assert "█" in logo_std.plain
    for span in logo_std.spans:
        assert span.style == "bold cyan"


# 7. Truth table for should_show_banner
def test_should_show_banner_truth_table() -> None:
    """Verify should_show_banner logic across TTY status, flags, and environment variables."""
    tty = DummyStream(tty=True)
    non_tty = DummyStream(tty=False)

    # TTY + no flags -> True
    assert should_show_banner(stream=tty, env={}) is True

    # TTY + --json -> False
    assert should_show_banner(json_flag=True, stream=tty, env={}) is False

    # TTY + --quiet -> False
    assert should_show_banner(quiet_flag=True, stream=tty, env={}) is False

    # TTY + --no-banner -> False
    assert should_show_banner(no_banner_flag=True, stream=tty, env={}) is False
    assert should_show_banner(no_banner=True, stream=tty, env={}) is False

    # TTY + NETPOLICY_NO_BANNER=1 -> False
    assert should_show_banner(stream=tty, env={"NETPOLICY_NO_BANNER": "1"}) is False
    assert should_show_banner(stream=tty, env={"NETPOLICY_NO_BANNER": "true"}) is False

    # TTY + NETPOLICY_NO_BANNER=0 -> True
    assert should_show_banner(stream=tty, env={"NETPOLICY_NO_BANNER": "0"}) is True
    assert should_show_banner(stream=tty, env={"NETPOLICY_NO_BANNER": "false"}) is True

    # non-TTY + no flags -> False
    assert should_show_banner(stream=non_tty, env={}) is False


# 8. Exit codes preserved: exit code 1, 2, and 0 under ui_session
def test_exit_codes_preserved_under_ui_session() -> None:
    """Verify ui_session context manager preserves typer.Exit codes untouched."""
    # Exit code 1
    with pytest.raises(typer.Exit) as exc1:
        with ui_session(command="audit", target="demo.local", mode="auto"):
            raise typer.Exit(code=1)
    assert exc1.value.exit_code == 1

    # Exit code 2
    with pytest.raises(typer.Exit) as exc2:
        with ui_session(command="audit", target="demo.local", mode="auto"):
            raise typer.Exit(code=2)
    assert exc2.value.exit_code == 2

    # Exit code 0
    with pytest.raises(typer.Exit) as exc0:
        with ui_session(command="audit", target="demo.local", mode="auto"):
            raise typer.Exit(code=0)
    assert exc0.value.exit_code == 0


# 9. Every flag mentioned in TIPS exists in the CLI's real --help output
def test_tips_flags_exist_in_cli_help() -> None:
    """Verify all CLI flags referenced in tips exist in real command help output."""
    help_text = ""
    for cmd in ["", "audit", "ports", "dns", "http", "compare", "reclassify"]:
        args = [cmd, "--help"] if cmd else ["--help"]
        res = runner.invoke(app, args)
        help_text += "\n" + res.output

    flag_pattern = re.compile(r"--[a-z0-9\-]+")
    for tip in TIPS:
        mentioned_flags = flag_pattern.findall(tip)
        for flag in mentioned_flags:
            assert flag in help_text, (
                f"Flag '{flag}' in tip '{tip}' does not exist in CLI help output"
            )


# 10. Test environment inspection and compact header/footer
def test_detect_environment_and_privilege() -> None:
    """Verify runtime environment inspection and privilege detection."""
    priv = detect_privilege()
    assert priv in ("root", "admin", "user")

    env = detect_environment()
    assert env["platform"] in ("Windows", "Linux", "WSL")
    assert env["privilege"] in ("root", "admin", "user")
    assert env["default_mode"] in ("raw", "socket")
    assert env["netpolicy_version"] == __version__
    assert isinstance(env["has_scapy"], bool)


def test_compact_header_and_footer_render() -> None:
    """Verify print_compact_header and print_footer output formatting."""
    string_io = io.StringIO()
    test_console = Console(file=string_io, width=120, force_terminal=True, color_system="truecolor")

    print_compact_header(command="audit", target="probe.test", mode="auto", console=test_console)
    print_footer(command="audit", mode="auto", console=test_console)

    plain_output = strip_ansi(string_io.getvalue())
    assert f"netpolicy v{__version__}" in plain_output
    assert "audit" in plain_output
    assert "target probe.test" in plain_output
    assert "exit codes: 0 clean | 1 findings | 2 error" in plain_output


# 11. Sweep frames test: 12 frames, 8 lines equal width, ghost in frame 0, gradient in frame 11
def test_sweep_frames_structure_and_progression() -> None:
    """Verify sweep_frames produces exactly 12 frames of 8 equal-width lines matching formula."""
    frames = sweep_frames(__version__, utf8=True)
    assert len(frames) == 12

    W = 51
    N = 12

    for idx, frame in enumerate(frames):
        lines = frame.plain.split("\n")
        assert len(lines) == 8, f"Frame {idx} has {len(lines)} lines, expected 8"
        line_lens = [len(line) for line in lines]
        assert len(set(line_lens)) == 1, f"Frame {idx} lines have unequal widths: {line_lens}"

    # Frame 0: contains only ghost cells and no gradient cells
    f0 = frames[0]
    assert "░" in f0.plain
    assert "█" not in f0.plain
    # All styled character spans in wordmark must be #2f2f44 (ghost)
    for span in f0.spans:
        if span.end <= 5 * 61:  # within wordmark rows
            if f0.plain[span.start : span.end].strip() == "░":
                assert span.style == "#2f2f44"

    # Frame 11 (final): contains full gradient wordmark and no ghost cells
    f11 = frames[11]
    assert "░" not in f11.plain
    assert "█" in f11.plain
    assert "see what your network silently blocks, rewrites or intercepts" in f11.plain
    assert f"v{__version__}" in f11.plain

    # Verify beam position formula on sweep frames 0..10
    for f_idx in range(11):
        expected_p = -3 + round(f_idx * (W + 6) / (N - 2))
        expected_beam_col = expected_p + 2
        frame = frames[f_idx]
        if 0 <= expected_beam_col < W:
            assert "▌" in frame.plain
        else:
            assert "▌" not in frame.plain


def test_sweep_frames_ascii_substitutes() -> None:
    """Verify sweep_frames uses ASCII substitutes '#' for █, '.' for ░, '|' for ▌ when utf8=False."""
    frames = sweep_frames(__version__, utf8=False)
    assert len(frames) == 12

    # Frame 0 uses '.' for ghost
    assert "." in frames[0].plain
    assert "░" not in frames[0].plain

    # Sweep frame with beam uses '|'
    f3 = frames[3]
    assert "|" in f3.plain
    assert "▌" not in f3.plain

    # Final frame uses '#' for block
    f11 = frames[11]
    assert "#" in f11.plain
    assert "█" not in f11.plain


# 12. Animation timing with injected fake sleep
def test_animation_timing_with_injected_sleep() -> None:
    """Verify total requested animation sleep is between 1.1 and 1.4 seconds."""
    sleep_calls: list[float] = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    console = Console(file=io.StringIO(), force_terminal=True, color_system="truecolor", width=80)
    print_welcome(console, sleep_fn=fake_sleep)

    total_sleep = sum(sleep_calls)
    assert 1.1 <= total_sleep <= 1.4, f"Total sleep {total_sleep}s not in [1.1, 1.4]"
    assert len(sleep_calls) == 11, f"Expected 11 sleep intervals, got {len(sleep_calls)}"


# 13. Fallback matrix: only truecolor + width >= 64 + utf8 + no_color=False animates
def test_fallback_matrix_degradation() -> None:
    """Verify fallback matrix routes to static banner or plain text appropriately."""
    with (
        patch("netpolicy.ui.banner.render_animation") as mock_animate,
        patch("netpolicy.ui.banner.render_static_banner") as mock_static,
    ):
        # 1. Truecolor + width=80 + utf8 -> animates
        c_tc = Console(file=io.StringIO(), force_terminal=True, color_system="truecolor", width=80)
        print_welcome(c_tc)
        assert mock_animate.called
        assert not mock_static.called
        mock_animate.reset_mock()
        mock_static.reset_mock()

        # 2. 256 colors -> static
        c_256 = Console(file=io.StringIO(), force_terminal=True, color_system="256", width=80)
        print_welcome(c_256)
        assert not mock_animate.called
        assert mock_static.called
        mock_animate.reset_mock()
        mock_static.reset_mock()

        # 3. Standard 16-color -> static
        c_std = Console(file=io.StringIO(), force_terminal=True, color_system="standard", width=80)
        print_welcome(c_std)
        assert not mock_animate.called
        assert mock_static.called
        mock_animate.reset_mock()
        mock_static.reset_mock()

        # 4. None / no_color -> static
        c_none = Console(file=io.StringIO(), force_terminal=True, color_system=None, width=80)
        print_welcome(c_none)
        assert not mock_animate.called
        assert mock_static.called
        mock_animate.reset_mock()
        mock_static.reset_mock()

        # 5. Narrow terminal width=60 (<64) -> static (which renders plain bold NETPOLICY)
        c_narrow = Console(
            file=io.StringIO(), force_terminal=True, color_system="truecolor", width=60
        )
        print_welcome(c_narrow)
        assert not mock_animate.called
        assert mock_static.called
        mock_animate.reset_mock()
        mock_static.reset_mock()

        # 6. Non-UTF8 encoding -> static
        ascii_stream = DummyStream(tty=True, encoding="ascii")
        c_ascii = Console(
            file=ascii_stream, force_terminal=True, color_system="truecolor", width=80
        )
        print_welcome(c_ascii)
        assert not mock_animate.called
        assert mock_static.called


# 14. Static banner renders expected text
def test_static_banner_output() -> None:
    """Verify render_static_banner outputs wordmark and tagline."""
    buf = io.StringIO()
    c = Console(file=buf, width=80, force_terminal=True, color_system="standard")
    render_static_banner(__version__, c)
    plain = strip_ansi(buf.getvalue())
    assert "█" in plain
    assert "silently blocks, rewrites or intercepts" in plain
    assert f"v{__version__}" in plain

    buf_narrow = io.StringIO()
    c_narrow = Console(file=buf_narrow, width=50, force_terminal=True, color_system="standard")
    render_static_banner(__version__, c_narrow)
    plain_narrow = strip_ansi(buf_narrow.getvalue())
    assert "NETPOLICY" in plain_narrow
    assert f"v{__version__}" in plain_narrow


# 15. Stdout contract: bare invocation with non-interactive stream produces help on stdout
def test_bare_invocation_stdout_help_contract() -> None:
    """Verify bare invocation prints exact help text to stdout when piped/non-interactive."""
    res_bare = runner.invoke(app, [])
    res_help = runner.invoke(app, ["--help"])

    assert res_bare.exit_code == 0
    assert res_bare.stdout == res_help.stdout
    # Ensure no animation/banner leaks into stdout
    assert "CLI network policy auditor" in res_bare.stdout
    assert "silent blocking" in res_bare.stdout
    assert "█" not in res_bare.stdout
    assert "░" not in res_bare.stdout


def test_bare_invocation_with_no_banner_flag() -> None:
    """Verify bare invocation with --no-banner prints help and exit 0."""
    res = runner.invoke(app, ["--no-banner"])
    assert res.exit_code == 0
    assert "Usage: netpolicy" in res.stdout
    assert "█" not in res.stdout
