# ruff: noqa: E501, N806
"""Modern gradient banner, status footer, and interactive UI session for netpolicy CLI.

Presentation layer only: handles welcome screen, gradient text generation,
environment inspection, compact audit headers, and terminal status footers.
All output is routed to stderr to ensure stdout remains clean for pipeline consumers.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from rich.align import Align
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Reconfigure Windows standard streams to UTF-8 to prevent cp1252 encode errors
if sys.platform.startswith("win"):
    try:
        if sys.stderr:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        if sys.stdout:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ------------------------------------------------------------------------------
# Constants and Glyph Definitions
# ------------------------------------------------------------------------------

GRADIENT_STOPS: list[str] = [
    "#ff55ff",  # Bright Magenta
    "#9d4edd",  # Purple
    "#7b61ff",  # Indigo
    "#4ea8de",  # Sky Blue
    "#48bfe3",  # Light Cyan
]

# 5-row block font definitions for N, E, T, P, O, L, I, C, Y
GLYPHS: dict[str, list[str]] = {
    "N": [
        "█   █",
        "██  █",
        "█ █ █",
        "█  ██",
        "█   █",
    ],
    "E": [
        "█████",
        "█    ",
        "████ ",
        "█    ",
        "█████",
    ],
    "T": [
        "█████",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
    ],
    "P": [
        "████ ",
        "█   █",
        "████ ",
        "█    ",
        "█    ",
    ],
    "O": [
        " ███ ",
        "█   █",
        "█   █",
        "█   █",
        " ███ ",
    ],
    "L": [
        "█    ",
        "█    ",
        "█    ",
        "█    ",
        "█████",
    ],
    "I": [
        "███",
        " █ ",
        " █ ",
        " █ ",
        "███",
    ],
    "C": [
        " ████",
        "█    ",
        "█    ",
        "█    ",
        " ████",
    ],
    "Y": [
        "█   █",
        " █ █ ",
        "  █  ",
        "  █  ",
        "  █  ",
    ],
}

# Tips verified directly against CLI --help options
TIPS: list[str] = [
    "Use --demo to run an audit with realistic mock data without sending live packets.",
    "Pass --mode socket to audit outbound ports without root or administrator privileges.",
    "Use --json to output structured JSON suitable for automated ingestion and CI/CD pipelines.",
    "Pass --output report.md to export audit results as a GitHub-flavored Markdown report.",
    "Use --ports 21,22,25,80,443 to restrict the port reachability audit to specific services.",
    "Set --runs 10 to increase statistical sampling confidence on lossy network paths.",
    "Use --control-port 443 to specify a known open port for link health verification.",
    "Pass --quiet to suppress live progress spinners and configuration tables.",
    "Use --no-color to disable ANSI color styling when redirecting terminal output.",
    "Pass --include-identifiers to display unmasked IP addresses and network labels.",
    "Run netpolicy compare baseline.json tampered.json to diff two audit reports.",
    "Run netpolicy reclassify <path.jsonl> to re-run classifiers offline on saved raw observations.",
]

_ui_console: Console | None = None
_global_no_banner: bool = False


def set_global_no_banner(value: bool = True) -> None:
    """Set process-wide banner suppression flag."""
    global _global_no_banner
    _global_no_banner = value


def get_ui_console() -> Console:
    """Return the dedicated rich Console instance configured strictly for stderr."""
    global _ui_console
    if _ui_console is None:
        _ui_console = Console(stderr=True)
    return _ui_console


def _hex_to_rgb(hex_code: str) -> tuple[int, int, int]:
    """Parse a 6-digit hex string into an (R, G, B) integer tuple."""
    hex_clean = hex_code.lstrip("#")
    return (
        int(hex_clean[0:2], 16),
        int(hex_clean[2:4], 16),
        int(hex_clean[4:6], 16),
    )


def interpolate_gradient(stops: list[str], t: float) -> str:
    """Interpolate RGB color hex across multiple color stops for t in [0.0, 1.0]."""
    t = max(0.0, min(1.0, t))
    if len(stops) == 1:
        return stops[0]

    num_segments = len(stops) - 1
    segment = int(t * num_segments)
    if segment >= num_segments:
        segment = num_segments - 1
        u = 1.0
    else:
        u = (t * num_segments) - segment

    r0, g0, b0 = _hex_to_rgb(stops[segment])
    r1, g1, b1 = _hex_to_rgb(stops[segment + 1])

    r = int(round(r0 + (r1 - r0) * u))
    g = int(round(g0 + (g1 - g0) * u))
    b = int(round(b0 + (b1 - b0) * u))
    return f"#{r:02x}{g:02x}{b:02x}"


def mix_toward_white(hex_code: str, ratio: float = 0.65) -> str:
    """Blend an RGB hex color toward pure white (#ffffff) by the given ratio."""
    r, g, b = _hex_to_rgb(hex_code)
    r_mixed = int(round(r + (255 - r) * ratio))
    g_mixed = int(round(g + (255 - g) * ratio))
    b_mixed = int(round(b + (255 - b) * ratio))
    return f"#{r_mixed:02x}{g_mixed:02x}{b_mixed:02x}"


def _is_utf8(console: Console) -> bool:
    """Check if the console stream supports UTF-8 character encoding."""
    enc = getattr(console, "encoding", None) or getattr(
        getattr(console, "file", None), "encoding", None
    )
    if enc:
        clean = enc.lower().replace("-", "").replace("_", "")
        return clean in ("utf8", "utf")
    return True


def sweep_frames(version: str, utf8: bool = True) -> list[Text]:
    """Generate 12 frames of the animated packet sweep welcome logo.

    Canvas layout (8 lines):
      Rows 0-4: 5-row block font wordmark NETPOLICY (W = 51)
      Row 5: blank line
      Row 6: status ('probing network policy …') or final tagline
      Row 7: version string ('v<version>')

    Each frame has exactly 8 lines of equal width (centered) to prevent jitter.
    """
    N = 12
    W = 51
    tagline = "see what your network silently blocks, rewrites or intercepts"
    status_text = "probing network policy …" if utf8 else "probing network policy ..."
    canvas_w = max(W, len(tagline))  # 61 columns
    pad_left = (canvas_w - W) // 2  # 5 spaces
    pad_right = canvas_w - W - pad_left  # 5 spaces

    block_char = "█" if utf8 else "#"
    ghost_char = "░" if utf8 else "."
    beam_char = "▌" if utf8 else "|"

    base_rows = [" ".join(GLYPHS[ch][r] for ch in "NETPOLICY") for r in range(5)]

    col_colors = [interpolate_gradient(GRADIENT_STOPS, c / (W - 1)) for c in range(W)]
    white_mixed_colors = [mix_toward_white(col_colors[c], 0.65) for c in range(W)]

    frames: list[Text] = []

    for f in range(N):
        text = Text()
        is_final = f == N - 1
        p = -3 + round(f * (W + 6) / (N - 2)) if not is_final else W + 10

        # Rows 0-4: Wordmark
        for r in range(5):
            if pad_left > 0:
                text.append(" " * pad_left)
            for c in range(W):
                if not is_final and 0 <= p + 2 < W and c == p + 2:
                    text.append(beam_char, style="#48bfe3")
                else:
                    ch = base_rows[r][c]
                    if ch == "█":
                        if is_final or c < p - 2:
                            text.append(block_char, style=col_colors[c])
                        elif c <= p + 1:
                            text.append(block_char, style=white_mixed_colors[c])
                        else:
                            text.append(ghost_char, style="#2f2f44")
                    else:
                        text.append(" ")
            if pad_right > 0:
                text.append(" " * pad_right)
            text.append("\n")

        # Row 5: Blank line of equal width
        text.append(" " * canvas_w + "\n")

        # Row 6: Status or Tagline centered to canvas_w
        r6_content = tagline if is_final else status_text
        r6_lpad = (canvas_w - len(r6_content)) // 2
        r6_rpad = canvas_w - len(r6_content) - r6_lpad
        text.append(" " * r6_lpad)
        text.append(r6_content, style="dim #7a7a8c" if not is_final else "#7a7a8c")
        text.append(" " * r6_rpad + "\n")

        # Row 7: Version centered to canvas_w
        ver_str = f"v{version}"
        r7_lpad = (canvas_w - len(ver_str)) // 2
        r7_rpad = canvas_w - len(ver_str) - r7_lpad
        text.append(" " * r7_lpad)
        text.append(ver_str, style="#7a7a8c")
        text.append(" " * r7_rpad)

        frames.append(text)

    return frames


def render_animation(
    frames: list[Text],
    console: Console,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Render packet sweep animation frames to console using Rich Live.

    Catches KeyboardInterrupt cleanly, restores cursor, and exits with code 130.
    """
    from rich.live import Live

    try:
        with Live(console=console, auto_refresh=False, transient=False) as live:
            for idx, frame in enumerate(frames):
                live.update(Align.center(frame))
                live.refresh()
                if idx < len(frames) - 1:
                    sleep_fn(0.11)
    except KeyboardInterrupt:
        console.show_cursor(True)
        sys.exit(130)


def render_static_banner(version: str, console: Console) -> None:
    """Render single static banner fallback based on console capabilities."""
    dim_style = "dim" if (console.color_system is None or console.no_color) else "dim #7a7a8c"

    if console.width < 64:
        text = Text()
        text.append("NETPOLICY", style="bold")
        text.append("\n")
        text.append(f"v{version}", style=dim_style)
        console.print(Align.center(text))
        return

    block_char = "█" if _is_utf8(console) else "#"
    style = "bold" if (console.color_system is None or console.no_color) else "bold cyan"

    base_rows = [
        " ".join(GLYPHS[ch][r].replace("█", block_char) for ch in "NETPOLICY") for r in range(5)
    ]
    tagline = "see what your network silently blocks, rewrites or intercepts"
    canvas_w = max(51, len(tagline))
    pad_left = (canvas_w - 51) // 2
    pad_right = canvas_w - 51 - pad_left

    text = Text()
    for r in range(5):
        if pad_left > 0:
            text.append(" " * pad_left)
        text.append(base_rows[r], style=style)
        if pad_right > 0:
            text.append(" " * pad_right)
        text.append("\n")

    text.append(" " * canvas_w + "\n")

    r6_lpad = (canvas_w - len(tagline)) // 2
    r6_rpad = canvas_w - len(tagline) - r6_lpad
    text.append(" " * r6_lpad)
    text.append(tagline, style=dim_style)
    text.append(" " * r6_rpad + "\n")

    ver_str = f"v{version}"
    r7_lpad = (canvas_w - len(ver_str)) // 2
    r7_rpad = canvas_w - len(ver_str) - r7_lpad
    text.append(" " * r7_lpad)
    text.append(ver_str, style=dim_style)
    text.append(" " * r7_rpad)

    console.print(Align.center(text))


def build_logo(console: Console) -> Text:
    """Build the word NETPOLICY in a 5-row block font with horizontal gradient coloring.

    Fallbacks:
    - If console.color_system is None, applies bold style.
    - If console.color_system is 'standard' or 'windows', applies bold cyan.
    - If the terminal is narrower than 64 columns, returns plain bold 'NETPOLICY'.
    """
    if console.width < 64:
        return Text("NETPOLICY", style="bold")

    block_char = "█" if _is_utf8(console) else "#"
    rows = [
        " ".join(GLYPHS[ch][row_idx].replace("█", block_char) for ch in "NETPOLICY")
        for row_idx in range(5)
    ]
    row_len = len(rows[0])

    if console.color_system is None or console.no_color:
        text = Text()
        for idx, row in enumerate(rows):
            text.append(row, style="bold")
            if idx < 4:
                text.append("\n")
        return text

    if console.color_system in ("standard", "windows"):
        text = Text()
        for idx, row in enumerate(rows):
            text.append(row, style="bold cyan")
            if idx < 4:
                text.append("\n")
        return text

    # Truecolor / 256 colors: interpolate across stops for each horizontal column
    text = Text()
    for row_idx, row in enumerate(rows):
        for col_idx, ch in enumerate(row):
            if ch == block_char:
                t = col_idx / (row_len - 1) if row_len > 1 else 0.0
                color = interpolate_gradient(GRADIENT_STOPS, t)
                text.append(ch, style=color)
            else:
                text.append(ch)
        if row_idx < 4:
            text.append("\n")
    return text


def detect_privilege() -> str:
    """Detect current execution privilege: 'root' on POSIX, 'admin' on Windows, else 'user'."""
    if hasattr(os, "geteuid"):
        try:
            return "root" if os.geteuid() == 0 else "user"
        except Exception:
            return "user"

    if sys.platform.startswith("win"):
        try:
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            return "admin" if is_admin else "user"
        except Exception:
            return "user"

    return "user"


def detect_environment() -> dict[str, Any]:
    """Inspect and return runtime environment metadata (platform, versions, privilege, mode)."""
    from netpolicy import __version__

    # Platform detection
    if sys.platform.startswith("win"):
        platform_str = "Windows"
    else:
        is_wsl = False
        proc_ver = Path("/proc/version")
        if proc_ver.is_file():
            try:
                content = proc_ver.read_text(encoding="utf-8", errors="ignore").lower()
                if "microsoft" in content:
                    is_wsl = True
            except Exception:
                pass
        platform_str = "WSL" if is_wsl else "Linux"

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # Check whether Scapy imports cleanly
    try:
        import scapy  # noqa: F401

        has_scapy = True
    except ImportError:
        has_scapy = False

    privilege = detect_privilege()
    is_privileged = privilege in ("root", "admin")
    default_mode = "raw" if (is_privileged and has_scapy) else "socket"

    # Current working directory shortened with ~ if within user home
    cwd = Path.cwd()
    try:
        home = Path.home()
        if cwd == home:
            cwd_str = "~"
        elif cwd.is_relative_to(home):
            cwd_str = f"~/{cwd.relative_to(home).as_posix()}"
        else:
            cwd_str = str(cwd)
    except Exception:
        cwd_str = str(cwd)

    return {
        "platform": platform_str,
        "python_version": py_ver,
        "netpolicy_version": __version__,
        "has_scapy": has_scapy,
        "privilege": privilege,
        "default_mode": default_mode,
        "cwd": cwd_str,
    }


def print_welcome(
    console: Console | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Render animated packet sweep welcome logo or static fallback to stderr."""
    if os.environ.get("NETPOLICY_HANDOFF") == "1":
        return

    if console is None:
        console = get_ui_console()

    from netpolicy import __version__

    version = __version__

    can_animate = (
        console.color_system == "truecolor"
        and not console.no_color
        and console.width >= 64
        and _is_utf8(console)
    )

    if can_animate:
        frames = sweep_frames(version, utf8=True)
        render_animation(frames, console, sleep_fn=sleep_fn)
    else:
        render_static_banner(version, console)


def print_static_logo(console: Console | None = None) -> None:
    """Render a single static gradient logo without animation."""
    if os.environ.get("NETPOLICY_HANDOFF") == "1":
        return
    if console is None:
        console = get_ui_console()
    from netpolicy import __version__

    render_static_banner(__version__, console)


def print_compact_header(
    command: str,
    target: str | None = None,
    mode: str | None = None,
    console: Console | None = None,
) -> None:
    """Print a single gradient-colored line header before command execution."""
    if console is None:
        console = get_ui_console()

    from netpolicy import __version__

    mode_str = mode.value if hasattr(mode, "value") else str(mode or "auto")
    target_str = target or "(none)"
    line_str = f"netpolicy v{__version__} | {command} | target {target_str} | mode {mode_str}"

    if console.color_system in ("truecolor", "256"):
        text = Text()
        n = len(line_str)
        for i, ch in enumerate(line_str):
            t = i / (n - 1) if n > 1 else 0.0
            col = interpolate_gradient(GRADIENT_STOPS, t)
            text.append(ch, style=col)
        console.print(text)
    elif console.color_system == "standard":
        console.print(Text(line_str, style="bold cyan"))
    else:
        console.print(Text(line_str, style="bold"))


def print_footer(
    command: str | None = None,
    mode: str | None = None,
    console: Console | None = None,
) -> None:
    """Print a horizontal divider rule and a two-column status footer."""
    if console is None:
        console = get_ui_console()

    env = detect_environment()
    mode_str = mode.value if hasattr(mode, "value") else str(mode or env["default_mode"])

    console.print(Rule(style="dim cyan"))

    grid = Table.grid(expand=True)
    grid.add_column(justify="left")
    grid.add_column(justify="right")

    left_text = (
        f"netpolicy v{env['netpolicy_version']} | mode {mode_str} "
        f"({env['privilege']}) | {env['cwd']}"
    )
    right_text = "exit codes: 0 clean | 1 findings | 2 error"

    grid.add_row(f"[dim]{left_text}[/dim]", f"[dim]{right_text}[/dim]")
    console.print(grid)


def should_show_banner(
    json_flag: bool = False,
    quiet_flag: bool = False,
    no_banner_flag: bool = False,
    no_banner: bool = False,
    env: dict[str, str] | None = None,
    stream: Any = None,
) -> bool:
    """Determine whether welcome banner or compact headers/footers should be shown.

    Rules:
    - Stderr stream must be an interactive terminal.
    - None of these may apply:
      * json_flag is True (--json)
      * quiet_flag is True (--quiet)
      * no_banner_flag / no_banner is True (--no-banner)
      * NETPOLICY_NO_BANNER environment variable is set.
    """
    if json_flag or quiet_flag or no_banner_flag or no_banner:
        return False

    if env is None and _global_no_banner:
        return False

    environ = os.environ if env is None else env
    if environ.get("NETPOLICY_HANDOFF") == "1":
        return False
    val = environ.get("NETPOLICY_NO_BANNER")
    if val is not None and val != "" and val.lower() not in ("0", "false", "no"):
        return False

    out_stream = sys.stderr if stream is None else stream

    # Check terminal status across Rich Console or native stream
    if hasattr(out_stream, "is_terminal"):
        if not out_stream.is_terminal:
            return False
    elif hasattr(out_stream, "isatty"):
        try:
            if not out_stream.isatty():
                return False
        except Exception:
            return False
    else:
        return False

    return True


@contextmanager
def ui_session(
    command: str,
    target: str | None = None,
    mode: str | None = None,
    json_flag: bool = False,
    quiet_flag: bool = False,
    no_banner: bool = False,
    no_banner_flag: bool | None = None,
    console: Console | None = None,
) -> Iterator[None]:
    """Context manager printing compact header on entry and footer in finally block."""
    if console is None:
        console = get_ui_console()

    flag = no_banner if no_banner_flag is None else no_banner_flag

    show = should_show_banner(
        json_flag=json_flag,
        quiet_flag=quiet_flag,
        no_banner_flag=flag,
        stream=console.file,
    )

    if show:
        print_compact_header(command=command, target=target, mode=mode, console=console)

    try:
        yield
    finally:
        if show:
            print_footer(command=command, mode=mode, console=console)
