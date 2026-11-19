# ruff: noqa: E501
"""Interactive UI adapter, screens, and state handlers (Stage 2 & 3 Overhaul)."""

from __future__ import annotations

import datetime
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

from netpolicy.models import AuditReport
from netpolicy.report.humanize import (
    STRINGS,
)
from netpolicy.wizard.capabilities import detect_capabilities
from netpolicy.wizard.fsm import Event, State, reset_context_for_new_run

try:
    from .keys import KeyboardUnavailable, flush_stdin, read_key
except ImportError:
    from keys import KeyboardUnavailable, flush_stdin, read_key  # type: ignore[no-redef]
from netpolicy.wizard.plan import (
    PORT_PRESETS,
    CommandPlan,
    build_audit_plan,
    build_compare_plan,
    build_dns_plan,
    build_http_plan,
    build_lab_plan,
    build_ports_plan,
    build_reclassify_plan,
    validate_ports,
    validate_target,
)

# ==============================================================================
# Brand Colors & Style Constants
# ==============================================================================

COLOR_MAGENTA = "#ff55ff"
COLOR_PURPLE = "#7b61ff"
COLOR_CYAN = "#48bfe3"
COLOR_GREEN = "#5ee89a"
COLOR_YELLOW = "#ffd166"
COLOR_RED = "#ff6b6b"
COLOR_DIM = "#7a7a8c"

BREADCRUMB_STEPS = ["Goal", "Target", "Services", "Options", "Permission", "Review", "Results"]

VERDICT_PANEL_CONFIG: dict[str, tuple[str, str, str]] = {
    "CLEAN": (
        COLOR_GREEN,
        STRINGS["results"]["clean"],
        STRINGS["results"]["clean_msg"],
    ),
    "LIMITED": (
        COLOR_YELLOW,
        STRINGS["results"]["findings"],
        STRINGS["results"]["findings_msg"],
    ),
    "ACTION_REQUIRED": (
        COLOR_YELLOW,
        STRINGS["verdict_headlines"]["ACTION_REQUIRED"],
        STRINGS["verdict_descriptions"]["ACTION_REQUIRED"],
    ),
    "RESTRICTED": (
        COLOR_RED,
        STRINGS["verdict_headlines"]["RESTRICTED"],
        STRINGS["verdict_descriptions"]["RESTRICTED"],
    ),
    "INCONCLUSIVE": (
        COLOR_DIM,
        STRINGS["verdict_headlines"]["INCONCLUSIVE"],
        STRINGS["verdict_descriptions"]["INCONCLUSIVE"],
    ),
}


def extract_verdict(report: AuditReport | dict[str, Any] | None) -> str | None:
    """Extract and normalize overall audit verdict from an AuditReport or dict payload."""
    if report is None:
        return None

    # 1. Direct attribute or dictionary key lookup
    candidate: Any = None
    if isinstance(report, dict):
        candidate = report.get("verdict")
        if candidate is None:
            candidate = report.get("level")
        if isinstance(candidate, dict):
            candidate = candidate.get("level") or candidate.get("verdict")
    else:
        candidate = getattr(report, "verdict", None)
        if candidate is None:
            candidate = getattr(report, "level", None)
        if candidate is not None and hasattr(candidate, "level"):
            candidate = candidate.level

    if candidate is not None:
        if hasattr(candidate, "value"):
            candidate = candidate.value
        if isinstance(candidate, str):
            norm = candidate.strip().upper()
            if norm:
                return norm

    # 2. Compute verdict from AuditReport structure or serializable dict
    try:
        from netpolicy.report.summary import aggregate, apply_reliability_gates, compute_verdict

        rep_obj: AuditReport | None = None
        if isinstance(report, AuditReport):
            rep_obj = report
        elif isinstance(report, dict) and (
            "port_results" in report or "dns_results" in report or "http_results" in report
        ):
            rep_obj = AuditReport.model_validate(report)

        if rep_obj is not None:
            raw_issues = aggregate(rep_obj)
            issues, caveats = apply_reliability_gates(raw_issues, rep_obj)
            v_summary = compute_verdict(issues, caveats, rep_obj)
            return v_summary.level.strip().upper()
    except Exception:
        return None

    return None


def _is_utf8(console: Console) -> bool:
    """Check if console stream supports UTF-8 character encoding."""
    enc = getattr(console, "encoding", None) or getattr(
        getattr(console, "file", None), "encoding", None
    )
    if enc:
        clean = enc.lower().replace("-", "").replace("_", "")
        return clean in ("utf8", "utf")
    return True


def _get_symbols(console: Console) -> dict[str, str]:
    """Return UTF-8 symbols or ASCII fallbacks based on console capabilities."""
    legacy = getattr(console, "legacy_windows", False)
    utf8 = _is_utf8(console) and not legacy
    if utf8:
        return {
            "diamond": "◆",
            "diamond_empty": "◇",
            "check": "✔",
            "cross": "✖",
            "chevron": "❯",
            "rail": "│",
            "corner": "└",
            "dot": "●",
            "bar": "━",
            "dash": "─",
            "prompt": "›",
        }
    return {
        "diamond": "*",
        "diamond_empty": "o",
        "check": "v",
        "cross": "x",
        "chevron": ">",
        "rail": "|",
        "corner": "+",
        "dot": "*",
        "bar": "-",
        "dash": "-",
        "prompt": ">",
    }


# ==============================================================================
# UI Abstraction Protocol & Data Models
# ==============================================================================


@dataclass(frozen=True)
class Option:
    """A selectable option in a menu."""

    key: str
    label: str
    enabled: bool = True
    reason_disabled: str = ""
    bracket: str = ""


class WizardInterruptError(Exception):
    """Raised when the user requests an interrupt (Ctrl+C)."""


WizardInterrupt = WizardInterruptError


class IO(Protocol):
    """Abstract user interaction protocol supporting interactive and scripted sessions."""

    def clear(self) -> None: ...

    def begin_screen(self, state: Any) -> None: ...

    def render_summary(self, question: str, answer_label: str) -> None: ...

    def ask_choice(
        self,
        question: str,
        options: list[Option],
        help_text: str = "",
        allow_back: bool = True,
        default: str | None = None,
    ) -> str: ...

    def ask_text(
        self,
        question: str,
        default: str = "",
        validator: Callable[[str], tuple[bool, str]] | None = None,
        help_text: str = "",
    ) -> str: ...

    def ask_confirm(self, question: str, default: bool = True) -> bool: ...

    def show(self, renderable: RenderableType) -> None: ...

    def show_header(self, title: str, step: str) -> None: ...


# ==============================================================================
# Isolated Clack-Style Choice Prompt
# ==============================================================================


def ask_choice(
    title: str,
    options: Sequence[str | tuple[str, str]],
    *,
    default: int = 0,
    allow_back: bool = True,
    out: Console | None = None,
) -> int | None:
    """Clack-style interactive menu prompt returning selected index or None."""
    parsed: list[tuple[str, str]] = []
    for item in options:
        if isinstance(item, (tuple, list)):
            label = str(item[0])
            hint = str(item[1]) if len(item) > 1 else ""
        else:
            label = str(item)
            hint = ""
        parsed.append((label, hint))

    if not parsed:
        return None

    console = out if out is not None else Console()

    # Determine UTF-8 vs ASCII fallback based on stdout encoding and console
    is_utf8 = True
    stdout_enc = getattr(sys.stdout, "encoding", None)
    if stdout_enc:
        clean = stdout_enc.lower().replace("-", "").replace("_", "")
        if clean not in ("utf8", "utf"):
            is_utf8 = False
    if getattr(console, "legacy_windows", False) or not _is_utf8(console):
        is_utf8 = False

    if is_utf8:
        sym_prompt = "◆"
        sym_selected = "●"
        sym_unselected = "○"
        sym_check = "✔"
    else:
        sym_prompt = "*"
        sym_selected = "*"
        sym_unselected = "o"
        sym_check = "v"

    current_idx = default % len(parsed) if len(parsed) > 0 else 0
    show_all_hints = False

    footer_text = (
        "Up/Down move | Enter select | Esc back | ? show all hints"
        if allow_back
        else "Up/Down move | Enter select | ? show all hints"
    )

    def _render_menu(current: int, show_all: bool) -> Group:
        lines: list[Text] = []

        # Title row
        title_line = Text()
        title_line.append("  ")
        title_line.append(sym_prompt, style="bold cyan")
        title_line.append(f"  {title}", style="bold")
        lines.append(title_line)

        # Option rows
        for idx, (label, hint) in enumerate(parsed):
            row = Text()
            is_sel = idx == current
            marker = sym_selected if is_sel else sym_unselected

            if is_sel:
                row.append(f"  {marker} ", style="bold cyan")
                row.append(label, style="bold")
            else:
                row.append(f"  {marker} ", style="dim")
                row.append(label, style="dim")

            if hint and (is_sel or show_all):
                row.append(f" [{hint}]", style="dim")

            lines.append(row)

        # Dim footer
        footer_line = Text()
        footer_line.append(f"  {footer_text}", style="dim")
        lines.append(footer_line)

        return Group(*lines)

    selected_idx: int | None = None

    with Live(
        _render_menu(current_idx, show_all_hints),
        console=console,
        transient=True,
        auto_refresh=False,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as live:
        live.refresh()
        while True:
            try:
                k = read_key()
            except KeyboardInterrupt:
                raise

            if k == "up":
                new_idx = (current_idx - 1) % len(parsed)
                if new_idx != current_idx:
                    current_idx = new_idx
                    live.update(_render_menu(current_idx, show_all_hints), refresh=True)
                continue

            if k == "down":
                new_idx = (current_idx + 1) % len(parsed)
                if new_idx != current_idx:
                    current_idx = new_idx
                    live.update(_render_menu(current_idx, show_all_hints), refresh=True)
                continue

            if k == "?":
                show_all_hints = not show_all_hints
                live.update(_render_menu(current_idx, show_all_hints), refresh=True)
                continue

            if k == "enter":
                selected_idx = current_idx
                break

            if k == "esc":
                if allow_back:
                    selected_idx = None
                    break
                continue

            # EVERY other value, including "unknown", "left", "right", letters and backspace,
            # must hit continue and leave the loop running. Never exit, return or go back on an unrecognised key.
            continue

    if selected_idx is not None:
        chosen_label = parsed[selected_idx][0]
        console.print(
            f"  [bold {COLOR_GREEN}]{sym_check}[/bold {COLOR_GREEN}]  [bold]{title}[/bold]   [dim]{chosen_label}[/dim]"
        )
        return selected_idx

    return None


# ==============================================================================
# Premium Rich Terminal UI Implementation (stderr)
# ==============================================================================


class RichIO:
    """Interactive Rich console IO implementation routing wizard chrome to stderr."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(stderr=True)
        self.recorded_inputs: list[Any] = []
        self.completed_answers: list[tuple[State, str, str]] = []
        self.clear_count: int = 0
        self.current_state: State | None = None

    def clear(self) -> None:
        """Wipes the visible screen using rich console.clear() if terminal."""
        if getattr(self.console, "is_terminal", False):
            self.clear_count += 1
            self.console.clear()

    def begin_screen(self, state: Any) -> None:
        """Sets the active screen/state."""
        self.current_state = state

    def render_summary(self, question: str, answer_label: str) -> None:
        """Renders a compact completed answer summary line (Clack-style)."""
        sym = _get_symbols(self.console)
        self.console.print(
            f"  [bold {COLOR_GREEN}]{sym['check']}[/bold {COLOR_GREEN}]  [bold]{question}[/bold]   [dim]{answer_label}[/dim]"
        )

    def show_header(self, title: str, step: str) -> None:
        """Renders slim breadcrumb header bar."""
        sym = _get_symbols(self.console)
        prompt_sym = sym["prompt"]

        header_text = Text()
        header_text.append("  netpolicy", style=f"dim {COLOR_DIM}")
        header_text.append(f"  {prompt_sym}  ", style=f"dim {COLOR_DIM}")

        # Render standard breadcrumbs if step matches, or single breadcrumb
        matched_any = False
        step_lower = step.lower()
        for idx, s in enumerate(BREADCRUMB_STEPS):
            if s.lower() == step_lower or (step_lower in s.lower()):
                header_text.append(s, style=f"bold {COLOR_CYAN}")
                matched_any = True
            else:
                header_text.append(s, style=f"dim {COLOR_DIM}")
            if idx < len(BREADCRUMB_STEPS) - 1:
                header_text.append(f"  {prompt_sym}  ", style=f"dim {COLOR_DIM}")

        if not matched_any:
            # Step is not in standard breadcrumbs (e.g. Check or Export)
            header_text = Text()
            header_text.append("  netpolicy", style=f"dim {COLOR_DIM}")
            header_text.append(f"  {prompt_sym}  ", style=f"dim {COLOR_DIM}")
            header_text.append(step, style=f"bold {COLOR_CYAN}")

        self.console.print()
        self.console.print(header_text)
        self.console.print()

    def show(self, renderable: RenderableType) -> None:
        """Prints a renderable to stderr."""
        self.console.print(renderable)

    def _ask_choice_simple(
        self,
        question: str,
        options: list[Option],
        help_text: str = "",
        allow_back: bool = True,
        default: str | None = None,
    ) -> str:
        """Accessible numbered prompt fallback when live raw keys are unavailable."""
        flush_stdin()
        sym = _get_symbols(self.console)
        self.console.print(
            f"  [bold {COLOR_MAGENTA}]{sym['diamond']}[/bold {COLOR_MAGENTA}]  [bold]{question}[/bold]"
        )
        valid_keys: list[str] = []

        for opt in options:
            bracket_str = f" [dim][{opt.bracket}][/dim]" if opt.bracket else ""
            if opt.enabled:
                valid_keys.append(opt.key)
                self.console.print(f"    [{opt.key}] {opt.label}{bracket_str}")
            else:
                self.console.print(
                    f"    [{opt.key}] [dim]{opt.label} ({opt.reason_disabled}){bracket_str}[/dim]"
                )

        choices = list(valid_keys)
        if allow_back:
            choices.append("b")
        choices.extend(["q", "?"])

        while True:
            ans = Prompt.ask(
                "  Choose",
                choices=choices,
                default=default or (valid_keys[0] if valid_keys else "q"),
                console=self.console,
                show_choices=False,
            ).strip()

            if ans == "?":
                if help_text:
                    self.console.print(f"    [dim]{help_text}[/dim]")
                continue

            chosen_label = next((o.label for o in options if o.key == ans), ans)
            self.console.print(
                f"  [bold {COLOR_GREEN}]{sym['check']}[/bold {COLOR_GREEN}]  [bold]{question}[/bold]   [dim]{chosen_label}[/dim]"
            )
            self.recorded_inputs.append(ans)
            if self.current_state and ans not in ("b", "q"):
                self.completed_answers.append((self.current_state, question, chosen_label))
            return ans

    def ask_choice(
        self,
        question: str,
        options: list[Option],
        help_text: str = "",
        allow_back: bool = True,
        default: str | None = None,
    ) -> str:
        """Renders a live, in-place clack-style menu with arrow navigation."""
        flush_stdin()

        # Check for simple UI fallback
        if (
            os.environ.get("NETPOLICY_SIMPLE_UI") == "1"
            or not hasattr(sys.stdin, "isatty")
            or not sys.stdin.isatty()
        ):
            return self._ask_choice_simple(question, options, help_text, allow_back, default)

        opts_data = [
            (opt.label, opt.bracket if opt.enabled else (opt.reason_disabled or "disabled"))
            for opt in options
        ]

        def_idx = 0
        if default:
            for idx, opt in enumerate(options):
                if opt.key == default:
                    def_idx = idx
                    break

        try:
            res = ask_choice(
                question,
                opts_data,
                default=def_idx,
                allow_back=allow_back,
                out=self.console,
            )
        except KeyboardInterrupt:
            raise WizardInterruptError() from None
        except Exception:
            return self._ask_choice_simple(question, options, help_text, allow_back, default)

        if res is None:
            chosen_key = "b"
        else:
            chosen_key = options[res].key
            chosen_label = options[res].label
            if self.current_state and chosen_key not in ("b", "q"):
                self.completed_answers.append((self.current_state, question, chosen_label))

        self.recorded_inputs.append(chosen_key)
        return chosen_key

    def ask_confirm(self, question: str, default: bool = True) -> bool:
        """Renders a one-line horizontal toggle or falls back to accessible prompt."""
        flush_stdin()
        sym = _get_symbols(self.console)

        if (
            os.environ.get("NETPOLICY_SIMPLE_UI") == "1"
            or not hasattr(sys.stdin, "isatty")
            or not sys.stdin.isatty()
        ):
            res = Confirm.ask(
                f"  [bold {COLOR_MAGENTA}]{sym['diamond']}[/bold {COLOR_MAGENTA}]  [bold]{question}[/bold]",
                default=default,
                console=self.console,
            )
            self.console.print(
                f"  [bold {COLOR_GREEN}]{sym['check']}[/bold {COLOR_GREEN}]  [bold]{question}[/bold]   [dim]{'Yes' if res else 'No'}[/dim]"
            )
            self.recorded_inputs.append(res)
            if self.current_state:
                self.completed_answers.append((self.current_state, question, "Yes" if res else "No"))
            return res

        val = default
        done = False

        def _render_toggle() -> Text:
            t = Text()
            t.append("  ")
            t.append(sym["diamond"], style=f"bold {COLOR_MAGENTA}")
            t.append(f"  {question}   ", style="bold")
            if val:
                t.append(f"{sym['chevron']} Yes", style=f"bold {COLOR_MAGENTA}")
                t.append("   No", style=f"dim {COLOR_DIM}")
            else:
                t.append("Yes   ", style=f"dim {COLOR_DIM}")
                t.append(f"{sym['chevron']} No", style=f"bold {COLOR_MAGENTA}")
            return t

        try:
            with Live(console=self.console, transient=True, auto_refresh=False) as live:
                while not done:
                    live.update(_render_toggle())
                    live.refresh()

                    try:
                        k = read_key()
                    except KeyboardInterrupt:
                        raise WizardInterruptError() from None
                    except KeyboardUnavailable:
                        res = Confirm.ask(
                            f"  [bold {COLOR_MAGENTA}]{sym['diamond']}[/bold {COLOR_MAGENTA}]  [bold]{question}[/bold]",
                            default=default,
                            console=self.console,
                        )
                        self.recorded_inputs.append(res)
                        if self.current_state:
                            self.completed_answers.append(
                                (self.current_state, question, "Yes" if res else "No")
                            )
                        return res

                    if k in ("unknown", "ignored"):
                        continue
                    if k in ("left", "right", "tab"):
                        val = not val
                    elif k in ("y", "Y"):
                        val = True
                        done = True
                    elif k in ("n", "N"):
                        val = False
                        done = True
                    elif k == "enter":
                        done = True
                    elif k in ("esc", "q"):
                        val = False
                        done = True
                    elif k == "ctrl-c":
                        raise WizardInterruptError()
        except WizardInterruptError:
            raise
        except Exception:
            val = default
        finally:
            flush_stdin()

        self.console.print(
            f"  [bold {COLOR_GREEN}]{sym['check']}[/bold {COLOR_GREEN}]  [bold]{question}[/bold]   [dim]{'Yes' if val else 'No'}[/dim]"
        )
        self.recorded_inputs.append(val)
        if self.current_state:
            self.completed_answers.append((self.current_state, question, "Yes" if val else "No"))
        return val

    def ask_text(
        self,
        question: str,
        default: str = "",
        validator: Callable[[str], tuple[bool, str]] | None = None,
        help_text: str = "",
    ) -> str:
        """Prompts for text input with inline error feedback and collapsed trail."""
        flush_stdin()
        sym = _get_symbols(self.console)
        self.console.print(
            f"  [bold {COLOR_MAGENTA}]{sym['diamond']}[/bold {COLOR_MAGENTA}]  [bold]{question}[/bold]"
        )
        if help_text:
            self.console.print(f"  [dim {COLOR_DIM}]{help_text}[/dim {COLOR_DIM}]")

        while True:
            try:
                raw_input = self.console.input(
                    f"  [bold {COLOR_MAGENTA}]{sym['prompt']}[/bold {COLOR_MAGENTA}] "
                )
            except KeyboardInterrupt:
                raise WizardInterruptError() from None

            ans = raw_input.strip() or default

            if ans == "?":
                if help_text:
                    self.console.print(f"  [dim {COLOR_DIM}]{help_text}[/dim {COLOR_DIM}]")
                continue

            if ans in ("b", "back"):
                self.recorded_inputs.append("b")
                return "b"
            if ans in ("q", "quit"):
                self.recorded_inputs.append("q")
                return "q"

            if validator:
                ok, err = validator(ans)
                if not ok:
                    self.console.print(
                        f"  [bold {COLOR_RED}]{sym['cross']}[/bold {COLOR_RED}]  [#ff6b6b]{err}[/#ff6b6b]"
                    )
                    continue

            self.console.print(
                f"  [bold {COLOR_GREEN}]{sym['check']}[/bold {COLOR_GREEN}]  [bold]{question}[/bold]   [dim]{ans}[/dim]"
            )
            self.recorded_inputs.append(ans)
            if self.current_state and ans not in ("b", "q", "back", "quit"):
                self.completed_answers.append((self.current_state, question, ans))
            return ans


UI = RichIO


# ==============================================================================
# Scripted IO Implementation (Automated Tests & Replay)
# ==============================================================================


class ScriptedIO:
    """Deterministic, non-interactive IO consuming canned answers."""

    def __init__(self, inputs: list[Any]) -> None:
        self.inputs = list(inputs)
        self.recorded_inputs: list[Any] = []
        self.completed_answers: list[tuple[State, str, str]] = []
        self.clear_count: int = 0
        self.current_state: State | None = None
        self.log: list[str] = []

    def clear(self) -> None:
        """Records a clear screen event."""
        self.clear_count += 1
        self.log.append("CLEAR")

    def begin_screen(self, state: Any) -> None:
        """Sets the active screen/state."""
        self.current_state = state
        self.log.append(f"BEGIN_SCREEN: {getattr(state, 'name', str(state))}")

    def render_summary(self, question: str, answer_label: str) -> None:
        """Records rendering a compact completed answer summary line."""
        self.log.append(f"SUMMARY: {question} -> {answer_label}")

    def show_header(self, title: str, step: str) -> None:
        self.log.append(f"HEADER: {title} ({step})")

    def show(self, renderable: RenderableType) -> None:
        self.log.append(f"SHOW: {renderable}")

    def ask_choice(
        self,
        question: str,
        options: list[Option],
        help_text: str = "",
        allow_back: bool = True,
        default: str | None = None,
    ) -> str:
        if not self.inputs:
            ans = default or "q"
            self.recorded_inputs.append(ans)
            if self.current_state and ans not in ("b", "q"):
                chosen_label = next((o.label for o in options if o.key == ans), ans)
                self.completed_answers.append((self.current_state, question, chosen_label))
            return ans
        val = str(self.inputs.pop(0))
        self.recorded_inputs.append(val)
        self.log.append(f"CHOICE: {question} -> {val}")
        if self.current_state and val not in ("b", "q"):
            chosen_label = next((o.label for o in options if o.key == val), val)
            self.completed_answers.append((self.current_state, question, chosen_label))
        return val

    def ask_text(
        self,
        question: str,
        default: str = "",
        validator: Callable[[str], tuple[bool, str]] | None = None,
        help_text: str = "",
    ) -> str:
        if not self.inputs:
            ans = default
            self.recorded_inputs.append(ans)
            if self.current_state and ans not in ("b", "q", "back", "quit"):
                self.completed_answers.append((self.current_state, question, ans))
            return ans
        val = str(self.inputs.pop(0))
        self.recorded_inputs.append(val)
        self.log.append(f"TEXT: {question} -> {val}")
        if self.current_state and val not in ("b", "q", "back", "quit"):
            self.completed_answers.append((self.current_state, question, val))
        return val

    def ask_confirm(self, question: str, default: bool = True) -> bool:
        if not self.inputs:
            ans = default
            self.recorded_inputs.append(ans)
            if self.current_state:
                self.completed_answers.append((self.current_state, question, "Yes" if ans else "No"))
            return ans
        raw = self.inputs.pop(0)
        val = bool(raw) if not isinstance(raw, str) else raw.lower() in ("y", "yes", "true", "1")
        self.recorded_inputs.append(val)
        self.log.append(f"CONFIRM: {question} -> {val}")
        if self.current_state:
            self.completed_answers.append((self.current_state, question, "Yes" if val else "No"))
        return val


# ==============================================================================
# State Handler Functions (Stage 3 Redesign)
# ==============================================================================


def handle_start(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Initial transition to Preflight."""
    return Event.NEXT, {}


def handle_preflight(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Inspects environment and renders 'Your computer' status panel with chips."""
    caps = detect_capabilities()
    io.show_header(STRINGS["preflight"]["title"], STRINGS["preflight"]["step"])

    # Determine status chips
    # OS chip
    os_family = getattr(caps, "os_family", "linux")
    if os_family == "wsl":
        os_label = STRINGS["preflight"]["chips"]["linux_wsl"]
    elif os_family == "windows":
        os_label = STRINGS["preflight"]["chips"]["windows"]
    else:
        os_label = STRINGS["preflight"]["chips"]["linux"]

    chip_os = f"✔ {os_label}"
    py_ver = (
        caps.versions.get("python", sys.version.split()[0])
        if hasattr(caps, "versions")
        else sys.version.split()[0]
    )
    chip_py = f"✔ Python {py_ver}"
    saved_count = len(caps.saved_runs) if hasattr(caps, "saved_runs") else 0
    chip_runs = f"✔ {saved_count} {STRINGS['preflight']['saved_checks']}"

    # Extras chips
    can_raw = getattr(caps, "can_raw", False)
    can_capture = getattr(caps, "can_capture", False)
    lab_capable = getattr(caps, "lab_capable", False)

    sym_adv = "✔" if can_raw else "○"
    sym_rec = "✔" if can_capture else "○"
    sym_lab = "✔" if lab_capable else "○"

    chip_adv = f"{sym_adv} {STRINGS['preflight']['chips']['advanced']}"
    chip_rec = f"{sym_rec} {STRINGS['preflight']['chips']['record']}"
    chip_lab = f"{sym_lab} {STRINGS['preflight']['chips']['practice']}"

    # Summary sentence
    if getattr(caps, "is_root", False) or can_raw:
        summary_sentence = "All features and advanced tests are unlocked on this computer."
    else:
        summary_sentence = (
            f"{STRINGS['preflight']['ready_summary']} {STRINGS['preflight']['admin_note']}"
        )

    # Render as a single padded rounded panel
    panel_content = Text()
    panel_content.append(f"{chip_os}    {chip_py}    {chip_runs}\n", style="bold cyan")
    panel_content.append(f"{chip_adv}    {chip_rec}    {chip_lab}\n\n", style="dim")
    panel_content.append(summary_sentence, style="bold")

    panel = Panel(
        panel_content,
        title=f"[bold {COLOR_PURPLE}]{STRINGS['preflight']['title']}[/bold {COLOR_PURPLE}]",
        box=box.ROUNDED,
        padding=(1, 2),
        border_style=COLOR_PURPLE,
    )
    io.show(panel)

    return Event.NEXT, {
        "lab_capable": lab_capable,
        "saved_runs": tuple(caps.saved_runs) if hasattr(caps, "saved_runs") else (),
    }


def handle_main_menu(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Presents high-level user goals in plain language."""
    io.show_header(STRINGS["main_menu"]["title"], STRINGS["main_menu"]["step"])

    raw_saved = getattr(ctx, "saved_runs", 0)
    saved_runs = (
        len(raw_saved) if isinstance(raw_saved, (list, tuple, set)) else int(raw_saved or 0)
    )
    lab_capable = getattr(ctx, "lab_capable", False)

    opts_data = STRINGS["main_menu"]["options"]
    brackets = STRINGS["main_menu"].get("brackets", [])

    def _bracket(idx: int) -> str:
        return brackets[idx] if idx < len(brackets) else ""

    options = [
        Option("1", opts_data[0][1], bracket=_bracket(0)),
        Option("2", opts_data[1][1], bracket=_bracket(1)),
        Option("3", opts_data[2][1], bracket=_bracket(2)),
        Option("4", opts_data[3][1], bracket=_bracket(3)),
        Option(
            "5",
            opts_data[4][1],
            enabled=(saved_runs >= 2),
            reason_disabled="needs at least 2 saved checks",
            bracket=_bracket(4),
        ),
        Option(
            "6",
            opts_data[5][1],
            enabled=(saved_runs >= 1),
            reason_disabled="needs at least 1 saved check",
            bracket=_bracket(5),
        ),
        Option(
            "7",
            opts_data[6][1],
            enabled=lab_capable,
            reason_disabled="needs practice network",
            bracket=_bracket(6),
        ),
        Option("8", opts_data[7][1], bracket=_bracket(7)),
        Option("9", opts_data[8][1], bracket=_bracket(8)),
    ]

    ans = io.ask_choice(
        STRINGS["main_menu"]["question"],
        options,
        help_text=STRINGS["main_menu"]["help"],
        allow_back=False,
    )

    if ans in ("q", "9"):
        return Event.QUIT, {}

    intent_map = {
        "1": (Event.INTENT_AUDIT, "audit"),
        "2": (Event.INTENT_PORTS, "ports"),
        "3": (Event.INTENT_DNS, "dns"),
        "4": (Event.INTENT_HTTP, "http"),
        "5": (Event.INTENT_COMPARE, "compare"),
        "6": (Event.INTENT_RECLASSIFY, "reclassify"),
        "7": (Event.INTENT_LAB, "lab"),
        "8": (Event.INTENT_HELP_ALL, "help_all"),
    }

    if ans in intent_map:
        ev, intent = intent_map[ans]
        return ev, {"intent": intent}

    return Event.QUIT, {}


def handle_ask_network_env(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Prompts for network testing environment with context-aware choices."""
    io.show_header(STRINGS["network_env"]["title"], STRINGS["network_env"]["step"])

    env_opts = STRINGS["network_env"]["options"]
    options = [
        Option(
            opt[0],
            opt[1],
            bracket=opt[2] if len(opt) > 2 else "",
        )
        for opt in env_opts
    ]

    ans = io.ask_choice(
        STRINGS["network_env"]["question"],
        options,
        help_text=STRINGS["network_env"]["help"],
        allow_back=True,
        default="1",
    )

    if ans == "b":
        return Event.BACK, {}
    if ans == "q":
        return Event.QUIT, {}

    network_kind_map = {
        "1": "home",
        "2": "public_wifi",
        "3": "corporate",
        "4": "mobile",
        "5": "server",
    }
    selected_kind = network_kind_map.get(ans, "unknown")
    return Event.NEXT, {"network_kind": selected_kind}

    return Event.QUIT, {}


def handle_help_all(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Displays plain-language descriptions of subcommands and concepts."""
    io.show_header("Command List", "Help")
    help_text = Text()
    help_text.append("netpolicy commands:\n\n", style="bold cyan")
    help_text.append("  audit       Check outbound services, address lookups, and web pages\n")
    help_text.append("  ports       Check specific outbound services for network blocks\n")
    help_text.append("  dns         Check address lookups for silent redirection\n")
    help_text.append("  http        Check web pages for login redirects or altered content\n")
    help_text.append("  compare     Compare two earlier check reports side-by-side\n")
    help_text.append("  reclassify  Re-run rules on saved observations\n")
    help_text.append("  lab         Manage the safe practice network\n")
    help_text.append("  wizard      Start this guided interactive helper\n")

    panel = Panel(
        help_text,
        title="[bold #7b61ff]Classic Commands[/bold #7b61ff]",
        box=box.ROUNDED,
        padding=(1, 2),
        border_style=COLOR_PURPLE,
    )
    io.show(panel)
    io.ask_choice(
        "Ready to return?", [Option("1", "Back to main menu")], default="1", allow_back=False
    )
    return Event.NEXT, {}


def handle_target(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Prompts for target destination with friendly guidance."""
    io.show_header(STRINGS["target"]["title"], STRINGS["target"]["step"])

    lab_cap = getattr(ctx, "lab_capable", False)
    options = [
        Option("1", STRINGS["target"]["options"][0][1]),
        Option(
            "2",
            STRINGS["target"]["options"][1][1],
            enabled=lab_cap,
            reason_disabled="practice network unavailable",
        ),
        Option("3", STRINGS["target"]["options"][2][1]),
    ]

    ans = io.ask_choice(
        STRINGS["target"]["question"],
        options,
        help_text=STRINGS["target"]["help"],
    )
    if ans == "b":
        return Event.BACK, {}
    if ans == "q":
        return Event.QUIT, {}

    if ans == "1":
        target = io.ask_text(
            STRINGS["target"]["address_question"],
            default="127.0.0.1",
            validator=validate_target,
        )
        if target in ("b", "q"):
            return (Event.BACK if target == "b" else Event.QUIT), {}
        return Event.NEXT, {"target": target, "target_kind": "own"}

    if ans == "2":
        return Event.NEXT, {"target": "10.200.2.2", "target_kind": "lab"}

    # Public target warning panel
    io.show(
        Panel(
            f"[{COLOR_YELLOW}]{STRINGS['target']['warning_public']}[/{COLOR_YELLOW}]",
            title="[bold yellow]Public Target Note[/bold yellow]",
            box=box.ROUNDED,
            padding=(1, 2),
            border_style=COLOR_YELLOW,
        )
    )
    confirmed = io.ask_confirm(STRINGS["target"]["warning_confirm"], default=False)
    if not confirmed:
        return Event.BACK, {}

    target = io.ask_text(
        STRINGS["target"]["address_question"],
        default="probe.example.com",
        validator=validate_target,
    )
    if target in ("b", "q"):
        return (Event.BACK if target == "b" else Event.QUIT), {}
    return Event.NEXT, {"target": target, "target_kind": "public"}


def handle_ports(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Configures service ports using plain-language groupings."""
    io.show_header(STRINGS["ports"]["title"], STRINGS["ports"]["step"])

    options = [Option(k, v) for k, v in STRINGS["ports"]["options"]]

    ans = io.ask_choice(
        STRINGS["ports"]["question"],
        options,
        help_text=STRINGS["ports"]["help"],
    )
    if ans == "b":
        return Event.BACK, {}
    if ans == "q":
        return Event.QUIT, {}

    preset_map = {
        "1": "25,465,587",
        "2": "22",
        "3": "21",
        "4": "80,443",
        "5": PORT_PRESETS["Everything common"],
    }

    if ans in preset_map:
        return Event.NEXT, {"ports": preset_map[ans]}

    # Custom ports prompt
    ports_str = io.ask_text(
        STRINGS["ports"]["custom_prompt"],
        default="80,443,8080",
        validator=lambda s: (validate_ports(s)[0], validate_ports(s)[1]),
    )
    if ports_str in ("b", "q"):
        return (Event.BACK if ports_str == "b" else Event.QUIT), {}

    _, _, plist = validate_ports(ports_str)
    return Event.NEXT, {"ports": ",".join(str(p) for p in plist)}


def handle_options(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Configures check thoroughness, testing method, and traffic recording."""
    io.show_header(STRINGS["options"]["title"], STRINGS["options"]["step"])

    # Thoroughness
    thorough_opts = [Option(k, v) for k, v in STRINGS["options"]["runs_options"]]
    ans_r = io.ask_choice(STRINGS["options"]["runs_question"], thorough_opts, default="2")
    if ans_r in ("b", "q"):
        return (Event.BACK if ans_r == "b" else Event.QUIT), {}
    runs_map = {"1": 1, "2": 5, "3": 10}
    runs = runs_map.get(ans_r, 5)

    # Mode
    caps = detect_capabilities()
    mode_opts = [
        Option("1", STRINGS["options"]["mode_options"][0][1]),
        Option("2", STRINGS["options"]["mode_options"][1][1]),
        Option(
            "3",
            STRINGS["options"]["mode_options"][2][1],
            enabled=caps.can_raw,
            reason_disabled="needs admin access in Linux",
        ),
    ]
    ans_m = io.ask_choice(STRINGS["options"]["mode_question"], mode_opts, default="1")
    if ans_m in ("b", "q"):
        return (Event.BACK if ans_m == "b" else Event.QUIT), {}
    mode_map = {"1": "auto", "2": "socket", "3": "raw"}
    mode = mode_map.get(ans_m, "auto")

    # Packet capture
    capture = io.ask_confirm(STRINGS["options"]["capture_question"], default=False)

    return Event.NEXT, {
        "runs": runs,
        "mode": mode,
        "timeout": 3.0,
        "capture": capture,
    }


def handle_authorize(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Safety authorization check before executing network traffic."""
    io.show_header(STRINGS["authorize"]["title"], STRINGS["authorize"]["step"])

    confirmed = io.ask_confirm(STRINGS["authorize"]["question"], default=True)
    if not confirmed:
        io.show(
            Panel(
                f"[dim]{STRINGS['authorize']['decline_note']}[/dim]",
                title="[dim]Safety Check Declined[/dim]",
                box=box.ROUNDED,
                padding=(1, 2),
                border_style=COLOR_DIM,
            )
        )
        return Event.DECLINE, {"authorized": False}

    utc_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return Event.CONFIRM, {
        "authorized": True,
        "consent_text": STRINGS["authorize"]["question"],
        "consent_utc": utc_now,
    }


def handle_pick_run_a(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Select baseline run file for comparison."""
    io.show_header("Compare Checks", "Step 1 of 2")
    runs = sorted(list(Path("reports").glob("*.json")) + list(Path("reports").glob("*.jsonl")))
    if not runs:
        runs = sorted(list(Path(".").glob("*.json")) + list(Path(".").glob("*.jsonl")))

    if len(runs) < 2:
        io.show(Panel("At least 2 saved check reports are needed for comparison.", title="Notice"))
        return Event.BACK, {}

    opts = [Option(str(idx + 1), r.name) for idx, r in enumerate(runs[:9])]
    ans = io.ask_choice("Select baseline check (Run A):", opts, default="1")
    if ans in ("b", "q"):
        return (Event.BACK if ans == "b" else Event.QUIT), {}

    chosen_run = runs[int(ans) - 1]
    return Event.NEXT, {"run_a": str(chosen_run)}


def handle_pick_run_b(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Select comparison run file."""
    io.show_header("Compare Checks", "Step 2 of 2")
    runs = sorted(list(Path("reports").glob("*.json")) + list(Path("reports").glob("*.jsonl")))
    if not runs:
        runs = sorted(list(Path(".").glob("*.json")) + list(Path(".").glob("*.jsonl")))

    opts = [Option(str(idx + 1), r.name) for idx, r in enumerate(runs[:9])]
    ans = io.ask_choice(
        "Select current check (Run B):", opts, default="2" if len(opts) > 1 else "1"
    )
    if ans in ("b", "q"):
        return (Event.BACK if ans == "b" else Event.QUIT), {}

    chosen_run = runs[int(ans) - 1]
    return Event.NEXT, {"run_b": str(chosen_run)}


def handle_pick_run(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Select run file to reclassify."""
    io.show_header("Review Saved Check", "Select")
    runs = sorted(list(Path("reports").glob("*.jsonl")) + list(Path("reports").glob("*.json")))
    if not runs:
        runs = sorted(list(Path(".").glob("*.jsonl")) + list(Path(".").glob("*.json")))

    if not runs:
        io.show(Panel("No saved check reports found.", title="Notice"))
        return Event.BACK, {}

    opts = [Option(str(idx + 1), r.name) for idx, r in enumerate(runs[:9])]
    ans = io.ask_choice("Select check to review:", opts, default="1")
    if ans in ("b", "q"):
        return (Event.BACK if ans == "b" else Event.QUIT), {}

    chosen_run = runs[int(ans) - 1]
    return Event.NEXT, {"run_id": str(chosen_run)}


def handle_lab_menu(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Safe practice network options."""
    io.show_header("Practice Network", "Lab")
    opts = [
        Option("1", "Check practice network status"),
        Option("2", "Test against practice server"),
        Option("3", "Reset practice network rules"),
    ]
    ans = io.ask_choice("What would you like to do in the practice network?", opts, default="1")
    if ans in ("b", "q"):
        return (Event.BACK if ans == "b" else Event.QUIT), {}

    action_map = {"1": "status", "2": "test", "3": "reset"}
    return Event.NEXT, {"lab_action": action_map.get(ans, "status")}


def handle_review(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Presents plan in a rounded panel with 'What will happen' and 'What this does' tags."""
    io.show_header(STRINGS["review"]["title"], STRINGS["review"]["step"])
    intent = ctx.intent or "audit"

    # Build plan
    plan: CommandPlan
    if intent == "audit":
        plan = build_audit_plan(
            target=ctx.target or "127.0.0.1",
            ports=ctx.ports,
            runs=ctx.runs or 5,
            timeout=ctx.timeout or 3.0,
            mode=ctx.mode or "auto",
            capture=getattr(ctx, "capture", False),
        )
    elif intent == "ports":
        plan = build_ports_plan(
            target=ctx.target or "127.0.0.1",
            ports=ctx.ports or "80,443",
            runs=ctx.runs or 5,
            timeout=ctx.timeout or 3.0,
            mode=ctx.mode or "auto",
            capture=getattr(ctx, "capture", False),
        )
    elif intent == "dns":
        plan = build_dns_plan(
            target=ctx.target or "127.0.0.1",
            runs=ctx.runs or 5,
            timeout=ctx.timeout or 3.0,
            capture=getattr(ctx, "capture", False),
        )
    elif intent == "http":
        plan = build_http_plan(
            target=ctx.target or "127.0.0.1",
            runs=ctx.runs or 5,
            timeout=ctx.timeout or 3.0,
            capture=getattr(ctx, "capture", False),
        )
    elif intent == "compare":
        plan = build_compare_plan(run_a=ctx.run_a or "run_a.json", run_b=ctx.run_b or "run_b.json")
    elif intent == "reclassify":
        plan = build_reclassify_plan(run_id=ctx.run_id or "run.jsonl")
    elif intent == "lab":
        plan = build_lab_plan(action=ctx.lab_action or "status")
    else:
        plan = build_audit_plan(target="127.0.0.1")

    # Render plan panel
    pcontent = Text()
    pcontent.append("What will happen:\n", style="bold")
    pcontent.append(f"  {STRINGS['review']['what_will_happen']}\n\n", style="white")

    # Tags
    tags: list[str] = [STRINGS["review"]["what_this_does"]["report"]]
    if plan.kind == "traffic":
        tags.insert(0, STRINGS["review"]["what_this_does"]["traffic"])
    if getattr(plan, "mode", "auto") == "raw":
        tags.append(STRINGS["review"]["what_this_does"]["admin"])
    if getattr(plan, "capture", False):
        tags.append(STRINGS["review"]["what_this_does"]["capture"])

    pcontent.append("What this does:\n", style="bold")
    pcontent.append("  ")
    for idx, t in enumerate(tags):
        if idx > 0:
            pcontent.append("   ")
        pcontent.append(f"• {t}", style="bold cyan")
    pcontent.append("\n\n")

    duration_str = getattr(
        plan,
        "estimated_duration",
        f"~{int(getattr(plan, 'upper_bound_seconds', 15))}s",
    )
    pcontent.append(
        f"How long:\n  {STRINGS['review']['duration_label']} {duration_str}\n\n", style="bold"
    )
    pcontent.append("Equivalent command:\n", style="bold")
    pcontent.append(f"  {plan.cli_equivalent}\n", style="dim")

    panel = Panel(
        pcontent,
        title=f"[bold {COLOR_PURPLE}]{STRINGS['review']['title']}[/bold {COLOR_PURPLE}]",
        box=box.ROUNDED,
        padding=(1, 2),
        border_style=COLOR_PURPLE,
    )
    io.show(panel)

    review_opts = [
        Option("1", STRINGS["review"]["ready_options"][0][1]),
        Option("2", STRINGS["review"]["ready_options"][1][1]),
    ]
    ans = io.ask_choice(STRINGS["review"]["ready_question"], review_opts, default="1")
    if ans == "b":
        return Event.BACK, {"plan": plan}
    if ans == "q":
        return Event.QUIT, {}
    if ans == "2":
        cmd_text = Text()
        cmd_text.append("\nCommand to run:\n", style="bold green")
        cmd_text.append(f"  {plan.cli_equivalent}\n")
        io.show(cmd_text)
        return Event.DECLINE, {"plan": plan}

    return Event.CONFIRM, {"plan": plan}


def handle_run_traffic(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Executes traffic measurement plan in-process with optional packet capture."""
    from netpolicy.wizard.capture import PacketCapture
    from netpolicy.wizard.recommend import load_report_for_run
    from netpolicy.wizard.runner import execute_plan_in_process

    io.show_header("Executing Check", "In Progress")
    plan = ctx.plan

    cap_obj = None
    capture_res = None
    run_id_hint = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if getattr(plan, "capture", False):
        cap_obj = PacketCapture(target=getattr(ctx, "target", None), run_id=run_id_hint)
        cap_obj.__enter__()

    try:
        run_res = execute_plan_in_process(plan)
    finally:
        if cap_obj is not None:
            cap_obj.__exit__(None, None, None)
            capture_res = cap_obj.result

    actual_run_id = run_res.run_id or run_id_hint
    loaded_report = load_report_for_run(actual_run_id) if actual_run_id else None

    if run_res.interrupted:
        return Event.INTERRUPT, {
            "result": run_res,
            "report": loaded_report,
            "capture_result": capture_res,
            "run_id": actual_run_id,
        }
    if run_res.exit_code == 2:
        return Event.FAILED, {
            "result": run_res,
            "report": loaded_report,
            "capture_result": capture_res,
            "run_id": actual_run_id,
        }

    return Event.DONE, {
        "result": run_res,
        "report": loaded_report,
        "capture_result": capture_res,
        "run_id": actual_run_id,
    }


def handle_run_offline(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Executes offline command (compare / reclassify) in-process."""
    from netpolicy.wizard.recommend import load_report_for_run
    from netpolicy.wizard.runner import execute_plan_in_process

    io.show_header("Processing Check", "In Progress")
    plan = ctx.plan
    run_res = execute_plan_in_process(plan)

    actual_run_id = run_res.run_id or (getattr(ctx, "run_id", None) or "offline_run")
    loaded_report = load_report_for_run(actual_run_id) if actual_run_id else None

    if run_res.interrupted:
        return Event.INTERRUPT, {
            "result": run_res,
            "report": loaded_report,
            "run_id": actual_run_id,
        }
    if run_res.exit_code == 2:
        return Event.FAILED, {
            "result": run_res,
            "report": loaded_report,
            "run_id": actual_run_id,
        }

    return Event.DONE, {
        "result": run_res,
        "report": loaded_report,
        "run_id": actual_run_id,
    }


def handle_run_lab(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Executes lab inspection in-process."""
    from netpolicy.wizard.runner import execute_plan_in_process

    io.show_header("Executing Practice Network Command", "In Progress")
    plan = ctx.plan
    run_res = execute_plan_in_process(plan)

    if run_res.interrupted:
        return Event.INTERRUPT, {"result": run_res}
    if run_res.exit_code == 2:
        return Event.FAILED, {"result": run_res}

    return Event.DONE, {"result": run_res}


def handle_results(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Shows run outcome and optionally inquires about connection environment."""
    io.show_header(STRINGS["results"]["title"], STRINGS["results"]["step"])
    res = ctx.result
    code = getattr(res, "exit_code", 0) if res else 0

    if code == 2 or (res and getattr(res, "error", None)):
        err = getattr(res, "error", None) or STRINGS["results"]["error"]
        io.show(
            Panel(
                f"[{COLOR_RED}]{escape(str(err))}[/{COLOR_RED}]",
                title=f"[bold {COLOR_RED}]{STRINGS['results']['error']}[/bold {COLOR_RED}]",
                box=box.ROUNDED,
                padding=(1, 2),
                border_style=COLOR_RED,
            )
        )
        verdict = None
    else:
        verdict = extract_verdict(getattr(ctx, "report", None))
        if verdict == "CLEAN":
            color, headline, msg = VERDICT_PANEL_CONFIG["CLEAN"]
        elif verdict in VERDICT_PANEL_CONFIG:
            color, headline, msg = VERDICT_PANEL_CONFIG[verdict]
        else:
            color, headline, msg = VERDICT_PANEL_CONFIG["INCONCLUSIVE"]

        io.show(
            Panel(
                f"[{color}]{msg}[/{color}]",
                title=f"[bold {color}]{headline}[/bold {color}]",
                box=box.ROUNDED,
                padding=(1, 2),
                border_style=color,
            )
        )

    # Sub-prompt: Ask where the user is connected if findings exist
    network_kind = getattr(ctx, "network_kind", "unknown")
    has_findings = verdict in ("RESTRICTED", "LIMITED", "ACTION_REQUIRED") or code == 1
    if has_findings and network_kind == "unknown":
        loc_opts = [
            Option("1", "Home Wi-Fi"),
            Option("2", "School or office"),
            Option("3", "Public Wi-Fi (café, hotel, airport)"),
            Option("4", "Mobile data"),
            Option("5", "Skip"),
        ]
        loc_ans = io.ask_choice(
            "Where are you connected right now?", loc_opts, default="1", allow_back=False
        )
        loc_map = {
            "1": "home",
            "2": "school_or_office",
            "3": "public_wifi",
            "4": "mobile_data",
            "5": "unknown",
        }
        network_kind = loc_map.get(loc_ans, "unknown")

    # Post-scan prompt: Keep session open after scan completion
    is_interactive = True
    if hasattr(io, "console"):
        is_interactive = bool(getattr(io.console, "is_terminal", False))
    elif hasattr(io, "is_terminal"):
        is_interactive = bool(io.is_terminal)

    if not is_interactive:
        return Event.QUIT, {"network_kind": network_kind}

    post_opts = [
        Option("1", "Run another check", bracket="return to main menu"),
        Option("2", "Exit", bracket="close netpolicy"),
    ]
    ans = io.ask_choice(
        "What next?",
        post_opts,
        default="1",
        allow_back=True,
    )
    if ans == "1":
        return Event.MENU, {"network_kind": network_kind}

    return Event.QUIT, {"network_kind": network_kind}


def handle_next_steps(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Renders tailored next step recommendations and practical solutions."""
    from netpolicy.wizard.recommend import get_recommendations, support_message

    io.show_header(STRINGS["next_steps"]["title"], STRINGS["next_steps"]["step"])

    report = getattr(ctx, "report", None)
    recs = get_recommendations(report, current_intent=ctx.intent or "audit", target=ctx.target)

    # Add option to write support message if findings exist
    opts = [Option(r.key, r.label) for r in recs]
    ans = io.ask_choice(STRINGS["next_steps"]["question"], opts, default="1", allow_back=False)

    chosen_rec = next((r for r in recs if r.key == ans), None)
    if not chosen_rec or chosen_rec.action == "quit" or ans == "q":
        return Event.QUIT, {}
    if chosen_rec.action == "export":
        return Event.EXPORT_REPORT, {}
    if chosen_rec.action == "rerun":
        return Event.RERUN, chosen_rec.details
    if chosen_rec.action == "deep_dive":
        return Event.DEEP_DIVE, chosen_rec.details
    if chosen_rec.action == "menu":
        return Event.MENU, {}
    if chosen_rec.action == "support":
        # Generate and display support message
        msg = support_message(
            issues=[],
            verdict=None,  # Handled safely by support_message
            run_meta={"run_id": ctx.run_id or "run", "network_label": "audit"},
            network_kind=getattr(ctx, "network_kind", "unknown"),
        )
        io.show(
            Panel(
                msg,
                title="[bold cyan]Message for your Provider or IT Team[/bold cyan]",
                box=box.ROUNDED,
                padding=(1, 2),
                border_style=COLOR_CYAN,
            )
        )
        return Event.MENU, {}

    return Event.MENU, {}


def handle_export(ctx: Any, io: IO) -> tuple[Event, dict[str, Any]]:
    """Generates and writes structured lab report."""
    from netpolicy.wizard.labreport import render_lab_report, write_lab_report

    io.show_header("Exporting Report", "Export")
    report_content = render_lab_report(
        report=getattr(ctx, "report", None),
        run_meta={
            "run_id": ctx.run_id or "run",
            "consent_text": ctx.consent_text,
            "consent_utc": ctx.consent_utc,
        },
        metrics=getattr(ctx, "result", None),
        plan=getattr(ctx, "plan", None),
        transcript=getattr(ctx, "transcript", ()),
        capture=getattr(ctx, "capture_result", None),
    )
    run_id_val = ctx.run_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = write_lab_report(report_content, run_id=run_id_val)

    io.show(
        Panel(
            f"[{COLOR_GREEN}]Lab report exported successfully:[/{COLOR_GREEN}]\n\n"
            f"  [bold]{out_path}[/bold] ({out_path.stat().st_size:,} bytes)\n",
            title="[bold green]Report Export Complete[/bold green]",
            box=box.ROUNDED,
            padding=(1, 2),
            border_style=COLOR_GREEN,
        )
    )
    return Event.DONE, {"report_path": str(out_path)}


@dataclass(frozen=True)
class TranscriptEntry:
    """A single record of wizard step, prompt, and user answer."""

    state: str
    event: str
    details: dict[str, Any] = field(default_factory=dict)


def run_wizard(
    initial_ctx: Any | None = None,
    io: IO | None = None,
    transcript_path: Path | str | None = None,
) -> tuple[int, Any]:
    """Top-level driver loop executing the wizard state machine."""
    from dataclasses import replace

    from netpolicy.wizard.fsm import WizardContext, next_state

    ctx = initial_ctx or WizardContext()
    io_handler = io or RichIO()
    state = State.START
    transcript: list[Any] = list(ctx.transcript)

    while state != State.EXIT:
        handler = HANDLERS.get(state)
        if not handler:
            break

        history = (*ctx.history, state)
        ctx = replace(ctx, history=history)

        if hasattr(io_handler, "begin_screen"):
            io_handler.begin_screen(state)

        try:
            event, updates = handler(ctx, io_handler)
        except WizardInterruptError:
            event = Event.INTERRUPT
            updates = {}

        transcript.append(TranscriptEntry(state=state.name, event=event.name, details=updates))
        updates["transcript"] = tuple(transcript)

        ctx = replace(ctx, **updates)
        state = next_state(state, event, ctx)

        if event == Event.BACK:
            # Backward transitions: strict redraw loop
            # 1. Prune history to states strictly below destination state
            dest_state = state
            if dest_state in ctx.history:
                idx = ctx.history.index(dest_state)
                pruned_history = ctx.history[:idx]
            else:
                pruned_history = ctx.history[:-1]

            # 2. Prune completed answers so far
            current_answers = getattr(
                io_handler, "completed_answers", list(getattr(ctx, "answers", ()))
            )
            pruned_answers = [ans for ans in current_answers if ans[0] in pruned_history]
            if hasattr(io_handler, "completed_answers"):
                io_handler.completed_answers = list(pruned_answers)

            ctx = replace(ctx, history=pruned_history, answers=tuple(pruned_answers))

            # 3. Call clear BEFORE rendering the destination state
            if hasattr(io_handler, "clear"):
                io_handler.clear()

            # 4. Re-render compact "completed answers so far" summary lines (Clack-style)
            if hasattr(io_handler, "render_summary"):
                for _st, q, a in pruned_answers:
                    io_handler.render_summary(q, a)
        elif event == Event.MENU and state == State.MAIN_MENU:
            # Reset per-run context fields while preserving session-level environment
            ctx = reset_context_for_new_run(ctx)
            if hasattr(io_handler, "completed_answers"):
                io_handler.completed_answers.clear()
            if hasattr(io_handler, "clear"):
                io_handler.clear()
        else:
            # Sync forward completed answers to context
            if hasattr(io_handler, "completed_answers"):
                ctx = replace(ctx, answers=tuple(io_handler.completed_answers))

    exit_code = 130 if ctx.result and getattr(ctx.result, "interrupted", False) else 0

    if transcript_path:
        t_path = Path(transcript_path)
        t_path.parent.mkdir(parents=True, exist_ok=True)
        inputs = getattr(io_handler, "recorded_inputs", [])
        if not inputs and isinstance(io_handler, ScriptedIO):
            inputs = getattr(io_handler, "log", [])
        t_data = {
            "exit_code": exit_code,
            "inputs": inputs,
            "steps": [
                {
                    "state": e.state,
                    "event": e.event,
                    "details": {
                        k: str(v)
                        for k, v in e.details.items()
                        if k not in ("transcript", "report", "result")
                    },
                }
                for e in transcript
            ],
        }
        t_path.write_text(json.dumps(t_data, indent=2), encoding="utf-8")

    return exit_code, ctx


def run_replay(path: Path | str) -> int:
    """Replay a previously recorded wizard session using ScriptedIO."""
    p = Path(path)
    if not p.is_file():
        console = Console(stderr=True)
        console.print(f"[bold red]Error:[/bold red] Replay file not found: {p}")
        return 2

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        console = Console(stderr=True)
        console.print(f"[bold red]Error reading replay file:[/bold red] {exc}")
        return 2

    inputs = data.get("inputs", [])
    io = ScriptedIO(inputs)
    code, _ = run_wizard(io=io)
    return code


# ==============================================================================
# Handler Mapping
# ==============================================================================

HANDLERS: dict[State, Callable[[Any, IO], tuple[Event, dict[str, Any]]]] = {
    State.START: handle_start,
    State.PREFLIGHT: handle_preflight,
    State.MAIN_MENU: handle_main_menu,
    State.HELP_ALL: handle_help_all,
    State.ASK_NETWORK_ENV: handle_ask_network_env,
    State.TARGET: handle_target,
    State.PORTS: handle_ports,
    State.OPTIONS: handle_options,
    State.AUTHORIZE: handle_authorize,
    State.PICK_RUN_A: handle_pick_run_a,
    State.PICK_RUN_B: handle_pick_run_b,
    State.PICK_RUN: handle_pick_run,
    State.LAB_MENU: handle_lab_menu,
    State.REVIEW: handle_review,
    State.RUN_TRAFFIC: handle_run_traffic,
    State.RUN_OFFLINE: handle_run_offline,
    State.RUN_LAB: handle_run_lab,
    State.RESULTS: handle_results,
    State.NEXT_STEPS: handle_next_steps,
    State.EXPORT: handle_export,
}


if __name__ == "__main__":
    menu1 = [
        ("Alpha Option 1", "Hint for Alpha 1"),
        ("Alpha Option 2", "Hint for Alpha 2"),
        ("Alpha Option 3", "Hint for Alpha 3"),
    ]
    res1 = ask_choice("First Menu (Alpha)", menu1)
    print(f"Result 1: {res1}")
    if res1 is not None:
        menu2 = [
            ("Bravo Option 1", "Hint for Bravo 1"),
            ("Bravo Option 2", "Hint for Bravo 2"),
            ("Bravo Option 3", "Hint for Bravo 3"),
        ]
        res2 = ask_choice("Second Menu (Bravo)", menu2)
        print(f"Result 2: {res2}")
        if res2 is not None:
            menu3 = [
                ("Charlie Option 1", "Hint for Charlie 1"),
                ("Charlie Option 2", "Hint for Charlie 2"),
                ("Charlie Option 3", "Hint for Charlie 3"),
            ]
            res3 = ask_choice("Third Menu (Charlie)", menu3)
            print(f"Result 3: {res3}")

