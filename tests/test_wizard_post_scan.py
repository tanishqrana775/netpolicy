"""Tests for WizardContext field typing, handler updates compatibility,
and post-scan interactive loop with clean reset and exit (Tasks 1 & 2).
"""

from __future__ import annotations

import dataclasses
from typing import Any
from unittest.mock import MagicMock, patch

from rich.console import Console

from netpolicy.models import AuditReport, VerdictKind
from netpolicy.wizard.capture import CaptureResult
from netpolicy.wizard.fsm import (
    Event,
    State,
    WizardContext,
    next_state,
    reset_context_for_new_run,
)
from netpolicy.wizard.runner import RunResult
from netpolicy.wizard.ui import (
    COLOR_DIM,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_YELLOW,
    HANDLERS,
    RichIO,
    ScriptedIO,
    extract_verdict,
    handle_results,
    handle_review,
    handle_run_traffic,
    run_wizard,
)

# ==============================================================================
# Task 1: WizardContext Typing and Handler Updates Compatibility
# ==============================================================================


def test_wizard_context_has_capture_result_and_typed_report() -> None:
    """Verify WizardContext contains capture_result and accepts typed report."""
    fields_dict = {f.name: f for f in dataclasses.fields(WizardContext)}
    assert "capture_result" in fields_dict
    assert "report" in fields_dict

    cap = CaptureResult(
        pcap_path="test.pcap",
        packet_count=10,
        byte_count=512,
        sha256="abc",
        bpf_filter="host 127.0.0.1",
        interface="lo",
    )
    ctx = WizardContext(capture_result=cap, report={"raw": 123})
    assert ctx.capture_result == cap
    assert ctx.report == {"raw": 123}


def test_replace_compat_across_all_handlers() -> None:
    """Verify all updates dictionaries returned by handlers match WizardContext fields."""
    valid_field_names = {f.name for f in dataclasses.fields(WizardContext)}
    ctx = WizardContext(
        intent="audit",
        target="127.0.0.1",
        ports="80,443",
        network_kind="home",
        saved_runs=("run1",),
        lab_capable=True,
    )

    class DummyPlan:
        kind = "traffic"
        target = "127.0.0.1"
        ports = "80,443"
        runs = 1
        timeout = 1.0
        retries = 1
        mode = "socket"
        capture = False
        cli_equivalent = "netpolicy audit"

    ctx_with_plan = dataclasses.replace(ctx, plan=DummyPlan())

    fake_run_result = RunResult(
        exit_code=0,
        error=None,
        run_id="20261119_test",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.5,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )

    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_run_result),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=None),
        patch("netpolicy.wizard.capabilities.detect_capabilities") as mock_caps,
    ):
        mock_c = MagicMock()
        mock_c.saved_runs = ["run1"]
        mock_c.can_raw = False
        mock_c.can_capture = False
        mock_c.lab_capable = True
        mock_c.is_root = False
        mock_c.os_family = "linux"
        mock_caps.return_value = mock_c

        plan_states = (State.RUN_TRAFFIC, State.RUN_OFFLINE, State.RUN_LAB, State.REVIEW)
        for state, handler in HANDLERS.items():
            # Provide canned inputs for any interactive prompts
            io = ScriptedIO(["1", "127.0.0.1", "y", "1", "1", "1", "2"])
            use_ctx = ctx_with_plan if state in plan_states else ctx

            ev, updates = handler(use_ctx, io)
            update_keys = set(updates.keys())
            diff = update_keys - valid_field_names
            assert update_keys <= valid_field_names, (
                f"Handler {handler.__name__} returned unknown keys: {diff}"
            )

            # Verify dataclasses.replace succeeds without TypeError
            updated_ctx = dataclasses.replace(use_ctx, **updates)
            assert updated_ctx is not None


def test_handle_run_traffic_returns_capture_result() -> None:
    """Verify handle_run_traffic updates capture_result and dataclasses.replace succeeds."""
    ctx = WizardContext()
    cap = CaptureResult(
        pcap_path="reports/test.pcap",
        packet_count=5,
        byte_count=200,
        sha256="deadbeef",
        bpf_filter="host 127.0.0.1",
        interface="lo",
    )
    fake_run_result = RunResult(
        exit_code=0,
        error=None,
        run_id="test_run",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.2,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )

    class MockCapObj:
        result = cap

        def __enter__(self) -> MockCapObj:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    class CapturingPlan:
        kind = "traffic"
        capture = True

    ctx = dataclasses.replace(ctx, plan=CapturingPlan())
    io = ScriptedIO([])

    with (
        patch("netpolicy.wizard.capture.PacketCapture", return_value=MockCapObj()),
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_run_result),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=None),
    ):
        ev, updates = handle_run_traffic(ctx, io)
        assert ev == Event.DONE
        assert "capture_result" in updates
        assert updates["capture_result"] == cap

        new_ctx = dataclasses.replace(ctx, **updates)
        assert new_ctx.capture_result == cap


# ==============================================================================
# Task 2: Reset Context Helper Unit Test
# ==============================================================================


def test_reset_context_for_new_run() -> None:
    """Verify reset_context_for_new_run preserves session fields and resets per-run fields."""
    cap = CaptureResult("pcap", 1, 10, "sha", "bpf", "eth0")
    old_ctx = WizardContext(
        intent="audit",
        network_kind="corporate",
        target="10.0.0.5",
        target_kind="public",
        ports="80,443,8080",
        runs=10,
        timeout=5.0,
        retries=3,
        mode="socket",
        capture=True,
        authorized=True,
        run_a="a",
        run_b="b",
        run_id="run_123",
        lab_action="reset",
        plan="some_plan",
        result=RunResult(1, "err", "id", "", "", 1.0, 0.5, 10),
        history=(State.START, State.MAIN_MENU, State.RESULTS),
        transcript=("t1", "t2"),
        answers=((State.MAIN_MENU, "Q", "A"),),
        saved_runs=("saved1", "saved2"),
        lab_capable=True,
        consent_text="I consent",
        consent_utc="2026-11-19T00:00:00Z",
        error="some error",
        report_path="report.md",
        report={"k": "v"},
        capture_result=cap,
    )

    fresh_ctx = reset_context_for_new_run(old_ctx)

    # Session-level fields MUST be preserved
    assert fresh_ctx.network_kind == "corporate"
    assert fresh_ctx.saved_runs == ("saved1", "saved2")
    assert fresh_ctx.lab_capable is True

    # Per-run fields MUST be reset to default
    assert fresh_ctx.intent is None
    assert fresh_ctx.target is None
    assert fresh_ctx.target_kind is None
    assert fresh_ctx.ports is None
    assert fresh_ctx.runs == 5
    assert fresh_ctx.timeout == 3.0
    assert fresh_ctx.retries == 2
    assert fresh_ctx.mode == "auto"
    assert fresh_ctx.capture is False
    assert fresh_ctx.authorized is False
    assert fresh_ctx.run_a is None
    assert fresh_ctx.run_b is None
    assert fresh_ctx.run_id is None
    assert fresh_ctx.lab_action is None
    assert fresh_ctx.plan is None
    assert fresh_ctx.result is None
    assert fresh_ctx.history == ()
    assert fresh_ctx.transcript == ()
    assert fresh_ctx.answers == ()
    assert fresh_ctx.consent_text is None
    assert fresh_ctx.consent_utc is None
    assert fresh_ctx.error is None
    assert fresh_ctx.report_path is None
    assert fresh_ctx.report is None
    assert fresh_ctx.capture_result is None


# ==============================================================================
# Task 2: Post-Scan Prompt and Loop Flow
# ==============================================================================


def test_transition_table_has_results_menu_transition() -> None:
    """Verify (State.RESULTS, Event.MENU) -> State.MAIN_MENU exists and others preserved."""
    ctx = WizardContext()
    dest = next_state(State.RESULTS, Event.MENU, ctx)
    assert dest == State.MAIN_MENU

    # Pre-existing transitions preserved
    assert next_state(State.RESULTS, Event.NEXT, ctx) == State.NEXT_STEPS
    assert next_state(State.RESULTS, Event.QUIT, ctx) == State.EXIT


def test_post_scan_prompt_run_another_check_loops_back() -> None:
    """Test 2: Drive run_wizard to RESULTS, select 'Run another check', verify reset and loop."""
    fake_run_result = RunResult(
        exit_code=0,
        error=None,
        run_id="test_run_1",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.2,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )

    # Input sequence:
    # Pass 1:
    # - MAIN_MENU: "1" (audit)
    # - ASK_NETWORK_ENV: "1" (home)
    # - TARGET: "1" (own), address: "127.0.0.1"
    # - OPTIONS: thoroughness "1", mode "2", capture False
    # - AUTHORIZE: True
    # - REVIEW: "1" (confirm)
    # -> RUN_TRAFFIC executes
    # -> RESULTS: "1" (Run another check) -> triggers Event.MENU -> State.MAIN_MENU
    # Pass 2:
    # - MAIN_MENU: "9" (Quit)
    inputs = [
        "1",           # MAIN_MENU -> audit
        "1",           # ASK_NETWORK_ENV -> home
        "1",           # TARGET -> own
        "127.0.0.1",   # TARGET address
        "1",           # OPTIONS runs
        "2",           # OPTIONS mode (socket)
        False,         # OPTIONS capture
        True,          # AUTHORIZE confirm
        "1",           # REVIEW start
        "1",           # RESULTS: What next? -> "1" (Run another check)
        "9",           # MAIN_MENU -> Quit
    ]

    io = ScriptedIO(inputs)

    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_run_result),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=None),
        patch("netpolicy.wizard.capabilities.detect_capabilities") as mock_caps,
    ):
        mock_c = MagicMock()
        mock_c.saved_runs = []
        mock_c.can_raw = False
        mock_c.can_capture = False
        mock_c.lab_capable = False
        mock_c.is_root = False
        mock_c.os_family = "linux"
        mock_caps.return_value = mock_c

        code, end_ctx = run_wizard(io=io)

        assert code == 0
        # Verify screen was cleared upon returning to MAIN_MENU
        assert io.clear_count >= 1
        assert "CLEAR" in io.log

        # Verify completed answers from pass 1 were cleared
        pass1_states = (
            State.ASK_NETWORK_ENV,
            State.TARGET,
            State.OPTIONS,
            State.AUTHORIZE,
            State.REVIEW,
        )
        assert not any(ans[0] in pass1_states for ans in io.completed_answers)


def test_post_scan_prompt_exit_options() -> None:
    """Test 3: Choosing 'Exit' ('2') or Esc ('b') at post-scan prompt closes cleanly with 0."""
    fake_run_result = RunResult(
        exit_code=1,  # Scan had findings, but session exits cleanly
        error=None,
        run_id="test_run_findings",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.2,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )

    wsl_mock = MagicMock()

    # Case A: User selects option "2" (Exit)
    inputs_exit = [
        "1", "1", "1", "127.0.0.1", "1", "2", False, True, "1",
        "2",  # RESULTS: What next? -> "2" (Exit)
    ]
    io_exit = ScriptedIO(inputs_exit)

    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_run_result),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=None),
        patch("netpolicy.ui.wsl.maybe_launch_wsl", wsl_mock),
    ):
        code, _ = run_wizard(io=io_exit)
        assert code == 0
        assert not wsl_mock.called

    # Case B: User presses Esc ("b") at post-scan prompt
    inputs_esc = [
        "1", "1", "1", "127.0.0.1", "1", "2", False, True, "1",
        "b",  # RESULTS: What next? -> Esc ("b")
    ]
    io_esc = ScriptedIO(inputs_esc)

    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_run_result),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=None),
        patch("netpolicy.ui.wsl.maybe_launch_wsl", wsl_mock),
    ):
        code, _ = run_wizard(io=io_esc)
        assert code == 0
        assert not wsl_mock.called


def test_non_interactive_skips_post_scan_prompt() -> None:
    """Test 4: Non-TTY / non-interactive console skips post-scan prompt and exits cleanly."""
    console = Console(record=True, force_terminal=False)
    assert not console.is_terminal

    io = RichIO(console=console)

    ctx = WizardContext(
        result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
        network_kind="home",
    )

    ev, updates = handle_results(ctx, io)
    # Must immediately return Event.QUIT without asking questions
    assert ev == Event.QUIT
    assert updates.get("network_kind") == "home"
    assert len(io.recorded_inputs) == 0


# ==============================================================================
# Bug 1 & Bug 2 Live Fix Tests
# ==============================================================================


def test_review_panel_no_raw_tags_and_contains_command() -> None:
    """Test 1: Review panel renders without raw markup tags and shows full command."""
    console = Console(record=True, force_terminal=False, width=100)
    io = RichIO(console=console)
    # Choice "1" selects ready option
    io.ask_choice = lambda *args, **kwargs: "1"  # type: ignore[method-assign]

    ctx = WizardContext(
        intent="audit",
        target="127.0.0.1",
        runs=5,
        timeout=3.0,
        retries=2,
        mode="auto",
    )

    ev, updates = handle_review(ctx, io)
    assert ev == Event.CONFIRM
    assert "plan" in updates

    out = console.export_text()
    assert "[bold cyan]" not in out
    assert "[/bold cyan]" not in out
    assert "[dim]" not in out
    assert "[/dim]" not in out

    # Expected bullets and CLI command
    assert "• saves a report" in out
    assert "• sends test traffic" in out
    cmd_expected = (
        "netpolicy audit --target 127.0.0.1 --runs 5 --timeout 3.0 --retries 2 --mode auto"
    )
    assert cmd_expected in out


def test_review_panel_ipv6_target_literal_brackets() -> None:
    """Test 2: Review for target [::1] renders literal [::1] without raising MarkupError."""
    console = Console(record=True, force_terminal=False, width=100)
    io = RichIO(console=console)
    io.ask_choice = lambda *args, **kwargs: "1"  # type: ignore[method-assign]

    ctx = WizardContext(
        intent="audit",
        target="[::1]",
        runs=5,
        timeout=3.0,
        retries=2,
        mode="auto",
    )

    ev, updates = handle_review(ctx, io)
    assert ev == Event.CONFIRM

    out = console.export_text()
    assert "[::1]" in out
    assert "[bold cyan]" not in out


def test_extract_verdict_helper() -> None:
    """Test extract_verdict handles Enum, dict, object, casing, and fallback."""
    assert extract_verdict(None) is None
    assert extract_verdict({}) is None
    assert extract_verdict({"verdict": "restricted"}) == "RESTRICTED"
    assert extract_verdict({"verdict": VerdictKind.CLEAN}) == "CLEAN"
    assert extract_verdict({"level": "limited"}) == "LIMITED"
    assert extract_verdict({"verdict": {"level": "action_required"}}) == "ACTION_REQUIRED"

    class MockReport:
        verdict = "RESTRICTED"

    assert extract_verdict(MockReport()) == "RESTRICTED"  # type: ignore[arg-type]


def test_handle_results_restricted_limited_inconclusive() -> None:
    """Test 3: RESTRICTED, LIMITED, INCONCLUSIVE (AuditReport and dict) are never green."""
    cases = [
        ("RESTRICTED", COLOR_RED),
        ("LIMITED", COLOR_YELLOW),
        ("INCONCLUSIVE", COLOR_DIM),
    ]

    for verdict_name, expected_color in cases:
        # Case A: dict report payload
        console_dict = Console(record=True, force_terminal=False, width=100)
        io_dict = RichIO(console=console_dict)

        ctx_dict = WizardContext(
            report={"verdict": verdict_name},
            result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
            network_kind="home",
        )
        with patch.object(io_dict, "show", wraps=io_dict.show) as mock_show_dict:
            handle_results(ctx_dict, io_dict)
            out_dict = console_dict.export_text()
            assert "Everything looks normal" not in out_dict
            assert mock_show_dict.call_count == 1
            panel_dict = mock_show_dict.call_args[0][0]
            assert panel_dict.border_style == expected_color

        # Case B: AuditReport instance with attribute verdict
        console_obj = Console(record=True, force_terminal=False, width=100)
        io_obj = RichIO(console=console_obj)

        class CustomReport(AuditReport):
            verdict: str = verdict_name

        report_obj = CustomReport()
        ctx_obj = WizardContext(
            report=report_obj,
            result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
            network_kind="home",
        )
        with patch.object(io_obj, "show", wraps=io_obj.show) as mock_show_obj:
            handle_results(ctx_obj, io_obj)
            out_obj = console_obj.export_text()
            assert "Everything looks normal" not in out_obj
            assert mock_show_obj.call_count == 1
            panel_obj = mock_show_obj.call_args[0][0]
            assert panel_obj.border_style == expected_color


def test_handle_results_clean_verdict_shows_green() -> None:
    """Test 4: CLEAN verdict (AuditReport and dict) renders green 'Everything looks normal'."""
    # Case A: dict report
    console_dict = Console(record=True, force_terminal=False, width=100)
    io_dict = RichIO(console=console_dict)

    ctx_dict = WizardContext(
        report={"verdict": "CLEAN"},
        result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
        network_kind="home",
    )
    with patch.object(io_dict, "show", wraps=io_dict.show) as mock_show_dict:
        handle_results(ctx_dict, io_dict)
        out_dict = console_dict.export_text()
        assert "Everything looks normal" in out_dict
        panel_dict = mock_show_dict.call_args[0][0]
        assert panel_dict.border_style == COLOR_GREEN

    # Case B: AuditReport instance
    console_obj = Console(record=True, force_terminal=False, width=100)
    io_obj = RichIO(console=console_obj)

    class CleanReport(AuditReport):
        verdict: str = "CLEAN"

    ctx_obj = WizardContext(
        report=CleanReport(),
        result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
        network_kind="home",
    )
    with patch.object(io_obj, "show", wraps=io_obj.show) as mock_show_obj:
        handle_results(ctx_obj, io_obj)
        out_obj = console_obj.export_text()
        assert "Everything looks normal" in out_obj
        panel_obj = mock_show_obj.call_args[0][0]
        assert panel_obj.border_style == COLOR_GREEN


def test_handle_results_missing_or_unknown_never_green() -> None:
    """Test 5: None report, missing verdict, unknown verdict string, and error run are not green."""
    bad_contexts = [
        # 1. report is None
        WizardContext(report=None, result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100)),
        # 2. verdict missing in dict
        WizardContext(report={}, result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100)),
        # 3. unknown verdict string
        WizardContext(
            report={"verdict": "UNKNOWN_CUSTOM_VERDICT"},
            result=RunResult(0, None, "id", "", "", 0.1, 0.05, 100),
        ),
        # 4. failed / errored run (code 2)
        WizardContext(
            report={"verdict": "CLEAN"},
            result=RunResult(2, "Connection timeout", "id", "", "", 0.1, 0.05, 100),
        ),
    ]

    for ctx in bad_contexts:
        console = Console(record=True, force_terminal=False, width=100)
        io = RichIO(console=console)

        with patch.object(io, "show", wraps=io.show) as mock_show:
            handle_results(ctx, io)
            out = console.export_text()
            assert "Everything looks normal" not in out
            panel = mock_show.call_args[0][0]
            assert panel.border_style != COLOR_GREEN


def test_end_to_end_smoke_wizard_restricted_and_clean() -> None:
    """Smoke: Drive run_wizard through all 7 states for RESTRICTED and CLEAN audits."""
    fake_restricted_run = RunResult(
        exit_code=1,
        error=None,
        run_id="run_restricted",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.2,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )
    fake_restricted_report = {"verdict": "RESTRICTED"}

    # Pass 1: Runs audit with RESTRICTED result, selects "1" (Run another check)
    # Pass 2: Quits from main menu
    inputs_loop = [
        "1",           # Goal: audit
        "1",           # Environment: Home
        "1",           # Target: this computer
        "127.0.0.1",   # Address
        "1",           # Options runs
        "2",           # Options socket mode
        False,         # Options capture
        True,          # Permission confirm
        "1",           # Review start
        "1",           # Results: Run another check
        "9",           # Main Menu: Quit
    ]
    io_loop = ScriptedIO(inputs_loop)

    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_restricted_run),
        patch(
            "netpolicy.wizard.recommend.load_report_for_run", return_value=fake_restricted_report
        ),
        patch("netpolicy.wizard.capabilities.detect_capabilities") as mock_caps,
    ):
        mock_c = MagicMock()
        mock_c.saved_runs = []
        mock_c.can_raw = False
        mock_c.can_capture = False
        mock_c.lab_capable = False
        mock_c.is_root = False
        mock_c.os_family = "linux"
        mock_caps.return_value = mock_c

        code, end_ctx = run_wizard(io=io_loop)
        assert code == 0
        assert io_loop.clear_count >= 1

    # Now verify RESTRICTED with Exit ("2")
    inputs_exit = [
        "1", "1", "1", "127.0.0.1", "1", "2", False, True, "1",
        "2",  # Results: Exit
    ]
    io_exit = ScriptedIO(inputs_exit)
    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_restricted_run),
        patch(
            "netpolicy.wizard.recommend.load_report_for_run", return_value=fake_restricted_report
        ),
    ):
        code, end_ctx = run_wizard(io=io_exit)
        assert code == 0

    # Repeat with CLEAN report to confirm clean behavior
    fake_clean_run = RunResult(
        exit_code=0,
        error=None,
        run_id="run_clean",
        started_utc="2026-11-19T00:00:00Z",
        finished_utc="2026-11-19T00:00:01Z",
        wall_s=0.2,
        cpu_s=0.1,
        peak_rss_kb=1000,
    )
    fake_clean_report = {"verdict": "CLEAN"}
    inputs_clean = [
        "1", "1", "1", "127.0.0.1", "1", "2", False, True, "1",
        "2",  # Results: Exit
    ]
    io_clean = ScriptedIO(inputs_clean)
    with (
        patch("netpolicy.wizard.runner.execute_plan_in_process", return_value=fake_clean_run),
        patch("netpolicy.wizard.recommend.load_report_for_run", return_value=fake_clean_report),
    ):
        code, end_ctx = run_wizard(io=io_clean)
        assert code == 0

