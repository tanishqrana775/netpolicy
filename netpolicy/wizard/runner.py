"""In-process execution coordinator and resource metrics tracker (Stage 5)."""

from __future__ import annotations

import datetime
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from netpolicy.wizard.plan import CommandPlan


@dataclass(frozen=True)
class RunResult:
    """Outcome and execution telemetry of an in-process netpolicy command run."""

    exit_code: int
    error: str | None
    run_id: str | None
    started_utc: str
    finished_utc: str
    wall_s: float
    cpu_s: float
    peak_rss_kb: int | None
    interrupted: bool = False


def _get_peak_rss_kb() -> int | None:
    """Returns peak resident set size in kilobytes, or None on unsupported platforms."""
    try:
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return rss // 1024
        return rss
    except (ImportError, AttributeError):
        return None


def execute_plan_in_process(
    plan: CommandPlan,
    reports_dir: Path | str = "reports",
) -> RunResult:
    """Executes a CommandPlan in-process via Typer main without subprocessing."""
    import click
    import typer
    from typer.main import get_command

    from netpolicy.cli import app

    rep_dir = Path(reports_dir)
    snapshot_before: set[Path] = set()
    if rep_dir.is_dir():
        try:
            snapshot_before = set(rep_dir.glob("*.jsonl"))
        except Exception:
            snapshot_before = set()

    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    exit_code = 0
    error_msg: str | None = None
    interrupted = False

    cmd = get_command(app)

    try:
        # Run command in-process; stdout and stderr flow naturally to user terminal
        cmd.main(args=plan.argv, prog_name="netpolicy", standalone_mode=False)
    except typer.Exit as exc:
        exit_code = exc.exit_code
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except KeyboardInterrupt:
        exit_code = 130
        error_msg = "Interrupted by user (partial run)"
        interrupted = True
    except click.ClickException as exc:
        exit_code = exc.exit_code
        error_msg = str(exc)
    except Exception as exc:
        exit_code = 2
        error_msg = f"Runtime exception: {exc}"

    wall_s = max(0.001, time.perf_counter() - t0_wall)
    cpu_s = max(0.000, time.process_time() - t0_cpu)
    finished_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    peak_rss = _get_peak_rss_kb()

    # Detect new run ID
    detected_run_id: str | None = None
    if rep_dir.is_dir():
        try:
            snapshot_after = set(rep_dir.glob("*.jsonl"))
            new_files = snapshot_after - snapshot_before
            if new_files:
                newest = sorted(new_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]
                detected_run_id = newest.stem
        except Exception:
            pass

    # Fallback to existing run IDs from plan if reclassify / compare
    if not detected_run_id and plan.argv:
        if plan.argv[0] == "reclassify" and len(plan.argv) > 1:
            detected_run_id = Path(plan.argv[1]).stem
        elif plan.argv[0] == "compare" and len(plan.argv) > 2:
            detected_run_id = f"{Path(plan.argv[1]).stem}_vs_{Path(plan.argv[2]).stem}"

    return RunResult(
        exit_code=exit_code,
        error=error_msg,
        run_id=detected_run_id,
        started_utc=started_utc,
        finished_utc=finished_utc,
        wall_s=round(wall_s, 3),
        cpu_s=round(cpu_s, 3),
        peak_rss_kb=peak_rss,
        interrupted=interrupted,
    )
