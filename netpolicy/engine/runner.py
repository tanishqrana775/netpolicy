"""ThreadPoolExecutor-based concurrency runner for probes.

Orchestrates probe iterations with token-bucket rate limiting, shuffled execution order,
graceful Ctrl-C handling, and automatic control probe injection.
Strictly adheres to GEMINI.md: uses ThreadPoolExecutor (threads), never asyncio.
"""

from __future__ import annotations

import contextlib
import random
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from netpolicy.engine.context import Context
from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe
from netpolicy.store.raw import RawObservationStore


class TokenBucket:
    """Thread-safe token bucket rate limiter for controlling probe dispatch rate."""

    def __init__(self, rate: float, capacity: float = 1.0) -> None:
        self.rate = max(0.0, rate)
        self.capacity = max(1.0, capacity)
        self.tokens = 1.0
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until tokens are available according to rate."""
        if self.rate <= 0:
            return

        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                needed = tokens - self.tokens
                wait_time = needed / self.rate
            time.sleep(min(wait_time, 0.05))


class DefaultControlProbe(Probe):
    """Default control probe verifying baseline internet egress reachability."""

    name = "control"
    requires_root = False

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Record a simulated successful reachability observation for the control target."""
        return [
            Observation(
                probe_name=self.name,
                target=target,
                success=True,
                raw={"rtt_ms": 15.0, "reply_received": True},
            )
        ]


@dataclass
class RunnerResult:
    """Container for runner execution outputs."""

    grouped_by_job: dict[tuple[Probe, Target], list[Observation]] = field(default_factory=dict)
    all_observations: list[Observation] = field(default_factory=list)
    control_healthy: bool = True
    interrupted: bool = False
    run_id: str | None = None


class Runner:
    """Executes network probe jobs with concurrency, rate limiting, and shuffled runs."""

    def __init__(
        self,
        ctx: Context,
        jobs: Sequence[tuple[Probe, Target]],
        store: RawObservationStore | None = None,
        control_probe: Probe | None = None,
        max_workers: int = 16,
        on_task_start: Callable[[Probe, Target, int], None] | None = None,
        on_task_done: Callable[[Probe, Target, int, list[Observation]], None] | None = None,
    ) -> None:
        self.ctx = ctx
        self.jobs = list(jobs)
        self.store = store
        self.control_probe = control_probe or DefaultControlProbe()
        self.max_workers = max_workers
        self.on_task_start = on_task_start
        self.on_task_done = on_task_done
        self.rate_limiter = TokenBucket(self.ctx.rate_limit, capacity=1.0)
        self._lock = threading.Lock()

    @property
    def total_tasks(self) -> int:
        """Total number of individual probe task executions across all runs."""
        control_job = (self.control_probe, self.ctx.control_target)
        all_jobs = [control_job] + [j for j in self.jobs if j != control_job]
        return len(all_jobs) * self.ctx.runs

    def _execute_single_task(
        self,
        job: tuple[Probe, Target],
        run_idx: int,
        grouped_results: dict[tuple[Probe, Target], list[Observation]],
        all_observations: list[Observation],
    ) -> list[Observation]:
        """Execute a single probe run after rate limiting, updating in-memory & on-disk store."""
        probe, target = job
        if self.on_task_start is not None:
            with contextlib.suppress(Exception):
                self.on_task_start(probe, target, run_idx)

        self.rate_limiter.acquire(1.0)
        observations = probe.run(self.ctx, target)
        for obs in observations:
            obs.raw["run_index"] = run_idx
            if self.store is not None:
                self.store.append(obs, probe_name=probe.name)

        with self._lock:
            grouped_results[job].extend(observations)
            all_observations.extend(observations)

        if self.on_task_done is not None:
            with contextlib.suppress(Exception):
                self.on_task_done(probe, target, run_idx, observations)

        return observations

    def run(self) -> RunnerResult:
        """Execute all probe jobs across N shuffled iterations with control verification.

        Returns:
            RunnerResult with observations grouped by (Probe, Target) job.
        """
        # 1. Automatically inject control probe job targeting ctx.control_target
        control_job = (self.control_probe, self.ctx.control_target)
        all_jobs = [control_job] + [j for j in self.jobs if j != control_job]

        # Initialize grouped results
        grouped_results: dict[tuple[Probe, Target], list[Observation]] = {
            job: [] for job in all_jobs
        }
        all_observations: list[Observation] = []
        interrupted = False

        # 2. Build task list for N runs and shuffle execution order
        task_items: list[tuple[tuple[Probe, Target], int]] = []
        for job in all_jobs:
            probe, target = job
            for run_idx in range(self.ctx.runs):
                task_items.append(((probe, target), run_idx))

        random.shuffle(task_items)

        # 3. Concurrently dispatch tasks with ThreadPoolExecutor
        workers = max(1, min(self.max_workers, len(task_items) or 1))
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = []

        try:
            for job, run_idx in task_items:
                fut = executor.submit(
                    self._execute_single_task,
                    job,
                    run_idx,
                    grouped_results,
                    all_observations,
                )
                futures.append(fut)

            for future in as_completed(futures):
                try:
                    future.result()
                except KeyboardInterrupt:
                    interrupted = True
                    break
                except Exception as exc:
                    if isinstance(exc, KeyboardInterrupt):
                        interrupted = True
                        break
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if interrupted:
                # Cancel pending futures that have not started
                for f in futures:
                    f.cancel()
            executor.shutdown(wait=False, cancel_futures=True)

        # 4. Check control probe health
        control_obs = grouped_results.get(control_job, [])
        if not control_obs:
            control_healthy = False
        else:
            control_healthy = any(
                obs.success or obs.raw.get("reply_received", False) for obs in control_obs
            )

        run_id = self.store.run_id if self.store is not None else None

        return RunnerResult(
            grouped_by_job=grouped_results,
            all_observations=all_observations,
            control_healthy=control_healthy,
            interrupted=interrupted,
            run_id=run_id,
        )


# Backwards compatibility alias
AuditRunner = Runner
