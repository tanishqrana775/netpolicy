"""Tests for probe base class, engine context, concurrency runner, and raw storage."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from netpolicy.engine.context import Context
from netpolicy.engine.runner import Runner
from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe
from netpolicy.store.raw import RawObservationStore, chown_to_sudo_user, read_run


class DummyProbe(Probe):
    """Simulated probe for testing without real network traffic."""

    def __init__(
        self,
        name: str = "dummy",
        latency: float = 0.0,
        fail: bool = False,
        raise_keyboard_interrupt_on: int | None = None,
    ) -> None:
        self.name = name
        self.latency = latency
        self.fail = fail
        self.raise_keyboard_interrupt_on = raise_keyboard_interrupt_on
        self.call_count = 0
        self.execution_order: list[tuple[Target, int, float]] = []
        self._lock = threading.Lock()

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        with self._lock:
            self.call_count += 1
            current_call = self.call_count
            now = time.monotonic()
            self.execution_order.append((target, current_call, now))

        if (
            self.raise_keyboard_interrupt_on is not None
            and current_call == self.raise_keyboard_interrupt_on
        ):
            raise KeyboardInterrupt("Simulated Ctrl-C interrupt")

        if self.latency > 0:
            time.sleep(self.latency)

        return [
            Observation(
                probe_name=self.name,
                target=target,
                success=not self.fail,
                raw={"latency": self.latency, "call_index": current_call},
            )
        ]


def test_context_mode_resolution_and_fingerprint() -> None:
    """Verify Context resolves 'auto' mode and generates privacy-preserving fingerprints."""
    ctx_auto = Context(mode="auto")
    assert ctx_auto.mode in ("raw", "socket")

    ctx_explicit = Context(mode="socket")
    assert ctx_explicit.mode == "socket"

    # Deterministic network fingerprint
    fp1 = Context.compute_network_fingerprint("192.168.1.1", "1.1.1.1")
    fp2 = Context.compute_network_fingerprint("192.168.1.1", "1.1.1.1")
    fp3 = Context.compute_network_fingerprint("10.0.0.1", "8.8.8.8")

    assert len(fp1) == 64  # SHA256 length
    assert fp1 == fp2
    assert fp1 != fp3
    assert "192.168" not in fp1  # No raw IP leak


def test_runner_honours_rate_limit() -> None:
    """Verify Runner throttles task dispatch according to ctx.rate_limit."""
    # 5 probes at 10 probes/sec with capacity=1 -> ~0.4s minimum duration
    ctx = Context(rate_limit=10.0, runs=1)
    probe = DummyProbe(name="fast_dummy", latency=0.0)
    jobs = [(probe, Target(host="probe.test", port=p)) for p in range(1001, 1006)]

    # Runner automatically adds 1 control job -> 6 total jobs
    runner = Runner(ctx=ctx, jobs=jobs, max_workers=8)
    start = time.monotonic()
    result = runner.run()
    elapsed = time.monotonic() - start

    assert result.control_healthy is True
    assert elapsed >= 0.30  # Should be around 0.5s for 6 tokens


def test_runner_shuffles_order() -> None:
    """Verify Runner executes repeated runs across jobs in shuffled order."""
    ctx = Context(rate_limit=100.0, runs=10)
    probe = DummyProbe(name="shuffle_probe")
    targets = [Target(host="probe.test", port=p) for p in (21, 22, 25, 80)]
    jobs = [(probe, t) for t in targets]

    runner = Runner(ctx=ctx, jobs=jobs, max_workers=1)  # Single worker to check dispatch order
    runner.run()

    # Targets sequence should not be contiguous blocks of T1 x 10, T2 x 10, etc.
    executed_ports = [t.port for t, _, _ in probe.execution_order]
    # Check that at least some consecutive ports differ (interleaved)
    alternations = sum(
        1 for i in range(len(executed_ports) - 1) if executed_ports[i] != executed_ports[i + 1]
    )
    assert alternations > 5


def test_runner_persists_jsonl(tmp_path: Path) -> None:
    """Verify Runner writes append-only JSONL entries flushed after every line."""
    log_file = tmp_path / "observations.jsonl"
    store = RawObservationStore(log_file)

    ctx = Context(rate_limit=100.0, runs=2)
    probe = DummyProbe(name="logged_probe")
    jobs = [
        (probe, Target(host="probe.test", port=80)),
        (probe, Target(host="probe.test", port=443)),
    ]

    runner = Runner(ctx=ctx, jobs=jobs, store=store, max_workers=4)
    result = runner.run()

    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()

    # 2 jobs * 2 runs + 1 control job * 2 runs = 6 observations
    assert len(lines) == 6

    for line in lines:
        entry = json.loads(line)
        assert entry["run_id"] == store.run_id
        assert "timestamp" in entry
        assert "probe_name" in entry
        assert "observation" in entry
        assert entry["observation"]["target"]["host"] in ("probe.test", ctx.control_target.host)

    # Verify reading back from store and module-level read_run
    reloaded = store.read_run()
    assert len(reloaded) == len(result.all_observations)
    direct_read = read_run(log_file, run_id=store.run_id)
    assert len(direct_read) == len(result.all_observations)


def test_runner_handles_keyboard_interrupt(tmp_path: Path) -> None:
    """Verify graceful handling of Ctrl-C (KeyboardInterrupt) with partial results saved."""
    log_file = tmp_path / "partial.jsonl"
    store = RawObservationStore(log_file)

    ctx = Context(rate_limit=50.0, runs=5)
    # Probe will raise KeyboardInterrupt on the 4th run
    probe = DummyProbe(name="interrupt_probe", raise_keyboard_interrupt_on=4)
    jobs = [
        (probe, Target(host="probe.test", port=80)),
        (probe, Target(host="probe.test", port=443)),
    ]

    runner = Runner(ctx=ctx, jobs=jobs, store=store, max_workers=2)
    result = runner.run()

    assert result.interrupted is True
    # Verify partial results were preserved
    assert len(result.all_observations) > 0
    # Verify partial results were written to the store
    saved_records = store.read_run()
    assert len(saved_records) == len(result.all_observations)


def test_runner_flags_failing_control_probe() -> None:
    """Verify that a failing control probe is flagged in RunnerResult."""
    ctx = Context(rate_limit=100.0, runs=2)
    control_fail = DummyProbe(name="control", fail=True)
    probe = DummyProbe(name="normal_probe", fail=False)
    jobs = [(probe, Target(host="probe.test", port=80))]

    # Run with failing control probe
    runner_failing = Runner(ctx=ctx, jobs=jobs, control_probe=control_fail, max_workers=4)
    res_failing = runner_failing.run()
    assert res_failing.control_healthy is False

    # Run with succeeding control probe
    control_success = DummyProbe(name="control", fail=False)
    runner_success = Runner(ctx=ctx, jobs=jobs, control_probe=control_success, max_workers=4)
    res_success = runner_success.run()
    assert res_success.control_healthy is True


def test_chown_to_sudo_user_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify chown_to_sudo_user executes os.chown when SUDO_UID and SUDO_GID are set."""
    chown_log: list[tuple[Path, int, int]] = []

    def fake_chown(path: str | os.PathLike[str], uid: int, gid: int) -> None:
        chown_log.append((Path(path), uid, gid))

    monkeypatch.setattr(os, "chown", fake_chown, raising=False)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    target_file = tmp_path / "obs.jsonl"
    target_file.write_text("{}\n", encoding="utf-8")

    chown_to_sudo_user(target_file)
    assert len(chown_log) == 1
    assert chown_log[0] == (target_file, 1000, 1000)


def test_chown_to_sudo_user_noop_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify chown_to_sudo_user does nothing when SUDO_UID / SUDO_GID are not present."""
    chown_log: list[tuple[Path, int, int]] = []

    def fake_chown(path: str | os.PathLike[str], uid: int, gid: int) -> None:
        chown_log.append((Path(path), uid, gid))

    monkeypatch.setattr(os, "chown", fake_chown, raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    target_file = tmp_path / "obs.jsonl"
    target_file.write_text("{}\n", encoding="utf-8")

    chown_to_sudo_user(target_file)
    assert len(chown_log) == 0


def test_chown_to_sudo_user_handles_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify chown_to_sudo_user gracefully catches PermissionError or invalid integer strings."""

    def error_chown(path: str | os.PathLike[str], uid: int, gid: int) -> None:
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(os, "chown", error_chown, raising=False)
    monkeypatch.setenv("SUDO_UID", "invalid_uid")
    monkeypatch.setenv("SUDO_GID", "1000")

    target_file = tmp_path / "obs.jsonl"
    target_file.write_text("{}\n", encoding="utf-8")

    # Should not raise ValueError
    chown_to_sudo_user(target_file)

    monkeypatch.setenv("SUDO_UID", "1000")
    # Should not raise PermissionError
    chown_to_sudo_user(target_file)


def test_raw_store_chowns_file_and_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify RawObservationStore invokes chown on parent directory and JSONL file."""
    chown_log: list[tuple[Path, int, int]] = []

    def fake_chown(path: str | os.PathLike[str], uid: int, gid: int) -> None:
        chown_log.append((Path(path), uid, gid))

    monkeypatch.setattr(os, "chown", fake_chown, raising=False)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "502")

    nested_dir = tmp_path / "custom_reports"
    log_file = nested_dir / "audit.jsonl"

    store = RawObservationStore(log_file, run_id="r1")
    # Parent directory should have been chowned during store initialization
    assert any(p == nested_dir and uid == 501 and gid == 502 for p, uid, gid in chown_log)

    obs = Observation(
        probe_name="dummy",
        target=Target(host="probe.test", port=80),
        success=True,
    )
    store.append(obs)
    # The log file itself should have been chowned upon append
    assert any(p == log_file and uid == 501 and gid == 502 for p, uid, gid in chown_log)
