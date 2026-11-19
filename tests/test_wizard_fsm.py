"""Unit tests and formal graph analysis verification for Wizard FSM (Stage 1)."""

from __future__ import annotations

import collections
import random

import pytest

from netpolicy.wizard.fsm import (
    TRANSITIONS,
    Event,
    State,
    TransitionError,
    WizardContext,
    get_flow_graph,
    get_full_graph,
    next_state,
    to_dot,
    to_mermaid,
)


class MockPlan:
    """Mock plan object providing a .kind attribute."""

    def __init__(self, kind: str) -> None:
        self.kind = kind


# ==============================================================================
# Invariant & Structure Tests
# ==============================================================================


def test_determinism() -> None:
    """Verify that given identical inputs, next_state returns identical target."""
    ctx = WizardContext(intent="ports", authorized=True, plan=MockPlan("traffic"))
    for _ in range(20):
        target1 = next_state(State.REVIEW, Event.CONFIRM, ctx)
        target2 = next_state(State.REVIEW, Event.CONFIRM, ctx)
        assert target1 == target2 == State.RUN_TRAFFIC


def test_every_non_terminal_handles_quit_and_interrupt() -> None:
    """Verify every state except EXIT transitions safely on QUIT and INTERRUPT without error."""
    ctx = WizardContext()
    for st in State:
        if st == State.EXIT:
            continue
        # QUIT should lead to EXIT
        dest_quit = next_state(st, Event.QUIT, ctx)
        assert dest_quit == State.EXIT

        # INTERRUPT leads to RESULTS in RUN_* states, and EXIT in all other states
        dest_int = next_state(st, Event.INTERRUPT, ctx)
        if st in (State.RUN_TRAFFIC, State.RUN_OFFLINE, State.RUN_LAB):
            assert dest_int == State.RESULTS
        else:
            assert dest_int == State.EXIT


def test_no_transition_targets_undefined_state() -> None:
    """Verify every transition target is a valid member of State enum."""
    for (st, ev), rules in TRANSITIONS.items():
        assert isinstance(st, State)
        assert isinstance(ev, Event)
        for rule in rules:
            assert isinstance(rule.target, State)


def test_every_state_is_reachable_from_start() -> None:
    """Verify that in the full graph, every state has a directed path from START."""
    graph = get_full_graph()
    visited: set[State] = set()
    queue = collections.deque([State.START])

    while queue:
        curr = queue.popleft()
        if curr in visited:
            continue
        visited.add(curr)
        for nxt in graph.get(curr, set()):
            if nxt not in visited:
                queue.append(nxt)

    unreachable = set(State) - visited
    assert not unreachable, f"States unreachable from START: {unreachable}"


def test_exit_is_reachable_from_every_state() -> None:
    """Verify that EXIT is reachable from every non-terminal state."""
    graph = get_full_graph()
    for st in State:
        visited: set[State] = set()
        queue = collections.deque([st])
        found_exit = False

        while queue:
            curr = queue.popleft()
            if curr == State.EXIT:
                found_exit = True
                break
            if curr in visited:
                continue
            visited.add(curr)
            for nxt in graph.get(curr, set()):
                if nxt not in visited:
                    queue.append(nxt)

        assert found_exit, f"EXIT is unreachable from state {st.name}"


# ==============================================================================
# Graph Safety & Reachability Invariants
# ==============================================================================


def _reachable_nodes(
    graph: dict[State, set[State]],
    start: State,
    *,
    excluded: set[State],
) -> set[State]:
    """Helper to compute reachable states from start in a graph without excluded nodes."""
    visited: set[State] = set()
    queue = collections.deque([start])

    while queue:
        curr = queue.popleft()
        if curr in excluded or curr in visited:
            continue
        visited.add(curr)
        for nxt in graph.get(curr, set()):
            if nxt not in excluded and nxt not in visited:
                queue.append(nxt)

    return visited


def test_safety_invariant_removing_authorize_blocks_run_traffic() -> None:
    """SAFETY INVARIANT 1: Removing AUTHORIZE makes RUN_TRAFFIC unreachable from START."""
    traffic_graph = get_flow_graph(flow="traffic")
    reachable_without_auth = _reachable_nodes(
        traffic_graph,
        State.START,
        excluded={State.AUTHORIZE},
    )
    assert State.RUN_TRAFFIC not in reachable_without_auth, (
        "Invariant violated: RUN_TRAFFIC is reachable without passing through AUTHORIZE"
    )

    unauthorized_ctx = WizardContext(plan=MockPlan("traffic"), authorized=False)
    with pytest.raises(TransitionError):
        next_state(State.REVIEW, Event.CONFIRM, unauthorized_ctx)


def test_safety_invariant_removing_review_blocks_all_run_states() -> None:
    """SAFETY INVARIANT 2: Removing REVIEW makes every RUN_* state unreachable."""
    full_graph = get_full_graph()
    reachable_without_review = _reachable_nodes(
        full_graph,
        State.START,
        excluded={State.REVIEW},
    )
    assert State.RUN_TRAFFIC not in reachable_without_review
    assert State.RUN_OFFLINE not in reachable_without_review
    assert State.RUN_LAB not in reachable_without_review


def test_safety_invariant_run_lab_only_via_lab_menu() -> None:
    """SAFETY INVARIANT 3: RUN_LAB is only reachable through LAB_MENU."""
    lab_graph = get_flow_graph(flow="lab")
    reachable_without_lab_menu = _reachable_nodes(
        lab_graph,
        State.START,
        excluded={State.LAB_MENU},
    )
    assert State.RUN_LAB not in reachable_without_lab_menu, (
        "Invariant violated: RUN_LAB is reachable without passing through LAB_MENU"
    )

    non_lab_ctx = WizardContext(plan=MockPlan("traffic"), authorized=True)
    target = next_state(State.REVIEW, Event.CONFIRM, non_lab_ctx)
    assert target != State.RUN_LAB


def test_to_mermaid_and_to_dot() -> None:
    """Verify Mermaid and Graphviz DOT generators produce valid diagrams."""
    mermaid = to_mermaid()
    assert mermaid.startswith("stateDiagram-v2")
    assert "START --> PREFLIGHT : NEXT" in mermaid
    assert "AUTHORIZE --> REVIEW : CONFIRM" in mermaid

    dot = to_dot()
    assert dot.startswith("digraph")
    assert dot.endswith("}")
    assert "START -> PREFLIGHT" in dot
    assert "AUTHORIZE -> REVIEW" in dot


def test_seeded_random_walk_10000_steps() -> None:
    """Verify a seeded random walk over scripted events never raises and terminates cleanly."""
    rng = random.Random(42)

    def make_random_context() -> WizardContext:
        intents = ["audit", "ports", "dns", "http", "compare", "reclassify", "lab"]
        intent = rng.choice(intents)
        if intent in ("audit", "ports", "dns", "http"):
            plan_kind = "traffic"
        elif intent in ("compare", "reclassify"):
            plan_kind = "offline"
        else:
            plan_kind = "lab"

        return WizardContext(
            intent=intent,
            target="127.0.0.1",
            saved_runs=("run1.jsonl", "run2.jsonl"),
            lab_capable=True,
            authorized=True,
            plan=MockPlan(plan_kind),
        )

    ctx = make_random_context()
    state = State.START
    total_steps = 0
    runs = 0

    while total_steps < 10000:
        runs += 1
        state = State.START
        session_steps = 0
        while state != State.EXIT and session_steps < 500:
            total_steps += 1
            session_steps += 1
            possible_events = [ev for (st, ev) in TRANSITIONS if st == state]
            if not possible_events:
                break
            event = rng.choice(possible_events)
            try:
                state = next_state(state, event, ctx)
            except TransitionError:
                ctx = make_random_context()

    assert total_steps >= 10000
    assert runs > 0
