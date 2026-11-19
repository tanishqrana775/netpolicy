"""Formal finite-state machine (FSM) for the Netpolicy interactive wizard.

Pure state transitions, guard evaluations, and diagram generation.
No terminal I/O, no side effects.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from netpolicy.models import AuditReport
    from netpolicy.wizard.capture import CaptureResult


class State(Enum):
    """Wizard Finite State Machine states."""

    START = auto()
    PREFLIGHT = auto()
    MAIN_MENU = auto()
    HELP_ALL = auto()
    ASK_NETWORK_ENV = auto()
    TARGET = auto()
    PORTS = auto()
    OPTIONS = auto()
    AUTHORIZE = auto()
    PICK_RUN_A = auto()
    PICK_RUN_B = auto()
    PICK_RUN = auto()
    LAB_MENU = auto()
    REVIEW = auto()
    RUN_TRAFFIC = auto()
    RUN_OFFLINE = auto()
    RUN_LAB = auto()
    RESULTS = auto()
    NEXT_STEPS = auto()
    EXPORT = auto()
    EXIT = auto()


class Event(Enum):
    """Wizard Finite State Machine transition events."""

    NEXT = auto()
    BACK = auto()
    QUIT = auto()
    HELP = auto()
    INTERRUPT = auto()
    CONFIRM = auto()
    DECLINE = auto()
    DONE = auto()
    FAILED = auto()
    INTENT_AUDIT = auto()
    INTENT_PORTS = auto()
    INTENT_DNS = auto()
    INTENT_HTTP = auto()
    INTENT_COMPARE = auto()
    INTENT_RECLASSIFY = auto()
    INTENT_LAB = auto()
    INTENT_HELP_ALL = auto()
    EXPORT_REPORT = auto()
    RERUN = auto()
    DEEP_DIVE = auto()
    MENU = auto()


class TransitionError(RuntimeError):
    """Raised when no valid rule matches a state transition."""


@dataclass(frozen=True)
class WizardContext:
    """Immutable context carried through the state machine."""

    intent: str | None = None
    network_kind: str = "unknown"
    target: str | None = None
    target_kind: str | None = None  # "own", "lab", "public"
    ports: str | None = None
    runs: int = 5
    timeout: float = 3.0
    retries: int = 2
    mode: str = "auto"
    capture: bool = False
    authorized: bool = False
    run_a: str | None = None
    run_b: str | None = None
    run_id: str | None = None
    lab_action: str | None = None
    plan: Any = None
    result: Any = None
    history: tuple[State, ...] = ()
    transcript: tuple[Any, ...] = ()
    answers: tuple[tuple[State, str, str], ...] = ()
    # Auxiliary capabilities and metadata
    saved_runs: tuple[str, ...] = ()
    lab_capable: bool = False
    consent_text: str | None = None
    consent_utc: str | None = None
    error: str | None = None
    report_path: str | None = None
    report: AuditReport | dict[str, Any] | None = None
    capture_result: CaptureResult | None = None


def reset_context_for_new_run(ctx: WizardContext) -> WizardContext:
    """Resets per-run state while preserving session-level environment and capabilities."""
    return WizardContext(
        network_kind=ctx.network_kind,
        saved_runs=ctx.saved_runs,
        lab_capable=ctx.lab_capable,
    )


@dataclass(frozen=True)
class Rule:
    """A guarded transition rule targeting a destination state."""

    target: State
    guard: Callable[[WizardContext], bool] | None = None
    label: str = ""

    def is_valid(self, ctx: WizardContext) -> bool:
        """Check if guard condition is satisfied."""
        if self.guard is None:
            return True
        try:
            return bool(self.guard(ctx))
        except Exception:
            return False


# ==============================================================================
# Pure Guards
# ==============================================================================


def _guard_compare_ready(ctx: WizardContext) -> bool:
    return len(ctx.saved_runs) >= 2


def _guard_reclassify_ready(ctx: WizardContext) -> bool:
    return len(ctx.saved_runs) >= 1


def _guard_lab_ready(ctx: WizardContext) -> bool:
    return bool(ctx.lab_capable)


def _guard_intent_ports(ctx: WizardContext) -> bool:
    return ctx.intent == "ports"


def _guard_intent_not_ports(ctx: WizardContext) -> bool:
    return ctx.intent != "ports"


def _guard_plan_traffic_authorized(ctx: WizardContext) -> bool:
    kind = getattr(ctx.plan, "kind", None) if ctx.plan else None
    return kind == "traffic" and bool(ctx.authorized)


def _guard_plan_offline(ctx: WizardContext) -> bool:
    kind = getattr(ctx.plan, "kind", None) if ctx.plan else None
    return kind == "offline"


def _guard_plan_lab(ctx: WizardContext) -> bool:
    kind = getattr(ctx.plan, "kind", None) if ctx.plan else None
    return kind == "lab"


def _guard_history_back_compare(ctx: WizardContext) -> bool:
    return ctx.intent == "compare"


def _guard_history_back_reclassify(ctx: WizardContext) -> bool:
    return ctx.intent == "reclassify"


def _guard_history_back_lab(ctx: WizardContext) -> bool:
    return ctx.intent == "lab"


def _guard_history_back_traffic(ctx: WizardContext) -> bool:
    return ctx.intent in ("audit", "ports", "dns", "http")


# ==============================================================================
# Transition Table
# ==============================================================================


def _build_transition_table() -> dict[tuple[State, Event], list[Rule]]:
    """Build the explicit, deterministic transition table as data."""
    table: dict[tuple[State, Event], list[Rule]] = {}

    def add(
        state: State,
        event: Event,
        target: State,
        guard: Callable[[WizardContext], bool] | None = None,
        label: str = "",
    ) -> None:
        table.setdefault((state, event), []).append(Rule(target=target, guard=guard, label=label))

    # START & PREFLIGHT
    add(State.START, Event.NEXT, State.PREFLIGHT)
    add(State.PREFLIGHT, Event.NEXT, State.MAIN_MENU)

    # MAIN_MENU
    add(State.MAIN_MENU, Event.INTENT_AUDIT, State.ASK_NETWORK_ENV)
    add(State.MAIN_MENU, Event.INTENT_PORTS, State.ASK_NETWORK_ENV)
    add(State.MAIN_MENU, Event.INTENT_DNS, State.ASK_NETWORK_ENV)
    add(State.MAIN_MENU, Event.INTENT_HTTP, State.ASK_NETWORK_ENV)
    add(
        State.MAIN_MENU,
        Event.INTENT_COMPARE,
        State.PICK_RUN_A,
        guard=_guard_compare_ready,
        label="at least 2 saved runs",
    )
    add(
        State.MAIN_MENU,
        Event.INTENT_RECLASSIFY,
        State.PICK_RUN,
        guard=_guard_reclassify_ready,
        label="at least 1 saved run",
    )
    add(
        State.MAIN_MENU,
        Event.INTENT_LAB,
        State.LAB_MENU,
        guard=_guard_lab_ready,
        label="lab capable",
    )
    add(State.MAIN_MENU, Event.INTENT_HELP_ALL, State.HELP_ALL)
    add(State.MAIN_MENU, Event.QUIT, State.EXIT)

    # HELP_ALL
    add(State.HELP_ALL, Event.NEXT, State.MAIN_MENU)
    add(State.HELP_ALL, Event.BACK, State.MAIN_MENU)

    # ASK_NETWORK_ENV
    add(State.ASK_NETWORK_ENV, Event.NEXT, State.TARGET)
    add(State.ASK_NETWORK_ENV, Event.BACK, State.MAIN_MENU)
    add(State.ASK_NETWORK_ENV, Event.QUIT, State.EXIT)

    # TARGET
    add(State.TARGET, Event.NEXT, State.PORTS, guard=_guard_intent_ports, label="intent is ports")
    add(
        State.TARGET,
        Event.NEXT,
        State.OPTIONS,
        guard=_guard_intent_not_ports,
        label="intent not ports",
    )
    add(State.TARGET, Event.BACK, State.ASK_NETWORK_ENV)

    # PORTS
    add(State.PORTS, Event.NEXT, State.OPTIONS)
    add(State.PORTS, Event.BACK, State.TARGET)

    # OPTIONS
    add(State.OPTIONS, Event.NEXT, State.AUTHORIZE)
    add(State.OPTIONS, Event.BACK, State.PORTS, guard=_guard_intent_ports, label="intent is ports")
    add(
        State.OPTIONS,
        Event.BACK,
        State.TARGET,
        guard=_guard_intent_not_ports,
        label="intent not ports",
    )

    # AUTHORIZE
    add(State.AUTHORIZE, Event.CONFIRM, State.REVIEW)
    add(State.AUTHORIZE, Event.DECLINE, State.MAIN_MENU)
    add(State.AUTHORIZE, Event.BACK, State.OPTIONS)

    # PICK_RUN_A & PICK_RUN_B
    add(State.PICK_RUN_A, Event.NEXT, State.PICK_RUN_B)
    add(State.PICK_RUN_A, Event.BACK, State.MAIN_MENU)
    add(State.PICK_RUN_B, Event.NEXT, State.REVIEW)
    add(State.PICK_RUN_B, Event.BACK, State.PICK_RUN_A)

    # PICK_RUN (reclassify)
    add(State.PICK_RUN, Event.NEXT, State.REVIEW)
    add(State.PICK_RUN, Event.BACK, State.MAIN_MENU)

    # LAB_MENU
    add(State.LAB_MENU, Event.NEXT, State.REVIEW)
    add(State.LAB_MENU, Event.BACK, State.MAIN_MENU)

    # REVIEW
    add(
        State.REVIEW,
        Event.CONFIRM,
        State.RUN_TRAFFIC,
        guard=_guard_plan_traffic_authorized,
        label="plan.kind traffic & authorized",
    )
    add(
        State.REVIEW,
        Event.CONFIRM,
        State.RUN_OFFLINE,
        guard=_guard_plan_offline,
        label="plan.kind offline",
    )
    add(State.REVIEW, Event.CONFIRM, State.RUN_LAB, guard=_guard_plan_lab, label="plan.kind lab")
    add(State.REVIEW, Event.DECLINE, State.MAIN_MENU)
    add(
        State.REVIEW,
        Event.BACK,
        State.PICK_RUN_B,
        guard=_guard_history_back_compare,
        label="compare history",
    )
    add(
        State.REVIEW,
        Event.BACK,
        State.PICK_RUN,
        guard=_guard_history_back_reclassify,
        label="reclassify history",
    )
    add(
        State.REVIEW, Event.BACK, State.LAB_MENU, guard=_guard_history_back_lab, label="lab history"
    )
    add(
        State.REVIEW,
        Event.BACK,
        State.AUTHORIZE,
        guard=_guard_history_back_traffic,
        label="traffic history",
    )
    add(State.REVIEW, Event.BACK, State.MAIN_MENU)

    # RUN_TRAFFIC, RUN_OFFLINE, RUN_LAB
    for run_st in (State.RUN_TRAFFIC, State.RUN_OFFLINE, State.RUN_LAB):
        add(run_st, Event.DONE, State.RESULTS)
        add(run_st, Event.FAILED, State.RESULTS)
        add(run_st, Event.INTERRUPT, State.RESULTS)

    # RESULTS
    add(State.RESULTS, Event.NEXT, State.NEXT_STEPS)
    add(State.RESULTS, Event.MENU, State.MAIN_MENU)

    # NEXT_STEPS
    add(State.NEXT_STEPS, Event.EXPORT_REPORT, State.EXPORT)
    add(State.NEXT_STEPS, Event.RERUN, State.REVIEW)
    add(State.NEXT_STEPS, Event.DEEP_DIVE, State.TARGET)
    add(State.NEXT_STEPS, Event.MENU, State.MAIN_MENU)
    add(State.NEXT_STEPS, Event.QUIT, State.EXIT)

    # EXPORT
    add(State.EXPORT, Event.DONE, State.NEXT_STEPS)

    # GLOBAL RULES
    input_states = (
        State.START,
        State.PREFLIGHT,
        State.MAIN_MENU,
        State.HELP_ALL,
        State.ASK_NETWORK_ENV,
        State.TARGET,
        State.PORTS,
        State.OPTIONS,
        State.AUTHORIZE,
        State.PICK_RUN_A,
        State.PICK_RUN_B,
        State.PICK_RUN,
        State.LAB_MENU,
        State.REVIEW,
        State.RESULTS,
        State.NEXT_STEPS,
        State.EXPORT,
    )

    # HELP self-loop on all input states
    for st in input_states:
        if (st, Event.HELP) not in table:
            add(st, Event.HELP, st, label="contextual help")

    # QUIT and INTERRUPT lead to EXIT on all non-terminal states
    for st in State:
        if st == State.EXIT:
            continue
        # In RUN_* states, INTERRUPT goes to RESULTS (captured above). QUIT goes to EXIT.
        if (st, Event.QUIT) not in table:
            add(st, Event.QUIT, State.EXIT, label="quit")
        if (st, Event.INTERRUPT) not in table:
            add(st, Event.INTERRUPT, State.EXIT, label="interrupt")

    return table


TRANSITIONS: dict[tuple[State, Event], list[Rule]] = _build_transition_table()


def next_state(state: State, event: Event, ctx: WizardContext) -> State:
    """Pure transition function determining the next state from current state and event."""
    rules = TRANSITIONS.get((state, event))
    if not rules:
        raise TransitionError(
            f"No transition registered for state {state.name} on event {event.name}"
        )

    for rule in rules:
        if rule.is_valid(ctx):
            return rule.target

    raise TransitionError(
        f"All guards failed for transition from state {state.name} on event {event.name}"
    )


# ==============================================================================
# Diagram Generators (Single Source of Truth)
# ==============================================================================


def to_mermaid() -> str:
    """Generates a Mermaid state diagram directly from the transition table."""
    lines = ["stateDiagram-v2"]
    seen_transitions: set[tuple[str, str, str]] = set()

    for (st, ev), rules in TRANSITIONS.items():
        for rule in rules:
            src = st.name
            dst = rule.target.name
            label = ev.name
            if rule.label:
                label += f" [{rule.label}]"
            edge_key = (src, dst, label)
            if edge_key not in seen_transitions:
                seen_transitions.add(edge_key)
                lines.append(f"    {src} --> {dst} : {label}")

    return "\n".join(lines)


def to_dot() -> str:
    """Generates a Graphviz DOT state diagram directly from the transition table."""
    lines = [
        "digraph WizardFSM {",
        '    rankdir="TB";',
        (
            '    node [shape=box, style="rounded,filled", fontname="Calibri", '
            'fillcolor="#F8FAFC", color="#1B365D"];'
        ),
        '    edge [fontname="Calibri", fontsize=9, color="#2B547E"];',
    ]
    seen_edges: set[tuple[str, str, str]] = set()

    for (st, ev), rules in TRANSITIONS.items():
        for rule in rules:
            src = st.name
            dst = rule.target.name
            label = ev.name
            if rule.label:
                label += f"\\n[{rule.label}]"
            edge_key = (src, dst, label)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                lines.append(f'    {src} -> {dst} [label="{label}"];')

    lines.append("}")
    return "\n".join(lines)


# ==============================================================================
# Graph Analysis Helpers
# ==============================================================================


def get_forward_graph() -> dict[State, set[State]]:
    """Returns the forward progression graph excluding loopback and cancellation edges."""
    return get_flow_graph(flow="all")


def get_flow_graph(flow: str = "all") -> dict[State, set[State]]:
    """Returns the forward state graph for a specific flow ('traffic', 'lab', 'offline', or 'all').

    In a 'traffic' flow, only traffic-generating intents and transitions are included.
    In a 'lab' flow, only lab intents and lab execution transitions are included.
    In an 'offline' flow, only compare/reclassify intents and offline transitions are included.
    """
    loopback_events = {
        Event.BACK,
        Event.MENU,
        Event.RERUN,
        Event.QUIT,
        Event.INTERRUPT,
        Event.DECLINE,
        Event.HELP,
    }
    graph: dict[State, set[State]] = {s: set() for s in State}

    traffic_events = {Event.INTENT_AUDIT, Event.INTENT_PORTS, Event.INTENT_DNS, Event.INTENT_HTTP}
    offline_events = {Event.INTENT_COMPARE, Event.INTENT_RECLASSIFY}
    lab_events = {Event.INTENT_LAB}

    for (st, ev), rules in TRANSITIONS.items():
        if ev in loopback_events:
            continue

        # Filter by flow if specified
        if flow == "traffic":
            if st == State.MAIN_MENU and ev not in traffic_events and ev != Event.NEXT:
                continue
            if st == State.REVIEW:
                rules = [r for r in rules if r.target == State.RUN_TRAFFIC]
        elif flow == "lab":
            if st == State.MAIN_MENU and ev not in lab_events and ev != Event.NEXT:
                continue
            if st == State.REVIEW:
                rules = [r for r in rules if r.target == State.RUN_LAB]
        elif flow == "offline":
            if st == State.MAIN_MENU and ev not in offline_events and ev != Event.NEXT:
                continue
            if st == State.REVIEW:
                rules = [r for r in rules if r.target == State.RUN_OFFLINE]

        for rule in rules:
            graph[st].add(rule.target)

    return graph


def get_full_graph() -> dict[State, set[State]]:
    """Returns the full unconstrained directed graph of all possible state transitions."""
    graph: dict[State, set[State]] = {s: set() for s in State}

    for (st, _), rules in TRANSITIONS.items():
        for rule in rules:
            graph[st].add(rule.target)

    return graph
