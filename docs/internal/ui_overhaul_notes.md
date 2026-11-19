# Netpolicy UI Overhaul Architecture & Design Notes (Stage 0)

## 1. Real IO Protocol Signatures (`netpolicy/wizard/ui.py`)

The `IO` protocol definition is non-negotiable and strictly preserved:

```python
class IO(Protocol):
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
```

`Option` dataclass:
```python
@dataclass(frozen=True)
class Option:
    key: str
    label: str
    enabled: bool = True
    reason_disabled: str = ""
```

Exceptions:
- `WizardInterruptError` (aliased to `WizardInterrupt`) raised on Ctrl+C.

Implementations:
- `RichIO`: Interactive console routing chrome strictly to `Console(stderr=True)`.
- `ScriptedIO`: Deterministic, canned-input queue consuming answers without interactive blocking, recording prompts/answers into `.log` and `.recorded_inputs`.

---

## 2. Finite-State Machine Handlers and Returned Events

The FSM transitions (`netpolicy/wizard/fsm.py`) and return types are frozen:
`Callable[[WizardContext, IO], tuple[Event, dict[str, Any]]]`

| State | Handler | Events Emitted | Description / Context Updates |
|---|---|---|---|
| `START` | `handle_start` | `NEXT` | Moves to `PREFLIGHT` |
| `PREFLIGHT` | `handle_preflight` | `NEXT`, `QUIT`, `INTERRUPT` | Inspects system, updates `lab_capable`, `saved_runs` |
| `MAIN_MENU` | `handle_main_menu` | `INTENT_AUDIT`, `INTENT_PORTS`, `INTENT_DNS`, `INTENT_HTTP`, `INTENT_COMPARE`, `INTENT_RECLASSIFY`, `INTENT_LAB`, `INTENT_HELP_ALL`, `QUIT`, `INTERRUPT` | Updates `intent` |
| `HELP_ALL` | `handle_help_all` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Shows conceptual help and returns to `MAIN_MENU` |
| `TARGET` | `handle_target` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `target`, `target_kind` (`own`, `lab`, `public`) |
| `PORTS` | `handle_ports` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `ports` string |
| `OPTIONS` | `handle_options` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `runs`, `timeout`, `mode`, `capture` |
| `AUTHORIZE` | `handle_authorize` | `CONFIRM`, `DECLINE`, `BACK`, `QUIT`, `INTERRUPT` | Sets `authorized`, `consent_text`, `consent_utc` |
| `PICK_RUN_A` | `handle_pick_run_a` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `run_a` |
| `PICK_RUN_B` | `handle_pick_run_b` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `run_b` |
| `PICK_RUN` | `handle_pick_run` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `run_id` for reclassify |
| `LAB_MENU` | `handle_lab_menu` | `NEXT`, `BACK`, `QUIT`, `INTERRUPT` | Sets `lab_action` (`status`, `scenarios`, `reset`) |
| `REVIEW` | `handle_review` | `CONFIRM`, `DECLINE`, `BACK`, `QUIT`, `INTERRUPT` | Generates `CommandPlan` and prompts "Run now" or copy |
| `RUN_TRAFFIC` | `handle_run_traffic` | `DONE`, `FAILED`, `INTERRUPT` | In-process execution with optional `PacketCapture` |
| `RUN_OFFLINE` | `handle_run_offline` | `DONE`, `FAILED`, `INTERRUPT` | In-process compare / reclassify |
| `RUN_LAB` | `handle_run_lab` | `DONE`, `FAILED`, `INTERRUPT` | In-process lab execution |
| `RESULTS` | `handle_results` | `NEXT`, `QUIT`, `INTERRUPT` | Displays outcome panel |
| `NEXT_STEPS` | `handle_next_steps` | `EXPORT_REPORT`, `RERUN`, `DEEP_DIVE`, `MENU`, `QUIT`, `INTERRUPT` | Recommendations menu |
| `EXPORT` | `handle_export` | `DONE`, `QUIT`, `INTERRUPT` | Renders and writes Markdown lab report |

---

## 3. Current Screen Rendering Mechanism

- **Header / Chrome**: `show_header` prints `Rule(Text("netpolicy wizard | ... (Step N of M)"))` in cyan/purple.
- **Prompts**: `RichIO` prints the question with `console.print()`, then delegates choices to `Prompt.ask(..., choices=...)` with default bracketed prompts like `"Choose an option (1):"` or `Confirm.ask(...)` with `"[y/n] (y)"`.
- **Preflight**: Rendered as a `Table` showing platform, privilege, scapy, lab, and saved runs. *Current defect noted*: The "Namespace Lab" row shows `"Scripts: 83 saved runs"` because it merged lab scripts check with saved runs count.
- **Review**: Rendered as a `Table` showing Action, Target, Ports, Mode, Runs, Timeout, Capture, and Command.
- **Results**: Rendered as a simple `Panel` colored green (0), yellow (1), or red (2).

---

## 4. Production of Verdicts, Issues, and Recommendations

- **Aggregation (`netpolicy/report/summary.py:aggregate`)**:
  Takes `AuditReport` (`port_results`, `dns_results`, `http_results`).
  Groups port observations, DNS anomalies, and HTTP redirects/proxy headers into `Issue` objects.
  `Issue` fields: `area`, `subject`, `kind`, `confidence`, `attempts`, `runs_seen`, `runs_total`, `plain`, `technical`, `valid`, `invalid_reason`.
- **Reliability Gates (`netpolicy/report/summary.py:apply_reliability_gates`)**:
  Applies Gates `G1` (unverified canary), `G2` (blackhole probe validity), `G3` (benign upgrade), `G4` (control health), `G5` (sample size power).
  Returns `(issues: list[Issue], caveats: list[Caveat])`.
- **Verdict Computation (`netpolicy/report/summary.py:compute_verdict`)**:
  Synthesizes valid issues and caveats into `VerdictSummary`:
  `level`: `"CLEAN"`, `"LIMITED"`, `"ACTION_REQUIRED"`, `"RESTRICTED"`, or `"INCONCLUSIVE"`.
  `sentence`: Plain-English summary.
  `confidence`: Aggregate `Confidence` (`HIGH`, `MEDIUM`, `LOW`).
  `tested_summary`: String summarizing probe count (e.g. `5 ports, 4 DNS checks, 2 HTTP checks`).
- **Recommendations (`netpolicy/wizard/recommend.py:get_recommendations`)**:
  Maps `level` and issues into at most 5 `Recommendation` options:
  - `INCONCLUSIVE`: re-run against owned server.
  - `ACTION_REQUIRED`: sign in to captive login page.
  - `RESTRICTED`: deep dive into DNS, Web, or Ports.
  - Standard options: Export lab report, Re-run, Return to Menu, Quit.

---

## 5. Current WSL Launch Mechanism (`netpolicy/ui/wsl.py`)

- `is_native_windows()`: checks `platform.system() == "Windows"`.
- `distro_installed(name)`: runs `["wsl", "-l", "-q"]`, decodes UTF-16-LE / UTF-8, strips NUL and BOM.
- `maybe_launch_wsl(err_console)`:
  Prompts with `Confirm.ask("Raw packet crafting requires Linux. Launch Kali Linux WSL now?", default=True)`.
  If confirmed, calls `subprocess.run(["wsl", "-d", target_distro])`.
  *Current defect noted*: Drops the user into an empty Linux shell in the user's home directory. Does not launch `netpolicy`, does not pass the venv python, and when returning, prints banners twice.

---

## 6. Snapshot and Wording Tests Audit

The following existing tests check wording or prompt substrings:
1. `tests/test_wsl.py`:
   - `test_maybe_launch_wsl_confirmed_launches_subprocess`: Asserts `executed_cmds == [["wsl", "-d", "kali-linux"]]`. (Will be updated to verify the new zero-touch handoff argv).
   - `test_maybe_launch_wsl_custom_distro_respected`: Asserts `executed_cmds == [["wsl", "-d", "my-distro"]]`.
   - `test_maybe_launch_wsl_distro_not_installed`: Asserts `"Kali Linux is not installed in WSL. Install it with: wsl --install -d kali-linux"`.
2. `tests/test_report_redesign.py`:
   - Checks headers `"WHAT WE FOUND"`, `"WHAT YOU CAN DO"`, and verdict sentences.
3. `tests/test_wizard_stage7.py`:
   - Checks `--graph mermaid`, `wizard --help`.
4. `tests/test_banner.py`:
   - Checks `"NETPOLICY"`, `--json` clean stdout, `--version`.

*All non-wording tests (FSM logic, schema, exit codes, classifier math) remain strictly unchanged.*

---

## 7. Unverified Items

**None**. All mechanisms, data structures, and tests have been verified against current repository code.
