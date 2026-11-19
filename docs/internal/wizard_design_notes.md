# Netpolicy Wizard Design Notes & Ground-Truth Verification

This document records the exact, verified ground-truth from the repository codebase (`netpolicy/cli.py`, `netpolicy/report/summary.py`, `netpolicy/ui/`, `pyproject.toml`, and CLI `--help` outputs) as mandated by **STAGE 0**.

---

## 1. Verified CLI Commands and Exact Options

### Root Options
```
python -m netpolicy [OPTIONS] COMMAND [ARGS]...
  --version          Show netpolicy version and exit.
  --no-banner        Disable gradient welcome banner and compact headers.
  --help             Show help message and exit.
```

### `audit`
```
python -m netpolicy audit [OPTIONS]
  -t, --target <str>              Probe server host or IP (required for ports/http).
  -p, --ports <str>               Comma-separated port list to audit.
  -r, --runs <int>                Number of probe iterations [default: 5].
  --timeout <float>               Timeout per probe in seconds [default: 3.0].
  --retries <int>                 Retries before concluding a block [default: 2].
  -m, --mode <auto|raw|socket>    Probe mode [default: auto].
  --control-port <int>            Port known to be open on target for control probe (default 443).
  --json                          Format output as JSON.
  -q, --quiet                     Minimal terminal output.
  -v, --verbose                   Verbose debug output.
  --no-color                      Disable color formatting.
  -o, --output <path>             Path to write report (.json or .md).
  --include-identifiers           Include SSID/MAC/IP in output.
  --demo                          Run with mock data.
  -c, --config <path>             Path to YAML config.
  --no-banner                     Disable gradient header and footer.
  --help                          Show help message and exit.
```

### `ports`
```
python -m netpolicy ports [OPTIONS]
  -t, --target <str>              Probe server host or IP (required).
  -p, --ports <str>               Comma-separated port list to audit.
  -r, --runs <int>                Number of probe iterations [default: 5].
  --timeout <float>               Timeout per probe in seconds [default: 3.0].
  --retries <int>                 Retries before concluding a block [default: 2].
  -m, --mode <auto|raw|socket>    Probe mode [default: auto].
  --control-port <int>            Port known to be open on target for control probe (default 443).
  --json                          Format output as JSON.
  -q, --quiet                     Minimal terminal output.
  -v, --verbose                   Verbose debug output.
  --no-color                      Disable color formatting.
  -o, --output <path>             Path to write report (.json or .md).
  --include-identifiers           Include SSID/MAC/IP in output.
  --demo                          Run with mock data.
  -c, --config <path>             Path to YAML config.
  --no-banner                     Disable gradient header and footer.
  --help                          Show help message and exit.
```

### `dns`
```
python -m netpolicy dns [OPTIONS]
  -t, --target <str>              Optional specific DNS target server.
  -p, --ports <str>               Comma-separated port list to audit.
  -r, --runs <int>                Number of probe iterations [default: 5].
  --timeout <float>               Timeout per probe in seconds [default: 3.0].
  --retries <int>                 Retries before concluding a block [default: 2].
  -m, --mode <auto|raw|socket>    Probe mode [default: auto].
  --json                          Format output as JSON.
  -q, --quiet                     Minimal terminal output.
  -v, --verbose                   Verbose debug output.
  --no-color                      Disable color formatting.
  -o, --output <path>             Path to write report (.json or .md).
  --include-identifiers           Include SSID/MAC/IP in output.
  --demo                          Run with mock data.
  -c, --config <path>             Path to YAML config.
  --no-banner                     Disable gradient header and footer.
  --help                          Show help message and exit.
```

### `http`
```
python -m netpolicy http [OPTIONS]
  -t, --target <str>              Probe server host or IP (required).
  -p, --ports <str>               Comma-separated port list to audit.
  -r, --runs <int>                Number of probe iterations [default: 5].
  --timeout <float>               Timeout per probe in seconds [default: 3.0].
  --retries <int>                 Retries before concluding a block [default: 2].
  -m, --mode <auto|raw|socket>    Probe mode [default: auto].
  --json                          Format output as JSON.
  -q, --quiet                     Minimal terminal output.
  -v, --verbose                   Verbose debug output.
  --no-color                      Disable color formatting.
  -o, --output <path>             Path to write report (.json or .md).
  --include-identifiers           Include SSID/MAC/IP in output.
  --demo                          Run with mock data.
  -c, --config <path>             Path to YAML config.
  --no-banner                     Disable gradient header and footer.
  --help                          Show help message and exit.
```

### `compare`
```
python -m netpolicy compare [OPTIONS] REPORT_A REPORT_B
  Arguments:
    REPORT_A <path>               Path to baseline report (.json or .jsonl) [required].
    REPORT_B <path>               Path to comparison report (.json or .jsonl) [required].
  Options:
    --no-color                    Disable color formatting.
    --json                        Format output as JSON.
    --no-banner                   Disable gradient header and footer.
    --help                        Show help message and exit.
```

### `reclassify`
```
python -m netpolicy reclassify [OPTIONS] RUN_ID
  Arguments:
    RUN_ID <str>                  Run ID or path to .jsonl file to reclassify [required].
  Options:
    --json                        Format output as JSON.
    -q, --quiet                   Minimal terminal output.
    -v, --verbose                 Verbose debug output.
    --no-color                    Disable color formatting.
    -o, --output <path>           Path to write report (.json or .md).
    --include-identifiers         Include SSID/MAC/IP in output.
    -c, --config <path>           Path to YAML config.
    --no-banner                   Disable gradient header and footer.
    --help                        Show help message and exit.
```

### `lab`
```
python -m netpolicy lab [OPTIONS]
  Options:
    --help                        Show help message and exit.
```

---

## 2. Key Behavioral Invariants

### Does `compare` accept `.json`, `.jsonl`, or both?
- **Verified**: **Both**.
- **Evidence**: `_load_or_reclassify_report` in `netpolicy/cli.py:1137` checks the file extension. If `.jsonl`, it loads raw observations with `store.read_run()` and invokes the classification pipeline on the fly. If `.json`, it deserializes the stored `AuditReport`.

### Does `--output` also print the terminal report?
- **Verified**: **Yes**.
- **Evidence**: In `netpolicy/cli.py:_handle_report_output`, `--output` writes the report to disk (either `.json` or `.md`), and then proceeds to step 3 (`render_terminal_report(...)`) unless `--json` was also supplied. If `--quiet` is set, terminal output is reduced, but the report rendering logic is still invoked.

### What does `netpolicy lab` really offer?
- **Verified**: In `netpolicy/cli.py`, `def lab()` is currently a stub that prints `"not implemented yet"`.
- The actual namespace laboratory automation exists as standalone shell scripts in `lab/`:
  - `lab/setup.sh`: Provisions the 3-node namespace lab (`np-client`, `np-gw`, `np-server`).
  - `lab/services.sh`: Starts/stops mock daemons detached.
  - `lab/scenario.sh`: Applies middlebox impairment scenarios (flushes previous rules on `np-gw`).
  - `lab/status.sh`: Read-only inspection of namespaces and routes.
  - `lab/teardown.sh`: Destroys `np-*` namespaces.
  - `lab/validate.py`: Automated ground-truth test suite.
- **Wizard Implementation Rule**: Because `netpolicy lab` CLI command is a stub, the wizard's `LAB_MENU` must guide the user with clear information, check root/Linux capability, and print the exact commands to run (e.g. `sudo bash lab/setup.sh`) rather than executing unimplemented subcommands or running sudo directly.

### How does `reclassify` load a run?
- **Verified**: It takes a single positional argument `RUN_ID`, which can be either a bare run ID (e.g. `20261113_140000_a1b2c3d4`) or a relative/absolute path to a `.jsonl` file.
- It searches `reports/<run_id>.jsonl` if the path does not exist directly, reads raw observations using `read_run(path)`, reclassifies them through pure classifier rules, and prints/saves the resulting `AuditReport`.

### Does `summary.py` exist and what does it provide?
- **Verified**: **Yes**, `netpolicy/report/summary.py` exists (599 lines).
- It provides:
  - `compute_verdict(issues, caveats, report=None) -> VerdictSummary`
  - Verdict levels: `CLEAN`, `LIMITED`, `ACTION_REQUIRED`, `RESTRICTED`, `INCONCLUSIVE`.
  - Reliability gates:
    - `G1`: Target is not a netpolicy canary (`unverified canary`).
    - `G2`: DNS blackhole queried live server instead of RFC 5737 documentation IP.
    - `G3`: Same-host HTTP-to-HTTPS redirect recognized as security upgrade.
    - `G4`: Address-family mismatch (IPv6 egress vs IPv4 CIDR).
    - `G5`: Protocol/connection errors.
  - `extract_issues_and_caveats(report) -> tuple[list[Issue], list[Caveat]]`.

### Unknowns and UNVERIFIED items:
- None. All CLI options, commands, and modules have been directly verified against source code and `--help` executions.
