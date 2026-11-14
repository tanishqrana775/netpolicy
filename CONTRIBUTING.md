# Contributing to netpolicy

Thank you for contributing to `netpolicy`. This guide outlines how to set up your development environment, follow our architectural principles, and implement new probes.

---

## Development Setup

1. **Clone the repository and set up a virtual environment**:
   ```bash
   git clone https://github.com/netpolicy/netpolicy.git
   cd netpolicy

   python3 -m venv .venv
   source .venv/bin/activate   # On Windows: .venv\Scripts\Activate.ps1
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

2. **Run verification commands**:
   ```bash
   ruff check .
   ruff format --check .
   mypy netpolicy tests canary lab
   pytest
   ```

---

## Architectural & Safety Principles

All contributions must follow these non-negotiable design constraints:

1. **Probes Record Only Raw Observations**:
   - Probes make network measurements and record raw facts (replies, flags, TTLs, IP IDs, ICMP codes, response bodies, timings).
   - Probes **never** make policy decisions or assign verdicts.
2. **Classifiers Are Pure Functions**:
   - `classify_*(observations: list[Observation]) -> Verdict`
   - Classifiers perform zero network or disk I/O. They are deterministic, table-driven functions that evaluate observations and output a `Verdict` with a `Confidence` level and human-readable evidence strings.
3. **Control Probes Prevent False Positives**:
   - Audits include a control probe against a known reachable port/service. If the control probe fails, reachability verdicts become `UNKNOWN`, never `BLOCKED`.
4. **Safety & Zero Host Mutation**:
   - Python library code must never alter the host network namespace (no modifying host routes, firewall rules, or DNS settings).
   - In lab scripts, all commands run exclusively inside `np-*` Linux network namespaces via the `nsx()` helper or `ip netns exec np-<name>`. Never use `sudo` inside scripts.
5. **Privacy First**:
   - Reports redact MAC addresses and public client IP addresses by default. A privacy-preserving SHA-256 network fingerprint is computed from the gateway and resolver IP addresses.

---

## How to Add a New Probe

To add a new network probe family (e.g. TLS/SSL interception probe or NTP probe):

### Step 1: Define Probe Models & Config
- If the probe introduces new targets or raw observation structures, update [`netpolicy/models.py`](netpolicy/models.py).
- Add any required configuration parameters (timeouts, retries, ports, test targets) to the appropriate section in [`netpolicy/config.py`](netpolicy/config.py).

### Step 2: Implement the Probe Class
- Create or extend a module in `netpolicy/probes/` (e.g. `netpolicy/probes/tls.py`).
- Inherit from `BaseProbe` in [`netpolicy/probes/base.py`](netpolicy/probes/base.py):
  ```python
  from netpolicy.models import Observation, Target
  from netpolicy.probes.base import BaseProbe


  class MyCustomProbe(BaseProbe):
      name = "my_custom_probe"

      def run(self, target: Target, run_index: int) -> list[Observation]:
          # Perform measurement, enforce timeout and rate limiting.
          # Record raw measurements without interpreting policy meaning.
          return [
              Observation(
                  probe_name=self.name,
                  target=target,
                  success=True,
                  raw={"status_code": 200, "rtt_ms": 15.2, "server_banner": "..."},
              )
          ]
  ```

### Step 3: Implement Pure Classification Rules
- Create or update a module in `netpolicy/classify/` (e.g. `netpolicy/classify/tls.py`).
- Write pure classification functions with documented decision tables:
  ```python
  from netpolicy.models import Confidence, Observation, Verdict, VerdictKind


  def classify_custom(observations: list[Observation]) -> Verdict:
      # Pure function: inspect raw fields, return Verdict
      ...
  ```

### Step 4: Wire Probe into Engine & CLI
- Connect the probe in [`netpolicy/engine/pipeline.py`](netpolicy/engine/pipeline.py) so raw observations are grouped and routed to your classifier.
- If applicable, add high-level rule-based findings in [`netpolicy/findings.py`](netpolicy/findings.py).
- Expose the probe in [`netpolicy/cli.py`](netpolicy/cli.py) under the relevant subcommands (`audit`, etc.).

### Step 5: Write Comprehensive Unit Tests
- Create unit tests in `tests/` using mocked network responses (e.g. mocking sockets, HTTP clients, or DNS packets).
- Test both clean and anomalous cases (drops, resets, modified payloads).
- Verify type compliance with `mypy netpolicy tests canary lab`.
