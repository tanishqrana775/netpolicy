# Netpolicy Project Ground-Truth Technical Facts

This document serves as the canonical, verified technical reference for the `netpolicy` repository (v0.1.0+). Every fact recorded herein is derived directly from static inspection and command-line verification of the codebase as it currently exists on disk. No claims are made from memory or extrapolation. Any item that could not be verified directly against code or active commands is explicitly marked as `UNVERIFIED`.

---

## Section 1: Modules and Scripts Catalog

### 1.1 Core Package (`netpolicy/`)
- `netpolicy/__init__.py`: Package root initialization exporting package version `__version__ = "0.1.0"`.
- `netpolicy/__main__.py`: CLI executable entrypoint enabling module execution via `python -m netpolicy`.
- `netpolicy/cli.py`: Typer command-line application registering all user-facing subcommands (`audit`, `ports`, `dns`, `http`, `compare`, `lab`, `reclassify`) and formatting options.
- `netpolicy/config.py`: Pydantic models and loader for application configuration (`AppConfig`, `GeneralConfig`, `PortConfig`, `DNSConfig`, `HTTPConfig`), YAML parsing, and CLI port list overrides.
- `netpolicy/demo.py`: Factory generating synthetic, reproducible mock `AuditReport` data for demonstration and smoke testing without performing live network I/O.
- `netpolicy/findings.py`: Pure, rule-based inference engine mapping classified probe verdicts into structured `Finding` objects across severity tiers (`info`, `warn`, `critical`) with plain-English descriptions.
- `netpolicy/models.py`: Core domain data models for targets, raw observations, classified verdicts, findings, and complete audit reports (`AuditReport`, `ReportMetadata`, `Target`, `Observation`, `Verdict`, `Finding`).
- `netpolicy/canary/__init__.py`: Canary module namespace re-exporting canary server utilities.
- `netpolicy/canary/server.py`: Wrapper re-exporting `CanaryServer` and HTTP constants from `canary.server`.
- `netpolicy/canary/tamper_proxy.py`: Wrapper re-exporting `TamperProxy` from `tests.tamper_proxy`.
- `netpolicy/classify/__init__.py`: Classification package re-exporting pure, stateless verdict evaluation functions.
- `netpolicy/classify/dns.py`: Pure classification functions for DNS probe observations (evaluates NXDOMAIN hijacking, whoami resolver identity, blackhole interception, and DoH cross-checks).
- `netpolicy/classify/http.py`: Pure classification functions for HTTP probe observations (evaluates status codes, proxy header injection, body hash modification, and echoed nonces).
- `netpolicy/classify/tcp.py`: Pure classification functions for TCP reachability observations (classifies `OPEN`, `BLOCKED_DROP`, `BLOCKED_RESET`, `BLOCKED_ICMP`, `LOSSY`, `CLOSED_OR_RESET`, and `CONTROL_FAILED`).
- `netpolicy/engine/__init__.py`: Execution engine package exporting context provider, thread runner, and observation aggregation pipeline.
- `netpolicy/engine/context.py`: Runtime networking context discovering local IP, default gateway, active DNS resolver, and computing SHA-256 network fingerprints.
- `netpolicy/engine/pipeline.py`: Observation pipeline grouping raw observations by `(probe, target)` and routing them through classifiers to generate `AuditReport` models and findings.
- `netpolicy/engine/runner.py`: Multithreaded probe execution engine dispatching probe jobs with concurrency control, timeout handling, and append-only raw JSONL persistence.
- `netpolicy/lab/__init__.py`: Package marker for internal lab utilities.
- `netpolicy/lab/README.md`: High-level internal guidelines and safety rules for namespace-isolated testing.
- `netpolicy/probes/__init__.py`: Active probe package re-exporting base probe classes and protocol probe implementations.
- `netpolicy/probes/base.py`: Abstract base class `Probe` defining standard execution, result reporting, and timing contracts.
- `netpolicy/probes/dns.py`: Active DNS probes (`BlackholeProbe`, `WhoamiProbe`, `NxdomainProbe`, `DohCrossCheckProbe`) testing UDP/53 queries against control resolvers and public DoH.
- `netpolicy/probes/http.py`: Active HTTP probe (`HttpCanaryProbe`) querying control web servers, asserting headers, SHA-256 body integrity, and unique request nonces.
- `netpolicy/probes/tcp_connect.py`: Unprivileged TCP probe using standard operating system `connect()` socket calls with elapsed time measurement.
- `netpolicy/probes/tcp_syn.py`: Privileged TCP probe using Scapy to craft raw TCP SYN packets, detecting SYN-ACK, TCP RST, and in-path ICMP unreachable messages.
- `netpolicy/report/__init__.py`: Reporting package for formatting, serializing, and exporting audit findings.
- `netpolicy/report/compare.py`: Comparison engine computing diffs between two `AuditReport` instances across port results, DNS results, HTTP results, and findings.
- `netpolicy/report/jsonout.py`: Serializer and deserializer for `AuditReport` JSON representations, with support for identifier scrubbing.
- `netpolicy/report/markdown.py`: Exporter converting `AuditReport` data into formatted, standalone Markdown reports.
- `netpolicy/report/terminal.py`: Rich terminal renderer formatting classified port tables, DNS/HTTP check results, and finding panels.
- `netpolicy/store/__init__.py`: Raw storage package.
- `netpolicy/store/raw.py`: Append-only, thread-safe JSONL file manager (`RawObservationStore`) persisting telemetry and supporting offline reclassification.

### 1.2 Top-Level Support & Standalone Servers (`canary/`)
- `canary/__init__.py`: Package marker for standalone canary server.
- `canary/server.py`: Standalone HTTP canary server running on port 80 serving `/canary.txt` (fixed payload with known SHA-256), `/echo` (header echoing), and `/manifest.json`.
- `canary/tamper_proxy.py`: Re-export shim importing `tests.tamper_proxy` into the canary package namespace.

### 1.3 Lab Framework (`lab/`)
- `lab/__init__.py`: Lab package marker.
- `lab/banner_servers.py`: Multi-port TCP server listening inside `np-server` on ports 21, 22, 25, 443, and 587, sending authentic protocol banners to probe clients.
- `lab/dns_server.py`: dnspython-based UDP DNS responder answering `whoami.lab` with query source IP, fixed A records, authentic NXDOMAIN, and `--rewrite` hijacking mode.
- `lab/README.md`: Comprehensive documentation detailing lab network architecture, addressing, safety rules, scenario controls, and validation procedures.
- `lab/scenario.sh`: Exclusive middlebox scenario manager applying and verifying iptables firewall rules and service configurations inside `np-gw`.
- `lab/scenarios.yaml`: Ground-truth specification defining expected port, DNS, and HTTP verdicts for each middlebox scenario.
- `lab/services.sh`: Lifecycle manager starting, stopping, restarting, and inspecting detached background mock services (`banner_servers.py`, `canary/server.py`, `dns_server.py`) inside `np-server`.
- `lab/setup.sh`: Lab provisioning script creating isolated network namespaces `np-client`, `np-gw`, `np-server`, point-to-point veth links, addressing, and blackholes.
- `lab/status.sh`: Read-only diagnostic inspector reporting namespace presence, IP addresses, active scenario, `np-gw` firewall tables, and `np-server` sockets.
- `lab/teardown.sh`: Idempotent lab cleanup script stopping service processes and deleting only namespaces prefixed with `np-`.
- `lab/validate.py`: Automated validation harness running repeated audits inside `np-client`, comparing verdicts to `scenarios.yaml`, computing confusion matrices, and running `tc netem` sweeps.

### 1.4 Automation Scripts (`scripts/`)
- `scripts/bootstrap-python.sh`: Non-root provisioning script establishing user-owned `.linux-venv`, bootstrapping pip via `get-pip.py`, and installing `netpolicy` in editable mode with `.[lab]`.
- `scripts/bootstrap-system.sh`: Root-only package installer automating system dependency installation (Python, iproute2, iptables, curl, ping) across apt, dnf, and pacman systems.
- `scripts/demo.sh`: Root-only end-to-end verification script orchestrating environment diagnostics, lab setup, clean baseline audit, scenario tampering, report comparison, and exit code assertions.
- `scripts/doctor.sh`: Environment diagnostic script evaluating OS/WSL2 virtualization, repo location, Python/pip health, system tools, and throwaway namespace self-tests.

### 1.5 Test Suite & Fixtures (`tests/`)
- `tests/__init__.py`: Test suite package marker.
- `tests/tamper_proxy.py`: Standalone reverse proxy used in middlebox scenarios to inject proxy headers (`Via`, `X-Cache`), modify payload bodies, or tamper with nonces.
- `tests/test_classify_dns.py`: Unit tests for DNS observation classification across clean, intercepted, rewritten, and mismatch conditions.
- `tests/test_classify_http.py`: Unit tests for HTTP canary observation classification (clean, headers injected, body modified, proxied, redirected).
- `tests/test_classify_tcp.py`: Unit tests for TCP port observation classification (open, blocked drop, blocked reset, ICMP codes, lossy).
- `tests/test_cli.py`: Unit tests for CLI subcommands, flag parsing, `--help`, `--version`, and execution modes.
- `tests/test_dns_probes.py`: Unit tests for active DNS probes (blackhole, whoami, nxdomain, DoH).
- `tests/test_engine.py`: Unit tests for engine context, network fingerprinting, runner job scheduling, and observation aggregation.
- `tests/test_findings.py`: Unit tests for rule-based findings generation, severity tiers, and deduplication.
- `tests/test_http.py`: Unit tests for HTTP canary endpoints (`/canary.txt`, `/echo`, `/manifest.json`).
- `tests/test_http_canary.py`: Unit tests for HTTP canary server request handling and header validation.
- `tests/test_http_probe.py`: Unit tests for `HttpCanaryProbe` execution and response parsing.
- `tests/test_lab_banner.py`: Unit tests for `lab/banner_servers.py` multi-port listeners and protocol banners.
- `tests/test_lab_dns.py`: Unit tests for `lab/dns_server.py` UDP responses, TXT query echoing, and `--rewrite` mode.
- `tests/test_lab_safety.py`: Static AST and shell analysis suite enforcing non-negotiable safety rules and verifying script constraints.
- `tests/test_lab_validate.py`: Unit tests for validation framework metrics, confusion matrix computation, and scenario evaluation logic.
- `tests/test_ports_smoke.py`: Smoke tests for port auditing workflows.
- `tests/test_report.py`: Unit tests for report serializers, JSON export, Markdown export, terminal rendering, and comparison logic.
- `tests/test_tcp_connect.py`: Unit tests for socket-based unprivileged TCP connect probes.
- `tests/test_tcp_syn.py`: Unit tests for Scapy raw TCP SYN packet crafting and response sniffing.
- `tests/fixtures/`: Static JSON test fixtures simulating observation inputs for DNS, HTTP, and TCP classifiers.

---

## Section 2: Command-Line Interface (`netpolicy --help`)

The CLI is implemented using Typer in `netpolicy/cli.py`.

### 2.1 Root Command Options and Subcommands

```text
Usage: python -m netpolicy [OPTIONS] COMMAND [ARGS]...

CLI network policy auditor to detect silent blocking, interception, and tampering.

Options:
  --version  <bool>  Show netpolicy version and exit.
  --help     <bool>  Show this message and exit.

Commands:
  audit       Execute full network audit (ports + DNS + HTTP).
  ports       Audit outbound port reachability and firewall behavior.
  dns         Audit DNS interception, redirection, and tampering.
  http        Audit HTTP tampering, header injection, and captive portal interception.
  compare     Compare two audit reports (.json or .jsonl) to highlight differences in network policies.
  lab         Manage and inspect reproducible Linux network namespace test labs.
  reclassify  Reclassify raw observations from a saved .jsonl file through updated classifier rules.
```

### 2.2 Subcommand Options and Defaults

#### `audit`
Executes a complete network audit encompassing outbound TCP ports, DNS resolution integrity, and HTTP content/proxy tampering.

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | `<str>` | `None` | Probe server host or IP (required for ports/http). |
| `--ports` | `-p` | `<str>` | `None` | Comma-separated port list to audit (falls back to config: `21,22,25,80,443,587`). |
| `--runs` | `-r` | `<int>` | `5` | Number of probe iterations. |
| `--timeout` | — | `<float>` | `3.0` | Timeout per probe in seconds. |
| `--retries` | — | `<int>` | `2` | Retries before concluding a block. |
| `--mode` | `-m` | `<auto\|raw\|socket>` | `auto` | Probe mode (`auto`, `raw`, `socket`). |
| `--control-port` | — | `<int>` | `None` | Port known to be open on target for control probe (falls back to config: `443`). |
| `--json` | — | `<bool>` | `False` | Format output as JSON. |
| `--quiet` | `-q` | `<bool>` | `False` | Minimal terminal output. |
| `--verbose` | `-v` | `<bool>` | `False` | Verbose debug output. |
| `--no-color` | — | `<bool>` | `False` | Disable color formatting. |
| `--output` | `-o` | `<path>` | `None` | Path to write report (`.json` or `.md`). |
| `--include-identifiers`| — | `<bool>` | `False` | Include SSID/MAC/IP in output. |
| `--demo` | — | `<bool>` | `False` | Run with mock data. |
| `--config` | `-c` | `<path>` | `None` | Path to YAML config. |
| `--help` | — | `<bool>` | `False` | Show this message and exit. |

#### `ports`
Audits outbound port reachability and firewall behavior against specified destination ports.

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | `<str>` | `None` | Probe server host or IP (required). |
| `--ports` | `-p` | `<str>` | `None` | Comma-separated port list to audit. |
| `--runs` | `-r` | `<int>` | `5` | Number of probe iterations. |
| `--timeout` | — | `<float>` | `3.0` | Timeout per probe in seconds. |
| `--retries` | — | `<int>` | `2` | Retries before concluding a block. |
| `--mode` | `-m` | `<auto\|raw\|socket>` | `auto` | Probe mode. |
| `--control-port` | — | `<int>` | `None` | Port known to be open on target for control probe (default 443). |
| `--json` | — | `<bool>` | `False` | Format output as JSON. |
| `--quiet` | `-q` | `<bool>` | `False` | Minimal terminal output. |
| `--verbose` | `-v` | `<bool>` | `False` | Verbose debug output. |
| `--no-color` | — | `<bool>` | `False` | Disable color formatting. |
| `--output` | `-o` | `<path>` | `None` | Path to write report. |
| `--include-identifiers`| — | `<bool>` | `False` | Include SSID/MAC/IP in output. |
| `--demo` | — | `<bool>` | `False` | Run with mock data. |
| `--config` | `-c` | `<path>` | `None` | Path to YAML config. |
| `--help` | — | `<bool>` | `False` | Show this message and exit. |

#### `dns`
Audits DNS resolution integrity, interception, redirection, and tampering.

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | `<str>` | `None` | Optional specific DNS target server. |
| `--ports` | `-p` | `<str>` | `None` | Comma-separated port list to audit. |
| `--runs` | `-r` | `<int>` | `5` | Number of probe iterations. |
| `--timeout` | — | `<float>` | `3.0` | Timeout per probe in seconds. |
| `--retries` | — | `<int>` | `2` | Retries before concluding a block. |
| `--mode` | `-m` | `<auto\|raw\|socket>` | `auto` | Probe mode. |
| `--json` | — | `<bool>` | `False` | Format output as JSON. |
| `--quiet` | `-q` | `<bool>` | `False` | Minimal terminal output. |
| `--verbose` | `-v` | `<bool>` | `False` | Verbose debug output. |
| `--no-color` | — | `<bool>` | `False` | Disable color formatting. |
| `--output` | `-o` | `<path>` | `None` | Path to write report. |
| `--include-identifiers`| — | `<bool>` | `False` | Include SSID/MAC/IP in output. |
| `--demo` | — | `<bool>` | `False` | Run with mock data. |
| `--config` | `-c` | `<path>` | `None` | Path to YAML config. |
| `--help` | — | `<bool>` | `False` | Show this message and exit. |

#### `http`
Audits HTTP tampering, proxy header injection, and payload alteration against an HTTP canary server.

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | `<str>` | `None` | Probe server host or IP (required). |
| `--ports` | `-p` | `<str>` | `None` | Comma-separated port list to audit. |
| `--runs` | `-r` | `<int>` | `5` | Number of probe iterations. |
| `--timeout` | — | `<float>` | `3.0` | Timeout per probe in seconds. |
| `--retries` | — | `<int>` | `2` | Retries before concluding a block. |
| `--mode` | `-m` | `<auto\|raw\|socket>` | `auto` | Probe mode. |
| `--json` | — | `<bool>` | `False` | Format output as JSON. |
| `--quiet` | `-q` | `<bool>` | `False` | Minimal terminal output. |
| `--verbose` | `-v` | `<bool>` | `False` | Verbose debug output. |
| `--no-color` | — | `<bool>` | `False` | Disable color formatting. |
| `--output` | `-o` | `<path>` | `None` | Path to write report. |
| `--include-identifiers`| — | `<bool>` | `False` | Include SSID/MAC/IP in output. |
| `--demo` | — | `<bool>` | `False` | Run with mock data. |
| `--config` | `-c` | `<path>` | `None` | Path to YAML config. |
| `--help` | — | `<bool>` | `False` | Show this message and exit. |

#### `compare`
Compares two audit reports (`.json` or `.jsonl`) and highlights differences in network policy verdicts and findings.

- **Positional Arguments**:
  - `report_a` (`<path>`, required): Path to baseline report (`.json` or `.jsonl`).
  - `report_b` (`<path>`, required): Path to comparison report (`.json` or `.jsonl`).
- **Options**:
  - `--no-color` (`<bool>`, default `False`): Disable color formatting.
  - `--json` (`<bool>`, default `False`): Format output as JSON.
  - `--help` (`<bool>`): Show this message and exit.
- **Exit Codes**:
  - `0`: Reports are identical (no policy changes).
  - `1`: Policy differences detected between reports.
  - `2`: Invalid report file or loading error.

#### `lab`
Management entrypoint for Linux network namespace test labs.
- **Current State**: Stub command. When invoked, outputs `"not implemented yet"` and returns.
- **Options**:
  - `--help` (`<bool>`): Show this message and exit.

#### `reclassify`
Loads raw observation telemetry from a `.jsonl` file, re-runs observation aggregation and classification through updated rules, and renders or saves the classified report.

- **Positional Arguments**:
  - `run_id` (`<str>`, required): Run ID or path to `.jsonl` file to reclassify. Searched in current directory and `./reports/`.
- **Options**:
  - `--json` (`<bool>`, default `False`): Format output as JSON.
  - `--quiet` / `-q` (`<bool>`, default `False`): Minimal terminal output.
  - `--verbose` / `-v` (`<bool>`, default `False`): Verbose debug output.
  - `--no-color` (`<bool>`, default `False`): Disable color formatting.
  - `--output` / `-o` (`<path>`, default `None`): Path to write report.
  - `--include-identifiers` (`<bool>`, default `False`): Include SSID/MAC/IP in output.
  - `--config` / `-c` (`<path>`, default `None`): Path to YAML config.
  - `--help` (`<bool>`): Show this message and exit.

---

## Section 3: Lab Architecture, Scripts, and Ground Truth

### 3.1 Topology, Namespaces, Links, and Addressing

The lab environment ([`lab/setup.sh`](lab/setup.sh)) configures an isolated 3-node network using Linux network namespaces connected by peer-to-peer veth links:

```text
[ np-client ]                                [ np-gw ]                                [ np-server ]
10.200.1.2/24                                10.200.1.1/24                            10.200.2.2/24
(veth-client) <==== veth pair 1 ====> (veth-gw-c)    (veth-gw-s) <==== veth pair 2 ====> (veth-server)
Default route:                               IPv4 Forwarding = 1                      Default route:
  via 10.200.1.1                                                                        via 10.200.2.1
```

- **Namespaces**:
  - `np-client`: Originates audit probe traffic.
  - `np-gw`: Forwarding gateway and middlebox policy enforcement point.
  - `np-server`: Destination target server hosting mock services and listeners.
- **Veth Pairs**:
  - Pair 1: `veth-client` (created directly in `np-client`) $\leftrightarrow$ `veth-gw-c` (created directly in `np-gw`).
  - Pair 2: `veth-gw-s` (created directly in `np-gw`) $\leftrightarrow$ `veth-server` (created directly in `np-server`).
- **IP Addressing**:
  - `np-client`: `veth-client` = `10.200.1.2/24`, `lo` = `127.0.0.1/8`.
  - `np-gw`: `veth-gw-c` = `10.200.1.1/24`, `veth-gw-s` = `10.200.2.1/24`, `lo` = `127.0.0.1/8`.
  - `np-server`: `veth-server` = `10.200.2.2/24`, `lo` = `127.0.0.1/8`.
- **Routing & Forwarding**:
  - `np-client`: Default route `default via 10.200.1.1 dev veth-client`.
  - `np-server`: Default route `default via 10.200.2.1 dev veth-server`.
  - `np-gw`: Forwarding enabled strictly inside namespace (`sysctl -w net.ipv4.ip_forward=1`).
  - `np-gw`: RFC 5737 blackhole routes: `192.0.2.0/24` and `198.51.100.0/24`.
- **DNS Resolution Configuration**:
  - Preserves host `/etc/resolv.conf`; writes per-namespace configurations to `/etc/netns/np-{client,gw,server}/resolv.conf`:
    ```text
    nameserver 10.200.2.2
    nameserver 10.200.1.1
    options timeout:1 attempts:2
    ```

### 3.2 Target Services & Listeners (`np-server`)

Managed via [`lab/services.sh`](lab/services.sh):
1. **TCP Banner Listeners** ([`lab/banner_servers.py`](lab/banner_servers.py)):
   - Bound to `0.0.0.0` on ports `21,22,25,443,587`.
   - Protocol Banners:
     - Port 21: `b"220 FTP server ready (NetPolicy Lab)\r\n"`
     - Port 22: `b"SSH-2.0-OpenSSH_9.3p1 NetPolicy\r\n"`
     - Port 25: `b"220 mail.lab ESMTP NetPolicy-Lab Service\r\n"`
     - Port 443: `b"HTTP/1.1 200 OK\r\nServer: NetPolicy-Control\r\nContent-Length: 2\r\n\r\nOK"`
     - Port 587: `b"220 mail.lab ESMTP Submission NetPolicy-Lab\r\n"`
2. **Canary HTTP Server** ([`canary/server.py`](canary/server.py)):
   - Bound to `0.0.0.0:80`.
   - Endpoints:
     - `/canary.txt`: Serves fixed text with known SHA-256 (`e3b0c44298fc1c14...`), asserts required headers (`Server: NetPolicy-Canary/1.0`, `X-Canary-ID`).
     - `/echo`: Echoes client headers and nonces.
     - `/manifest.json`: Serves metadata on expected canary headers and content hashes.
3. **Lab DNS Responder** ([`lab/dns_server.py`](lab/dns_server.py)):
   - Bound to UDP `0.0.0.0:53`.
   - Responds to `whoami.lab` (TXT) with client's source IP address.
   - Responds to fixed A records: `whoami.lab` (`10.200.2.2`), `canary.lab` (`10.200.2.2`), `server.lab` (`10.200.2.2`), `mail.lab` (`10.200.2.2`), `gw.lab` (`10.200.2.1`), `client.lab` (`10.200.1.2`), `example.com` (`93.184.216.34`).
   - Returns authentic `NXDOMAIN` for unknown records, or hijacks queries with an A record when started with `--rewrite`.

### 3.3 Middlebox Scenarios & Exact Firewall Rules

Configured via [`lab/scenario.sh`](lab/scenario.sh):

#### Reset/Flush Behavior
Before applying any scenario, `lab/scenario.sh` executes an exclusive flush:
1. `nsx gw iptables -F` (flushes filter table).
2. `nsx gw iptables -X` (deletes custom filter chains).
3. `nsx gw iptables -t nat -F` (flushes nat table).
4. `nsx gw iptables -t nat -X` (deletes custom nat chains).
5. `nsx gw iptables -t mangle -F` (flushes mangle table).
6. Resets default policies: `FORWARD ACCEPT`, `INPUT ACCEPT`, `OUTPUT ACCEPT`.
7. Stops any running reverse tamper proxy processes recorded in `lab/run/proxy.pid` or `/tmp/np-proxy.pid`.
8. If current scenario is not `nxdomain-rewrite`, restarts `dns_server.py` inside `np-server` without the `--rewrite` flag.
9. Writes the active scenario name to `lab/run/active_scenario`.

#### Scenario Rules Specification

| Scenario Name | Exact Command / Mechanism | Target NS | Expected Outcome (from `scenarios.yaml`) |
|---|---|---|---|
| `clean` | Flush all rules; policies ACCEPT | `np-gw` | Ports 21, 22, 25, 443, 587 `OPEN`; DNS `CLEAN`; HTTP `CLEAN` |
| `drop-smtp` | `iptables -A FORWARD -p tcp --dport 25 -j DROP` | `np-gw` | Port 25 `BLOCKED_DROP`; others `OPEN`; DNS/HTTP `CLEAN` |
| `reset-smtp` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with tcp-reset` | `np-gw` | Port 25 `BLOCKED_RESET`; others `OPEN`; DNS/HTTP `CLEAN` |
| `icmp-admin` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-admin-prohibited` | `np-gw` | Port 25 `BLOCKED_ICMP` (code 13); others `OPEN`; DNS/HTTP `CLEAN` |
| `icmp-port-unreach` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable` | `np-gw` | Port 25 `BLOCKED_ICMP` (code 3); others `OPEN`; DNS/HTTP `CLEAN` |
| `dns-dnat` | `iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53` | `np-gw` | Ports `OPEN`; DNS `INTERCEPTED`; HTTP `CLEAN` |
| `nxdomain-rewrite` | Kills DNS server in `np-server`, restarts with `--rewrite` flag | `np-server` | Ports `OPEN`; DNS `REWRITTEN`; HTTP `CLEAN` |
| `http-proxy` | Spawns `tests/tamper_proxy.py` on `10.200.1.1:8080`; `iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.200.1.1:8080` | `np-gw` | Ports `OPEN`; DNS `CLEAN`; HTTP `HEADERS_INJECTED` |
| `campus` | Composite: applies `reset-smtp` + `dns-dnat` + `http-proxy` | `np-gw` | Port 25 `BLOCKED_RESET`; DNS `INTERCEPTED`; HTTP `HEADERS_INJECTED` |

### 3.4 Ground-Truth Validation Harness (`lab/validate.py`)

- **Requirements**:
  - Must run with root privileges (`EUID == 0`).
  - Active namespaces `np-client`, `np-gw`, `np-server`.
  - Python dependencies: `matplotlib`, `numpy`, `yaml`, `rich`, `pandas`. (Exits code 2 if missing).
  - Ground truth specification: `lab/scenarios.yaml`.
- **Harness Operations**:
  - Executes `N` runs (default: 30) of `netpolicy audit --target 10.200.2.2 --json` inside `np-client` per scenario.
  - Evaluates actual verdicts against `expected` verdicts in `scenarios.yaml`.
  - Optional `--netem` sweep: applies packet loss (`0%, 1%, 2%, 5%, 10%`) and RTT latency (`10ms, 50ms, 100ms, 200ms`) via `tc qdisc add dev veth-gw-s root netem` in `np-gw`.
- **Artifacts Produced** (in `--results-dir`, default `results/`):
  - `results/validation.csv`: Complete outcome table of all evaluated checks across runs.
  - `results/confusion_matrix.png`: Heatmap plot of confusion matrices per check domain (`port`, `dns`, `http`).
  - `results/accuracy.png`: Bar chart of classification accuracy across scenarios with standard error bars.
  - `results/netem_degradation.png`: Degradation curve plot (when `--netem` is passed).
- **Quality Gate Criteria**:
  - Fails (exit code 1) if false-positive rate on clean scenario > 0%.
  - Fails (exit code 1) if clean scenario accuracy < `--threshold` (default 0.95).
  - Succeeds (exit code 0) if all checks meet ground-truth standards.

### 3.5 Automation Scripts

- **`scripts/bootstrap-system.sh`**:
  - Requires root (`EUID == 0`).
  - Installs apt packages: `python3`, `python3-venv`, `python3-pip`, `iproute2`, `iptables`, `curl`, `ca-certificates`, `iputils-ping`, `psmisc`, `procps`.
  - Prints instructions for `dnf` and `pacman`.
- **`scripts/bootstrap-python.sh`**:
  - Requires non-root (`EUID != 0`).
  - Creates `.linux-venv` without pip, bootstraps pip via `get-pip.py` (falls back to ensurepip), installs `.[lab]` in editable mode.
  - Verifies CLI binaries and imports.
- **`scripts/doctor.sh`**:
  - Inspects OS (Linux/WSL2, warns WSL1), filesystem (`/mnt/` warning), Python >= 3.10, virtualenv health, tools (`ip`, `iptables`, `tc`, `curl`), iptables backend.
  - When run as root: executes namespace self-test in throwaway namespaces `np-doctor-<pid>-{a,b}` (testing veth, filter ACCEPT/REJECT tcp-reset, and nat redirect) and tears them down in a trap.
- **`scripts/demo.sh`**:
  - Requires root (`EUID == 0`).
  - Sequences: `scripts/doctor.sh` $\rightarrow$ `lab/setup.sh` $\rightarrow$ `lab/services.sh start` $\rightarrow$ baseline audit (expected exit code 0) $\rightarrow$ scenario application (default `reset-smtp`) $\rightarrow$ tampered audit (expected exit code 1) $\rightarrow$ `netpolicy compare` (expected exit code 1).
  - Installs cleanup trap on `EXIT INT TERM HUP` invoking `lab/teardown.sh`.
  - Preserves user file ownership by chowning `demo-output/` to `SUDO_UID:SUDO_GID`.

---

## Section 4: File Formats and Telemetry Data Flows

### 4.1 Raw Telemetry Storage (`.jsonl`)
- **File Location**: `./reports/{run_id}.jsonl` where `run_id` is generated as `{YYYYMMDD_HHMMSS}_{secrets.token_hex(4)}`.
- **Format**: JSON Lines (newline-delimited JSON).
- **Line Structure**:
  ```json
  {
    "run_id": "20261113_140000_a1b2c3d4",
    "timestamp": 1794568800.123,
    "probe_name": "tcp_syn_probe",
    "observation": {
      "probe_name": "tcp_syn_probe",
      "target": {"host": "10.200.2.2", "port": 25, "service": "SMTP"},
      "timestamp": 1794568800.123,
      "success": false,
      "rtt_ms": 1.25,
      "tcp_flags": "R",
      "icmp_type": null,
      "icmp_code": null,
      "ttl": 64,
      "raw_evidence": {"flags": "R", "ttl": 64}
    }
  }
  ```
- **Durability**: Flushed to disk immediately on every write; ownership adjusted to `SUDO_UID:SUDO_GID` when invoked with sudo.

### 4.2 Serialized Reports (`--json` and `--output`)
- **`--json` Output**: Pure JSON written to `stdout`.
- **`--output <path>`**:
  - `.json`: Writes complete `AuditReport` model to file.
  - `.md` or `.markdown`: Writes formatted Markdown table and findings document.
  - Any other extension: Raises error and exits with code 2.
- **Top-Level `AuditReport` Schema**:
  ```json
  {
    "metadata": {
      "tool_version": "0.1.0",
      "network_label": "Local-Network",
      "network_fingerprint": "fp:e3b0c44298fc1c14",
      "client_address": "127.0.0.1",
      "mode": "auto",
      "runs_per_check": 5,
      "target": "10.200.2.2",
      "include_identifiers": false
    },
    "target": {
      "host": "10.200.2.2",
      "control_port": 443,
      "healthy": true
    },
    "port_results": [
      {
        "probe": "tcp_syn_probe",
        "target": {"host": "10.200.2.2", "port": 25, "service": "SMTP"},
        "kind": "BLOCKED_RESET",
        "confidence": "HIGH",
        "evidence": "TCP RST received",
        "details": {}
      }
    ],
    "dns_results": [],
    "http_results": [],
    "findings": [
      {
        "severity": "critical",
        "code": "SMTP_BLOCKED",
        "title": "Outbound Email Submission Blocked",
        "explanation": "Outbound SMTP traffic to port 25 is terminated with TCP RST packets.",
        "verdicts": []
      }
    ],
    "summary": {
      "total_ports": 6,
      "open_ports": 5,
      "filtered_ports": 1,
      "dns_anomalies": 0,
      "http_tampering": 0
    }
  }
  ```

### 4.3 Input Formats for `compare` and `reclassify`

- **`compare <report_a> <report_b>`**:
  - Accepts both `.json` (pre-classified `AuditReport`) and `.jsonl` (raw observations file).
  - Automatically attempts `load_report()`; if input is `.jsonl` or loading fails, it invokes `read_run()` and runs raw observations through `build_audit_report()` before executing the diff.
  - Outputs visual Rich table diff or JSON (`{"changed": bool, "diffs": [...]}`).
- **`reclassify <run_id>`**:
  - Accepts either a file path or a run ID string. Searches `<path>`, `./reports/<run_id>`, `./reports/<run_id>.jsonl`, and `./reports/<stem>.jsonl`.
  - Requires raw `.jsonl` observation format.
  - Deserializes observations with `read_run()`, runs them through current classifier rules via `build_audit_report()`, and outputs to terminal, `--json`, or `--output`.

---

## Section 5: Inconsistencies and Discrepancies

The following discrepancies between code implementations, documentation (`README.md`), and lab guides (`lab/README.md`) have been verified:

1. **Validation Plot Output Filenames**:
   - `lab/validate.py` (lines 727, 734) writes: `confusion_matrix.png` and `netem_degradation.png`.
   - `lab/README.md` (lines 186, 188) documents them as: `results/confusion.png` and `results/netem_sweep.png`.
2. **`netpolicy http` Command Flag in README**:
   - `README.md` (line 134) states: `netpolicy http --target canary.example.com --port 80`.
   - `netpolicy/cli.py` (line 943) defines `--ports` / `-p`, and has no `--port` parameter. Running `--port 80` produces a Typer parameter error (`No such option: --port`).
3. **`campus` Scenario Omission in README Table**:
   - `README.md` Ground-Truth Validation Summary (lines 251-260) lists 8 scenarios, omitting `campus`.
   - `campus` is fully implemented and tested in `lab/scenarios.yaml`, `lab/scenario.sh`, `lab/README.md`, and `scripts/demo.sh`.
4. **Namespace Nomenclature Discrepancy in `netpolicy/lab/README.md`**:
   - `netpolicy/lab/README.md` (line 6) lists `np-firewall` as an example namespace (`np-client, np-firewall, np-server`).
   - The actual implementation across all scripts and tests uses `np-gw`.
5. **Python Invocation in Documentation vs Virtualenv Isolation**:
   - `README.md` (line 292) and `lab/README.md` (line 175) advise running: `sudo python3 lab/validate.py --runs 30 --netem`.
   - However, `scripts/bootstrap-python.sh` installs required lab packages (`matplotlib`, `pandas`, `yaml`) into `.linux-venv`. Calling `sudo python3` invokes the host system interpreter, which may fail the pre-flight import check unless `.linux-venv/bin/python` is explicitly passed (as `Makefile` correctly specifies).
6. **`netpolicy lab` CLI Subcommand Status**:
   - `netpolicy --help` advertises `lab: Manage and inspect reproducible Linux network namespace test labs.`
   - In `netpolicy/cli.py` (line 1160), the command is a stub that prints `"not implemented yet"`.
7. **`gw.lab` Fixed DNS Record Resolution in `lab/dns_server.py`**:
   - `DEFAULT_FIXED_A_RECORDS` in `lab/dns_server.py` maps `gw.lab` to `10.200.2.1` (the server-facing gateway interface) rather than `10.200.1.1` (the client-facing gateway interface).
8. **Empirical Field Findings Placeholders in README**:
   - Marked as `UNVERIFIED`: Validation accuracy numbers in `README.md` lines 251-260 are currently template placeholders (`[TBD: 100.0%]`, `[TBD: 0.0%]`) pending real-world field data population.
