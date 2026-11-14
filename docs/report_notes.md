# Netpolicy Technical Report Notes & Ground-Truth Fact Sheet

This document contains the structured technical fact sheet compiled directly from the `netpolicy` repository as of November 2026. It serves as the authoritative source of truth for the academic project report. Any item whose exact value or cause could not be verified directly in the repository is explicitly designated as `UNVERIFIED`.

---

## 1. Modules and Responsibilities

### 1.1 Core CLI & Configuration
- **`netpolicy/cli.py`**: Command-line interface built using Typer. Registers and dispatches seven subcommands:
  - `audit`: Executes full network audit (ports + DNS + HTTP).
  - `ports`: Audits outbound TCP port reachability and middlebox interference.
  - `dns`: Audits DNS resolution integrity, blackhole interception, and NXDOMAIN hijacking.
  - `http`: Audits HTTP canary tampering, header injection, body modification, and nonces.
  - `compare`: Compares two audit reports (`.json` or `.jsonl`) and identifies differences.
  - `reclassify`: Re-evaluates raw observation JSONL files through updated classifier logic.
  - `lab`: CLI entrypoint stub (`not implemented yet`).
- **`netpolicy/config.py`**: Pydantic configuration hierarchy (`AppConfig`, `GeneralConfig`, `PortConfig`, `DNSConfig`, `HTTPConfig`). Parses YAML configuration files and CLI override lists.
- **`netpolicy/__main__.py`**: Module executable entrypoint (`from netpolicy.cli import app; app()`) enabling `python -m netpolicy`.
- **`netpolicy/demo.py`**: Generates synthetic, realistic mock `AuditReport` data for demonstration without live I/O.
- **`netpolicy/findings.py`**: Pure, rule-based inference engine mapping classified probe verdicts into structured `Finding` objects across severity tiers (`info`, `warn`, `critical`) with plain-English summaries.

### 1.2 Execution Engine
- **`netpolicy/engine/context.py`**: Environment context provider discovering local IP address, default gateway IP, active DNS resolver IP, and computing a deterministic SHA-256 network fingerprint (`fp:...`).
- **`netpolicy/engine/runner.py`**: Multithreaded execution orchestrator using `ThreadPoolExecutor` (concurrency limit: 8 workers). Manages probe jobs, tracks progress, enforces per-probe timeouts, and logs raw observations to append-only JSONL storage.
- **`netpolicy/engine/pipeline.py`**: Data aggregation pipeline grouping raw observations by `(probe_name, target)`, dispatching them to domain classifiers, aggregating verdicts, verifying control probe health, and assembling the final `AuditReport`.

### 1.3 Active Measurement Probes
- **`netpolicy/probes/base.py`**: Abstract base class `Probe` defining standard contracts for probe execution, target binding, and observation emission.
- **`netpolicy/probes/tcp_connect.py`**: Unprivileged TCP probe using standard operating system `socket.connect()` calls with microsecond timing measurements.
- **`netpolicy/probes/tcp_syn.py`**: Privileged TCP probe using Scapy to construct raw TCP SYN packets with randomized source ports and sequence numbers. Sniffs responses to detect TCP SYN-ACK, TCP RST, and in-path ICMP unreachable datagrams.
- **`netpolicy/probes/dns.py`**: DNS probes querying UDP/53 and DoH:
  - `BlackholeProbe`: Queries RFC 5737 documentation addresses (`192.0.2.1`, `198.51.100.1`) to detect middlebox interceptors answering unroutable destinations.
  - `WhoamiProbe`: Queries TXT records (`whoami.lab` or public resolvers) to determine the apparent client resolver IP.
  - `NxdomainProbe`: Queries nonexistent `.invalid` domains to detect NXDOMAIN hijacking.
  - `DohCrossCheckProbe`: Cross-references unencrypted UDP/53 resolutions against encrypted DNS-over-HTTPS (`cloudflare-dns.com`).
  - `SourceMismatchProbe`: Detects resolver answer source IP divergence using raw UDP sockets.
- **`netpolicy/probes/http.py`**: Active HTTP canary probe querying `/canary.txt`, `/echo`, and `/manifest.json`. Transmits unique `X-NetPolicy-Nonce` headers, asserts response headers, and validates payload SHA-256 hashes.

### 1.4 Inference Classifiers
- **`netpolicy/classify/tcp.py`**: Pure classifier evaluating TCP observation sets into `OPEN`, `BLOCKED_DROP`, `BLOCKED_RESET`, `BLOCKED_ICMP`, `LOSSY`, `CLOSED_OR_RESET`, and `CONTROL_FAILED`.
- **`netpolicy/classify/dns.py`**: Pure classifier evaluating DNS observation sets into `CLEAN`, `INTERCEPTED`, `REWRITTEN`, `MISMATCH`, and `UNKNOWN`.
- **`netpolicy/classify/http.py`**: Pure classifier evaluating HTTP canary observation sets into `CLEAN`, `HEADERS_INJECTED`, `BODY_MODIFIED`, `PROXIED`, `REDIRECTED`, and `UNKNOWN`.

### 1.5 Telemetry & Reporting
- **`netpolicy/store/raw.py`**: Thread-safe, append-only JSONL persistence engine (`RawObservationStore`) flushing telemetry immediately to `reports/<run_id>.jsonl`. Includes `chown_to_sudo_user()` to prevent root ownership locks.
- **`netpolicy/report/compare.py`**: Report diffing engine identifying verdict divergences, reachability changes, and finding deltas.
- **`netpolicy/report/jsonout.py`**: Serializes and deserializes `AuditReport` models to and from JSON.
- **`netpolicy/report/markdown.py`**: Renders formatted Markdown audit reports with summary panels.
- **`netpolicy/report/terminal.py`**: Rich terminal renderer formatting classified port tables, DNS/HTTP checks, and findings.

### 1.6 Standalone Canary & Lab Services
- **`canary/server.py`**: Standalone HTTP canary server listening on port 80 serving `/canary.txt`, `/echo`, and `/manifest.json`.
- **`lab/banner_servers.py`**: Multi-port TCP server listening on ports 21, 22, 25, 443, and 587, sending protocol banners (FTP, SSH, SMTP, Control, Submission).
- **`lab/dns_server.py`**: dnspython-based UDP DNS responder on port 53 answering `whoami.lab` with query source IP, fixed A records, authentic NXDOMAIN, and `--rewrite` hijacking mode.
- **`tests/tamper_proxy.py`**: HTTP reverse proxy injecting `Via`/`X-Cache` headers, modifying body contents, or stripping nonces.

---

## 2. Domain Data Models

Implemented with Pydantic in `netpolicy/models.py`:
- **`Target`**: Destination descriptor (`host: str`, `port: int`, `protocol: str = "tcp"`, `service: str = "custom"`, `expect_open: bool = False`).
- **`Observation`**: Raw measurement record (`probe_name`, `target`, `timestamp`, `success`, `rtt_ms`, `tcp_flags`, `icmp_type`, `icmp_code`, `ttl`, `raw_evidence: dict`).
- **`VerdictKind` (Enum)**:
  - Port: `OPEN`, `OK`, `CLEAN`, `BLOCKED_DROP`, `BLOCKED_RESET`, `BLOCKED_ICMP`, `LOSSY`, `CLOSED_OR_RESET`, `CONTROL_FAILED`, `UNKNOWN`.
  - DNS: `CLEAN`, `OK`, `INTERCEPTED`, `REWRITTEN`, `MISMATCH`, `UNKNOWN`.
  - HTTP: `CLEAN`, `OK`, `HEADERS_INJECTED`, `BODY_MODIFIED`, `PROXIED`, `REDIRECTED`, `UNKNOWN`.
- **`Verdict`**: Evaluated check outcome (`probe`, `target`, `kind: VerdictKind`, `confidence: str` (`high`, `medium`, `low`), `evidence: list[str]`, `details: dict`).
- **`Finding`**: User-facing policy conclusion (`severity: str` (`info`, `warn`, `critical`), `code: str`, `title: str`, `explanation: str`, `verdicts: list[Verdict]`).
- **`ReportMetadata`**: Audit execution context (`tool_version`, `network_label`, `network_fingerprint`, `client_address`, `run_time`, `mode`, `runs_per_check`, `target`, `include_identifiers`).
- **`AuditReport`**: Comprehensive root report model aggregating metadata, target status, port results, DNS results, HTTP results, findings, and summary counts.

---

## 3. Active Probes and Recorded Telemetry

| Probe Name | Class | Target / Ports | Protocol | Measurements / Telemetry Recorded |
|---|---|---|---|---|
| `tcp_connect_probe` | `TcpConnectProbe` | Destination ports (e.g. 21, 22, 25, 80, 443, 587) | TCP (OS socket `connect`) | Success boolean, elapsed RTT (ms), OS socket error code/string (e.g. `ECONNREFUSED`, `ETIMEDOUT`). |
| `tcp_syn_probe` | `TcpSynProbe` | Destination ports (e.g. 21, 22, 25, 80, 443, 587) | TCP (Raw Scapy SYN) | SYN-ACK / RST response flags, response IP TTL, elapsed RTT (ms), in-path ICMP type and code if unreachable. |
| `blackhole_dns_probe` | `BlackholeProbe` | `192.0.2.1`, `198.51.100.1` | UDP/53, TCP/53 | Reply received boolean, rcode, answers, source address, elapsed RTT (ms). |
| `whoami_dns_probe` | `WhoamiProbe` | Queried nameserver | UDP/53 (TXT query) | Echoed client source IP address string, resolver identity, elapsed RTT (ms). |
| `nxdomain_probe` | `NxdomainProbe` | Nonexistent `.invalid` names | UDP/53 | Return code (`NXDOMAIN` vs `NOERROR`), returned A records, answers list. |
| `doh_crosscheck_probe`| `DohCrossCheckProbe` | Domain list (control vs public DoH) | UDP/53 vs DoH HTTPS | Plain DNS answer IP set, DoH answer IP set, subnet overlap comparison. |
| `source_mismatch_probe`|`SourceMismatchProbe`| Queried nameserver | Raw UDP socket (port 53) | Queried destination IP vs actual socket recvfrom source IP. |
| `http_canary_probe` | `HttpCanaryProbe` | Target host port 80 / 443 | HTTP/1.1 (GET `/canary.txt`, `/echo`) | HTTP status code, ordered response headers, payload SHA-256 hash, echoed nonce token, redirect location. |

---

## 4. Classifier Inference Rules & Decision Logic

### 4.1 TCP Reachability Classifier (`classify/tcp.py`)
- **`OPEN`** (Confidence: `HIGH`): Received TCP SYN-ACK in raw mode, or socket connect succeeded.
- **`BLOCKED_DROP`** (Confidence: `HIGH`): 0 replies received across all retries and runs, while target control probe (443) succeeded.
- **`BLOCKED_RESET`** (Confidence: `HIGH`): TCP RST received and RST TTL differs from control port SYN-ACK TTL by $> 2$ (when `expect_open=True`).
- **`BLOCKED_ICMP`** (Confidence: `HIGH`): ICMP Destination Unreachable received (Type 3 Code 13 `Admin Prohibited`, Code 3 `Port Unreachable`, Code 1 `Host Unreachable`, Code 0 `Net Unreachable`).
- **`CLOSED_OR_RESET`** (Confidence: `LOW`): TCP RST received when port was not known to be open (`expect_open=False`).
  - *Known Ambiguity*: Without ground-truth server state, a closed port on the target server and an injected RST from a firewall look identical.
- **`LOSSY`** (Confidence: `MEDIUM`): Mixed timeouts and successes across iterations, but control port remains healthy.
- **`CONTROL_FAILED`** (Confidence: `HIGH`): Target control port (443) timed out or failed. Suppresses false block conclusions.

### 4.2 DNS Resolution Classifier (`classify/dns.py`)
- **`CLEAN`** (Confidence: `HIGH`): Normal resolution; authentic `NXDOMAIN` for `.invalid` domain; resolver IP within expected subnet.
- **`INTERCEPTED`** (Confidence: `HIGH`): Reply received from RFC 5737 blackhole address, or UDP/53 answer source IP differs from queried IP, or `whoami` resolver identity is outside expected provider range.
- **`REWRITTEN`** (Confidence: `HIGH`): Nonexistent `.invalid` domain returned an `A` record instead of `NXDOMAIN` (NXDOMAIN hijacking).
- **`MISMATCH`** (Confidence: `MEDIUM` / `LOW`): Plain UDP/53 answers and DoH answers do not overlap (evaluated at `/16` subnet level).
  - *Known Ambiguity*: CDN Anycast geo-routing legitimately causes IP divergence; used strictly as supporting evidence.

### 4.3 HTTP Canary Classifier (`classify/http.py`)
- **`CLEAN`** (Confidence: `HIGH`): Status 200; payload SHA-256 matches manifest; no injected proxy headers; echoed nonce intact.
- **`HEADERS_INJECTED`** (Confidence: `HIGH`): Proxy headers detected (`Via`, `X-Cache`, `X-Forwarded-For`).
- **`BODY_MODIFIED`** (Confidence: `HIGH`): Status 200, but payload SHA-256 hash does not match expected manifest hash.
- **`PROXIED`** (Confidence: `HIGH`): Echoed `X-NetPolicy-Nonce` missing, altered, or replaced by gateway.
- **`REDIRECTED`** (Confidence: `HIGH`): Status 301/302/307/308 redirecting client to captive portal login page.

---

## 5. Lab Architecture & Cyber-Range Topology

### 5.1 Topology & Network Isolation
- **Namespaces**:
  - `np-client`: Origin node executing audit commands.
  - `np-gw`: Forwarding middlebox router enforcing iptables policies and traffic control (`tc netem`).
  - `np-server`: Destination target server hosting background mock listeners.
- **Veth Pairs**:
  - `veth-client` (`np-client`) $\leftrightarrow$ `veth-gw-c` (`np-gw`).
  - `veth-gw-s` (`np-gw`) $\leftrightarrow$ `veth-server` (`np-server`).
- **Addressing & Subnets**:
  - Subnet 1 (`10.200.1.0/24`): `np-client` = `10.200.1.2`, `np-gw` client-side = `10.200.1.1`.
  - Subnet 2 (`10.200.2.0/24`): `np-gw` server-side = `10.200.2.1`, `np-server` = `10.200.2.2`.
- **Routing & Blackholes**:
  - `np-client`: Default route via `10.200.1.1 dev veth-client`.
  - `np-server`: Default route via `10.200.2.1 dev veth-server`.
  - `np-gw`: Forwarding enabled (`sysctl -w net.ipv4.ip_forward=1`). Blackhole routes: `192.0.2.0/24`, `198.51.100.0/24`.
- **DNS Configuration**:
  - Per-namespace `/etc/netns/np-<name>/resolv.conf` pointing to `10.200.2.2` and `10.200.1.1`. Host `/etc/resolv.conf` untouched.
- **Target Services (`np-server`)**:
  - Banner Listeners (`lab/banner_servers.py`): TCP ports 21 (FTP), 22 (SSH), 25 (SMTP), 443 (HTTPS/Control), 587 (Submission).
  - Canary HTTP Server (`canary/server.py`): TCP port 80 (`/canary.txt`, `/echo`, `/manifest.json`).
  - Lab DNS Server (`lab/dns_server.py`): UDP port 53 (`whoami.lab`, fixed A records, NXDOMAIN, `--rewrite`).

---

## 6. Middlebox Scenarios Catalogue

Applied via `lab/scenario.sh` and defined in `lab/scenarios.yaml`:

| Scenario Name | Exact Command / Mechanism Applied | Target NS | Expected Port Verdict | Expected DNS Verdict | Expected HTTP Verdict |
|---|---|---|---|---|---|
| `clean` | All iptables rules flushed; policy `FORWARD ACCEPT` | `np-gw` | Ports 21, 22, 25, 443, 587 `OPEN` | `CLEAN` | `CLEAN` |
| `drop-smtp` | `iptables -A FORWARD -p tcp --dport 25 -j DROP` | `np-gw` | Port 25 `BLOCKED_DROP`; others `OPEN` | `CLEAN` | `CLEAN` |
| `reset-smtp` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with tcp-reset` | `np-gw` | Port 25 `BLOCKED_RESET`; others `OPEN` | `CLEAN` | `CLEAN` |
| `icmp-admin` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-admin-prohibited` | `np-gw` | Port 25 `BLOCKED_ICMP` (code 13); others `OPEN` | `CLEAN` | `CLEAN` |
| `icmp-port-unreach` | `iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable` | `np-gw` | Port 25 `BLOCKED_ICMP` (code 3); others `OPEN` | `CLEAN` | `CLEAN` |
| `dns-dnat` | `iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53` | `np-gw` | Ports `OPEN` | `INTERCEPTED` | `CLEAN` |
| `nxdomain-rewrite` | DNS server in `np-server` restarted with `--rewrite` flag | `np-server` | Ports `OPEN` | `REWRITTEN` | `CLEAN` |
| `http-proxy` | Tamper proxy on port 8080; `iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.200.1.1:8080` | `np-gw` | Ports `OPEN` | `CLEAN` | `HEADERS_INJECTED` |
| `campus` | Composite: applies `reset-smtp` + `dns-dnat` + `http-proxy` | `np-gw` | Port 25 `BLOCKED_RESET`; others `OPEN` | `INTERCEPTED` | `HEADERS_INJECTED` |

*Exclusivity Rule*: Every run of `lab/scenario.sh` first executes an unconditional flush (`iptables -F`, `-X`, `-t nat -F`, `-t nat -X`, `-t mangle -F`, proxy termination, DNS server restore) before applying the scenario.

---

## 7. Experimental Validation & Verified Data

### 7.1 Validation Framework (`lab/validate.py`)
- Evaluates $N$ audit runs per scenario inside `np-client` against `lab/scenarios.yaml`.
- Optional degradation sweep via `tc qdisc add dev veth-gw-s root netem` in `np-gw`:
  - Packet loss: 0%, 1%, 2%, 5%, 10%.
  - RTT latency: 10 ms, 50 ms, 100 ms, 200 ms.
- Computes confusion matrix per check type, classification accuracy, and clean scenario false-positive rate (FPR). Quality gate enforces $\text{FPR} = 0.0\%$ and $\text{Accuracy} \ge 95\%$.

### 7.2 Verified Artifacts Found in Repository
- **`results/validation.csv`**: **NOT FOUND** on disk (`UNVERIFIED: results to be inserted after running validate.py`).
- **`results/accuracy.png`**: Present on disk (82,421 bytes).
- **`results/confusion.png`**: Present on disk (150,510 bytes).
- **`demo-output/baseline.json`**: Present on disk (8,651 bytes). Verified values:
  - Tool version: `0.1.0`. Mode: `raw`. Target: `10.200.2.2`. Runs: 2.
  - Ports 21, 22, 25, 80, 443, 587 all verified `OPEN` with `high` confidence.
  - Findings: `[]` (empty list, zero findings).
- **`demo-output/tampered.json`**: Present on disk (9,433 bytes). Verified values:
  - Scenario applied: `reset-smtp`.
  - Port 25 classified as `CLOSED_OR_RESET` (`low` confidence; evidence: `TCP RST received (TTL 64); expect_open=False means closed port and injected reset look identical`).
  - Findings: `[{"title": "Direct SMTP (Port 25) Blocked", "severity": "info", "summary": "Direct SMTP port 25 is blocked (standard ISP anti-abuse policy); submission ports 465/587 remain accessible."}]`.

---

## 8. Telemetry Storage & Report Formats

- **Raw Telemetry (`.jsonl`)**: Persisted in `./reports/{YYYYMMDD_HHMMSS}_{token_hex}.jsonl`. Each line contains `{"run_id": str, "timestamp": float, "probe_name": str, "observation": {...}}`. Flushed immediately after every measurement.
- **Classified Reports**:
  - `--json`: Outputs serialized `AuditReport` JSON to `stdout`.
  - `--output <path>`: Writes to file; accepts `.json` (classified JSON) or `.md`/`.markdown` (Markdown report). Other extensions exit code 2.
- **`compare` Compatibility**: Accepts both `.json` (pre-classified) and `.jsonl` (raw observations, reclassified on the fly).
- **`reclassify` Compatibility**: Accepts `.jsonl` files (by path or by run ID from `./reports/`), re-running classifiers and generating report output without network I/O.

---

## 9. Technology Stack and Dependency Specifications

| Component / Subsystem | Technology | Version Constraint | Role & Justification |
|---|---|---|---|
| Runtime Language | Python | $\ge 3.10$ | Core application language; leverages modern type unions, match statements, and standard libraries. |
| CLI Framework | Typer | $\ge 0.12.0$ | Modern command-line interface framework with automatic type casting, flag parsing, and help generation. |
| Terminal Formatting | Rich | $\ge 13.0.0$ | Renders stylized tables, colored badges, progress bars, and structured terminal layouts. |
| Packet Crafting & Sniffing | Scapy | $\ge 2.5.0$ | Constructs raw TCP SYN packets with custom sequence numbers; captures SYN-ACK, RST, and ICMP unreachable packets. |
| DNS Wire Protocol | dnspython | $\ge 2.6.0$ (`[doh]`) | Encodes and decodes DNS wire format packets; executes UDP/53 and encrypted DoH queries. |
| HTTP Client | HTTPX | $\ge 0.27.0$ | Asynchronous and synchronous HTTP/1.1 and HTTP/2 client for DoH and canary verification. |
| Configuration | PyYAML | $\ge 6.0$ | Parses YAML configuration and scenario ground-truth definition files. |
| Data Modeling | Pydantic | $\ge 2.0.0$ | Validates runtime configuration and provides immutable schema serialization. |
| Test Framework | pytest | $\ge 8.0.0$ (`[dev]`, `[lab]`) | Unit test and static safety test suite execution. |
| Code Linting & Formatting | Ruff | $\ge 0.4.0$ (`[dev]`) | Static code analysis, linting, and automated formatting. |
| Static Type Checker | Mypy | $\ge 1.10.0$ (`[dev]`) | Static type checking enforcing strict typing across codebase. |
| Plotting & Visualization | Matplotlib | $\ge 3.8.0$ (`[lab]`) | Generates confusion matrix heatmaps and accuracy bar charts. |
| Data Frames & Analysis | Pandas | $\ge 2.2.0$ (`[lab]`) | Analyzes multi-run validation data and writes structured CSV datasets. |
| Document Generation | python-docx | `1.2.0` (in venv) | Generates academic-style `.docx` project reports. |
| Network Virtualization | Linux Namespaces (`netns`) | Kernel built-in | Provides isolated networking stacks (`np-client`, `np-gw`, `np-server`). |
| Virtual Links | Virtual Ethernet (`veth`) | Kernel built-in | Point-to-point bidirectional virtual cables connecting namespaces. |
| Middlebox Filtering | iptables (`nft` / `legacy`) | System tool | Injects packet drops, TCP resets, ICMP rejects, and DNAT redirection rules. |
| Traffic Impairment | `tc netem` | System tool | Injects synthetic packet loss ($0\text{--}10\%$) and latency ($10\text{--}200\text{ ms}$). |
| Virtualization Layer | WSL2 / Kali Linux | Microsoft WSL2 | Linux kernel virtualization enabling namespace execution on Windows 11. |
| AI Coding Assistant | Google Antigravity / Gemini CLI | Agent CLI | Assisted in architectural design, testing, safety linters, and documentation. |
