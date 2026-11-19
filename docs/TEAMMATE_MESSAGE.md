# Teammate Onboarding & Architecture Brief

**Document Role**: Teammate Orientation, Project Brief, and Architecture Reference  
**Author**: Principal Engineer / Technical Lead  
**Target Audience**: Collaborating Engineer / Onboarding Developer  

---

## 1. 2-Minute WhatsApp-Style Overview

> Hey! 👋 Quick update on `netpolicy`—it’s in great shape and ready for you to pull and test.
>
> **What is this tool?**  
> It’s a CLI network auditor (Python + Typer + Rich + Scapy) that tells you what your network is secretly doing—whether your hotel Wi-Fi, university network, or mobile hotspot is silently dropping mail ports, rewriting your DNS lookups, injecting proxy headers, or hiding behind a captive portal.
>
> **What did we build?**  
> 1. A super clean, Clack-style interactive wizard that launches when you just run `netpolicy` with no args. It guides non-technical users step-by-step through network checks, target selection, permission checks, and exports a 12-section Markdown report.
> 2. A custom, rock-solid single-key reader (`keys.py`) that handles arrow keys, Enter, and Esc across Windows (`msvcrt`) and Linux without any third-party terminal input dependencies.
> 3. Zero-touch Windows-to-Kali-WSL handoff (`wsl.py`): if you're on Windows and want raw packet injection (SYN probing), it seamlessly launches root Kali Linux in WSL2, runs the audit, and returns you to Windows.
> 4. Full test suite with 331 passing tests, plus comprehensive docs under `docs/`.
>
> **How to test it in 30 seconds?**  
> Clone the repo, set up a venv with Python 3.10+, run `pip install -e ".[dev]"`, and type `netpolicy audit --demo`. You’ll see the full gradient banner and report.
>
> Check out `docs/TEAMMATE_SETUP.md` for full setup instructions and `docs/TWO_LAPTOP_TEST.md` for testing between our two laptops on Wi-Fi and hotspot! 🚀

---

## 2. Technical Architecture Summary

`netpolicy` solves the problem of middlebox transparency. When a connection fails, ping and speedtests cannot explain *why*. `netpolicy` answers whether the target is down, or if an in-path firewall, transparent proxy, or ISP DNS resolver is tampering with the connection.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Entry Points                               │
│     Interactive Wizard (TUI)             Non-Interactive CLI           │
│     `netpolicy` (20-State FSM)           `netpolicy audit / ports ...` │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      In-Process Coordinator                            │
│                 `netpolicy.wizard.runner` & `cli.py`                   │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Active Probing Engine                          │
│  Layer 3/4 TCP Probes   │  DNS & DoH Probes     │  HTTP Integrity      │
│  • Raw SYN (Scapy)      │  • RFC 5737 Blackhole │  • Canary Manifest   │
│  • Socket Connect (OS)  │  • NXDOMAIN Hijack    │  • Header Injection  │
│  • Control Port (443)   │  • DoH Cross-check    │  • SHA-256 Hash      │
│  • ICMP Unreachables    │  • Socket Src Verify  │  • Nonce Reflection  │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Deterministic Inference                          │
│              `netpolicy.classify.*` & `report.summary`                 │
│  • Pure functional classifiers: Observations -> Verdict                │
│  • Reliability Gates (G1: Canary, G2: Blackhole, G3: Upgrade, G4: IPv6)│
│  • Plain-Language Humanizer (`netpolicy.report.humanize`)              │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Presentation & Storage                         │
│  • Terminal UI (`report.terminal`)     • Academic MD (`labreport.py`)  │
│  • JSON/JSONL Store (`reports/*.jsonl`) • Wireshark PCAP (`capture.py`) │
└────────────────────────────────────────────────────────────────────────┘
```

### Core Architecture Pillars:
1. **Layer 3/4 TCP Probing**: Differentiates between silent packet drops (`BLOCKED_DROP`), firewall RST injection (`BLOCKED_RESET`), and in-path ICMP unreachable rejections (Type 3 Codes 0, 1, 2, 3, 9, 10, 13).
2. **DNS & DoH Integrity**: Queries unroutable documentation IPs (`192.0.2.1`) to catch transparent middlebox resolvers, tests `.invalid` domains to catch NXDOMAIN search portal hijacking, and cross-checks plain UDP/53 against encrypted DNS-over-HTTPS (DoH).
3. **HTTP Tampering & Captive Portal Detection**: Validates status codes, ordered response headers (`Via`, `X-Cache`, `X-Forwarded-For`), body SHA-256 hashes, and custom `X-NetPolicy-Nonce` reflection against a known canary manifest.
4. **Reliability Gates (G1–G5)**: Prevents false positives by verifying control link reachability, distinguishing benign HTTP-to-HTTPS upgrades (G3), and calibrating unverified targets (G1).

---

## 3. Repository File & Folder Map

```text
netpolicy/
├── cli.py                     # Typer CLI application entry point, subcommands, and flags
├── config.py                  # YAML/CLI configuration parser and port definitions
├── demo.py                    # Synthetic anomaly generator for offline demonstrations
├── models.py                  # Pydantic and dataclass models (Observation, Verdict, AuditReport)
├── classify/                  # Pure functional inference engines (no I/O, no network)
│   ├── dns.py                 # Evaluates DNS hijacking, blackhole responses, and DoH discrepancies
│   ├── http.py                # Evaluates HTTP header injection, body modification, and status codes
│   └── tcp.py                 # Evaluates TCP SYN/socket responses, TTL deltas, and ICMP rejections
├── engine/                    # Probe execution pipeline and execution coordination
│   ├── context.py             # Runtime execution context carrying settings and metadata
│   ├── pipeline.py            # Aggregates raw observations and compiles final AuditReport
│   └── runner.py              # Parallel thread executor for probe dispatch
├── probes/                    # Network probe implementations
│   ├── base.py                # Abstract base class defining probe interfaces
│   ├── dns.py                 # DNS probes (Blackhole, NXDOMAIN, Whoami, DoH, SourceMismatch)
│   ├── http.py                # HTTP canary probe evaluating headers, nonces, and SHA-256 hashes
│   ├── tcp_connect.py         # Standard OS socket connect probe (unprivileged mode)
│   └── tcp_syn.py             # Scapy raw TCP SYN packet injector with randomized sequence numbers
├── report/                    # Reporting, data modeling, and presentation formatting
│   ├── compare.py             # Computes differences between two audit reports (.json or .jsonl)
│   ├── humanize.py            # Central plain-language string store, translations, and redirect formatters
│   ├── jsonout.py             # JSON serialization and report loading helpers
│   ├── markdown.py            # GitHub-flavored Markdown report exporter
│   ├── summary.py             # Issue aggregation, Reliability Gates (G1–G5), and verdict computation
│   └── terminal.py            # Rich terminal tables, color-coded verdict boxes, and summary banners
├── store/                     # Observation persistence
│   └── raw.py                 # Append-only JSONL observation store (`reports/<run_id>.jsonl`)
├── ui/                        # User interface and platform integration
│   ├── banner.py              # Gradient ASCII banner, compact headers, and terminal status footers
│   └── wsl.py                 # Zero-touch Windows-to-Kali-WSL interactive launcher
└── wizard/                    # Interactive guided wizard subsystem
    ├── capabilities.py        # System environment inspection (OS, root, Scapy, namespaces, saved runs)
    ├── capture.py             # BPF-filtered packet capture context manager (`reports/capture-*.pcap`)
    ├── fsm.py                 # Formal 20-state Finite-State Machine, transition rules, and guards
    ├── keys.py                # Low-level cross-platform single-keystroke reader (msvcrt / termios)
    ├── labreport.py           # 12-section structured Academic Markdown Lab Report generator
    ├── plan.py                # Translates user wizard choices into concrete CommandPlans
    ├── recommend.py           # Dynamic recommendation engine suggesting context-aware next steps
    ├── runner.py              # In-process execution coordinator and process resource tracker
    └── ui.py                  # Rich Live Clack-style UI adapter, menu loops, and state handlers
scripts/
├── bootstrap-python.sh        # Linux / WSL Python virtual environment bootstrap script
├── bootstrap-system.sh        # Linux / WSL system dependency installer (apt-get packages)
├── doctor.sh                  # Diagnostic script verifying network and system health
└── install-windows.ps1        # User-level Windows shim installer creating %LOCALAPPDATA%\netpolicy\bin
docs/
├── TESTING_PLAYBOOK.md        # Complete QA playbook, state machine guide, and bug matrix
├── GITHUB_HANDOFF.md          # Git staging sequence, .gitignore analysis, and pre-push checklist
├── TEAMMATE_MESSAGE.md        # This onboarding brief and architecture summary
├── TEAMMATE_SETUP.md          # Zero-to-running setup guide and troubleshooting matrix
└── TWO_LAPTOP_TEST.md         # Multi-machine testing playbook across Wi-Fi and mobile hotspot
```

---

## 4. Honest Known Limitations & Target Nuances

To test the tool effectively and avoid logging false bugs, keep these technical design realities in mind:

### 1. Why `127.0.0.1` or `8.8.8.8` Can Make Closed Ports Read as `RESTRICTED`
- When you audit a target host you do not own (or `127.0.0.1` where no services are running on ports 21, 22, 25), the operating system sends back a standard TCP RST (Connection Refused).
- In `netpolicy/classify/tcp.py`, receiving a TCP RST when `expect_open` is `False` is classified as `CLOSED_OR_RESET` with `LOW` confidence because it is technically impossible to know whether the endpoint has no listener or an in-path firewall injected the RST.
- In `netpolicy/report/summary.py`, if **two or more service groups** return `CLOSED_OR_RESET` (e.g. port 22 "remote login" and port 25 "sending mail" are both closed), `compute_verdict()` aggregates them into a `RESTRICTED` verdict:
  ```python
  if has_tampering or len(blocked_groups) >= 2:
      return VerdictSummary(level="RESTRICTED", ...)
  ```
- **Why this happens**: Without a control server or known open baseline, `netpolicy` conservatively treats multiple refused core services as potential policy blocks.
- **How to get accurate results**: Audit against a server hosting the netpolicy canary (`canary/server.py`), test in the namespace lab (`10.200.1.254`), or run against your own server where ports are configured and known.

### 2. The HTTP Canary Manifest Requirement
- `netpolicy http` tests request `/netpolicy-canary.json` and verify the cryptographic SHA-256 hash of the response payload.
- If you point `netpolicy http` at an arbitrary public web server (like `google.com` or `cloudflare.com`), the server returns an HTTP 404 or redirect.
- **Reliability Gate G1** fires immediately: it recognizes that the server does not host the netpolicy canary and marks the HTTP tampering checks inconclusive rather than claiming the network tampered with the web page.

### 3. Hyper-V NAT in WSL2
- WSL2 networking operates behind a virtual Hyper-V NAT switch. The Windows host kernel may rewrite IP headers, intercept RST packets, or modify TTL values before packets leave the physical network adapter.
- For complete raw packet accuracy and raw SYN injection, run inside Kali WSL with host bridging or on native Linux.
