# Changelog

All notable changes to `netpolicy` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-12

### Added
- Outbound TCP port reachability probes using raw TCP SYN (`scapy`) for root users and standard TCP connect (`socket`) for unprivileged users.
- Control probe mechanism on known open port (default 443) to distinguish general network packet loss from active firewall drops.
- Deterministic TCP classification rules identifying `OPEN`, `BLOCKED_DROP`, `BLOCKED_RESET`, `BLOCKED_ICMP` (with type/code breakdown), and `LOSSY`.
- DNS integrity probes:
  - `BlackholeProbe`: Queries RFC 5737 documentation addresses (192.0.2.1, 198.51.100.1) over UDP/53 and TCP/53 to detect middlebox interception.
  - `WhoamiProbe`: Queries TXT records to discover external resolver source IP.
  - `NxdomainProbe`: Queries nonexistent `.invalid` domains to detect NXDOMAIN hijacking / ISP search portal redirection.
  - `DohCrossCheckProbe`: Cross-references unencrypted UDP/53 responses against encrypted DNS-over-HTTPS (DoH).
  - `SourceMismatchProbe`: Detects resolver answer source IP divergence using raw UDP sockets.
- HTTP canary tampering probes (`HttpCanaryProbe`) and standalone canary server (`canary.server`):
  - Injected headers detection (`Via`, `X-Cache`, `X-Forwarded-For`).
  - SHA-256 payload integrity verification.
  - Nonce round-trip echoing (`X-NetPolicy-Nonce`) to identify rewriting proxies.
  - Reverse proxy test suite (`tests.tamper_proxy`).
- Pure rule-based findings engine synthesizing multi-probe signals into plain-English severity summaries (info, warn, critical).
- Terminal reporting with Rich tables, progress indicators, JSON export (`--json`), and Markdown reports (`--output`).
- `reclassify` CLI command to reload persisted JSONL runs and rerun updated classifier rules offline.
- Isolated Linux network namespace lab environment (`np-client`, `np-gw`, `np-server`) with automated ground-truth validation framework (`lab/validate.py`) and middlebox scenario manager (`lab/scenario.sh`).
- Static safety linter (`tests/test_lab_safety.py`) enforcing non-negotiable isolation rules and zero host modification.
