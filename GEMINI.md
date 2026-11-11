# PROJECT: netpolicy
A Python 3.10+ CLI that audits a network (Wi-Fi, hotspot, campus) to reveal what it silently blocks, rewrites or intercepts: outbound port reachability, firewall behaviour (timeout vs TCP RST vs ICMP reject), DNS interception, HTTP tampering.

# STACK
typer, rich, scapy, dnspython (with DoH extra), httpx, pydantic or dataclasses, pyyaml, pytest, ruff, mypy, matplotlib, pandas. Use threads (ThreadPoolExecutor), not asyncio.

# ARCHITECTURE
netpolicy/ cli.py, config.py, models.py, engine/{runner.py,context.py}, probes/{base.py,tcp_connect.py,tcp_syn.py,dns.py,http.py}, classify/{tcp.py,dns.py,http.py}, store/raw.py, report/{terminal.py,jsonout.py,markdown.py}, lab/ (shell + python for the namespace test environment), tests/.

# DESIGN RULES
1. Probes only record raw Observations (what was seen: replies, flags, TTLs, ICMP type/code, timings). They never decide what it means.
2. Classifiers are pure functions: list[Observation] -> Verdict with a confidence level (high/medium/low) and human-readable evidence strings. No I/O in classifiers.
3. Every audit includes a control probe (a target known to be reachable). If the control fails, verdicts become UNKNOWN, never BLOCKED.
4. A single missing reply is packet loss, not a block. Always retry before concluding.
5. Persist raw observations to append-only JSONL before classification so results can be re-classified later.
6. Every verdict carries a confidence level and the evidence behind it.
7. All output modes support --json, --quiet, --verbose, --no-color. Exit codes: 0 = clean, 1 = findings, 2 = error.

# SAFETY RULES (non-negotiable)
- Probes send traffic only to targets from config or the CLI. No range scanning, no default scan of third parties. Rate-limit all probes.
- Python package code never modifies the host: no iptables/nft, no route changes, no sysctl, no resolv.conf edits.
- All lab firewall, routing, sysctl and tc commands run ONLY inside Linux network namespaces named with the prefix np-, via "ip netns exec". Never generate a firewall, routing, sysctl or tc command that applies to the host namespace.
- Never run commands with sudo. Print them for the user to run.
- Never store SSIDs, MAC addresses or public IPs in reports unless --include-identifiers is passed.

# CODE QUALITY
Type hints everywhere, docstrings on public functions, ruff-clean, small modules, tests for every non-trivial function.