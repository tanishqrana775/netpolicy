# Terminal Report Redesign - Diagnostic Notes

This document records the diagnosis of suspected reporting and classification presentation defects identified during evaluation of `netpolicy reclassify` on saved real-world audit observations (specifically target `1.1.1.1`, run ID `20261115_150345_86c3aca1`).

Per the redesign constraints, these notes document the underlying behaviors without modifying any probing, classification, or engine logic. The presentation layer handles these edge cases gracefully through reliability gates, humanization, and aggregated summaries.

---

## Defect Diagnoses

### a) DNS Blackhole Probe Queries Audit Target
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/probes/dns.py:163-165`, `netpolicy/classify/dns.py:199`
- **Details**: In `BlackholeProbe.run()`, the code selects `servers = [target.host] if target.host not in ("auto", "default", "blackhole") else self.addresses`. When an audit runs against a target host such as `1.1.1.1`, the target host is passed as the resolver rather than the RFC 5737 documentation addresses (`192.0.2.1`, `198.51.100.1`). The classifier in `netpolicy/classify/dns.py:199` then outputs `f"Documentation address {r.raw.get('queried_address') or r.target.host} answered over {proto}/53"` assuming any queried address was a documentation address.

### b) Whoami IPv4-Only Ranges vs IPv6 Egress Addresses
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/classify/dns.py:61-68`, `netpolicy/classify/dns.py:291-308`
- **Details**: `DEFAULT_PROVIDER_WHOAMI_RANGES["1.1.1.1"]` only lists IPv4 CIDR blocks (`1.1.1.0/24`, `1.0.0.0/24`, `172.64.0.0/13`, `162.158.0.0/15`, `108.162.192.0/18`, `198.41.128.0/17`). When a dual-stack or IPv6-capable client queries 1.1.1.1, Cloudflare returns an authentic IPv6 egress resolver address (e.g., `2400:cb00:1007:1024::6816:306e`). The CIDR check `_is_ip_in_ranges()` returns `False` due to the address family mismatch, causing the classifier to falsely declare `INTERCEPTED` with `HIGH` confidence.

### c) HTTP Probe Attempts TLS on Port 80
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/probes/http.py:160-173`
- **Details**: When `target.port` is 80, line 166 sets `active_schemes = ["http", "https"]`. In the loop over `active_schemes`, line 169 checks `if target.port is not None: port = target.port`. For the `"https"` iteration, it keeps `port = 80` and calls `_fetch_https(host=host, port=80, ...)` instead of `self.https_port` (443). The server responds with plain HTTP to the TLS ClientHello, resulting in `[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1127)`.

### d) Same-Host HTTP-to-HTTPS 301 and 404 Classified as Captive Portal
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/classify/http.py:134-152`
- **Details**: `classify_http_checks()` checks `if redirects or status in (301, 302, 303, 307, 308, 403, 511):`. When an HTTP probe encounters a benign same-host upgrade (301 redirecting `http://1.1.1.1/canary.txt` to `https://1.1.1.1/canary.txt`), `redirects` is non-empty. When the endpoint subsequently returns 404 (because 1.1.1.1 is not a netpolicy canary server), lines 139-143 add `"Unexpected HTTP status code 404 on /canary.txt (expected 200) - possible captive portal or block page."` and classify the verdict as `REDIRECTED` with `HIGH` confidence.

### e) Third-Party Ports Without Reply Classified as BLOCKED_DROP HIGH
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/classify/tcp.py:227-237`
- **Details**: When a third-party host (such as `1.1.1.1`) is audited without owning the server, closed or unlistened ports (e.g. port 21 FTP or port 22 SSH) do not reply. Because `control_reachable` (port 443) is `True`, line 228 sets `conf = Confidence.HIGH` and classifies the port as `BLOCKED_DROP`. On third-party hosts where `expect_open` is False, lack of a reply cannot distinguish between server silence and an in-path firewall drop.

### f) Unreconciled Conflicting Verdicts (CLEAN & INTERCEPTED) in Same Run
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/classify/dns.py:278-321`
- **Details**: In `_evaluate_dns_probes()`, the loop over `answered_whoami` processes each observation individually without aggregation. One attempt returned IPv4 `172.69.202.51` (within range, yielding `CLEAN`), while subsequent attempts returned IPv6 `2400:cb00:...` (outside IPv4 ranges, yielding `INTERCEPTED`). Both verdicts were appended to `verdicts` for the exact same target and service, presenting contradictory output to the user.

### g) Client Address Displays 127.0.0.1
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/cli.py:442,1163,1191,1347`, `netpolicy/report/terminal.py:55-61`
- **Details**: When `include_identifiers` is False, `cli.py` defaults `client_address` to `"127.0.0.1"`. In `reclassify` (line 1347), `client_address` is unconditionally set to `"127.0.0.1"`. In `_render_header_panel()`, `127.0.0.1` is explicitly exempted from redaction masking and printed as the client's local IP address, misleading users into thinking the audit bound to the loopback interface.

### h) Summary Counts Tally Per-Attempt Rather Than Distinct Findings
- **Status**: CONFIRMED
- **File Reference**: `netpolicy/report/terminal.py:166-191`
- **Details**: `_render_summary_panel()` computes `dns_issues = sum(1 for d in report.dns_results if ...)` and `http_issues = sum(1 for h in report.http_results if ...)`. Multi-run audits produce multiple verdicts per probe (e.g., 20 observations for 5 runs across 2 paths and 2 schemes). The report prints `HTTP Anomalies: 20` when there was only 1 distinct failing endpoint repeated 20 times across attempts.
