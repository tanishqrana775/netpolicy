# Experimental Methodology & Validation Report

This document specifies the experimental methodology used to validate `netpolicy`. The evaluation follows a two-phase protocol:
1. **Phase 1: Ground-Truth Controlled Lab Experiments** inside isolated Linux network namespaces.
2. **Phase 2: In-the-Wild Auditing** across three distinct real-world network deployments (Campus Wi-Fi, Mobile Cellular Hotspot, and Residential Broadband).

---

## 1. Experimental Objectives

The experiment evaluates:
- **Detection Accuracy**: Whether deterministic classifiers correctly identify packet drops, TCP resets, ICMP administrative prohibitions, unencrypted DNS interception, NXDOMAIN hijacking, and transparent HTTP tampering.
- **False Positive Discipline**: Ensuring that on a clean, unfiltered network, the false-positive rate (FPR) remains at `0.0%`.
- **Robustness to Loss and Jitter**: Quantifying classifier accuracy degradation under emulated packet loss ($0\text{--}10\%$) and latency variance ($10\text{--}200\text{ ms}$).
- **Real-World Consistency**: Verifying that empirical policies in production networks are detected consistently across time and multiple audit runs.

---

## 2. Phase 1: Controlled Ground-Truth Lab Experiments

### 2.1 Topology & Network Isolation

The controlled testbed is instantiated using Linux network namespaces (`np-client`, `np-gw`, `np-server`) connected via point-to-point `veth` interfaces as described in [`lab/README.md`](../lab/README.md).

```text
+-------------------+             +-------------------+             +-------------------+
|     np-client     |             |       np-gw       |             |     np-server     |
|   10.200.1.2/24   |             |  10.200.1.1/24    |             |   10.200.2.2/24   |
|   [veth-client] <=|=== veth ===>|  [veth-gw-c]      |             |   [veth-server]   |
|   default route:  |             |  ip_forward = 1   |             |         ^         |
|   10.200.1.1      |             |  10.200.2.1/24    |             |        veth       |
|                   |             |  [veth-gw-s] <=---|=== veth ===>|         v         |
|                   |             |  blackhole doc IP |             |   default route:  |
|                   |             |                   |             |   10.200.2.1      |
+-------------------+             +-------------------+             +-------------------+
```

- **Zero Host Mutation**: All routing, interface bindings, and firewall rules exist strictly inside `np-*` namespaces.
- **Mock Services**: `np-server` runs background TCP listeners on ports 21 (FTP), 22 (SSH), 25 (SMTP), 443 (Control/HTTPS), and 587 (Submission), the Canary HTTP server on port 80, and the Lab DNS server on port 53.

### 2.2 Scenarios Evaluated

Middlebox firewall policies are applied strictly inside `np-gw` via [`lab/scenario.sh`](../lab/scenario.sh) and defined in [`lab/scenarios.yaml`](../lab/scenarios.yaml):

1. `clean`: Unfiltered baseline forwarding.
2. `drop-smtp`: Silent drop (`-j DROP`) on outbound TCP port 25.
3. `reset-smtp`: TCP RST injection (`-j REJECT --reject-with tcp-reset`) on TCP port 25.
4. `icmp-admin`: ICMP Administratively Prohibited (`-j REJECT --reject-with icmp-admin-prohibited`).
5. `icmp-port-unreach`: ICMP Port Unreachable (`-j REJECT --reject-with icmp-port-unreachable`).
6. `dns-dnat`: In-path UDP/53 transparent redirect to middlebox resolver (`-j DNAT --to-destination 10.200.1.1:53`).
7. `nxdomain-rewrite`: DNS responder returns fixed A record instead of NXDOMAIN (NXDOMAIN hijacking).
8. `http-proxy`: Transparent HTTP proxy on port 80 injecting `Via` and `X-Cache` headers.

### 2.3 Network Emulation (`tc netem`)

To evaluate classifier resilience against network impairment, `lab/validate.py --netem` sweeps:
- **Packet Loss**: 0%, 1%, 2%, 5%, 10%
- **Round-Trip Time (RTT)**: 10 ms, 50 ms, 100 ms, 200 ms

### 2.4 Controlled Lab Results

> *Note: Placeholders below reflect the test protocol structure. Run `sudo python3 lab/validate.py --runs 30 --netem` to generate populated empirical values.*

| Scenario | Ground Truth Policy | Target / Port | Expected Verdict | Observed Accuracy | Clean FPR |
|---|---|---|---|---|---|
| `clean` | Unfiltered routing | All ports, DNS, HTTP | `OPEN`, `CLEAN` | [TBD: e.g. 100.0%] | [TBD: 0.0%] |
| `drop-smtp` | Firewall silent drop | Port 25 | `BLOCKED_DROP` | [TBD: e.g. 100.0%] | — |
| `reset-smtp` | Firewall RST injection | Port 25 | `BLOCKED_RESET` | [TBD: e.g. 100.0%] | — |
| `icmp-admin` | ICMP Admin Prohibited | Port 25 | `BLOCKED_ICMP` | [TBD: e.g. 100.0%] | — |
| `icmp-port-unreach` | ICMP Port Unreach | Port 25 | `BLOCKED_ICMP` | [TBD: e.g. 100.0%] | — |
| `dns-dnat` | UDP/53 Redirection | Port 53 | `INTERCEPTED` | [TBD: e.g. 100.0%] | — |
| `nxdomain-rewrite` | NXDOMAIN Hijacking | `.invalid` domains | `REWRITTEN` | [TBD: e.g. 100.0%] | — |
| `http-proxy` | Injected Headers | Port 80 HTTP | `HEADERS_INJECTED` | [TBD: e.g. 100.0%] | — |

---

## 3. Phase 2: In-the-Wild Empirical Audits

### 3.1 Network Environments

Audits were conducted across three production environments:
1. **Campus Wi-Fi**: Enterprise WPA2/WPA3-Enterprise network with centralized perimeter firewalling and captive portal mechanisms.
2. **Cellular Mobile Hotspot**: 4G LTE / 5G mobile hotspot behind Carrier-Grade NAT (CGNAT) with operator-level egress policies.
3. **Residential Home Broadband**: Consumer fiber-to-the-home (FTTH) gateway with ISP-provided dual-stack routing.

### 3.2 Sampling Protocol

- **Independent Runs**: Minimum of 5 separate runs per network environment.
- **Temporal Distribution**: Runs executed across different times of day (morning, afternoon, peak evening, late night) to capture traffic load variance.
- **Control Port Verification**: Every audit verifies reachability against control port 443 before classifying non-responding ports.
- **Privacy Protections**: Client public IP addresses, MAC addresses, and network SSIDs were stripped from logs; network identity is tracked using SHA-256 fingerprint hashes.

### 3.3 Empirical Findings (Field Results)

> *Note: Placeholders below are to be populated from experimental field data.*

| Environment | Fingerprint (`fp:...`) | Outbound Port Policy Observed | DNS Resolution Integrity | HTTP Header Integrity | Consistency across 5 runs |
|---|---|---|---|---|---|
| **Campus Wi-Fi** | `fp:[TBD]` | Port 25: `[TBD: BLOCKED_DROP]`<br>Port 587: `[TBD: OPEN]`<br>Port 22: `[TBD: OPEN]` | `[TBD: INTERCEPTED or CLEAN]` | `[TBD: CLEAN or INJECTED]` | `[TBD: 5/5 runs consistent]` |
| **Cellular Hotspot** | `fp:[TBD]` | Port 25: `[TBD: BLOCKED_RESET]`<br>Port 587: `[TBD: OPEN]`<br>Port 22: `[TBD: OPEN]` | `[TBD: CLEAN]` | `[TBD: CLEAN]` | `[TBD: 5/5 runs consistent]` |
| **Home Broadband** | `fp:[TBD]` | Port 25: `[TBD: BLOCKED_DROP]`<br>Port 587: `[TBD: OPEN]`<br>Port 22: `[TBD: OPEN]` | `[TBD: CLEAN]` | `[TBD: CLEAN]` | `[TBD: 5/5 runs consistent]` |

---

## 4. Threats to Validity & Limitations

1. **Uncontrolled Target Ports**:
   When auditing an arbitrary target IP where the client does not operate the server, receiving a TCP RST is inherently ambiguous (it could indicate a closed port on the target or a middlebox injection). `netpolicy` classifies such RSTs as `CLOSED_OR_RESET` with `LOW` confidence unless the port is configured as `expect_open`.

2. **TTL Heuristic Distinctions**:
   Firewall RST injection detection relies on comparing the RST IP TTL with the SYN-ACK TTL observed on the control port. In networks with asymmetrical routing or multi-homed upstream paths, natural path variations can alter TTLs by $\pm 1$, which `netpolicy` accounts for by requiring a difference $> 2$ for high confidence.

3. **CDN DNS Variations**:
   When comparing plain DNS to DNS-over-HTTPS (DoH) baselines, geo-distributed CDNs (Cloudflare, Akamai, Google) often return different IPs for the same domain. `netpolicy` uses `/16` subnet matching and cross-provider overlap rather than strict equality to avoid false mismatch flags.

4. **WSL2 & Virtualization Boundaries**:
   Running under WSL2 or Docker introduces host NAT layers that rewrite raw IP headers, sequence numbers, or TTLs. For raw SYN probe fidelity, native Linux execution is required.
