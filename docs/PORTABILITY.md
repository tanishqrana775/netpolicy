# Final Changes and Portability Report

This report documents the empirical problems encountered during manual and automated cross-platform testing of `netpolicy` (on Windows 11, WSL2 Kali Linux, and native Linux distributions), the precise architectural fixes implemented to resolve them, proactive protections established against environment pitfalls, a reproducible fresh-device setup checklist, and known platform limitations.

---

## Part A: Problems Found in Manual Testing and Applied Fixes

### 1. `ip netns` Execution Failure in Windows PowerShell
- **Symptom**: Executing `ip netns`, `lab/setup.sh`, or namespace commands directly inside Windows PowerShell or CMD failed with command-not-found errors (`The term 'ip' is not recognized as the name of a cmdlet, function, script file, or operable program`).
- **Cause**: Linux network namespaces (`ip netns`) and the `iproute2` subsystem are native Linux kernel networking primitives. They do not exist on the Windows NT kernel.
- **Fix**: Install a Linux environment via Windows Subsystem for Linux (WSL2) with network namespace support. The tested distribution is Kali Linux (`wsl --install -d kali-linux`), though any modern WSL2 Linux distribution (such as Ubuntu via `wsl --install -d Ubuntu`) is supported. Enter the distribution terminal (`wsl -d kali-linux`) and maintain the repository strictly within the Linux home filesystem (`~/netpolicy`).
- **File That Prevents It**: [`scripts/doctor.sh`](../scripts/doctor.sh) detects the virtualization environment, warns when running on Windows or WSL1, verifies presence of `ip` and `iptables`, and instructs the user how to configure WSL2.

---

### 2. Missing Networking Tools on Fresh Linux Distributions
- **Symptom**: Clean installations of Debian, Ubuntu, or Kali Linux failed when executing lab scripts because core networking utilities (`ip`, `iptables`, `tc`, `ping`, `fuser`, `sysctl`) were missing.
- **Cause**: Minimal cloud, container, and WSL2 base images intentionally omit networking and diagnostic packages to minimize disk footprint.
- **Fix**: The manual fix was running `sudo apt update && sudo apt install iptables iproute2 -y`. This is now fully automated for all required probe and lab tools: `python3`, `python3-venv`, `python3-pip`, `iproute2`, `iptables`, `curl`, `ca-certificates`, `iputils-ping`, `psmisc` (provides `fuser`), and `procps` (provides `sysctl`).
- **File That Prevents It**: [`scripts/bootstrap-system.sh`](../scripts/bootstrap-system.sh) automates repository-wide system dependencies across apt, dnf, and pacman systems. [`scripts/doctor.sh`](../scripts/doctor.sh) verifies that `ip`, `iptables`, `tc`, and `curl` are present in `PATH`.

---

### 3. Broken `pip` in Debian/Kali `python3-venv` (`ModuleNotFoundError`)
- **Symptom**: Creating a virtual environment using `python3 -m venv .venv` succeeded, but any invocation of `pip` inside the new venv immediately crashed with:
  ```text
  ModuleNotFoundError: No module named 'pip._internal.utils'
  ```
- **Cause**: An upstream packaging discrepancy in Debian/Kali Linux between `python3-venv` and `python3-pip` where standard `ensurepip` generates a corrupted or incomplete internal wheel hierarchy. *The exact underlying package maintainer root cause was not established.*
- **Fix**: Recreate the virtual environment with `--without-pip`, download the official standalone `get-pip.py` (`curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py`), bootstrap pip directly via `.linux-venv/bin/python get-pip.py`, and fall back to `ensurepip` only if network access is unavailable.
- **File That Prevents It**: [`scripts/bootstrap-python.sh`](../scripts/bootstrap-python.sh) automates this clean bootstrap into `.linux-venv` and asserts that pip is operational before proceeding with package installation.

---

### 4. `No module named netpolicy.__main__` Entrypoint Failure
- **Symptom**: Invoking `python -m netpolicy` failed with:
  ```text
  No module named netpolicy.__main__
  ```
- **Cause Analysis**:
  - `No module named netpolicy` indicates that Python's module resolution cannot locate the top-level `netpolicy` package anywhere in `sys.path` (the package was not installed and the current working directory is not the repository root).
  - Conversely, `No module named netpolicy.__main__` proves that Python **did** successfully find and load the `netpolicy` package, but the package lacked a `__main__.py` entrypoint module. Python requires a `__main__.py` file inside any package directory when executed with the `-m` switch.
  - Inspection of the repository revealed that `netpolicy/__main__.py` was missing from the package root.
- **Fix**: Added [`netpolicy/__main__.py`](../netpolicy/__main__.py) containing:
  ```python
  from netpolicy.cli import app

  if __name__ == "__main__":
      app()
  ```
  Additionally, `scripts/bootstrap-python.sh` installs the package in editable mode (`pip install -e ".[lab]"`), ensuring both direct binary execution (`netpolicy --version`) and module execution (`python -m netpolicy --version`) succeed.
- **Files That Prevent It**: [`netpolicy/__main__.py`](../netpolicy/__main__.py), [`scripts/bootstrap-python.sh`](../scripts/bootstrap-python.sh), and [`tests/test_cli.py`](../tests/test_cli.py).

---

### 5. Terminal Apparent Freeze When Launching Background Jobs
- **Symptom**: Starting lab service listeners using standard shell backgrounding (`python3 lab/banner_servers.py &`) caused interactive terminal sessions to appear unresponsive or capture user input, leading developers to assume the script had hung.
- **Cause**: This is normal shell job control behavior. When background processes retain attached `stdout`/`stderr` streams to an active TTY or wait for socket events without output redirection, unbuffered output interrupts the shell prompt.
- **Fix**:
  1. `lab/services.sh` launches all background service daemons detached using `nohup`, redirects output to dedicated logs in `lab/run/*.log` (`banner_servers.log`, `canary_server.log`, `dns_server.log`), and tracks process PIDs in `lab/run/pids`.
  2. Execution returns immediately and displays a formatted ASCII table showing service names, namespaces, bound ports, and PIDs.
  3. `lab/status.sh` provides read-only inspection of daemon running states and verified socket listeners via `ss -ltnp`.
- **Files That Prevent It**: [`lab/services.sh`](../lab/services.sh) and [`lab/status.sh`](../lab/status.sh).

---

### 6. File Format Incompatibility Between `audit` Telemetry and `compare`
- **Symptom**: Running `netpolicy compare` directly against output generated by standard audit runs failed because `audit` persists raw telemetry as `.jsonl` (`reports/<run_id>.jsonl`), whereas `compare` originally expected a pre-classified `AuditReport` `.json` file.
- **Workaround**: Users had to explicitly pass `--output report.json` or `--json > report.json` to generate classified JSON reports.
- **Fix**: Updated `_load_or_reclassify_report` in `netpolicy/cli.py` and `netpolicy/report/compare.py`. `compare` now natively accepts:
  - Pre-classified `AuditReport` `.json` files (loaded via `load_report()`).
  - Raw observation `.jsonl` files (loaded via `read_run()` and automatically reclassified via `build_audit_report()` before diffing).
- **Files That Prevent It**: [`netpolicy/cli.py`](../netpolicy/cli.py) and [`netpolicy/report/compare.py`](../netpolicy/report/compare.py).

---

### 7. Non-Stacking Scenario Execution in `scenario.sh`
- **Symptom**: Developers assumed middlebox scenarios were additive—for example, applying `http-proxy` followed by `reset-smtp` with the expectation that both HTTP proxying and SMTP resets would remain active. However, only the last applied scenario was enforced.
- **Cause**: By deliberate design, `lab/scenario.sh` enforces strict **scenario exclusivity**. Every invocation flushes all existing `filter`, `nat`, and `mangle` tables in `np-gw`, terminates running proxies, and restores the DNS responder. This isolation is mandatory for ground-truth validation (`lab/validate.py`), which requires clean, unpolluted baseline conditions for each statistical test.
- **Fix**:
  1. `lab/scenario.sh` prints an explicit exclusivity notice on startup (`Scenarios are exclusive: all rules in np-gw are flushed first`).
  2. Added `--list` option to view all supported scenarios.
  3. Created the composite `campus` scenario, which explicitly combines `reset-smtp` (port 25 RST), `dns-dnat` (UDP/53 redirect), and `http-proxy` (port 80 tamper proxy) into a single unified rule set without breaking isolation.
- **Files That Prevent It**: [`lab/scenario.sh`](../lab/scenario.sh) and [`lab/scenarios.yaml`](../lab/scenarios.yaml).

---

### 8. Missing Visualization and Lab Validation Dependencies
- **Symptom**: Running `sudo python3 lab/validate.py` crashed on startup with `ModuleNotFoundError: No module named 'matplotlib'` (and similarly for `pandas`).
- **Cause**:
  1. Plotting and data frame packages (`matplotlib`, `pandas`) are optional dependencies needed only for statistical lab validation, not for daily CLI audits.
  2. In some testing runs, `rich` and `pyyaml` were also reported missing. Because `rich` and `pyyaml` are normal core runtime dependencies of `netpolicy`, their absence indicated that the package had never been installed into the active Python environment (the script was run against system Python rather than the virtual environment).
- **Fix**:
  1. Defined an optional `[lab]` extra in `pyproject.toml` containing `matplotlib`, `pandas`, `pyyaml`, `rich`, and `pytest`.
  2. Added an early pre-flight import check in `lab/validate.py` before third-party imports that outputs a helpful message (`Missing lab dependencies. Run: <python> -m pip install -e ".[lab]"`) and exits with code 2.
  3. `scripts/bootstrap-python.sh` automatically installs `.[lab]` into `.linux-venv`.
- **Files That Prevent It**: [`pyproject.toml`](../pyproject.toml), [`lab/validate.py`](../lab/validate.py), and [`scripts/bootstrap-python.sh`](../scripts/bootstrap-python.sh).

---

## Part B: Pitfalls Prevented Proactively

### 1. Windows CRLF Line Endings Breaking Shell Scripts
- **Pitfall**: Git checkouts on Windows default to `core.autocrlf=true`, converting Unix line feeds (`\n`) to Windows carriage-return line feeds (`\r\n`). When `.sh` scripts with CRLF endings are executed inside WSL2 or Linux, bash fails with obscure syntax errors (`\r: command not found`).
- **Proactive Protection**: Added [`.gitattributes`](../.gitattributes) at the repository root enforcing explicit LF line endings across shell scripts, Python sources, and YAML configs:
  ```gitattributes
  *.sh text eol=lf
  *.py text eol=lf
  *.yaml text eol=lf
  *.yml text eol=lf
  *.md text eol=lf
  ```

### 2. Slow I/O and Permission Issues on `/mnt/c` Windows Mounts
- **Pitfall**: In WSL2, files located under `/mnt/c/...` are accessed across a 9P network filesystem bridge. Running the repository on `/mnt/c` degrades disk I/O performance by up to $10\times$, causes intermittent file-locking conflicts, and breaks Linux socket permissions.
- **Proactive Protection**: [`scripts/doctor.sh`](../scripts/doctor.sh) inspects the absolute path of `REPO_ROOT`. If it detects `/mnt/[a-zA-Z]`, it emits a prominent `[WARN]` urging the developer to move the repository into native Linux ext4 storage (e.g. `~/netpolicy`).

### 3. Root-Owned Telemetry Files
- **Pitfall**: Running audits or lab scripts with `sudo` creates telemetry files (`reports/*.jsonl`) and output reports (`demo-output/*.json`) owned by `root:root`. Standard users cannot subsequently view, edit, or remove these files without sudo privileges.
- **Proactive Protection**:
  - `netpolicy/store/raw.py` defines `chown_to_sudo_user()`, which reads `SUDO_UID` and `SUDO_GID` from the execution environment and chowns newly created files back to the calling user.
  - `scripts/demo.sh` and `lab/validate.py` explicitly chown output directories (`demo-output/`, `results/`) back to `${SUDO_UID}:${SUDO_GID}`.

### 4. Incompatibility with WSL1
- **Pitfall**: WSL1 implements an emulation translation layer over the Windows NT kernel rather than a native Linux kernel. WSL1 lacks support for Linux network namespaces (`ip netns`), virtual Ethernet pairs (`veth`), and raw packet capture via Scapy.
- **Proactive Protection**: [`scripts/doctor.sh`](../scripts/doctor.sh) checks `/proc/version`. If Microsoft WSL1 is identified without WSL2 kernel virtualization, it issues an immediate `[WARN]` advising the user to upgrade with `wsl --set-version <distro> 2`.

### 5. `iptables` Backend Compatibility (`nf_tables` vs `legacy`)
- **Pitfall**: Modern Linux distributions default to `iptables-nft` (a userspace translation tool that translates iptables syntax into `nf_tables` kernel rules), whereas older distributions use `iptables-legacy`. Discrepancies between installed userspace wrappers and active kernel modules can cause silent rule failures.
- **What `doctor.sh` Can Confirm**: [`scripts/doctor.sh`](../scripts/doctor.sh) executes `iptables --version` and identifies whether the active userspace wrapper is `nf_tables (iptables-nft)` or `legacy (iptables-legacy)`.
- **What `doctor.sh` Cannot Confirm Statically**: A version string cannot prove that the kernel's active packet filtering engine is accepting and applying rules without testing live kernel hooks. Therefore, when run with root privileges, `doctor.sh` executes an automated live self-test inside throwaway network namespaces (`np-doctor-<pid>-a` and `np-doctor-<pid>-b`), asserting that `veth` pairs, filter `ACCEPT`, filter `REJECT` (`--reject-with tcp-reset`), and nat `REDIRECT` operate correctly in the running kernel.

---

## Part C: Fresh-Device Setup Checklist

Follow these verified steps on a newly configured machine. Every command has been verified against the current repository scripts.

### 1. Windows with WSL2

#### Step 1: Windows PowerShell Host Configuration (Run in Windows Terminal)
```powershell
# 1. Install WSL2 with Kali Linux distribution (or Ubuntu)
wsl --install -d kali-linux

# 2. Ensure distribution runs on WSL2
wsl --set-version kali-linux 2

# 3. Enter the WSL2 Linux environment
wsl -d kali-linux
```

#### Step 2: Inside WSL2 Linux Environment (Run in WSL Terminal)
```bash
# 1. Switch to native Linux home directory (NEVER run from /mnt/c)
cd ~

# 2. Clone the repository
git clone https://github.com/netpolicy/netpolicy.git && cd netpolicy

# 3. Install required OS packages (requires root)
sudo bash scripts/bootstrap-system.sh

# 4. Bootstrap user-owned Python virtual environment and install netpolicy with [lab]
bash scripts/bootstrap-python.sh

# 5. Run environment and tooling diagnostics
bash scripts/doctor.sh
```

---

### 2. Native Linux (Debian, Ubuntu, Kali, Fedora, Arch)

```bash
# 1. Clone repository and navigate to root
git clone https://github.com/netpolicy/netpolicy.git && cd netpolicy

# 2. Install OS-level dependencies (requires root)
sudo bash scripts/bootstrap-system.sh

# 3. Bootstrap user-owned Python virtual environment (.linux-venv)
bash scripts/bootstrap-python.sh

# 4. Run environment diagnostics
bash scripts/doctor.sh
```

---

### 3. Confirming Full System Health: `scripts/demo.sh`

Verify the entire project end-to-end with a single command:

```bash
sudo bash scripts/demo.sh
```

#### Expected Execution Sequence and Results:
1. **Privilege Check**: Verifies `EUID == 0`.
2. **Environment Diagnostics**: Executes `scripts/doctor.sh` and verifies tools and kernel self-tests.
3. **Lab Setup**: Provisions `np-client`, `np-gw`, `np-server`, veth links, and IP routes via `lab/setup.sh`.
4. **Services Launch**: Spawns detached TCP banner listeners, canary server, and DNS server via `lab/services.sh start`.
5. **Baseline Audit**: Runs clean audit from `np-client` against `10.200.2.2`; saves `demo-output/baseline.json`; confirms exit code `0`.
6. **Scenario Application**: Applies `reset-smtp` (or user-specified scenario) in `np-gw` via `lab/scenario.sh`.
7. **Tampered Audit**: Runs second audit from `np-client`; saves `demo-output/tampered.json`; confirms exit code `1` (detecting TCP RST on port 25).
8. **Report Comparison**: Executes `netpolicy compare demo-output/baseline.json demo-output/tampered.json`; confirms exit code `1` (detecting policy divergence).
9. **Teardown Trap**: Installs trap on `EXIT INT TERM HUP` invoking `lab/teardown.sh` to remove namespaces and stop background services.
10. **Ownership Preservation**: Chowns `demo-output/` back to `${SUDO_UID}:${SUDO_GID}`.
11. **Final Summary Output**:
    ```text
    ================================================================================
    DEMO SUMMARY
    --------------------------------------------------------------------------------
    Baseline Audit Exit Code: 0 (expected 0: clean / no findings)
    Tampered Audit Exit Code: 1 (expected 1: policy findings detected)
    Compare Reports Exit Code: 1 (expected 1: policy differences detected)
    Artifacts written to:     demo-output/
    --------------------------------------------------------------------------------
    PASS: All checks passed (baseline=0, tampered=1, compare=1). Demo complete.
    ```
    **Script Exit Code**: `0`.

---

## Part D: Known Limitations

1. **Emulated vs. Commercial Hardware Middleboxes**:
   - The lab validates classifiers against software Linux network implementations (`iptables`, `nftables`, Python reverse proxies).
   - Enterprise hardware middleboxes (such as Palo Alto Networks, Fortinet FortiGate, Check Point, or BlueCoat appliances) feature deep packet inspection (DPI), stateful TCP stream reassembly, active Layer 7 protocol anomaly detection, and commercial TLS interception proxies using enterprise root CAs. Real-world middlebox behaviors may exhibit protocol nuances not captured by basic packet-filtering rules.

2. **WSL2 NAT Boundary Effects on Real-World Audits**:
   - When using WSL2 to audit *real-world external networks* (such as a university campus Wi-Fi or hotel hotspot), traffic passes through a virtual Hyper-V NAT switch managed by the Windows host OS.
   - The Windows networking stack and Windows Defender Firewall may inspect, alter TTLs, intercept certain TCP handshakes, or drop raw TCP SYN packets before they reach physical adapters.
   - While the internal namespace lab is $100\%$ authoritative inside WSL2, native Linux is strongly recommended when auditing real external networks.

3. **Windows Host OS Is Not a Supported Lab Host**:
   - The Netpolicy test lab cannot be executed natively on Windows. Windows lacks native network namespaces (`ip netns`), Linux virtual Ethernet devices (`veth`), and `iptables`.
   - Windows users must run the lab within a WSL2 virtualized Linux distribution.
