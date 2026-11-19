# Teammate Onboarding & Zero-to-Running Setup Guide

**Author**: Principal DevOps Engineer & QA Lead  
**Scope**: Complete environment preparation, installation, smoke testing, and troubleshooting for `netpolicy`  
**Target Environments**: Windows 11 (PowerShell) and Kali Linux / Ubuntu under WSL2  

---

## 1. Prerequisites & System Requirements

Before installing, ensure your machine meets these requirements:

| Component | Minimum Requirement | Recommended / Verified | Notes |
|---|---|---|---|
| **Python** | Python `3.10` or higher (`pyproject.toml`) | Python `3.11`, `3.12`, or `3.14` | **Python 3.14 is NOT mandatory.** Any standard CPython release $\ge 3.10$ is fully supported. |
| **Git** | Git 2.30+ | Git for Windows with Git Credential Manager | Required for cloning and branch management. |
| **Shell** | Windows PowerShell 5.1 or PowerShell 7 | Windows Terminal with PowerShell 7 | Supports ANSI 24-bit truecolor and UTF-8 glyphs. |
| **WSL2** | Windows Subsystem for Linux (WSL2) | Kali Linux (`kali-linux`) or Ubuntu | Optional for everyday socket checks; **required** for raw TCP SYN packet injection and packet capture. |
| **Privileges** | Standard User | Local Administrator / root | Standard user handles everyday socket audits. Root/Admin is required for raw SYN packets and namespace labs. |

---

## 2. Step-by-Step Installation Guide

### Option A: Native Windows Setup (PowerShell)

#### Step 1: Clone the Repository
```powershell
# Windows PowerShell [VERIFIED]
git clone https://github.com/tanishqrana775/netpolicy.git
Set-Location netpolicy
```

#### Step 2: Create Virtual Environment & Install Dependencies
```powershell
# Windows PowerShell [VERIFIED]
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

#### Step 3: Configure Global Command Shim (`scripts/install-windows.ps1`)
To run `netpolicy` from any terminal window without activating `.venv`:
```powershell
# Windows PowerShell [VERIFIED]
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
```

##### What `install-windows.ps1` Actually Does:
1. **Locates Venv Executable**: Finds `<repo>\.venv\Scripts\netpolicy.exe`.
2. **Generates Lightweight Shim**: Creates a custom batch wrapper at `%LOCALAPPDATA%\netpolicy\bin\netpolicy.cmd`:
   ```cmd
   @echo off
   "<repo>\.venv\Scripts\netpolicy.exe" %*
   exit /b %ERRORLEVEL%
   ```
3. **Saves Registry Backup**: Backs up your existing user PATH to `%LOCALAPPDATA%\netpolicy\path-backup-<timestamp>.txt`.
4. **Updates User PATH**: Adds `%LOCALAPPDATA%\netpolicy\bin` to `HKCU\Environment\Path` without requiring Administrator privileges or modifying the system PATH.
5. **Broadcasts Environment Change**: Emits a Win32 `WM_SETTINGCHANGE` broadcast message via `SendMessageTimeout` so newly spawned terminal windows immediately recognize the command.
6. **Safe Uninstallation**: Running `.\scripts\install-windows.ps1 -Uninstall` completely removes the shim directory from your user PATH and deletes the `.cmd` file.

---

### Option B: Linux & WSL2 Setup (Kali Linux or Ubuntu)

To run advanced audits, raw TCP SYN packet injection, or practice namespace labs:

#### Step 1: Open WSL2 Terminal
```powershell
# Windows PowerShell [VERIFIED]
wsl -d kali-linux
```

#### Step 2: Install System Packages
```bash
# Kali / Ubuntu WSL [FROM CODE]
sudo bash scripts/bootstrap-system.sh
```
*Installs Python 3 headers, `python3-venv`, `iproute2`, `iptables`, `tcpdump`, and essential network build tools.*

#### Step 3: Bootstrap Python Environment
```bash
# Kali / Ubuntu WSL [FROM CODE]
bash scripts/bootstrap-python.sh
```
*Creates `.linux-venv` inside the project root and installs `netpolicy` with development and lab dependencies in editable mode.*

#### Step 4: Run Health Diagnostics
```bash
# Kali / Ubuntu WSL [FROM CODE]
bash scripts/doctor.sh
```

---

## 3. 60-Second Smoke Test

Verify that the installation succeeded by running the synthetic audit demo:

```powershell
# Windows PowerShell [VERIFIED]
netpolicy audit --demo
```

*(Alternatively, if `.venv` is activated: `python -m netpolicy audit --demo`)*

### Expected Terminal Output:
```text
netpolicy v0.1.0 | audit | target demo.netpolicy.local | mode auto
┌──────────────── netpolicy: Network Policy & Tampering Audit ────────────────┐
│ Tool Version:     0.1.0                                                     │
│ Network Label:    Guest-WiFi (Campus / Hotspot)                             │
│ Client Address:   192.168.*.* (redacted)                                    │
│ Target Host:      demo.netpolicy.local                                      │
└─────────────────────────────────────────────────────────────────────────────┘

                                OUTBOUND PORTS                                 
┌──────────────┬────────────────┬──────────────────┬───────────┬──────────────┐
│ Port         │ Service        │ Result           │ Evidence  │ Confidence   │
├──────────────┼────────────────┼──────────────────┼───────────┼──────────────┤
│ 22           │ SSH            │ ✓ OPEN           │ • SYN-ACK │ HIGH         │
│ 443          │ HTTPS (Ctrl)   │ ✓ OPEN           │ • SYN-ACK │ HIGH         │
│ 25           │ SMTP           │ ✗ DROPPED        │ • 0/5     │ HIGH         │
│ 587          │ Submission     │ ✗ RESET          │ • TCP RST │ HIGH         │
│ 21           │ FTP            │ ✗ REJECTED       │ • ICMP 3/ │ HIGH         │
└──────────────┴────────────────┴──────────────────┴───────────┴──────────────┘

DNS CHECKS
  ✗ INTERCEPTED DNS (8.8.8.8) - Confidence: HIGH
      • Queries to 8.8.8.8 answered by local gateway (TTL=64 instead of 115)
  ✓ OK DoH (cloudflare-dns.com) - Confidence: HIGH

HTTP INTEGRITY CHECKS
  ✗ TAMPERED HTTP (probe.netpolicy.org:80) - Confidence: HIGH
      • Injected proxy headers detected: 'Via: 1.1 squid-proxy', 'X-Cache: HIT'

───────────────────────────────────────────────────────────────────────────────
netpolicy v0.1.0 | mode auto (user) | ~              exit codes: 0 clean | 1 findings | 2 error
```
*Process exits with code `1` (indicating findings were detected).*

---

## 4. Troubleshooting & Known Error Recovery

Derived strictly from reproduced environment scenarios and codebase inspection:

| Symptom / Error Message | Root Cause | Verified Resolution |
|---|---|---|
| `The term 'netpolicy' is not recognized` | `%LOCALAPPDATA%\netpolicy\bin` is not yet loaded into the current terminal session. | Close and reopen your terminal window. Alternatively, activate the venv manually: `.\.venv\Scripts\Activate.ps1`, or run `.\scripts\install-windows.ps1`. |
| `File ... Activate.ps1 cannot be loaded because running scripts is disabled` | Windows PowerShell execution policy blocks unsigned scripts by default. | Run: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in PowerShell, then re-run the activation script. |
| `PermissionError: [Errno 1] Operation not permitted` (in Linux/WSL) | Raw TCP SYN mode (`--mode raw`) requires root privileges to open raw AF_PACKET sockets. | Run with sudo: `sudo .linux-venv/bin/netpolicy audit ...` or pass `--mode socket` to audit without root privileges. |
| `Kali Linux is not installed in WSL` | Target WSL distro specified in `NETPOLICY_WSL_DISTRO` (default `kali-linux`) is not installed. | Install Kali via `wsl --install -d kali-linux`, or set an environment override to use Ubuntu: `$env:NETPOLICY_WSL_DISTRO="Ubuntu"`. |
| WSL2 hangs, reports virtual disk lock, or fails to start | WSL Hyper-V virtual machine state has deadlocked or is waiting on a frozen background daemon. | Run `wsl --shutdown` from Windows PowerShell, wait 5 seconds, and reopen your WSL terminal. |
| `AssertionError: assert 'MAIN_MENU --> REVIEW_PLAN' in ...` (in pytest) | Stale test assertion in `tests/test_wizard_stage7.py` referencing the abandoned 4-state experimental FSM. | Expected known issue (classified in `docs/TESTING_PLAYBOOK.md`). Do not modify source code. The authentic state in the restored 20-state FSM is `REVIEW`. |
| `UnicodeEncodeError: 'charmap' codec can't encode character ...` (Windows CMD) | Legacy Windows command prompt uses code page 437 / 1252 instead of UTF-8. | Run `chcp 65001` before launching Python, or use Windows Terminal (which natively enforces UTF-8). `netpolicy/ui/banner.py` auto-reconfigures standard streams to UTF-8 on load. |
