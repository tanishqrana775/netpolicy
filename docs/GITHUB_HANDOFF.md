# GitHub Handoff & Version Control Strategy

**Author**: Principal DevOps Engineer & QA Architect  
**Project**: `netpolicy` CLI Network Policy Auditor  
**Date**: November 2026  
**Status**: Ready for User Review and Staging (Do NOT run mutating commands automatically)  

---

## 1. Repository Reality Audit

A comprehensive read-only git audit (`git status`, `git diff --stat`, `git check-ignore`, and `git ls-files`) reveals the exact current state of the repository.

### 1.1 Modified Tracked Files (Must Be Staged)

These files already exist in git history and contain critical bugfixes and CLI extensions:

| File Path | Changes | Status in Git | Role in Project |
|---|---|---|---|
| `README.md` | +56 lines | Modified | Updated installation guides, wizard options, and usage examples. |
| `netpolicy/cli.py` | +856 / -568 lines | Modified | Typer subcommands, in-process wizard integration, and global banner handling. |
| `netpolicy/report/terminal.py` | +759 / -568 lines | Modified | Restored green/amber/red verdict formatting and table presentation. |

### 1.2 Untracked Files That MUST Be Committed

These newly created production packages and scripts are currently untracked and essential for the tool to function:

| Directory / File Path | Verification | Importance |
|---|---|---|
| `netpolicy/wizard/` | `[VERIFIED]` | Entire interactive wizard subsystem: FSM (`fsm.py`), single-key reader (`keys.py`), UI adapter (`ui.py`), in-process runner (`runner.py`), capabilities (`capabilities.py`), packet capture (`capture.py`), academic lab report (`labreport.py`), recommendations (`recommend.py`), and command plan (`plan.py`). |
| `netpolicy/ui/` | `[VERIFIED]` | UI presentation layer: gradient banner (`banner.py`), zero-touch WSL handoff (`wsl.py`), and package exports (`__init__.py`). |
| `netpolicy/report/humanize.py` | `[VERIFIED]` | Central plain-language string repository, translations, and redirect formatters. |
| `netpolicy/report/summary.py` | `[VERIFIED]` | Core inference engine: issue aggregation, Reliability Gates (G1–G5), and verdict calculations. |
| `scripts/install-windows.ps1` | `[VERIFIED]` | Production Windows user-level shim installer (`netpolicy.cmd` in `%LOCALAPPDATA%\netpolicy\bin`). |
| `docs/TESTING_PLAYBOOK.md` | `[VERIFIED]` | Comprehensive interactive wizard, CLI matrix, and test validation guide. |
| `docs/GITHUB_HANDOFF.md` | `[VERIFIED]` | Git staging sequence, `.gitignore` audit, and pre-push checklist (this document). |
| `docs/TEAMMATE_MESSAGE.md` | `[VERIFIED]` | Plain-language WhatsApp overview, technical architecture, and honest limitations. |
| `docs/TEAMMATE_SETUP.md` | `[VERIFIED]` | Zero-to-running onboarding guide, WSL setup, and troubleshooting matrix. |
| `docs/TWO_LAPTOP_TEST.md` | `[VERIFIED]` | Multi-machine testing playbook with exact listener and firewall rules. |
| `docs/WIZARD.md` | `[VERIFIED]` | Wizard design documentation. |
| `docs/internal/` | `[VERIFIED]` | Design notes: `report_redesign_notes.md`, `ui_overhaul_notes.md`, `wizard_design_notes.md`. |

---

### 1.3 Off-Limits Files & Directories (Must NOT Be Committed)

These real files exist on disk in the local working environment and must strictly remain excluded:

| Path Pattern | Real Local Offender Found | Reason for Exclusion |
|---|---|---|
| `reports/*.jsonl` | `reports/*.jsonl` | Append-only raw packet observations from local runs; contains machine-specific telemetry. |
| `reports/*.json` | `reports/*.json` | Generated audit reports from local testing. |
| `reports/*.pcap` | `reports/capture-*.pcap` | Raw binary packet captures; would bloat git repository history. |
| `reports/*.md` | `reports/lab-report-*.md` | Exported academic reports from local audits. |
| `.venv/` | `C:\Users\tanis\Downloads\netpolicy\.venv` | Windows Python 3.14 virtual environment containing gigabytes of binaries and dependencies. |
| `.linux-venv/` | `.linux-venv/` | Kali Linux virtual environment for WSL. |
| `**/__pycache__/` | `tests/__pycache__/`, `netpolicy/**/__pycache__/` | Bytecode cache files (`*.pyc`). |
| `scratch/` | `C:\Users\tanis\...\scratch/` | Temporary inspection scripts and helper outputs. |
| Local artifacts | `my_wifi.json`, `my_hotspot.json`, `demo-output/` | Ad-hoc run outputs generated during local verification. |

---

## 2. `.gitignore` Critical Flaw & Recommended Resolution

### 2.1 The Issue: Test Suite Is Silently Ignored

Running `git check-ignore -v tests reports .venv` reveals:
```text
.gitignore:51:tests/    tests
.gitignore:18:reports/  reports
.gitignore:7:.venv/     .venv
```

Lines 49–51 of `.gitignore` currently read:
```gitignore
# Testing & Cyber-Range Lab (Keep local only)
lab/
scripts/demo.sh
tests/
```

Because `tests/` is ignored, git tracks only `tests/__init__.py` (committed in initial release `a570dc1`). Over **30 test suites and fixture directories** (`tests/test_*.py`, `tests/fixtures/`) are invisible to git!

> [!CAUTION]
> **Consequence if Pushed As-Is**:  
> If the teammate clones the repository from GitHub, **they will receive an empty test folder with zero automated tests**. CI pipelines will fail to execute test suites, and regressions cannot be caught.

### 2.2 Recommended `.gitignore` Modification

Un-ignore `tests/`, preserve the exclusion of `lab/` and `scripts/demo.sh`, and explicitly ignore packet captures (`*.pcap`).

#### Exact Proposed Diff:
```diff
--- a/.gitignore
+++ b/.gitignore
@@ -20,6 +20,7 @@ dist/
 # Netpolicy audit data and reports
 reports/
 *.jsonl
+*.pcap

 # Testing & Quality
 .pytest_cache/
@@ -48,7 +49,7 @@ Thumbs.db
 # Testing & Cyber-Range Lab (Keep local only)
 lab/
 scripts/demo.sh
-tests/

 # Generated Documents
 *.docx
```

---

## 3. Copy-Paste Safe Git Command Sequence

Do **NOT** use `git add .` or `git add -A`, which risk accidentally committing virtual environments or large binary captures. Follow this explicit, path-by-path sequence:

### Step 1: Create a Feature Branch
```powershell
# Windows PowerShell [VERIFIED command shape]
Set-Location "C:\Users\tanis\Downloads\netpolicy"
git checkout -b feature/wizard-and-onboarding-docs
```

### Step 2: Update `.gitignore` to Include Tests
Open `.gitignore` and remove line 51 (`tests/`). Save the file, then verify git now sees the test suite:
```powershell
# Windows PowerShell [VERIFIED command shape]
git status --short tests/
```
*Expected: List of untracked test files (`?? tests/test_*.py`, `?? tests/fixtures/`).*

### Step 3: Explicitly Stage Production Packages & Files
```powershell
# Windows PowerShell [VERIFIED command shape]
# 1. Configuration & Root Docs
git add .gitignore README.md pyproject.toml

# 2. CLI and Presentation Layer
git add netpolicy/cli.py netpolicy/report/terminal.py netpolicy/report/humanize.py netpolicy/report/summary.py
git add netpolicy/ui/

# 3. Interactive Wizard Core
git add netpolicy/wizard/

# 4. Windows Installation Scripts
git add scripts/install-windows.ps1

# 5. Comprehensive Onboarding & Testing Playbooks
git add docs/TESTING_PLAYBOOK.md
git add docs/GITHUB_HANDOFF.md
git add docs/TEAMMATE_MESSAGE.md
git add docs/TEAMMATE_SETUP.md
git add docs/TWO_LAPTOP_TEST.md
git add docs/WIZARD.md
git add docs/internal/

# 6. Test Suite and Test Fixtures
git add tests/
```

### Step 4: Verify Staged Changes Before Committing
```powershell
# Windows PowerShell [VERIFIED command shape]
git status
```

Verify that **NO** unwanted files are staged:
- [ ] No files from `.venv/` or `.linux-venv/`
- [ ] No `reports/*.jsonl`, `reports/*.json`, or `reports/*.pcap`
- [ ] No `__pycache__` directories
- [ ] No files from `scratch/`

### Step 5: Commit With Structured Conventional Message
```powershell
# Windows PowerShell [VERIFIED command shape]
git commit -m "feat(wizard): restore full 20-state FSM, add single-key reader, and testing playbooks

- Integrate production 20-state FSM in netpolicy/wizard/fsm.py and ui.py
- Implement robust single-keystroke reader with msvcrt/termios in keys.py
- Add zero-touch Windows-to-Kali-WSL interactive launcher in ui/wsl.py
- Add user-level Windows shim installer in scripts/install-windows.ps1
- Add complete QA testing playbook, teammate setup, and two-laptop testing guide
- Un-ignore tests/ in .gitignore to ensure test suite ships to collaborators"
```

### Step 6: Push Branch to GitHub Remote
```powershell
# Windows PowerShell [VERIFIED command shape]
git push -u origin feature/wizard-and-onboarding-docs
```

### Step 7: Open Pull Request
1. Open the repository in your browser: `https://github.com/tanishqrana775/netpolicy`.
2. Click **Compare & pull request** for `feature/wizard-and-onboarding-docs`.
3. Set base branch to `main`, paste the technical summary from `docs/TEAMMATE_MESSAGE.md` into the PR description, and assign your teammate as a reviewer.

---

## 4. Pre-Push Quality & Security Checklist

Before pushing to the remote repository, complete these quality assurance verifications:

1. **Secrets & Credentials Scan**:
   ```powershell
   # Windows PowerShell [VERIFIED command shape]
   git diff --staged | Select-String -Pattern "(password|secret|key|token|PRIVATE KEY)"
   ```
   *Expected: Zero matches or only standard test mock tokens.*

2. **Binary Bloat Prevention**:
   Verify that no binary files exceeding 1 MB are staged:
   ```powershell
   # Windows PowerShell [VERIFIED command shape]
   git diff --staged --stat | Select-String -Pattern "(\.pcap|\.exe|\.dll|\.zip|\.tar)"
   ```
   *Expected: Zero matches.*

3. **Encoding & Line Endings**:
   Ensure all Python and Markdown files are saved as standard UTF-8 without byte order marks (BOM).

4. **Automated Verification Baseline**:
   - `python -m py_compile` passes cleanly across all 89 files.
   - `ruff check netpolicy tests` reports 0 errors.
   - Known failing tests (4) are documented in `docs/TESTING_PLAYBOOK.md` with clear classifications.

---

## 5. Rollback & Emergency Recovery Notes

If you encounter an error during the staging or committing process, use these non-destructive commands to recover:

- **To unstage a file without losing local edits**:
  ```powershell
  git restore --staged <file_path>
  ```
- **To unstage everything while preserving all local modifications**:
  ```powershell
  git restore --staged .
  ```
- **To undo the latest local commit while keeping all changes in your working directory**:
  ```powershell
  git reset --soft HEAD~1
  ```
- **To switch back to main without losing current work**:
  ```powershell
  git stash push -u -m "wip-wizard-onboarding"
  git checkout main
  ```
- **To restore your stashed work later**:
  ```powershell
  git checkout feature/wizard-and-onboarding-docs
  git stash pop
  ```
