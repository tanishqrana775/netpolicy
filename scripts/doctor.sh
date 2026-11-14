#!/usr/bin/env bash
# ==============================================================================
# Netpolicy Environment Doctor
#
# Diagnoses the host, runtime environment, Python virtualenv, and required
# networking utilities for netpolicy.
#
# CHECKS:
# 1. OS & Virtualization: Native Linux or WSL2 (WARN on WSL1)
# 2. Filesystem Location: Warn if running from Windows /mnt/ mount
# 3. Python Version: Python >= 3.10 required
# 4. Virtualenv Health: .linux-venv exists and has working pip
# 5. Netpolicy Importable: Verified in .linux-venv
# 6. System Tools: ip, iptables, tc, curl present in PATH
# 7. iptables Backend: Detect nft vs legacy (INFO)
# 8. Namespace & Firewall Self-Test: When run as root, creates throwaway
#    namespaces named np-doctor-<pid>, tests veth creation, filter ACCEPT,
#    filter REJECT (tcp-reset), and nat table redirect. Skipped if not root.
#
# SAFETY GUARANTEES:
# - Any firewall, routing, or link commands execute ONLY inside throwaway
#   namespaces named np-doctor-<pid> via "ip netns exec"; never on host.
# - Clean trap deletes all throwaway namespaces on ANY script exit.
# - NEVER calls sudo.
# ==============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

FAIL_COUNT=0
WARN_COUNT=0

# Color formatting helpers (if terminal supports colors)
if [[ -t 1 ]]; then
    C_GREEN="\033[1;32m"
    C_RED="\033[1;31m"
    C_YELLOW="\033[1;33m"
    C_CYAN="\033[1;36m"
    C_BLUE="\033[1;34m"
    C_RESET="\033[0m"
else
    C_GREEN=""
    C_RED=""
    C_YELLOW=""
    C_CYAN=""
    C_BLUE=""
    C_RESET=""
fi

pass() {
    local msg="$1"
    echo -e "[${C_GREEN}PASS${C_RESET}] ${msg}"
}

fail() {
    local msg="$1"
    echo -e "[${C_RED}FAIL${C_RESET}] ${msg}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
    local msg="$1"
    echo -e "[${C_YELLOW}WARN${C_RESET}] ${msg}"
    WARN_COUNT=$((WARN_COUNT + 1))
}

info() {
    local msg="$1"
    echo -e "[${C_CYAN}INFO${C_RESET}] ${msg}"
}

skip() {
    local msg="$1"
    echo -e "[${C_BLUE}SKIP${C_RESET}] ${msg}"
}

echo "=== Netpolicy Environment Diagnostics ==="
echo ""

# ------------------------------------------------------------------------------
# 1. OS & Virtualization Environment
# ------------------------------------------------------------------------------
PROC_VER=""
if [[ -f /proc/version ]]; then
    PROC_VER=$(cat /proc/version)
else
    PROC_VER=$(uname -r 2>/dev/null || true)
fi

if echo "${PROC_VER}" | grep -qi "microsoft" && ! echo "${PROC_VER}" | grep -qi "wsl2"; then
    warn "OS: WSL1 detected. Network namespaces and raw sockets require WSL2 or native Linux. Upgrade to WSL2 using: wsl --set-version <distro> 2"
elif echo "${PROC_VER}" | grep -qi "wsl2"; then
    pass "OS: WSL2 environment detected (network namespaces and raw sockets supported)."
else
    pass "OS: Native Linux environment detected."
fi

# ------------------------------------------------------------------------------
# 2. Repository Filesystem Location
# ------------------------------------------------------------------------------
if [[ "${REPO_ROOT}" =~ ^/mnt/[a-zA-Z] ]]; then
    warn "Repo Location: Repository is located on a Windows filesystem mount (${REPO_ROOT}). 9P filesystem mounts suffer from slow I/O, socket limitations, and permission issues. Move to Linux filesystem (e.g. ~/netpolicy)."
else
    pass "Repo Location: Located on native Linux filesystem (${REPO_ROOT})."
fi

# ------------------------------------------------------------------------------
# 3. Python Version (>= 3.10)
# ------------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    PY_CHECK=$(python3 -c 'import sys; print("OK" if sys.version_info >= (3, 10) else "OLD")' 2>/dev/null || echo "ERR")
    PY_VER_STR=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "unknown")
    if [[ "${PY_CHECK}" == "OK" ]]; then
        pass "Python: python3 version is ${PY_VER_STR} (>= 3.10)."
    else
        fail "Python: python3 version is ${PY_VER_STR}. Python 3.10+ is required."
    fi
else
    fail "Python: python3 binary not found in PATH. Run sudo bash scripts/bootstrap-system.sh."
fi

# ------------------------------------------------------------------------------
# 4. Virtualenv Health (.linux-venv)
# ------------------------------------------------------------------------------
VENV_DIR="${REPO_ROOT}/.linux-venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

if [[ -x "${VENV_PYTHON}" ]]; then
    if "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
        PIP_VER=$("${VENV_PYTHON}" -m pip --version 2>/dev/null | awk '{print $2}')
        pass "Virtualenv: .linux-venv is healthy (pip ${PIP_VER})."
    else
        fail "Virtualenv: .linux-venv exists but pip is broken. Run bash scripts/bootstrap-python.sh."
    fi
else
    fail "Virtualenv: .linux-venv not found. Run bash scripts/bootstrap-python.sh."
fi

# ------------------------------------------------------------------------------
# 5. Netpolicy Package Importable
# ------------------------------------------------------------------------------
if [[ -x "${VENV_PYTHON}" ]]; then
    NETPOLICY_VER=$("${VENV_PYTHON}" -c 'import netpolicy; from netpolicy.cli import app; print(netpolicy.__version__)' 2>/dev/null || true)
    if [[ -n "${NETPOLICY_VER}" ]]; then
        pass "Netpolicy: Package importable and verified in .linux-venv (version ${NETPOLICY_VER})."
    else
        fail "Netpolicy: Cannot import netpolicy in .linux-venv. Run bash scripts/bootstrap-python.sh."
    fi
else
    fail "Netpolicy: Virtual environment missing; cannot verify netpolicy package."
fi

# ------------------------------------------------------------------------------
# 6. Required System Tools (ip, iptables, tc, curl)
# ------------------------------------------------------------------------------
MISSING_TOOLS=()
for tool in ip iptables tc curl; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        MISSING_TOOLS+=("${tool}")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -eq 0 ]]; then
    pass "Tools: All required system tools present (ip, iptables, tc, curl)."
else
    fail "Tools: Missing required tools: ${MISSING_TOOLS[*]}. Run sudo bash scripts/bootstrap-system.sh."
fi

# ------------------------------------------------------------------------------
# 7. Active iptables Backend (INFO)
# ------------------------------------------------------------------------------
if command -v iptables >/dev/null 2>&1; then
    IPT_VER_OUTPUT=$(iptables --version 2>/dev/null || true)
    if echo "${IPT_VER_OUTPUT}" | grep -qi "nf_tables"; then
        BACKEND="nf_tables (iptables-nft)"
    elif echo "${IPT_VER_OUTPUT}" | grep -qi "legacy"; then
        BACKEND="legacy (iptables-legacy)"
    else
        BACKEND="standard/unknown (${IPT_VER_OUTPUT})"
    fi
    info "iptables backend: ${BACKEND}."
else
    info "iptables backend: iptables binary not found."
fi

# ------------------------------------------------------------------------------
# 8. Namespace & Firewall Self-Test (when run as root)
#
# HARD CONSTRAINTS:
# - Any firewall, routing, or link commands execute ONLY inside throwaway
#   namespaces named np-doctor-<pid> via "ip netns exec"; never on host.
# - Clean trap deletes all throwaway namespaces on ANY script exit.
# ------------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    skip "Namespace & Firewall Self-Test: Skipped (run with root privileges, e.g. 'sudo bash scripts/doctor.sh', to test network namespaces and iptables)."
else
    echo ""
    echo "Running namespace & firewall self-test (as root)..."
    DOCTOR_PID="$$"
    DOC_NS_A="np-doctor-${DOCTOR_PID}-a"
    DOC_NS_B="np-doctor-${DOCTOR_PID}-b"

    cleanup_doctor_namespaces() {
        ip netns del "np-doctor-${DOCTOR_PID}-a" 2>/dev/null || true
        ip netns del "np-doctor-${DOCTOR_PID}-b" 2>/dev/null || true
    }
    trap cleanup_doctor_namespaces EXIT INT TERM HUP

    TEST_OK=true

    # Step 1: Create throwaway namespaces
    if ! ip netns add "np-doctor-${DOCTOR_PID}-a" 2>/dev/null || ! ip netns add "np-doctor-${DOCTOR_PID}-b" 2>/dev/null; then
        fail "Self-Test: Failed to create throwaway network namespaces (${DOC_NS_A}, ${DOC_NS_B})."
        TEST_OK=false
    fi

    # Step 2: Create veth pair directly between them
    if [[ "${TEST_OK}" == "true" ]]; then
        if ! ip link add veth-doc-a netns "np-doctor-${DOCTOR_PID}-a" type veth peer name veth-doc-b netns "np-doctor-${DOCTOR_PID}-b" 2>/dev/null; then
            fail "Self-Test: Failed to create veth pair placed directly into namespaces."
            TEST_OK=false
        fi
    fi

    # Step 3: Apply standard iptables ACCEPT rule inside np-doctor-* namespace
    if [[ "${TEST_OK}" == "true" ]]; then
        if ! ip netns exec "np-doctor-${DOCTOR_PID}-a" iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; then
            fail "Self-Test: Failed to apply standard iptables rule inside ${DOC_NS_A}."
            TEST_OK=false
        fi
    fi

    # Step 4: Apply REJECT rule (tcp-reset) inside np-doctor-* namespace
    if [[ "${TEST_OK}" == "true" ]]; then
        if ! ip netns exec "np-doctor-${DOCTOR_PID}-a" iptables -A INPUT -p tcp --dport 25 -j REJECT --reject-with tcp-reset 2>/dev/null; then
            fail "Self-Test: Failed to apply iptables REJECT --reject-with tcp-reset inside ${DOC_NS_A}."
            TEST_OK=false
        fi
    fi

    # Step 5: Apply NAT table redirect rule inside np-doctor-* namespace
    if [[ "${TEST_OK}" == "true" ]]; then
        if ! ip netns exec "np-doctor-${DOCTOR_PID}-a" iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null; then
            fail "Self-Test: Failed to apply iptables nat table rule inside ${DOC_NS_A}."
            TEST_OK=false
        fi
    fi

    cleanup_doctor_namespaces
    trap - EXIT INT TERM HUP

    if [[ "${TEST_OK}" == "true" ]]; then
        pass "Self-Test: Successfully verified throwaway namespaces (${DOC_NS_A}, ${DOC_NS_B}), veth pair, filter ACCEPT/REJECT rules, and nat redirect."
    fi
fi

# ------------------------------------------------------------------------------
# Diagnostics Summary
# ------------------------------------------------------------------------------
echo ""
echo "--------------------------------------------------------------------------------"
if [[ ${FAIL_COUNT} -gt 0 ]]; then
    echo -e "Diagnostics Result: ${C_RED}FAILED${C_RESET} (${FAIL_COUNT} failure(s), ${WARN_COUNT} warning(s))"
    exit 1
elif [[ ${WARN_COUNT} -gt 0 ]]; then
    echo -e "Diagnostics Result: ${C_GREEN}PASSED${C_RESET} with ${C_YELLOW}${WARN_COUNT} warning(s)${C_RESET}"
    exit 0
else
    echo -e "Diagnostics Result: ${C_GREEN}ALL CHECKS PASSED${C_RESET}"
    exit 0
fi
