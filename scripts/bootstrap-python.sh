#!/usr/bin/env bash
# ==============================================================================
# Netpolicy Python Environment Bootstrap
#
# Creates a clean, user-owned virtual environment (.linux-venv) and installs
# netpolicy along with optional lab dependencies (.[lab]).
#
# Resolves Debian/Kali Linux python3-venv broken pip bugs (e.g.
# "ModuleNotFoundError: No module named 'pip._internal.utils'") by bootstrapping
# pip with official get-pip.py before falling back to ensurepip.
#
# SAFETY GUARANTEES:
# - Must NOT run as root so files in .linux-venv remain owned by normal user.
# - Modifies only files inside .linux-venv within the repository.
# - Alters no system packages or system configuration.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# 1. Privilege Check (Must NOT run as root)
# ------------------------------------------------------------------------------
if [[ "${EUID}" -eq 0 ]]; then
    echo "ERROR: scripts/bootstrap-python.sh must NOT be run as root." >&2
    echo "Run this script as your regular user so the virtualenv remains user-owned." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VENV_DIR="${REPO_ROOT}/.linux-venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

echo "=== Netpolicy Python Environment Bootstrap ==="
echo "Target virtual environment: ${VENV_DIR}"

# ------------------------------------------------------------------------------
# 2. Check Existing Virtual Environment
# ------------------------------------------------------------------------------
NEED_CREATE=true
if [[ -x "${VENV_PYTHON}" ]]; then
    if "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
        PIP_VER=$("${VENV_PYTHON}" -m pip --version 2>/dev/null | awk '{print $2}')
        echo "[+] Found existing healthy virtualenv (pip ${PIP_VER}); reusing."
        NEED_CREATE=false
    else
        echo "[-] Existing virtualenv at ${VENV_DIR} has a broken pip; recreating..."
        rm -rf "${VENV_DIR}"
    fi
fi

# ------------------------------------------------------------------------------
# 3. Create Virtual Environment & Bootstrap pip
# ------------------------------------------------------------------------------
if [[ "${NEED_CREATE}" == "true" ]]; then
    echo "[+] Creating virtual environment without pip..."
    python3 -m venv --without-pip "${VENV_DIR}"

    echo "[+] Bootstrapping pip with official get-pip.py..."
    GET_PIP_TMP="$(mktemp -t get-pip-XXXXXX.py)"
    INSTALL_SUCCESS=false

    if curl -fsSL "https://bootstrap.pypa.io/get-pip.py" -o "${GET_PIP_TMP}" 2>/dev/null; then
        if "${VENV_PYTHON}" "${GET_PIP_TMP}" --no-setuptools --no-wheel >/dev/null 2>&1 || \
           "${VENV_PYTHON}" "${GET_PIP_TMP}" >/dev/null 2>&1; then
            INSTALL_SUCCESS=true
        fi
    fi
    rm -f "${GET_PIP_TMP}"

    # Fallback to standard ensurepip-based venv if get-pip download/install failed
    if [[ "${INSTALL_SUCCESS}" != "true" ]]; then
        echo "[-] get-pip.py bootstrap failed or network unreachable; falling back to ensurepip..."
        rm -rf "${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
    fi

    # Verify pip is functional inside the new venv
    if ! "${VENV_PYTHON}" -m pip --version >/dev/null 2>&1; then
        echo "ERROR: Failed to establish a working pip inside ${VENV_DIR}." >&2
        echo "Please ensure python3-pip and python3-venv are installed:" >&2
        echo "  sudo bash scripts/bootstrap-system.sh" >&2
        exit 1
    fi
    echo "[+] Virtualenv created with functional pip: $("${VENV_PYTHON}" -m pip --version)"
fi

# ------------------------------------------------------------------------------
# 4. Install Netpolicy with Lab Dependencies (.[lab])
# ------------------------------------------------------------------------------
echo "[+] Installing netpolicy in editable mode with lab dependencies (.[lab])..."
"${VENV_PYTHON}" -m pip install -e ".[lab]"

# ------------------------------------------------------------------------------
# 5. Verification
# ------------------------------------------------------------------------------
echo "=== Verifying Installation ==="

echo "  [-] Checking netpolicy CLI binary..."
"${VENV_DIR}/bin/netpolicy" --version

echo "  [-] Checking python -m netpolicy..."
"${VENV_PYTHON}" -m netpolicy --version

echo "  [-] Checking lab module imports (matplotlib, yaml, rich)..."
"${VENV_PYTHON}" -c "import matplotlib, yaml, rich; print('[OK] matplotlib, yaml, rich imported successfully')"

# ------------------------------------------------------------------------------
# 6. Print Next Steps
# ------------------------------------------------------------------------------
cat << 'EOF'

================================================================================
BOOTSTRAP COMPLETE
================================================================================

Next steps:
  1. Run system diagnostics (regular user):
     bash scripts/doctor.sh

  2. Or run full diagnostics including namespace & firewall self-test (as root):
     sudo bash scripts/doctor.sh

  3. Activate virtual environment and audit your network:
     source .linux-venv/bin/activate
     netpolicy audit --target probe.example.com
================================================================================
EOF
