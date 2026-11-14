#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd /home/tanishq

echo "[1/3] Generating PDF study guide inside Linux local storage..."
"${REPO_ROOT}/.linux-venv/bin/python" "${REPO_ROOT}/scripts/generate_team_pdf.py" ./netpolicy_team_guide.pdf

echo "[2/3] Resolving destination Windows Downloads path..."
# The user's exact bash resolution expression:
DEST_BASE="$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')" 2>/dev/null || true)"
if [[ -z "${DEST_BASE}" || ! -d "${DEST_BASE}/Downloads" ]]; then
    # Fallback to unquoted echo if single-quote interop behaves differently
    DEST_BASE="$(wslpath "$(cmd.exe /c echo %USERPROFILE% 2>/dev/null | tr -d '\r\n')" 2>/dev/null || true)"
fi
if [[ -z "${DEST_BASE}" || ! -d "${DEST_BASE}/Downloads" ]]; then
    DEST_BASE="/mnt/c/Users/tanis"
fi
TARGET_DIR="${DEST_BASE}/Downloads/"

echo "[3/3] Copying uncorrupted PDF into Windows Downloads folder: ${TARGET_DIR}"
cp ./netpolicy_team_guide.pdf "${TARGET_DIR}"

# Also place a copy inside repo for convenience
cp ./netpolicy_team_guide.pdf "${REPO_ROOT}/netpolicy_team_guide.pdf"

echo "[SUCCESS] PDF exported cleanly to:"
echo "  - Windows Downloads: ${TARGET_DIR}netpolicy_team_guide.pdf"
echo "  - Local Linux: /home/tanishq/netpolicy_team_guide.pdf"
echo "  - Repository: ${REPO_ROOT}/netpolicy_team_guide.pdf"
