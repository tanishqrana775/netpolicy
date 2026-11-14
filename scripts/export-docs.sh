#!/usr/bin/env bash
# ==============================================================================
# Netpolicy Documentation Exporter
#
# Exports documentation (docs/netpolicy_master_guide.md and docs/PORTABILITY.md)
# from the WSL2 Linux environment into the Windows host Downloads\netpolicy
# folder.
#
# SAFETY & PORTABILITY GUARANTEES:
# - Runs completely unprivileged (requires NO root, calls NO sudo).
# - Never silently overwrites: existing destination files are moved to
#   timestamped backups (.bak.<timestamp>) with notice to the user.
# - Resolves Windows user profile dynamically via cmd.exe and wslpath:
#   wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
# - Provides graceful fallback with \\wsl$\<distro>\... UNC paths and manual
#   copy instructions if not in WSL or if cmd.exe interop is disabled.
# - Supports an optional command-line argument for a custom destination folder.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CUSTOM_DEST="${1:-}"

# Documentation files to export
DOCS_TO_EXPORT=(
    "docs/netpolicy_master_guide.md"
    "docs/PORTABILITY.md"
)

# ------------------------------------------------------------------------------
# 1. Determine Destination Directory
# ------------------------------------------------------------------------------
DEST_DIR=""
INTEROP_OK=false

if [[ -n "${CUSTOM_DEST}" ]]; then
    # Custom destination provided by user (supports both Windows and Linux paths)
    if command -v wslpath >/dev/null 2>&1 && [[ "${CUSTOM_DEST}" =~ ^[A-Za-z]:[/\\] || "${CUSTOM_DEST}" =~ ^\\\\ ]]; then
        DEST_DIR="$(wslpath -u "${CUSTOM_DEST}" 2>/dev/null || echo "${CUSTOM_DEST}")"
    else
        DEST_DIR="${CUSTOM_DEST}"
    fi
    echo "Using custom destination: ${DEST_DIR}"
else
    # Automatic resolution for Windows Downloads\netpolicy via WSL interop
    if command -v wslpath >/dev/null 2>&1 && command -v cmd.exe >/dev/null 2>&1; then
        WIN_PROFILE_RAW="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r' || true)"
        if [[ -n "${WIN_PROFILE_RAW}" && "${WIN_PROFILE_RAW}" != "%USERPROFILE%" ]]; then
            WIN_PROFILE="$(wslpath "${WIN_PROFILE_RAW}" 2>/dev/null || true)"
            if [[ -n "${WIN_PROFILE}" && -d "${WIN_PROFILE}" ]]; then
                DEST_DIR="${WIN_PROFILE}/Downloads/netpolicy"
                INTEROP_OK=true
            fi
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 2. Handle Non-WSL or Missing Interop Fallback
# ------------------------------------------------------------------------------
if [[ -z "${DEST_DIR}" ]]; then
    echo "================================================================================"
    echo "NOTICE: Not running in WSL with active cmd.exe interop, or Windows profile"
    echo "could not be automatically resolved."
    echo "================================================================================"
    echo ""
    echo "Available Documentation Files in Linux repository:"
    for rel_doc in "${DOCS_TO_EXPORT[@]}"; do
        full_doc="${REPO_ROOT}/${rel_doc}"
        if [[ -f "${full_doc}" ]]; then
            echo "  - Linux path: ${full_doc}"
            if command -v wslpath >/dev/null 2>&1; then
                unc_path="$(wslpath -w "${full_doc}" 2>/dev/null || true)"
                if [[ -n "${unc_path}" ]]; then
                    echo "    Windows UNC path: ${unc_path}"
                fi
            fi
        fi
    done
    echo ""
    echo "Manual Copy Instructions:"
    echo "  1. If running in WSL, access files directly from Windows File Explorer at:"
    echo "     \\\\wsl$\\<distro-name>\\home\\<username>\\netpolicy\\docs\\"
    echo "  2. Or specify a custom Linux mount/target directory as an argument:"
    echo "     bash scripts/export-docs.sh /path/to/destination"
    echo "     e.g., bash scripts/export-docs.sh /mnt/c/Users/<username>/Downloads/netpolicy"
    echo "================================================================================"
    exit 0
fi

# ------------------------------------------------------------------------------
# 3. Create Target Directory & Export Files
# ------------------------------------------------------------------------------
mkdir -p "${DEST_DIR}"
echo "Exporting documentation to: ${DEST_DIR}"
echo ""

COPIED_COUNT=0

for rel_doc in "${DOCS_TO_EXPORT[@]}"; do
    SRC_FILE="${REPO_ROOT}/${rel_doc}"
    if [[ ! -f "${SRC_FILE}" ]]; then
        echo "[-] Skipping ${rel_doc} (file not found)."
        continue
    fi

    BASE_NAME="$(basename "${rel_doc}")"
    TARGET_FILE="${DEST_DIR}/${BASE_NAME}"

    # Backup existing file with timestamp; never silently overwrite
    if [[ -f "${TARGET_FILE}" ]]; then
        TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
        BACKUP_FILE="${TARGET_FILE}.${TIMESTAMP}.bak"
        mv "${TARGET_FILE}" "${BACKUP_FILE}"
        echo "[!] Existing file found at destination. Created backup:"
        echo "    ${BACKUP_FILE}"
        if command -v wslpath >/dev/null 2>&1; then
            WIN_BACKUP="$(wslpath -w "${BACKUP_FILE}" 2>/dev/null || true)"
            if [[ -n "${WIN_BACKUP}" ]]; then
                echo "    Windows backup path: ${WIN_BACKUP}"
            fi
        fi
    fi

    # Perform copy
    cp "${SRC_FILE}" "${TARGET_FILE}"
    echo "[+] Exported: ${BASE_NAME}"
    echo "    Linux path:   ${TARGET_FILE}"

    if command -v wslpath >/dev/null 2>&1; then
        WIN_TARGET="$(wslpath -w "${TARGET_FILE}" 2>/dev/null || true)"
        if [[ -n "${WIN_TARGET}" ]]; then
            echo "    Windows path: ${WIN_TARGET}"
        fi
    fi
    echo ""
    COPIED_COUNT=$((COPIED_COUNT + 1))
done

echo "================================================================================"
echo "Export complete: ${COPIED_COUNT} documentation file(s) copied."
if command -v wslpath >/dev/null 2>&1; then
    WIN_DEST_DIR="$(wslpath -w "${DEST_DIR}" 2>/dev/null || true)"
    if [[ -n "${WIN_DEST_DIR}" ]]; then
        echo "Windows folder: ${WIN_DEST_DIR}"
    fi
fi
echo "================================================================================"
