#!/usr/bin/env bash
# ==============================================================================
# Netpolicy System Dependencies Bootstrap
#
# Installs all required OS-level packages for netpolicy and its validation lab.
# Supported on apt-based Linux distributions (Debian, Ubuntu, Kali Linux, etc.).
# Prints equivalent package commands for non-apt package managers (dnf, pacman).
#
# SAFETY GUARANTEES:
# - Installs packages only; alters NO system configuration, firewall, or routing.
# - Refuses execution if not running as root (EUID != 0) and NEVER calls sudo.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# 1. Privilege Check (Root required, never invoke sudo)
# ------------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: scripts/bootstrap-system.sh must be run with root privileges (EUID 0)." >&2
    echo "Please run: sudo bash scripts/bootstrap-system.sh" >&2
    exit 1
fi

echo "=== Netpolicy System Dependencies Bootstrap ==="

# ------------------------------------------------------------------------------
# 2. Package Manager Detection & Installation
# ------------------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    echo "[+] Debian/Ubuntu/Kali (apt) detected. Updating package index..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    echo "[+] Installing required runtime, probe, and lab dependencies..."
    # Dependencies required by netpolicy probes and lab scripts:
    # - python3, python3-venv, python3-pip: core runtime & packaging
    # - iproute2: ip netns, ip link, ip addr, ip route, tc (traffic control)
    # - iptables: middlebox filtering, DNAT, and RST injection inside lab np-gw
    # - curl, ca-certificates: HTTPS probe verification, canary testing, get-pip
    # - iputils-ping: ICMP baseline reachability verification
    # - psmisc: fuser (used by lab/services.sh to stop listeners cleanly)
    # - procps: sysctl (used to configure IP forwarding inside np-gw)
    apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        iproute2 \
        iptables \
        curl \
        ca-certificates \
        iputils-ping \
        psmisc \
        procps

    echo ""
    echo "[OK] All system packages successfully installed."
    echo "Next: set up the Python virtual environment (run as regular user):"
    echo "  bash scripts/bootstrap-python.sh"
    exit 0

elif command -v dnf >/dev/null 2>&1; then
    echo "[-] Non-apt system detected (Fedora/RHEL/CentOS with dnf)." >&2
    echo "Please install the equivalent packages using:" >&2
    echo "  sudo dnf install -y python3 python3-pip iproute iptables curl ca-certificates iputils psmisc procps-ng" >&2
    exit 1

elif command -v pacman >/dev/null 2>&1; then
    echo "[-] Non-apt system detected (Arch Linux with pacman)." >&2
    echo "Please install the equivalent packages using:" >&2
    echo "  sudo pacman -S --needed python python-pip iproute2 iptables curl ca-certificates iputils psmisc procps-ng" >&2
    exit 1

else
    echo "[-] Unsupported package manager. Required tools:" >&2
    echo "  - python3 (>= 3.10), python3-pip, python3-venv" >&2
    echo "  - iproute2 (ip, tc), iptables" >&2
    echo "  - curl, ca-certificates, ping (iputils), fuser (psmisc), sysctl (procps)" >&2
    exit 1
fi
