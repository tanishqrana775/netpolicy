"""Execution context and runtime environment for probes."""

from __future__ import annotations

import ctypes
import hashlib
import os
from dataclasses import dataclass, field

from netpolicy.models import Target


@dataclass
class Context:
    """Carries runtime execution options, probe limits, and network environment context."""

    mode: str = "auto"
    timeout: float = 3.0
    retries: int = 2
    runs: int = 5
    rate_limit: float = 20.0  # probes per second
    server_address: str = "127.0.0.1"
    control_target: Target = field(
        default_factory=lambda: Target(host="1.1.1.1", port=443, service="Control-HTTPS")
    )

    def __post_init__(self) -> None:
        """Resolve 'auto' mode to 'raw' (privileged) or 'socket' (unprivileged)."""
        if self.mode == "auto":
            is_root = False
            if hasattr(os, "geteuid"):
                is_root = os.geteuid() == 0
            elif hasattr(ctypes, "windll"):
                try:
                    is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    is_root = False
            self.mode = "raw" if is_root else "socket"

    @staticmethod
    def compute_network_fingerprint(
        gateway_ip: str | None = None,
        resolver_ip: str | None = None,
    ) -> str:
        """Compute a privacy-preserving SHA-256 network fingerprint.

        Hashes the gateway and resolver IP addresses so network changes can be
        identified without exposing raw IP addresses, MACs, or SSIDs.
        """
        gw = (gateway_ip or "0.0.0.0").strip()
        dns = (resolver_ip or "0.0.0.0").strip()
        raw_token = f"{gw}|{dns}".encode()
        return hashlib.sha256(raw_token).hexdigest()

    def network_fingerprint(
        self,
        gateway_ip: str | None = None,
        resolver_ip: str | None = None,
    ) -> str:
        """Instance helper returning the computed SHA-256 network fingerprint."""
        return self.compute_network_fingerprint(gateway_ip, resolver_ip)


# Backwards compatibility alias
AuditContext = Context
