"""Re-export of TamperProxy for netpolicy.canary module namespace."""

from __future__ import annotations

from tests.tamper_proxy import (
    TamperProxy,
    TamperProxyHandler,
    TamperProxyServer,
    main,
)

__all__ = ["TamperProxy", "TamperProxyHandler", "TamperProxyServer", "main"]
