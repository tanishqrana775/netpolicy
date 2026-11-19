"""Tests for HttpCanaryProbe (alias for test_http.py)."""

from __future__ import annotations

from tests.test_http import (
    test_canary_server_direct_endpoints,
    test_http_canary_probe_against_canary_clean,
    test_http_canary_probe_against_tamper_proxy,
    test_http_canary_probe_https_mocked,
    test_http_probe_class_aliases,
)

__all__ = [
    "test_canary_server_direct_endpoints",
    "test_http_canary_probe_against_canary_clean",
    "test_http_canary_probe_against_tamper_proxy",
    "test_http_canary_probe_https_mocked",
    "test_http_probe_class_aliases",
]
