"""Tests for HttpCanaryProbe, CanaryServer, and TamperProxy."""

from __future__ import annotations

import hashlib
import http.client
import json
from unittest.mock import MagicMock, patch

from canary.server import CANARY_BODY, CANARY_SHA256, CanaryServer
from netpolicy.engine.context import Context
from netpolicy.models import Target
from netpolicy.probes.http import HTTPCanaryProbe, HttpCanaryProbe, HTTPProbe

try:
    from .tamper_proxy import TamperProxy
except (ImportError, ValueError):
    from tests.tamper_proxy import TamperProxy


def test_canary_server_direct_endpoints() -> None:
    """Verify CanaryServer endpoints /canary.txt, /echo, and /manifest.json directly."""
    server = CanaryServer(host="127.0.0.1", port=0)
    server.start()

    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2.0)

        # 1. /canary.txt
        conn.request("GET", "/canary.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read()
        assert body == CANARY_BODY
        assert hashlib.sha256(body).hexdigest() == CANARY_SHA256

        # 2. /echo with custom nonce
        test_nonce = "abc123nonce456"
        conn.request("GET", "/echo", headers={"X-NetPolicy-Nonce": test_nonce})
        resp = conn.getresponse()
        assert resp.status == 200
        echo_json = json.loads(resp.read().decode("utf-8"))
        assert echo_json["nonce"] == test_nonce
        assert "x-netpolicy-nonce" in {k.lower(): v for k, v in echo_json["headers"].items()}

        # 3. /manifest.json
        conn.request("GET", "/manifest.json")
        resp = conn.getresponse()
        assert resp.status == 200
        manifest = json.loads(resp.read().decode("utf-8"))
        assert manifest["expected_sha256"] == CANARY_SHA256
        assert "x-netpolicy-nonce" in [h.lower() for h in manifest["expected_headers"]]

        conn.close()
    finally:
        server.stop()


def test_http_canary_probe_against_canary_clean() -> None:
    """Verify HttpCanaryProbe against canary server reports clean headers and matching SHA."""
    server = CanaryServer(host="127.0.0.1", port=0)
    server.start()

    try:
        probe = HttpCanaryProbe(schemes=["http"])
        ctx = Context(timeout=2.0)
        target = Target(host="127.0.0.1", port=server.port, service="HTTP-Canary")

        observations = probe.run(ctx, target)
        assert len(observations) == 2

        canary_obs = next(o for o in observations if o.raw["path"] == "/canary.txt")
        echo_obs = next(o for o in observations if o.raw["path"] == "/echo")

        # Verify /canary.txt observation
        assert canary_obs.success is True
        assert canary_obs.raw["status"] == 200
        assert canary_obs.raw["body_sha256"] == CANARY_SHA256
        assert isinstance(canary_obs.raw["headers"], list)
        header_names = [k.lower() for k, _ in canary_obs.raw["headers"]]
        assert "via" not in header_names
        assert "x-cache" not in header_names

        # Verify /echo observation
        assert echo_obs.success is True
        assert echo_obs.raw["status"] == 200
        assert echo_obs.raw["nonce_matches"] is True
        assert echo_obs.raw["nonce_echoed"] == echo_obs.raw["nonce_sent"]
        assert echo_obs.raw["echoed_headers"] is not None
        assert echo_obs.raw["rtt_ms"] is not None and echo_obs.raw["rtt_ms"] >= 0
    finally:
        server.stop()


def test_http_canary_probe_against_tamper_proxy() -> None:
    """Verify HttpCanaryProbe records injected Via/X-Cache headers and modified body hash."""
    canary = CanaryServer(host="127.0.0.1", port=0)
    canary.start()

    proxy = TamperProxy(
        upstream_host="127.0.0.1",
        upstream_port=canary.port,
        modify_body=True,
        port=0,
    )
    proxy.start()

    try:
        probe = HttpCanaryProbe(schemes=["http"])
        ctx = Context(timeout=2.0)
        target = Target(host="127.0.0.1", port=proxy.port, service="HTTP-Tampered")

        observations = probe.run(ctx, target)
        assert len(observations) == 2

        canary_obs = next(o for o in observations if o.raw["path"] == "/canary.txt")
        echo_obs = next(o for o in observations if o.raw["path"] == "/echo")

        # 1. Extra headers injected by the proxy
        header_dict_canary = {k.lower(): v for k, v in canary_obs.raw["headers"]}
        assert header_dict_canary.get("via") == "1.1 netpolicy-test-proxy"
        assert header_dict_canary.get("x-cache") == "HIT"

        # 2. Body was modified, SHA-256 must differ from clean canary SHA-256
        assert canary_obs.raw["body_sha256"] != CANARY_SHA256

        # 3. Nonce was forwarded through proxy to upstream canary
        assert echo_obs.raw["nonce_matches"] is True
        assert echo_obs.raw["nonce_echoed"] == echo_obs.raw["nonce_sent"]
        header_dict_echo = {k.lower(): v for k, v in echo_obs.raw["headers"]}
        assert header_dict_echo.get("via") == "1.1 netpolicy-test-proxy"
    finally:
        proxy.stop()
        canary.stop()


@patch("netpolicy.probes.http._fetch_https")
def test_http_canary_probe_https_mocked(mock_fetch_https: MagicMock) -> None:
    """Verify HTTPS probing branches correctly and records observation."""
    mock_fetch_https.return_value = (
        200,
        [("Server", "Cloudflare"), ("Content-Type", "text/plain")],
        b"NETPOLICY_CANARY_STABLE_VERIFICATION_PAYLOAD\n",
        [],
        25.0,
        None,
    )

    probe = HttpCanaryProbe(schemes=["https"])
    ctx = Context(timeout=2.0)
    target = Target(host="canary.example.com", port=443)

    observations = probe.run(ctx, target)
    assert len(observations) == 2
    for obs in observations:
        assert obs.raw["scheme"] == "https"
        assert obs.raw["status"] == 200
        assert obs.raw["headers"] == [
            ("Server", "Cloudflare"),
            ("Content-Type", "text/plain"),
        ]
        assert obs.raw["body_sha256"] == CANARY_SHA256


def test_http_probe_class_aliases() -> None:
    """Verify backwards-compatible aliases for HttpCanaryProbe."""
    assert HTTPCanaryProbe is HttpCanaryProbe
    assert HTTPProbe is HttpCanaryProbe
