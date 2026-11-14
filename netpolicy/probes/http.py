"""HTTP and HTTPS canary probing module.

Audits HTTP traffic against a canary server to detect middlebox tampering,
header injection (e.g. Via, X-Cache), body rewriting, captive portal redirection,
and request header stripping.
Uses stdlib http.client for plain HTTP to preserve raw header order and case,
and httpx for HTTPS.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import secrets
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

import httpx

from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe

if TYPE_CHECKING:
    from netpolicy.engine.context import Context


__all__ = ["HttpCanaryProbe", "HTTPCanaryProbe", "HTTPProbe"]


def _fetch_plain_http(
    host: str,
    port: int,
    path: str,
    headers: dict[str, str],
    timeout: float = 3.0,
    max_redirects: int = 5,
) -> tuple[int | None, list[tuple[str, str]], bytes, list[dict[str, Any]], float, str | None]:
    """Fetch endpoint via stdlib http.client, preserving raw response header order."""
    start_time = time.perf_counter()
    redirects: list[dict[str, Any]] = []

    current_host = host
    current_port = port
    current_path = path

    for _ in range(max_redirects):
        conn = http.client.HTTPConnection(current_host, current_port, timeout=timeout)
        try:
            req_headers = dict(headers)
            req_headers["Host"] = (
                f"{current_host}:{current_port}" if current_port != 80 else current_host
            )
            conn.request("GET", current_path, headers=req_headers)
            resp = conn.getresponse()
            status = resp.status
            resp_headers = resp.getheaders()
            body = resp.read()

            # Check for HTTP redirect response (301, 302, 303, 307, 308)
            if status in (301, 302, 303, 307, 308):
                location = next(
                    (v for k, v in resp_headers if k.lower() == "location"),
                    None,
                )
                if location:
                    redirects.append({"status": status, "location": location})
                    parsed = urllib.parse.urlsplit(location)
                    if parsed.netloc:
                        netloc_parts = parsed.netloc.split(":")
                        current_host = netloc_parts[0]
                        current_port = int(netloc_parts[1]) if len(netloc_parts) > 1 else 80
                    if parsed.path:
                        current_path = parsed.path
                        if parsed.query:
                            current_path += f"?{parsed.query}"
                    continue

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return status, resp_headers, body, redirects, round(elapsed_ms, 3), None

        except (TimeoutError, http.client.RemoteDisconnected):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return None, [], b"", redirects, round(elapsed_ms, 3), "timeout"
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return None, [], b"", redirects, round(elapsed_ms, 3), str(exc)
        finally:
            conn.close()

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return status, resp_headers, body, redirects, round(elapsed_ms, 3), None


def _fetch_https(
    host: str,
    port: int,
    path: str,
    headers: dict[str, str],
    timeout: float = 3.0,
) -> tuple[int | None, list[tuple[str, str]], bytes, list[dict[str, Any]], float, str | None]:
    """Fetch endpoint over HTTPS using httpx, preserving header order."""
    start_time = time.perf_counter()
    url = f"https://{host}:{port}{path}" if port != 443 else f"https://{host}{path}"

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Decode raw headers to preserve order and case
            resp_headers: list[tuple[str, str]] = [
                (k.decode("latin1"), v.decode("latin1")) for k, v in resp.headers.raw
            ]
            redirects = [{"status": r.status_code, "location": str(r.url)} for r in resp.history]
            return (
                resp.status_code,
                resp_headers,
                resp.content,
                redirects,
                round(elapsed_ms, 3),
                None,
            )

    except httpx.TimeoutException:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, [], b"", [], round(elapsed_ms, 3), "timeout"
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, [], b"", [], round(elapsed_ms, 3), str(exc)


class HttpCanaryProbe(Probe):
    """Probes canary endpoints over HTTP and HTTPS to record raw response metrics and headers."""

    name = "http_canary"
    requires_root = False

    def __init__(
        self,
        http_port: int = 80,
        https_port: int = 443,
        schemes: list[str] | None = None,
        user_agent: str = "netpolicy/0.1.0",
    ) -> None:
        self.http_port = http_port
        self.https_port = https_port
        self.schemes = list(schemes) if schemes else None
        self.user_agent = user_agent

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Fetch /canary.txt and /echo over configured schemes and record raw observations."""
        host = target.host
        observations: list[Observation] = []

        # Determine which schemes to probe
        if self.schemes is not None:
            active_schemes = self.schemes
        elif target.port == 443:
            active_schemes = ["https"]
        elif target.port is not None and target.port != 80:
            # Custom port (e.g. local test canary on 127.0.0.1:port)
            active_schemes = ["http"]
        else:
            active_schemes = ["http", "https"]

        for scheme in active_schemes:
            if target.port is not None:
                port = target.port
            else:
                port = self.https_port if scheme == "https" else self.http_port

            for path in ("/canary.txt", "/echo"):
                nonce = secrets.token_hex(16)
                req_headers = {
                    "User-Agent": self.user_agent,
                    "X-NetPolicy-Nonce": nonce,
                    "Accept": "*/*",
                }

                if scheme == "http":
                    status, resp_headers, body, redirects, rtt, err = _fetch_plain_http(
                        host=host,
                        port=port,
                        path=path,
                        headers=req_headers,
                        timeout=ctx.timeout,
                    )
                else:
                    status, resp_headers, body, redirects, rtt, err = _fetch_https(
                        host=host,
                        port=port,
                        path=path,
                        headers=req_headers,
                        timeout=ctx.timeout,
                    )

                body_sha256 = hashlib.sha256(body).hexdigest() if body else None

                echoed_nonce: str | None = None
                echoed_headers: dict[str, str] | None = None

                if path == "/echo" and body and status == 200:
                    try:
                        echo_data = json.loads(body.decode("utf-8"))
                        echoed_nonce = echo_data.get("nonce")
                        echoed_headers = echo_data.get("headers")
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass

                raw_fields: dict[str, Any] = {
                    "scheme": scheme,
                    "path": path,
                    "port": port,
                    "url": f"{scheme}://{host}:{port}{path}",
                    "status": status,
                    "headers": resp_headers,
                    "body_sha256": body_sha256,
                    "body_len": len(body),
                    "nonce_sent": nonce,
                    "nonce_echoed": echoed_nonce,
                    "echoed_headers": echoed_headers,
                    "nonce_matches": (echoed_nonce == nonce) if echoed_nonce else None,
                    "redirects": redirects,
                    "rtt_ms": rtt,
                    "error": err,
                }

                obs = Observation(
                    probe_name=self.name,
                    target=Target(
                        host=host,
                        port=port,
                        service=f"HTTP-{scheme.upper()}",
                    ),
                    timestamp=time.time(),
                    success=(status == 200 and err is None),
                    raw=raw_fields,
                )
                observations.append(obs)

        return observations


# Class aliases
HTTPCanaryProbe = HttpCanaryProbe
HTTPProbe = HttpCanaryProbe
