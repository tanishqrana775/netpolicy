"""Canary HTTP server for network policy verification.

Provides endpoints to detect header injection, payload tampering, and proxy interference:
- GET /canary.txt: returns fixed static body for SHA-256 integrity check.
- GET /echo: returns JSON containing all request headers observed by the server.
- GET /manifest.json: returns the expected body SHA-256 and expected header allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

CANARY_BODY: bytes = b"NETPOLICY_CANARY_STABLE_VERIFICATION_PAYLOAD\n"
CANARY_SHA256: str = hashlib.sha256(CANARY_BODY).hexdigest()

EXPECTED_HEADERS: list[str] = [
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "x-netpolicy-nonce",
]

DISALLOWED_HEADERS: list[str] = [
    "via",
    "x-cache",
    "x-forwarded-for",
    "x-forwarded-proto",
    "cf-ray",
]


class CanaryHTTPRequestHandler(BaseHTTPRequestHandler):
    """Handler serving /canary.txt, /echo, and /manifest.json."""

    def log_message(self, format_str: str, *args: Any) -> None:
        """Suppress standard stderr log messages to keep CLI/tests clean."""
        pass

    def do_GET(self) -> None:
        """Handle GET requests for canary verification endpoints."""
        clean_path = self.path.split("?")[0]

        if clean_path == "/canary.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(CANARY_BODY)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(CANARY_BODY)

        elif clean_path == "/echo":
            # Collect all request headers seen by the server
            received_headers = dict(self.headers.items())
            received_nonce = self.headers.get("X-NetPolicy-Nonce")

            payload = {
                "nonce": received_nonce,
                "headers": received_headers,
                "path": self.path,
                "client_address": self.client_address[0] if self.client_address else None,
            }
            body = json.dumps(payload, indent=2).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store")
            self.end_headers()
            self.wfile.write(body)

        elif clean_path == "/manifest.json":
            manifest_payload: dict[str, Any] = {
                "canary_path": "/canary.txt",
                "expected_sha256": CANARY_SHA256,
                "expected_headers": EXPECTED_HEADERS,
                "disallowed_headers": DISALLOWED_HEADERS,
            }
            body = json.dumps(manifest_payload, indent=2).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")


class CanaryServer:
    """Configurable stdlib http.server canary server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """Return the actual bound listening port."""
        if self.httpd is None:
            return self._requested_port
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        """Start the canary server in a background thread."""
        self.httpd = HTTPServer((self.host, self._requested_port), CanaryHTTPRequestHandler)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shut down and close the canary server."""
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def main() -> None:
    """CLI entrypoint to run the canary server standalone."""
    parser = argparse.ArgumentParser(description="NetPolicy Canary HTTP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), CanaryHTTPRequestHandler)
    print(f"Canary server listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down canary server.")
        server.server_close()
        sys.exit(0)


if __name__ == "__main__":
    main()
