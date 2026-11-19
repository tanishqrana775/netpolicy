"""Test reverse proxy that injects middlebox headers and modifies responses."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# Ensure project root is in sys.path when executed directly as a script
_REPO_ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


class TamperProxyHandler(BaseHTTPRequestHandler):
    """Forwards incoming requests to upstream canary and injects Via/X-Cache headers."""

    def log_message(self, format_str: str, *args: Any) -> None:
        """Suppress standard stderr log messages."""
        pass

    def do_GET(self) -> None:
        """Forward GET request to upstream, inject headers, and modify body if enabled."""
        server = self.server
        if not isinstance(server, TamperProxyServer):
            self.send_error(500, "Internal Server Error: Unexpected server instance")
            return

        upstream_host = server.upstream_host
        upstream_port = server.upstream_port
        modify_body = server.modify_body

        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=5.0)
        try:
            # Forward client headers except Host
            forward_headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
            forward_headers["Host"] = f"{upstream_host}:{upstream_port}"

            conn.request("GET", self.path, headers=forward_headers)
            resp = conn.getresponse()
            status = resp.status
            raw_headers = resp.getheaders()
            body = resp.read()
        except (http.client.HTTPException, OSError, TimeoutError) as exc:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Bad Gateway: {exc}".encode())
            return
        finally:
            conn.close()

        # Invalidate body hash on /canary.txt if modification is enabled
        if modify_body and self.path.startswith("/canary") and body:
            body = body + b"\n<!-- TAMPERED_BY_MIDDLEBOX -->\n"

        self.send_response(status)

        # Forward upstream headers excluding Content-Length (which we recompute)
        for name, value in raw_headers:
            if name.lower() != "content-length":
                self.send_header(name, value)

        # Inject middlebox signature headers
        self.send_header("Via", "1.1 netpolicy-test-proxy")
        self.send_header("X-Cache", "HIT")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)


class TamperProxyServer(HTTPServer):
    """HTTPServer carrying upstream target configuration."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        upstream_host: str,
        upstream_port: int,
        modify_body: bool = False,
    ) -> None:
        super().__init__(server_address, request_handler_class)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.modify_body = modify_body


class TamperProxy:
    """Threaded test reverse proxy for simulating network middlebox tampering."""

    def __init__(
        self,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8080,
        modify_body: bool = False,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.modify_body = modify_body
        self.host = host
        self._requested_port = port
        self.httpd: TamperProxyServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """Return the actual bound port."""
        if self.httpd is None:
            return self._requested_port
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        """Start the proxy server in a background thread gracefully."""
        if self._thread is not None and self._thread.is_alive():
            return

        try:
            self.httpd = TamperProxyServer(
                (self.host, self._requested_port),
                TamperProxyHandler,
                upstream_host=self.upstream_host,
                upstream_port=self.upstream_port,
                modify_body=self.modify_body,
            )
        except OSError as exc:
            raise RuntimeError(
                f"Failed to bind TamperProxy on {self.host}:{self._requested_port}: {exc}"
            ) from exc

        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop and close the proxy server gracefully."""
        if self.httpd is not None:
            with contextlib.suppress(Exception):
                self.httpd.shutdown()
                self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def main() -> None:
    """CLI entrypoint to run the tamper proxy standalone."""
    parser = argparse.ArgumentParser(description="NetPolicy Test Tamper Proxy")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind")
    parser.add_argument("--port", type=int, default=8081, help="Port to listen on")
    parser.add_argument("--upstream-host", default="127.0.0.1", help="Upstream target host")
    parser.add_argument("--upstream-port", type=int, default=8080, help="Upstream target port")
    parser.add_argument("--modify-body", action="store_true", help="Modify response body payload")
    args = parser.parse_args()

    proxy = TamperProxy(
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        modify_body=args.modify_body,
        host=args.host,
        port=args.port,
    )
    try:
        proxy.start()
    except (RuntimeError, OSError) as exc:
        print(f"Error starting tamper proxy: {exc}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Tamper proxy listening on http://{args.host}:{proxy.port} -> "
        f"http://{args.upstream_host}:{args.upstream_port}"
    )
    try:
        if proxy._thread is not None:
            proxy._thread.join()
    except KeyboardInterrupt:
        print("\nShutting down tamper proxy.")
        proxy.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
