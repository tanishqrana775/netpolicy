"""Smoke tests for the ports command running against a local TCP listener in socket mode."""

from __future__ import annotations

import contextlib
import json
import socket
import threading
from pathlib import Path

from typer.testing import CliRunner

from netpolicy.cli import app

runner = CliRunner()


class LocalTCPListener(threading.Thread):
    """Local TCP server accepting connections on an ephemeral loopback port."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port: int = self.sock.getsockname()[1]
        self.running = True
        self.connection_count = 0

    def run(self) -> None:
        while self.running:
            try:
                self.sock.settimeout(0.2)
                client_sock, _ = self.sock.accept()
                self.connection_count += 1
                client_sock.close()
            except (TimeoutError, OSError):
                continue

    def stop(self) -> None:
        self.running = False
        with contextlib.suppress(OSError):
            self.sock.close()


def test_ports_smoke_local_listener() -> None:
    """Verify ports command connects to a local listener, saves JSONL, and renders raw table."""
    listener = LocalTCPListener()
    listener.start()
    try:
        result = runner.invoke(
            app,
            [
                "ports",
                "--target",
                "127.0.0.1",
                "--ports",
                str(listener.port),
                "--control-port",
                str(listener.port),
                "--runs",
                "1",
                "--mode",
                "socket",
                "--no-color",
            ],
        )

        assert result.exit_code == 0, f"Command failed with output: {result.output}"
        # Assert clean verdict in redesigned report
        assert "CLEAN" in result.output

        # Assert JSONL report file was created under reports/
        reports_dir = Path("reports")
        assert reports_dir.exists()
        jsonl_files = list(reports_dir.glob("*.jsonl"))
        assert len(jsonl_files) > 0

        # Read the latest jsonl file and assert contents
        latest_file = max(jsonl_files, key=lambda f: f.stat().st_mtime)
        lines = latest_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 1

        parsed_records = [json.loads(line) for line in lines]
        found_connected = any(
            r.get("probe_name") == "tcp_connect"
            and r.get("observation", {}).get("target", {}).get("port") == listener.port
            and r.get("observation", {}).get("raw", {}).get("outcome") == "connected"
            for r in parsed_records
        )
        assert found_connected, f"Did not find connected observation in {latest_file}"
        assert listener.connection_count >= 1

    finally:
        listener.stop()
        listener.join(timeout=1.0)


def test_ports_missing_target_safety_check() -> None:
    """Verify ports command without target prints helpful error and exits code 2."""
    result = runner.invoke(app, ["ports"])
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "--target is required" in result.output


def test_http_missing_target_safety_check() -> None:
    """Verify http command without target prints helpful error and exits code 2."""
    result = runner.invoke(app, ["http"])
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "--target is required" in result.output


def test_audit_missing_target_safety_check() -> None:
    """Verify audit command without target prints helpful error and exits code 2."""
    result = runner.invoke(app, ["audit"])
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "--target is required" in result.output


def test_ports_output_file_markdown(tmp_path: Path) -> None:
    """Verify ports --output my_report.md writes a valid Markdown table."""
    listener = LocalTCPListener()
    listener.start()
    out_file = tmp_path / "raw_report.md"
    try:
        result = runner.invoke(
            app,
            [
                "ports",
                "--target",
                "127.0.0.1",
                "--ports",
                str(listener.port),
                "--control-port",
                str(listener.port),
                "--runs",
                "1",
                "--mode",
                "socket",
                "--output",
                str(out_file),
                "--no-color",
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "# Network Policy Audit Report" in content
        assert "Outbound Port Reachability" in content
        assert "OPEN" in content
    finally:
        listener.stop()
        listener.join(timeout=1.0)
