"""Tests for unprivileged socket-based TCP connect probe."""

from __future__ import annotations

import errno
import select
import socket
import threading
from unittest.mock import patch

import pytest

from netpolicy.engine.context import Context
from netpolicy.models import Target
from netpolicy.probes.tcp_connect import TCPConnectProbe, TcpConnectProbe


def test_tcp_connect_probe_exports() -> None:
    """Verify TcpConnectProbe is the primary class and TCPConnectProbe is an alias."""
    assert TcpConnectProbe is not None
    assert TCPConnectProbe is TcpConnectProbe


def _run_local_listener(server_sock: socket.socket, stop_event: threading.Event) -> None:
    """Accept a single client connection and close cleanly."""
    server_sock.settimeout(2.0)
    try:
        conn, _ = server_sock.accept()
        conn.close()
    except (TimeoutError, OSError):
        pass
    finally:
        server_sock.close()


def test_tcp_connect_success_local_listener() -> None:
    """Verify TCPConnectProbe successfully records connected outcome on an open local port."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    stop_event = threading.Event()
    listener_thread = threading.Thread(
        target=_run_local_listener,
        args=(server_sock, stop_event),
        daemon=True,
    )
    listener_thread.start()

    probe = TCPConnectProbe()
    target = Target(host="127.0.0.1", port=port, service="Test-Echo", expect_open=True)
    ctx = Context(timeout=1.0, retries=1)

    observations = probe.run(ctx, target)
    listener_thread.join(timeout=1.0)

    assert len(observations) == 1
    obs = observations[0]
    assert obs.success is True
    assert obs.probe_name == "tcp_connect"
    assert obs.raw["outcome"] == "connected"
    assert obs.raw["errno"] == 0
    assert obs.raw["errno_name"] == "0"
    assert obs.raw["rtt_ms"] > 0
    assert obs.raw["expect_open"] is True
    assert obs.raw["attempt"] == 1
    assert obs.raw["reply_received"] is True


def test_tcp_connect_refused_closed_port() -> None:
    """Verify TCPConnectProbe records refused outcome and retries on closed localhost port."""
    # Find an unused port by binding and immediately closing
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    closed_port = temp_sock.getsockname()[1]
    temp_sock.close()

    probe = TCPConnectProbe()
    target = Target(host="127.0.0.1", port=closed_port, service="Closed", expect_open=False)
    # retries=2 -> 1 initial + 2 retries = 3 observations
    ctx = Context(timeout=0.2, retries=2)

    # Check if host platform drops closed loopback packets (e.g. Windows Firewall stealth mode)
    refused_err = getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED)
    stealth_mode = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check_sock:
        check_sock.setblocking(False)
        check_sock.connect_ex(("127.0.0.1", closed_port))
        _, w, x = select.select([], [check_sock], [check_sock], 0.05)
        if not (w or x):
            stealth_mode = True

    if stealth_mode:
        # On Windows where loopback RST is suppressed by stealth mode, mock the RST return
        with (
            patch.object(select, "select", return_value=([], [1], [1])),
            patch.object(socket.socket, "getsockopt", return_value=refused_err),
        ):
            observations = probe.run(ctx, target)
    else:
        observations = probe.run(ctx, target)

    assert len(observations) == 3
    for idx, obs in enumerate(observations, start=1):
        assert obs.success is False
        assert obs.raw["outcome"] == "refused"
        assert "ECONNREFUSED" in obs.raw["errno_name"]
        assert obs.raw["attempt"] == idx
        assert obs.raw["expect_open"] is False
        assert obs.raw["reply_received"] is True


def test_tcp_connect_timeout_mocked() -> None:
    """Verify TCPConnectProbe records timeout outcome and retries when select times out."""
    probe = TCPConnectProbe()
    target = Target(host="127.0.0.1", port=9999, service="Blackhole", expect_open=True)
    ctx = Context(timeout=0.05, retries=1)

    in_progress = getattr(errno, "WSAEINPROGRESS", errno.EINPROGRESS)

    # Mock connect_ex to report connection in progress, and select to time out with no descriptors
    with (
        patch.object(socket.socket, "connect_ex", return_value=in_progress),
        patch.object(select, "select", return_value=([], [], [])),
    ):
        observations = probe.run(ctx, target)

    assert len(observations) == 2  # initial + 1 retry
    for idx, obs in enumerate(observations, start=1):
        assert obs.success is False
        assert obs.raw["outcome"] == "timeout"
        assert "ETIMEDOUT" in obs.raw["errno_name"]
        assert obs.raw["attempt"] == idx
        assert obs.raw["expect_open"] is True
        assert obs.raw["reply_received"] is False


def test_tcp_connect_missing_port_raises() -> None:
    """Verify TCPConnectProbe raises ValueError if target does not have a port specified."""
    probe = TCPConnectProbe()
    target = Target(host="127.0.0.1", port=None)
    ctx = Context()

    with pytest.raises(ValueError, match="requires target with explicit port"):
        probe.run(ctx, target)
