"""Unit tests for privileged raw TCP SYN probe using Scapy mocks."""

from __future__ import annotations

import os
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from scapy.config import conf
from scapy.layers.inet import ICMP, IP, TCP

from netpolicy.engine.context import Context
from netpolicy.models import Target
from netpolicy.probes.tcp_syn import TCPSYNProbe, TcpSynProbe


def test_tcp_syn_exports() -> None:
    """Verify TcpSynProbe is the canonical class and TCPSYNProbe is an alias."""
    assert TcpSynProbe is not None
    assert TCPSYNProbe is TcpSynProbe


def test_tcp_syn_non_root_raises_permission_error() -> None:
    """Verify probe raises PermissionError advising sudo or socket mode when not root."""
    probe = TcpSynProbe()
    target = Target(host="93.184.216.34", port=443, service="HTTPS")
    ctx = Context()

    with (
        patch.object(os, "geteuid", return_value=1000, create=True),
        pytest.raises(
            PermissionError,
            match=r"sudo \.venv/bin/netpolicy.*--mode socket",
        ),
    ):
        probe.run(ctx, target)


@patch("netpolicy.probes.tcp_syn.send")
@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_syn_ack_response(mock_sr1: MagicMock, mock_send: MagicMock) -> None:
    """Verify SYN-ACK reply parses all raw fields, records syn_ack_ttl, and sends RST."""
    target_host = "93.184.216.34"
    target_port = 443

    # Craft realistic SYN-ACK reply
    syn_ack_pkt = IP(src=target_host, dst="192.168.1.100", ttl=56, id=1234) / TCP(
        sport=target_port,
        dport=54321,
        flags="SA",
        seq=10000,
        ack=20001,
        window=65535,
        options=[("MSS", 1460)],
    )
    mock_sr1.return_value = syn_ack_pkt

    probe = TcpSynProbe()
    target = Target(host=target_host, port=target_port, service="HTTPS", expect_open=True)
    ctx = Context(timeout=1.0, retries=2)

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, target)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is True
    assert obs.probe_name == "tcp_syn"
    assert obs.raw["reply_type"] == "SYN-ACK"
    assert obs.raw["tcp_flags"] == "SA"
    assert obs.raw["ip_ttl"] == 56
    assert obs.raw["ip_id"] == 1234
    assert obs.raw["window_size"] == 65535
    assert obs.raw["tcp_options"] == [("MSS", 1460)]
    assert obs.raw["syn_ack_ttl"] == 56
    assert obs.raw["reply_received"] is True
    assert obs.raw["attempt"] == 1
    assert obs.raw["expect_open"] is True
    assert obs.raw["is_control"] is False
    assert obs.raw["rtt_ms"] >= 0

    # Verify a RST packet was sent to prevent leaving a half-open connection
    assert mock_send.call_count == 1
    rst_call = mock_send.call_args
    rst_pkt = rst_call[0][0]
    assert TCP in rst_pkt
    assert str(rst_pkt[TCP].flags) == "R"
    assert rst_pkt[TCP].seq == 20001
    assert rst_pkt[IP].dst == target_host


@patch("netpolicy.probes.tcp_syn.send")
@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_rst_response(mock_sr1: MagicMock, mock_send: MagicMock) -> None:
    """Verify RST response is recorded correctly and does not send follow-up RST."""
    target_host = "93.184.216.34"
    target_port = 25

    rst_pkt = IP(src=target_host, dst="192.168.1.100", ttl=64, id=2345) / TCP(
        sport=target_port, dport=54321, flags="R", seq=1000, window=0
    )
    mock_sr1.return_value = rst_pkt

    probe = TcpSynProbe()
    target = Target(host=target_host, port=target_port, service="SMTP", expect_open=False)
    ctx = Context(timeout=0.1, retries=0)

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, target)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is False
    assert obs.raw["reply_type"] == "RST"
    assert obs.raw["tcp_flags"] == "R"
    assert obs.raw["ip_ttl"] == 64
    assert obs.raw["ip_id"] == 2345
    assert obs.raw["window_size"] == 0
    assert obs.raw["syn_ack_ttl"] is None
    assert obs.raw["reply_received"] is True
    assert mock_send.call_count == 0


@patch("netpolicy.probes.tcp_syn.send")
@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_rst_ack_response(mock_sr1: MagicMock, mock_send: MagicMock) -> None:
    """Verify RST-ACK response flags are distinguished from pure RST."""
    target_host = "93.184.216.34"
    target_port = 25

    rst_ack_pkt = IP(src=target_host, dst="192.168.1.100", ttl=64, id=2346) / TCP(
        sport=target_port, dport=54321, flags="RA", seq=0, ack=20001, window=0
    )
    mock_sr1.return_value = rst_ack_pkt

    probe = TcpSynProbe()
    target = Target(host=target_host, port=target_port, service="SMTP", expect_open=False)
    ctx = Context(timeout=0.1, retries=0)

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, target)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is False
    assert obs.raw["reply_type"] == "RST-ACK"
    assert obs.raw["tcp_flags"] == "RA"
    assert obs.raw["syn_ack_ttl"] is None
    assert mock_send.call_count == 0


@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_icmp_admin_prohibited(mock_sr1: MagicMock) -> None:
    """Verify ICMP Destination Unreachable (type 3, code 13) extracts router IP and difference."""
    target_host = "93.184.216.34"
    gateway_ip = "192.168.1.1"

    # Firewall sends ICMP type 3 code 13 from its own gateway IP, encapsulating the original SYN
    orig_pkt = IP(dst=target_host) / TCP(dport=21, flags="S")
    icmp_base = cast(
        Any,
        IP(src=gateway_ip, dst="192.168.1.100", ttl=255, id=999) / ICMP(type=3, code=13),
    )
    icmp_pkt = icmp_base / orig_pkt
    mock_sr1.return_value = icmp_pkt

    probe = TcpSynProbe()
    target = Target(host=target_host, port=21, service="FTP", expect_open=False)
    ctx = Context(timeout=0.1, retries=0)

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, target)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is False
    assert obs.raw["reply_type"] == "ICMP"
    assert obs.raw["icmp_type"] == 3
    assert obs.raw["icmp_code"] == 13
    assert obs.raw["icmp_src"] == gateway_ip
    assert obs.raw["icmp_src_differs"] is True
    assert obs.raw["ip_ttl"] == 255
    assert obs.raw["ip_id"] == 999
    assert obs.raw["reply_received"] is True


@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_timeout_and_retries(mock_sr1: MagicMock) -> None:
    """Verify timeout when no packet is returned, and retries are sequentially executed."""
    mock_sr1.return_value = None

    probe = TcpSynProbe()
    target = Target(host="93.184.216.34", port=9999, service="Blackhole", expect_open=True)
    # retries=2 -> 1 initial + 2 retries = 3 observations
    ctx = Context(timeout=0.01, retries=2, rate_limit=100.0)

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, target)

    assert len(observations) == 3
    assert mock_sr1.call_count == 3

    for idx, obs in enumerate(observations, start=1):
        assert obs.success is False
        assert obs.raw["reply_type"] == "none"
        assert obs.raw["reply_received"] is False
        assert obs.raw["attempt"] == idx
        assert obs.raw["expect_open"] is True
        assert obs.raw["ip_ttl"] is None
        assert obs.raw["icmp_type"] is None


@patch("netpolicy.probes.tcp_syn.send")
@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_control_target_records_syn_ack_ttl(
    mock_sr1: MagicMock, mock_send: MagicMock
) -> None:
    """Verify control target SYN-ACK records is_control=True and captures syn_ack_ttl."""
    ctx = Context(timeout=1.0, retries=0)
    control_target = ctx.control_target

    syn_ack_pkt = IP(src=control_target.host, dst="192.168.1.100", ttl=58, id=777) / TCP(
        sport=control_target.port, dport=54321, flags="SA", seq=100, ack=200
    )
    mock_sr1.return_value = syn_ack_pkt

    probe = TcpSynProbe()

    with patch.object(os, "geteuid", return_value=0, create=True):
        observations = probe.run(ctx, control_target)

    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is True
    assert obs.raw["is_control"] is True
    assert obs.raw["reply_type"] == "SYN-ACK"
    assert obs.raw["syn_ack_ttl"] == 58


@patch("netpolicy.probes.tcp_syn.sr1")
def test_tcp_syn_loopback_workaround(mock_sr1: MagicMock) -> None:
    """Verify 127.0.0.1 explicitly passes the loopback interface name to sr1()."""
    mock_sr1.return_value = None

    probe = TcpSynProbe()
    target = Target(host="127.0.0.1", port=80, service="HTTP")
    ctx = Context(timeout=0.01, retries=0)

    with patch.object(os, "geteuid", return_value=0, create=True):
        probe.run(ctx, target)

    assert mock_sr1.call_count == 1
    call_kwargs = mock_sr1.call_args[1]
    expected_iface = getattr(conf, "loopback_name", "lo")
    assert call_kwargs.get("iface") == expected_iface


def test_tcp_syn_missing_port_raises() -> None:
    """Verify ValueError is raised if target port is None."""
    probe = TcpSynProbe()
    target = Target(host="93.184.216.34", port=None)
    ctx = Context()

    with (
        patch.object(os, "geteuid", return_value=0, create=True),
        pytest.raises(ValueError, match="requires target with explicit port"),
    ):
        probe.run(ctx, target)
