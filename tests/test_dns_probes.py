"""Unit tests for DNS probes with socket mocks and a local UDP responder."""

from __future__ import annotations

import contextlib
import socket
import threading
from typing import Any
from unittest.mock import MagicMock, patch

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from netpolicy.config import DNSConfig
from netpolicy.engine.context import Context
from netpolicy.models import Target
from netpolicy.probes.dns import (
    BlackholeProbe,
    DNSProbe,
    DohCrossCheckProbe,
    NxdomainProbe,
    SourceMismatch,
    SourceMismatchProbe,
    WhoamiProbe,
)


class LocalDNSResponder(threading.Thread):
    """Local in-process UDP DNS server for testing raw socket recvfrom and wire queries."""

    def __init__(self, answer_ip: str = "93.184.216.34") -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port: int = self.sock.getsockname()[1]
        self.answer_ip = answer_ip
        self.running = True

    def run(self) -> None:
        while self.running:
            try:
                self.sock.settimeout(0.2)
                data, addr = self.sock.recvfrom(4096)
                query = dns.message.from_wire(data)
                resp = dns.message.make_response(query)
                qname = query.question[0].name
                resp.answer.append(dns.rrset.from_text(qname, 300, "IN", "A", self.answer_ip))
                self.sock.sendto(resp.to_wire(), addr)
            except TimeoutError:
                continue
            except OSError:
                break

    def stop(self) -> None:
        self.running = False
        with contextlib.suppress(OSError):
            self.sock.close()


def test_local_udp_responder_e2e() -> None:
    """Verify raw socket UDP DNS query against a local running UDP responder."""
    responder = LocalDNSResponder(answer_ip="93.184.216.34")
    responder.start()

    try:
        probe = SourceMismatchProbe(resolvers=["127.0.0.1"])
        ctx = Context(timeout=1.0)
        target = Target(host="127.0.0.1", port=responder.port, service="Test-DNS")

        observations = probe.run(ctx, target)
        assert len(observations) == 1
        obs = observations[0]

        assert obs.success is True
        assert obs.raw["protocol"] == "udp"
        assert obs.raw["queried_address"] == "127.0.0.1"
        assert obs.raw["source_address"] == "127.0.0.1"
        assert obs.raw["source_differs"] is False
        assert obs.raw["reply_received"] is True
        assert obs.raw["rcode_name"] == "NOERROR"
        assert obs.raw["answers"] == ["93.184.216.34"]
        assert obs.raw["rtt_ms"] is not None and obs.raw["rtt_ms"] >= 0
    finally:
        responder.stop()
        responder.join(timeout=1.0)


@patch("netpolicy.probes.dns._query_tcp")
@patch("netpolicy.probes.dns._query_udp")
def test_blackhole_probe_timeout(mock_udp: MagicMock, mock_tcp: MagicMock) -> None:
    """Verify BlackholeProbe records no replies on timeouts across UDP and TCP."""
    mock_udp.return_value = (None, None, 50.0, "timeout")
    mock_tcp.return_value = (None, None, 50.0, "timeout")

    probe = BlackholeProbe(addresses=["192.0.2.1"])
    ctx = Context(timeout=0.05, retries=1, rate_limit=100.0)
    target = Target(host="blackhole", port=53)

    observations = probe.run(ctx, target)
    # 1 address * 2 protocols (udp, tcp) * 2 attempts (initial + 1 retry) = 4 observations
    assert len(observations) == 4
    for obs in observations:
        assert obs.success is False
        assert obs.raw["reply_received"] is False
        assert obs.raw["error"] == "timeout"
        assert obs.raw["queried_address"] == "192.0.2.1"


@patch("netpolicy.probes.dns._query_tcp")
@patch("netpolicy.probes.dns._query_udp")
def test_blackhole_probe_intercepted_reply(mock_udp: MagicMock, mock_tcp: MagicMock) -> None:
    """Verify BlackholeProbe records raw reply details when middlebox intercepts query."""
    q = dns.message.make_query("bh.test.invalid", dns.rdatatype.A)
    resp = dns.message.make_response(q)
    resp.answer.append(dns.rrset.from_text("bh.test.invalid", 60, "IN", "A", "10.0.0.1"))

    mock_udp.return_value = (resp, "192.0.2.1", 12.5, None)
    mock_tcp.return_value = (None, None, 50.0, "timeout")

    probe = BlackholeProbe(addresses=["192.0.2.1"])
    ctx = Context(timeout=0.1, retries=0)
    target = Target(host="192.0.2.1", port=53)

    observations = probe.run(ctx, target)
    udp_obs = [o for o in observations if o.raw["protocol"] == "udp"]
    assert len(udp_obs) == 1
    assert udp_obs[0].raw["reply_received"] is True
    assert udp_obs[0].raw["rcode_name"] == "NOERROR"
    assert udp_obs[0].raw["answers"] == ["10.0.0.1"]
    assert udp_obs[0].raw["source_differs"] is False


@patch("netpolicy.probes.dns._query_udp")
def test_whoami_probe_txt_answer(mock_udp: MagicMock) -> None:
    """Verify WhoamiProbe records TXT answer revealing public resolver view."""
    q = dns.message.make_query("o-o.myaddr.l.google.com", dns.rdatatype.TXT)
    resp = dns.message.make_response(q)
    resp.answer.append(
        dns.rrset.from_text("o-o.myaddr.l.google.com", 60, "IN", "TXT", '"198.51.100.42"')
    )
    mock_udp.return_value = (resp, "8.8.8.8", 14.2, None)

    probe = WhoamiProbe(whoami_name="o-o.myaddr.l.google.com", resolver="8.8.8.8")
    ctx = Context()
    target = Target(host="8.8.8.8", port=53)

    observations = probe.run(ctx, target)
    assert len(observations) == 1
    obs = observations[0]

    assert obs.success is True
    assert obs.raw["qtype"] == "TXT"
    assert obs.raw["txt_answers"] == ["198.51.100.42"]
    assert obs.raw["rcode_name"] == "NOERROR"


@patch("netpolicy.probes.dns._query_udp")
def test_nxdomain_probe_hijacking_detection(mock_udp: MagicMock) -> None:
    """Verify NxdomainProbe queries both system and public resolvers, recording A records."""

    def mock_query(query: dns.message.Message, host: str, port: int, timeout: float) -> Any:
        resp = dns.message.make_response(query)
        qname = query.question[0].name.to_text()
        if host == "192.168.1.1":
            # System resolver simulates ISP hijacking by synthesizing an advertising A record
            resp.answer.append(dns.rrset.from_text(qname, 60, "IN", "A", "203.0.113.99"))
            return resp, host, 10.0, None
        # Public resolver correctly returns NXDOMAIN
        resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp, host, 15.0, None

    mock_udp.side_effect = mock_query

    probe = NxdomainProbe(
        count=2,
        public_resolver="8.8.8.8",
        system_resolver="192.168.1.1",
    )
    ctx = Context()
    target = Target(host="nxdomain", port=53)

    observations = probe.run(ctx, target)
    assert len(observations) == 4  # 2 count * 2 resolvers (system, public)

    sys_obs = [o for o in observations if o.raw["resolver_type"] == "system"]
    pub_obs = [o for o in observations if o.raw["resolver_type"] == "public"]

    assert len(sys_obs) == 2
    assert len(pub_obs) == 2

    # System resolver synthesized an A record
    for o in sys_obs:
        assert o.raw["a_records"] == ["203.0.113.99"]
        assert o.raw["rcode_name"] == "NOERROR"

    # Public resolver gave NXDOMAIN
    for o in pub_obs:
        assert o.raw["a_records"] == []
        assert o.raw["rcode_name"] == "NXDOMAIN"


@patch("netpolicy.probes.dns._query_doh")
@patch("netpolicy.probes.dns._query_udp")
def test_doh_crosscheck_probe_success(mock_udp: MagicMock, mock_doh: MagicMock) -> None:
    """Verify DohCrossCheckProbe compares answer sets from plain DNS and DoH."""
    q1 = dns.message.make_query("example.com", dns.rdatatype.A)
    resp_plain = dns.message.make_response(q1)
    resp_plain.answer.append(dns.rrset.from_text("example.com", 300, "IN", "A", "93.184.216.34"))

    q2 = dns.message.make_query("example.com", dns.rdatatype.A)
    resp_doh = dns.message.make_response(q2)
    resp_doh.answer.append(dns.rrset.from_text("example.com", 300, "IN", "A", "93.184.216.34"))

    mock_udp.return_value = (resp_plain, "1.1.1.1", 10.0, None)
    mock_doh.return_value = (resp_doh, "https://cloudflare-dns.com/dns-query", 35.0, None)

    probe = DohCrossCheckProbe(
        domains=["example.com"],
        resolver_ip="1.1.1.1",
        doh_url="https://cloudflare-dns.com/dns-query",
    )
    ctx = Context()
    target = Target(host="doh_crosscheck", port=53)

    observations = probe.run(ctx, target)
    assert len(observations) == 2

    plain_obs = observations[0]
    doh_obs = observations[1]

    assert plain_obs.raw["method"] == "plain"
    assert plain_obs.raw["answers"] == ["93.184.216.34"]
    assert doh_obs.raw["method"] == "doh"
    assert doh_obs.raw["answers"] == ["93.184.216.34"]


@patch("netpolicy.probes.dns._query_doh")
@patch("netpolicy.probes.dns._query_udp")
def test_doh_crosscheck_probe_failure_not_raised(mock_udp: MagicMock, mock_doh: MagicMock) -> None:
    """Verify DoH failures are captured as error strings and not raised as exceptions."""
    mock_udp.return_value = (None, None, 50.0, "timeout")
    mock_doh.return_value = (None, None, 50.0, "TLS handshake failed")

    probe = DohCrossCheckProbe(domains=["example.com"])
    ctx = Context()
    target = Target(host="doh_crosscheck", port=53)

    observations = probe.run(ctx, target)
    assert len(observations) == 2

    doh_obs = observations[1]
    assert doh_obs.raw["method"] == "doh"
    assert doh_obs.raw["reply_received"] is False
    assert doh_obs.raw["error"] == "TLS handshake failed"


@patch("netpolicy.probes.dns._query_udp")
def test_source_mismatch_detected(mock_udp: MagicMock) -> None:
    """Verify SourceMismatchProbe flags source_differs=True when reply source IP changes."""
    q = dns.message.make_query("src.test.example.com", dns.rdatatype.A)
    resp = dns.message.make_response(q)
    resp.answer.append(dns.rrset.from_text("src.test.example.com", 60, "IN", "A", "93.184.216.34"))
    # Reply comes from spoofed / proxy IP 10.0.0.1 instead of queried 8.8.8.8
    mock_udp.return_value = (resp, "10.0.0.1", 15.0, None)

    probe = SourceMismatch(resolvers=["8.8.8.8"])
    ctx = Context()
    target = Target(host="8.8.8.8", port=53)

    observations = probe.run(ctx, target)
    assert len(observations) == 1
    obs = observations[0]

    assert obs.raw["queried_address"] == "8.8.8.8"
    assert obs.raw["source_address"] == "10.0.0.1"
    assert obs.raw["source_differs"] is True
    assert obs.success is False  # Flagged because source differed


def test_source_mismatch_probe_alias() -> None:
    """Verify SourceMismatch is an alias for SourceMismatchProbe."""
    assert SourceMismatch is SourceMismatchProbe


def test_dns_config_defaults() -> None:
    """Verify DNSConfig includes all configurable probe defaults."""
    cfg = DNSConfig()
    assert cfg.blackhole_servers == ["192.0.2.1", "198.51.100.1"]
    assert cfg.whoami_name == "o-o.myaddr.l.google.com"
    assert cfg.whoami_resolver == "8.8.8.8"
    assert cfg.nxdomain_count == 5
    assert cfg.nxdomain_resolver == "8.8.8.8"
    assert "example.com" in cfg.doh_crosscheck_domains
    assert cfg.doh_crosscheck_resolver == "1.1.1.1"
    assert cfg.doh_crosscheck_url == "https://cloudflare-dns.com/dns-query"
    assert cfg.source_mismatch_resolvers == ["8.8.8.8", "1.1.1.1"]


@patch.object(SourceMismatchProbe, "run", return_value=[])
@patch.object(DohCrossCheckProbe, "run", return_value=[])
@patch.object(NxdomainProbe, "run", return_value=[])
@patch.object(WhoamiProbe, "run", return_value=[])
@patch.object(BlackholeProbe, "run", return_value=[])
def test_dns_probe_aggregate(
    mock_bh: MagicMock,
    mock_whoami: MagicMock,
    mock_nx: MagicMock,
    mock_doh: MagicMock,
    mock_sm: MagicMock,
) -> None:
    """Verify DNSProbe invokes all five subprobes."""
    probe = DNSProbe()
    ctx = Context()
    target = Target(host="auto", port=53)

    probe.run(ctx, target)
    assert mock_bh.called
    assert mock_whoami.called
    assert mock_nx.called
    assert mock_doh.called
    assert mock_sm.called
