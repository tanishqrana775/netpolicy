"""Unit tests for the lab DNS responder (lab/dns_server.py)."""

from __future__ import annotations

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from lab.dns_server import DEFAULT_FIXED_A_RECORDS, LabDNSServer


@pytest.fixture
def dns_server() -> LabDNSServer:
    return LabDNSServer(host="127.0.0.1", port=5353)


@pytest.fixture
def rewrite_dns_server() -> LabDNSServer:
    return LabDNSServer(host="127.0.0.1", port=5353, rewrite=True, rewrite_ip="192.0.2.100")


def test_whoami_txt_echoes_client_ip(dns_server: LabDNSServer) -> None:
    client_ip = "10.200.1.25"
    client_port = 54321

    query = dns.message.make_query("whoami.lab", dns.rdatatype.TXT)
    resp_wire = dns_server.handle_query_wire(query.to_wire(), (client_ip, client_port))

    assert resp_wire is not None
    resp = dns.message.from_wire(resp_wire)
    assert resp.rcode() == dns.rcode.NOERROR
    assert len(resp.answer) == 1

    rdata = resp.answer[0][0]
    # Check that echoed TXT record contains client_ip
    assert client_ip in rdata.to_text()


def test_fixed_a_records_returned(dns_server: LabDNSServer) -> None:
    client_addr = ("127.0.0.1", 12345)

    for domain, expected_ip in DEFAULT_FIXED_A_RECORDS.items():
        query = dns.message.make_query(domain, dns.rdatatype.A)
        resp_wire = dns_server.handle_query_wire(query.to_wire(), client_addr)
        assert resp_wire is not None

        resp = dns.message.from_wire(resp_wire)
        assert resp.rcode() == dns.rcode.NOERROR
        assert len(resp.answer) == 1
        assert resp.answer[0][0].to_text() == expected_ip


def test_unknown_domain_returns_nxdomain_normally(dns_server: LabDNSServer) -> None:
    client_addr = ("127.0.0.1", 12345)

    query = dns.message.make_query("nonexistent.invalid", dns.rdatatype.A)
    resp_wire = dns_server.handle_query_wire(query.to_wire(), client_addr)
    assert resp_wire is not None

    resp = dns.message.from_wire(resp_wire)
    assert resp.rcode() == dns.rcode.NXDOMAIN
    assert len(resp.answer) == 0


def test_unknown_domain_returns_rewrite_a_record_when_flag_enabled(
    rewrite_dns_server: LabDNSServer,
) -> None:
    client_addr = ("127.0.0.1", 12345)

    query = dns.message.make_query("nonexistent.invalid", dns.rdatatype.A)
    resp_wire = rewrite_dns_server.handle_query_wire(query.to_wire(), client_addr)
    assert resp_wire is not None

    resp = dns.message.from_wire(resp_wire)
    assert resp.rcode() == dns.rcode.NOERROR
    assert len(resp.answer) == 1
    assert resp.answer[0][0].to_text() == "192.0.2.100"


def test_malformed_wire_handling(dns_server: LabDNSServer) -> None:
    bad_wire = b"this is completely invalid dns wire data"
    resp_wire = dns_server.handle_query_wire(bad_wire, ("127.0.0.1", 12345))
    assert resp_wire is None
