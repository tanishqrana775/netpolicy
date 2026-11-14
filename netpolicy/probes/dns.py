"""DNS probing module for reachability, interception, hijacking, and spoofing detection.

Implements dnspython-driven probes:
- BlackholeProbe: documentation IP address probing (192.0.2.1, 198.51.100.1).
- WhoamiProbe: TXT query to discover apparent client egress IP.
- NxdomainProbe: random .invalid queries to detect NXDOMAIN hijacking.
- DohCrossCheckProbe: side-by-side comparison of plain DNS vs encrypted DoH answers.
- SourceMismatchProbe: raw UDP socket recvfrom check for reply source IP mismatch.
"""

from __future__ import annotations

import ipaddress
import random
import secrets
import socket
import time
from typing import TYPE_CHECKING, Any

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from netpolicy.config import DNSConfig
from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe

if TYPE_CHECKING:
    from netpolicy.engine.context import Context


__all__ = [
    "BlackholeProbe",
    "WhoamiProbe",
    "NxdomainProbe",
    "DohCrossCheckProbe",
    "SourceMismatchProbe",
    "SourceMismatch",
    "DNSProbe",
]


def _is_ipv4(address_str: str) -> bool:
    """Return True if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(address_str.strip())
        return True
    except ValueError:
        return False


def _extract_response_fields(
    resp: dns.message.Message | None,
) -> tuple[int | None, str | None, list[str]]:
    """Extract integer rcode, symbolic rcode name, and list of answer records."""
    if resp is None:
        return None, None, []

    rcode_int = resp.rcode()
    rcode_name = dns.rcode.to_text(rcode_int)
    answers: list[str] = []
    for rrset in resp.answer:
        for rdata in rrset:
            answers.append(rdata.to_text())
    return rcode_int, rcode_name, answers


def _query_udp(
    query: dns.message.Message,
    host: str,
    port: int = 53,
    timeout: float = 3.0,
) -> tuple[dns.message.Message | None, str | None, float, str | None]:
    """Execute raw UDP DNS query with socket recvfrom to capture actual source address.

    Returns:
        (response_message, source_address, elapsed_ms, error_string)
    """
    wire = query.to_wire()
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(wire, (host, port))
        data, (src_ip, _) = sock.recvfrom(4096)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        resp = dns.message.from_wire(data)
        return resp, str(src_ip), round(elapsed_ms, 3), None
    except TimeoutError:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), "timeout"
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), str(exc)
    finally:
        sock.close()


def _query_tcp(
    query: dns.message.Message,
    host: str,
    port: int = 53,
    timeout: float = 3.0,
) -> tuple[dns.message.Message | None, str | None, float, str | None]:
    """Execute raw TCP DNS query.

    Returns:
        (response_message, source_address, elapsed_ms, error_string)
    """
    start_time = time.perf_counter()
    try:
        resp = dns.query.tcp(query, host, port=port, timeout=timeout)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return resp, host, round(elapsed_ms, 3), None
    except (TimeoutError, dns.exception.Timeout):
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), "timeout"
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), str(exc)


def _query_doh(
    query: dns.message.Message,
    url: str,
    timeout: float = 3.0,
) -> tuple[dns.message.Message | None, str | None, float, str | None]:
    """Execute DNS over HTTPS query via dnspython dns.query.https.

    DoH failures are recorded as errors and never raised.
    """
    start_time = time.perf_counter()
    try:
        resp = dns.query.https(query, url, timeout=timeout)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return resp, url, round(elapsed_ms, 3), None
    except (TimeoutError, dns.exception.Timeout):
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), "timeout"
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return None, None, round(elapsed_ms, 3), str(exc)


class BlackholeProbe(Probe):
    """Send DNS A queries to documentation addresses over UDP/53 and TCP/53.

    RFC 5737 documentation addresses (192.0.2.1, 198.51.100.1) should never answer.
    A response indicates an in-path middlebox / intercepting DNS proxy.
    """

    name = "dns_blackhole"
    requires_root = False

    def __init__(self, addresses: list[str] | None = None) -> None:
        self.addresses = list(addresses) if addresses else ["192.0.2.1", "198.51.100.1"]

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Probe blackhole documentation targets over UDP and TCP."""
        servers = (
            [target.host] if target.host not in ("auto", "default", "blackhole") else self.addresses
        )
        observations: list[Observation] = []
        max_attempts = 1 + max(0, ctx.retries)

        for server in servers:
            for proto in ("udp", "tcp"):
                for attempt in range(1, max_attempts + 1):
                    qname = f"bh-{secrets.token_hex(4)}.netpolicy.invalid"
                    query = dns.message.make_query(qname, dns.rdatatype.A)
                    query.id = random.randint(1, 65535)

                    if proto == "udp":
                        resp, src_addr, rtt, err = _query_udp(
                            query, server, target.port or 53, ctx.timeout
                        )
                    else:
                        resp, src_addr, rtt, err = _query_tcp(
                            query, server, target.port or 53, ctx.timeout
                        )

                    rcode, rcode_name, answers = _extract_response_fields(resp)
                    reply_received = resp is not None
                    source_differs = (src_addr != server) if src_addr else None

                    raw_fields: dict[str, Any] = {
                        "protocol": proto,
                        "qname": qname,
                        "qtype": "A",
                        "queried_address": server,
                        "source_address": src_addr,
                        "source_differs": source_differs,
                        "reply_received": reply_received,
                        "rcode": rcode,
                        "rcode_name": rcode_name,
                        "answers": answers,
                        "rtt_ms": rtt,
                        "error": err,
                        "attempt": attempt,
                    }

                    obs = Observation(
                        probe_name=self.name,
                        target=Target(
                            host=server,
                            port=target.port or 53,
                            service=f"DNS-Blackhole-{proto.upper()}",
                        ),
                        timestamp=time.time(),
                        success=reply_received,
                        raw=raw_fields,
                    )
                    observations.append(obs)

                    if reply_received:
                        break

                    if attempt < max_attempts:
                        delay = (
                            max(0.01, 1.0 / ctx.rate_limit)
                            if ctx.rate_limit > 0
                            else min(0.05, ctx.timeout / 10.0)
                        )
                        time.sleep(delay)

        return observations


class WhoamiProbe(Probe):
    """Query a configurable 'who am I' TXT name at a public resolver."""

    name = "dns_whoami"
    requires_root = False

    def __init__(
        self,
        whoami_name: str | None = None,
        resolver: str | None = None,
    ) -> None:
        self.whoami_name = whoami_name or "o-o.myaddr.l.google.com"
        self.resolver = resolver or "8.8.8.8"

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Query whoami TXT record to identify client's external resolver address."""
        resolver = (
            target.host if target.host not in ("auto", "default", "whoami") else self.resolver
        )
        max_attempts = 1 + max(0, ctx.retries)
        observations: list[Observation] = []

        for attempt in range(1, max_attempts + 1):
            query = dns.message.make_query(self.whoami_name, dns.rdatatype.TXT)
            query.id = random.randint(1, 65535)

            resp, src_addr, rtt, err = _query_udp(query, resolver, target.port or 53, ctx.timeout)
            rcode, rcode_name, answers = _extract_response_fields(resp)
            reply_received = resp is not None
            txt_answers = [ans.strip('"') for ans in answers]
            source_differs = (src_addr != resolver) if src_addr else None

            raw_fields: dict[str, Any] = {
                "protocol": "udp",
                "qname": self.whoami_name,
                "qtype": "TXT",
                "queried_address": resolver,
                "source_address": src_addr,
                "source_differs": source_differs,
                "reply_received": reply_received,
                "rcode": rcode,
                "rcode_name": rcode_name,
                "answers": answers,
                "txt_answers": txt_answers,
                "rtt_ms": rtt,
                "error": err,
                "attempt": attempt,
            }

            obs = Observation(
                probe_name=self.name,
                target=Target(host=resolver, port=target.port or 53, service="DNS-Whoami"),
                timestamp=time.time(),
                success=(reply_received and rcode == 0),
                raw=raw_fields,
            )
            observations.append(obs)

            if reply_received:
                break

            if attempt < max_attempts:
                delay = (
                    max(0.01, 1.0 / ctx.rate_limit)
                    if ctx.rate_limit > 0
                    else min(0.05, ctx.timeout / 10.0)
                )
                time.sleep(delay)

        return observations


class NxdomainProbe(Probe):
    """Query random .invalid labels via system and public resolvers to detect hijacking."""

    name = "dns_nxdomain"
    requires_root = False

    def __init__(
        self,
        count: int = 5,
        public_resolver: str | None = None,
        system_resolver: str | None = None,
    ) -> None:
        self.count = max(1, count)
        self.public_resolver = public_resolver or "8.8.8.8"
        self.system_resolver = system_resolver

    def _get_system_resolver(self) -> str:
        """Resolve primary system nameserver from resolver configuration."""
        if self.system_resolver:
            return self.system_resolver
        try:
            res = dns.resolver.Resolver()
            if res.nameservers:
                return str(res.nameservers[0])
        except Exception:
            pass
        return "127.0.0.1"

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Query N random .invalid domains and record rcode and any A records returned."""
        sys_ip = self._get_system_resolver()
        pub_ip = (
            target.host
            if target.host not in ("auto", "default", "nxdomain")
            else self.public_resolver
        )

        observations: list[Observation] = []

        for _ in range(self.count):
            label = f"nx-{secrets.token_hex(4)}.invalid"

            # 1. System resolver query
            q_sys = dns.message.make_query(label, dns.rdatatype.A)
            q_sys.id = random.randint(1, 65535)
            resp_sys, src_sys, rtt_sys, err_sys = _query_udp(q_sys, sys_ip, 53, ctx.timeout)
            rcode_s, rcode_name_s, answers_s = _extract_response_fields(resp_sys)
            a_records_s = [ans for ans in answers_s if _is_ipv4(ans)]

            obs_sys = Observation(
                probe_name=self.name,
                target=Target(host=sys_ip, port=53, service="DNS-NXDOMAIN-System"),
                timestamp=time.time(),
                success=(resp_sys is not None),
                raw={
                    "resolver_type": "system",
                    "protocol": "udp",
                    "qname": label,
                    "qtype": "A",
                    "queried_address": sys_ip,
                    "source_address": src_sys,
                    "reply_received": resp_sys is not None,
                    "rcode": rcode_s,
                    "rcode_name": rcode_name_s,
                    "answers": answers_s,
                    "a_records": a_records_s,
                    "rtt_ms": rtt_sys,
                    "error": err_sys,
                },
            )
            observations.append(obs_sys)

            # 2. Public resolver query
            q_pub = dns.message.make_query(label, dns.rdatatype.A)
            q_pub.id = random.randint(1, 65535)
            resp_pub, src_pub, rtt_pub, err_pub = _query_udp(q_pub, pub_ip, 53, ctx.timeout)
            rcode_p, rcode_name_p, answers_p = _extract_response_fields(resp_pub)
            a_records_p = [ans for ans in answers_p if _is_ipv4(ans)]

            obs_pub = Observation(
                probe_name=self.name,
                target=Target(host=pub_ip, port=53, service="DNS-NXDOMAIN-Public"),
                timestamp=time.time(),
                success=(resp_pub is not None),
                raw={
                    "resolver_type": "public",
                    "protocol": "udp",
                    "qname": label,
                    "qtype": "A",
                    "queried_address": pub_ip,
                    "source_address": src_pub,
                    "reply_received": resp_pub is not None,
                    "rcode": rcode_p,
                    "rcode_name": rcode_name_p,
                    "answers": answers_p,
                    "a_records": a_records_p,
                    "rtt_ms": rtt_pub,
                    "error": err_pub,
                },
            )
            observations.append(obs_pub)

        return observations


class DohCrossCheckProbe(Probe):
    """Compare plain DNS answers with encrypted DoH answers to uncover DNS tampering."""

    name = "dns_doh_crosscheck"
    requires_root = False

    def __init__(
        self,
        domains: list[str] | None = None,
        resolver_ip: str | None = None,
        doh_url: str | None = None,
    ) -> None:
        self.domains = list(domains) if domains else ["example.com", "cloudflare.com"]
        self.resolver_ip = resolver_ip or "1.1.1.1"
        self.doh_url = doh_url or "https://cloudflare-dns.com/dns-query"

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Resolve domains via plain DNS and DoH, recording both raw answer sets."""
        resolver_ip = (
            target.host
            if target.host not in ("auto", "default", "doh_crosscheck")
            else self.resolver_ip
        )
        observations: list[Observation] = []

        for domain in self.domains:
            # 1. Plain DNS resolution
            query_plain = dns.message.make_query(domain, dns.rdatatype.A)
            query_plain.id = random.randint(1, 65535)
            resp_p, src_p, rtt_p, err_p = _query_udp(query_plain, resolver_ip, 53, ctx.timeout)
            rcode_p, rcode_name_p, answers_p = _extract_response_fields(resp_p)

            obs_plain = Observation(
                probe_name=self.name,
                target=Target(host=resolver_ip, port=53, service="DNS-Plain"),
                timestamp=time.time(),
                success=(resp_p is not None and rcode_p == 0),
                raw={
                    "method": "plain",
                    "protocol": "udp",
                    "qname": domain,
                    "qtype": "A",
                    "queried_address": resolver_ip,
                    "source_address": src_p,
                    "reply_received": resp_p is not None,
                    "rcode": rcode_p,
                    "rcode_name": rcode_name_p,
                    "answers": sorted(answers_p),
                    "rtt_ms": rtt_p,
                    "error": err_p,
                },
            )
            observations.append(obs_plain)

            # 2. DoH resolution
            query_doh = dns.message.make_query(domain, dns.rdatatype.A)
            query_doh.id = random.randint(1, 65535)
            resp_d, src_d, rtt_d, err_d = _query_doh(query_doh, self.doh_url, ctx.timeout)
            rcode_d, rcode_name_d, answers_d = _extract_response_fields(resp_d)

            obs_doh = Observation(
                probe_name=self.name,
                target=Target(host=self.doh_url, port=443, service="DNS-DoH"),
                timestamp=time.time(),
                success=(resp_d is not None and rcode_d == 0),
                raw={
                    "method": "doh",
                    "protocol": "https",
                    "qname": domain,
                    "qtype": "A",
                    "queried_address": self.doh_url,
                    "source_address": src_d,
                    "reply_received": resp_d is not None,
                    "rcode": rcode_d,
                    "rcode_name": rcode_name_d,
                    "answers": sorted(answers_d),
                    "rtt_ms": rtt_d,
                    "error": err_d,
                },
            )
            observations.append(obs_doh)

        return observations


class SourceMismatchProbe(Probe):
    """Query resolvers with plain UDP socket to check for source IP mismatches."""

    name = "dns_source_mismatch"
    requires_root = False

    def __init__(self, resolvers: list[str] | None = None) -> None:
        self.resolvers = list(resolvers) if resolvers else ["8.8.8.8", "1.1.1.1"]

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Send queries over UDP socket using recvfrom to capture the real source IP."""
        resolvers = (
            [target.host]
            if target.host not in ("auto", "default", "source_mismatch")
            else self.resolvers
        )
        observations: list[Observation] = []

        for resolver in resolvers:
            qname = f"src-{secrets.token_hex(4)}.example.com"
            query = dns.message.make_query(qname, dns.rdatatype.A)
            query.id = random.randint(1, 65535)

            resp, src_addr, rtt, err = _query_udp(query, resolver, target.port or 53, ctx.timeout)
            rcode, rcode_name, answers = _extract_response_fields(resp)
            reply_received = resp is not None
            source_differs = (src_addr != resolver) if src_addr else None

            raw_fields: dict[str, Any] = {
                "protocol": "udp",
                "qname": qname,
                "qtype": "A",
                "queried_address": resolver,
                "source_address": src_addr,
                "source_differs": source_differs,
                "reply_received": reply_received,
                "rcode": rcode,
                "rcode_name": rcode_name,
                "answers": answers,
                "rtt_ms": rtt,
                "error": err,
            }

            obs = Observation(
                probe_name=self.name,
                target=Target(
                    host=resolver,
                    port=target.port or 53,
                    service="DNS-SourceMismatch",
                ),
                timestamp=time.time(),
                success=(reply_received and not source_differs),
                raw=raw_fields,
            )
            observations.append(obs)

        return observations


# Class alias
SourceMismatch = SourceMismatchProbe


class DNSProbe(Probe):
    """Aggregate DNS policy audit probe combining all specific DNS checks."""

    name = "dns"
    requires_root = False

    def __init__(self, config: DNSConfig | None = None) -> None:
        self.config = config or DNSConfig()
        self.blackhole = BlackholeProbe(self.config.blackhole_servers)
        self.whoami = WhoamiProbe(self.config.whoami_name, self.config.whoami_resolver)
        self.nxdomain = NxdomainProbe(
            count=self.config.nxdomain_count,
            public_resolver=self.config.nxdomain_resolver,
        )
        self.doh_crosscheck = DohCrossCheckProbe(
            domains=self.config.doh_crosscheck_domains,
            resolver_ip=self.config.doh_crosscheck_resolver,
            doh_url=self.config.doh_crosscheck_url,
        )
        self.source_mismatch = SourceMismatchProbe(self.config.source_mismatch_resolvers)

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Execute all configured DNS inspection probes."""
        observations: list[Observation] = []
        observations.extend(self.blackhole.run(ctx, target))
        observations.extend(self.whoami.run(ctx, target))
        observations.extend(self.nxdomain.run(ctx, target))
        observations.extend(self.doh_crosscheck.run(ctx, target))
        observations.extend(self.source_mismatch.run(ctx, target))
        return observations
