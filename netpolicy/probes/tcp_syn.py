"""Raw packet TCP SYN probe using Scapy (privileged root mode).

Sends crafted IP/TCP SYN packets and captures incoming replies, TCP flags
(SYN-ACK, RST, RST-ACK), IP TTLs, IP IDs, window sizes, TCP options,
and ICMP unreachable responses without altering host firewall or sysctl settings.
"""

from __future__ import annotations

import os
import random
import time
from typing import TYPE_CHECKING, Any

from scapy.config import conf
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import send, sr1

from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe

if TYPE_CHECKING:
    from scapy.packet import Packet

    from netpolicy.engine.context import Context


__all__ = ["TcpSynProbe", "TCPSYNProbe"]


def _check_root() -> None:
    """Verify root privileges via os.geteuid().

    Raises PermissionError advising sudo or --mode socket fallback if not root.
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        raise PermissionError(
            "Raw SYN probe requires root privileges. "
            "Please run 'sudo .venv/bin/netpolicy ...' or fall back to '--mode socket'."
        )


def _get_loopback_iface(host: str) -> str | None:
    """Determine explicit loopback interface name for local targets.

    Scapy loopback quirk workaround:
    When sending raw packets to 127.0.0.1 (or loopback subnets), Scapy's default
    route resolution often bypasses or fails to capture loopback replies unless
    the loopback interface (e.g. conf.loopback_name or 'lo') is passed explicitly
    to sr1() and send().
    """
    if host in ("127.0.0.1", "localhost") or host.startswith("127."):
        return str(getattr(conf, "loopback_name", "lo"))
    return None


def _classify_reply(
    reply: Packet | None,
    target_host: str,
) -> dict[str, Any]:
    """Extract raw network fields from a received Scapy packet."""
    if reply is None:
        return {
            "reply_type": "none",
            "reply_received": False,
            "tcp_flags": None,
            "ip_ttl": None,
            "ip_id": None,
            "window_size": None,
            "tcp_options": None,
            "icmp_type": None,
            "icmp_code": None,
            "icmp_src": None,
            "icmp_src_differs": None,
            "syn_ack_ttl": None,
        }

    reply_received = True
    tcp_flags: str | None = None
    ip_ttl: int | None = None
    ip_id: int | None = None
    window_size: int | None = None
    tcp_options: list[Any] | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_src: str | None = None
    icmp_src_differs: bool | None = None
    syn_ack_ttl: int | None = None

    if IP in reply:
        ip_ttl = int(reply[IP].ttl)
        ip_id = int(reply[IP].id)

    # Check ICMP first: ICMP error replies often encapsulate the original TCP packet,
    # so reply.haslayer(TCP) may also evaluate to True on an ICMP packet.
    if ICMP in reply:
        reply_type = "ICMP"
        icmp_type = int(reply[ICMP].type)
        icmp_code = int(reply[ICMP].code)
        if IP in reply:
            icmp_src = str(reply[IP].src)
            icmp_src_differs = reply[IP].src != target_host
    elif TCP in reply:
        flags_val = reply[TCP].flags
        flags_int = int(flags_val)
        tcp_flags = str(flags_val)
        window_size = int(reply[TCP].window)
        if hasattr(reply[TCP], "options"):
            tcp_options = list(reply[TCP].options)

        # Flag bitmasks: S = 0x02, R = 0x04, A = 0x10
        if flags_int & 0x04:  # RST set
            reply_type = "RST-ACK" if flags_int & 0x10 else "RST"
        elif (flags_int & 0x02) and (flags_int & 0x10):  # SYN + ACK
            reply_type = "SYN-ACK"
            syn_ack_ttl = ip_ttl
        else:
            reply_type = str(flags_val)
    else:
        reply_type = getattr(reply, "name", "unknown")

    return {
        "reply_type": reply_type,
        "reply_received": reply_received,
        "tcp_flags": tcp_flags,
        "ip_ttl": ip_ttl,
        "ip_id": ip_id,
        "window_size": window_size,
        "tcp_options": tcp_options,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "icmp_src": icmp_src,
        "icmp_src_differs": icmp_src_differs,
        "syn_ack_ttl": syn_ack_ttl,
    }


def _send_rst(
    target_host: str,
    target_port: int,
    sport: int,
    ack_num: int,
    iface: str | None,
) -> None:
    """Send a TCP RST packet to tear down a half-open connection after SYN-ACK."""
    try:
        rst_pkt = IP(dst=target_host) / TCP(
            sport=sport,
            dport=target_port,
            flags="R",
            seq=ack_num,
        )
        send_kwargs: dict[str, Any] = {"verbose": 0}
        if iface:
            send_kwargs["iface"] = iface
        send(rst_pkt, **send_kwargs)
    except Exception:
        # Best-effort teardown: do not fail observation if RST transmission fails
        pass


class TcpSynProbe(Probe):
    """Raw packet TCP SYN reachability probe requiring root privileges."""

    name = "tcp_syn"
    requires_root = True

    check_root = staticmethod(_check_root)

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Send raw TCP SYN packets to target and capture packet-level observations.

        Crafts IP/TCP SYN with random source port and sequence number.
        Records raw fields: reply_type, tcp_flags, ip_ttl, ip_id, window_size,
        tcp_options, ICMP fields (type, code, src, differs), and RTT.
        Sends RST after SYN-ACK to tear down half-open connection.
        """
        _check_root()

        if target.port is None:
            raise ValueError(f"TcpSynProbe requires target with explicit port: {target}")

        iface = _get_loopback_iface(target.host)
        is_control = False
        if ctx.control_target is not None:
            is_control = (
                target.host == ctx.control_target.host and target.port == ctx.control_target.port
            ) or (target.service is not None and target.service == ctx.control_target.service)

        observations: list[Observation] = []
        max_attempts = 1 + max(0, ctx.retries)

        for attempt in range(1, max_attempts + 1):
            sport = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)

            syn_pkt = IP(dst=target.host) / TCP(
                sport=sport,
                dport=target.port,
                flags="S",
                seq=seq,
            )

            sr1_kwargs: dict[str, Any] = {
                "timeout": ctx.timeout,
                "verbose": 0,
            }
            if iface:
                sr1_kwargs["iface"] = iface

            start_time = time.perf_counter()
            try:
                reply = sr1(syn_pkt, **sr1_kwargs)
            except Exception:
                reply = None
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            raw_fields = _classify_reply(reply, target.host)
            raw_fields["rtt_ms"] = round(elapsed_ms, 3)
            raw_fields["attempt"] = attempt
            raw_fields["expect_open"] = target.expect_open
            raw_fields["is_control"] = is_control

            # If SYN-ACK received, immediately send RST to tear down half-open connection
            if raw_fields["reply_type"] == "SYN-ACK" and reply is not None and TCP in reply:
                ack_num = int(getattr(reply[TCP], "ack", seq + 1))
                _send_rst(target.host, target.port, sport, ack_num, iface)

            obs = Observation(
                probe_name=self.name,
                target=target,
                timestamp=time.time(),
                success=(raw_fields["reply_type"] == "SYN-ACK"),
                raw=raw_fields,
            )
            observations.append(obs)

            # If SYN-ACK confirmed, target reached; no retry needed
            if raw_fields["reply_type"] == "SYN-ACK":
                break

            # Sequential retry delay honouring rate limit
            if attempt < max_attempts:
                delay = (
                    max(0.01, 1.0 / ctx.rate_limit)
                    if ctx.rate_limit > 0
                    else min(0.05, ctx.timeout / 10.0)
                )
                time.sleep(delay)

        return observations


# Backwards compatibility alias
TCPSYNProbe = TcpSynProbe
