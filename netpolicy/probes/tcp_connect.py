"""Standard socket-based unprivileged TCP connect reachability probe.

Probes outbound port reachability via standard non-blocking OS connect() calls.
Records raw observations including exact errno, symbolic error name, RTT, attempts,
and best-effort ICMP error queue data on Linux platforms.

Note on firewall classification:
ECONNREFUSED alone cannot distinguish a TCP RST from an ICMP port-unreachable.
"""

from __future__ import annotations

import contextlib
import errno
import select
import socket
import struct
import time
from typing import TYPE_CHECKING, Any

from netpolicy.models import Observation, Target
from netpolicy.probes.base import Probe

if TYPE_CHECKING:
    from netpolicy.engine.context import Context


__all__ = ["TcpConnectProbe", "TCPConnectProbe"]


def _read_icmp_errqueue(sock: socket.socket) -> tuple[int | None, int | None, str | None]:
    """Attempt to read ICMP error from socket error queue (best effort on Linux).

    ECONNREFUSED alone cannot distinguish a TCP RST from an ICMP port-unreachable.
    On Linux, IP_RECVERR causes ICMP errors to be queued in MSG_ERRQUEUE.
    """
    if not hasattr(socket, "MSG_ERRQUEUE") or not hasattr(sock, "recvmsg"):
        return None, None, None

    try:
        # MSG_ERRQUEUE returns ancillary data containing sock_extended_err
        _, ancdata, _, addr = sock.recvmsg(1024, 1024, socket.MSG_ERRQUEUE)
        ip_level = getattr(socket, "IPPROTO_IP", 0)
        recverr_type = getattr(socket, "IP_RECVERR", 11)

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == ip_level and cmsg_type == recverr_type and len(cmsg_data) >= 8:
                # struct sock_extended_err: uint32_t ee_errno; uint8_t ee_origin, ee_type, ee_code
                _, _, ee_type, ee_code = struct.unpack_from("=IBBB", cmsg_data)
                src_ip = addr[0] if (addr and isinstance(addr, tuple)) else None
                return int(ee_type), int(ee_code), str(src_ip) if src_ip else None
    except (OSError, AttributeError, struct.error):
        pass

    return None, None, None


def _normalize_errno(err: int) -> tuple[str, str]:
    """Map raw errno code to outcome category and symbolic name.

    Note: ECONNREFUSED alone cannot distinguish a TCP RST from an ICMP port-unreachable.
    """
    if err == 0:
        return "connected", "0"

    err_name = errno.errorcode.get(err, f"ERRNO_{err}")

    refused_codes = {errno.ECONNREFUSED}
    if hasattr(errno, "WSAECONNREFUSED"):
        refused_codes.add(errno.WSAECONNREFUSED)

    timeout_codes = {errno.ETIMEDOUT}
    if hasattr(errno, "WSAETIMEDOUT"):
        timeout_codes.add(errno.WSAETIMEDOUT)

    unreach_codes = {errno.EHOSTUNREACH, errno.ENETUNREACH}
    if hasattr(errno, "WSAEHOSTUNREACH"):
        unreach_codes.add(errno.WSAEHOSTUNREACH)
    if hasattr(errno, "WSAENETUNREACH"):
        unreach_codes.add(errno.WSAENETUNREACH)

    if err in refused_codes:
        # ECONNREFUSED alone cannot distinguish a TCP RST from an ICMP port-unreachable.
        return "refused", err_name
    if err in timeout_codes:
        return "timeout", err_name
    if err in unreach_codes:
        return "unreachable", err_name

    return "other", err_name


class TcpConnectProbe(Probe):
    """Probes outbound port reachability via standard unprivileged OS connect() calls."""

    name = "tcp_connect"
    requires_root = False

    def _attempt_connect(
        self,
        host: str,
        port: int,
        timeout: float,
    ) -> tuple[str, int, str, float, int | None, int | None, str | None]:
        """Perform a single non-blocking TCP connect attempt with timing & ICMP errqueue checks."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)

        # Best effort: set IP_RECVERR on Linux platforms to capture ICMP errors
        ip_level = getattr(socket, "IPPROTO_IP", None)
        recverr_opt = getattr(socket, "IP_RECVERR", None)
        if ip_level is not None and recverr_opt is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(ip_level, recverr_opt, 1)

        start_time = time.perf_counter()
        err = 0
        try:
            err = sock.connect_ex((host, port))
            in_progress_codes = {errno.EINPROGRESS, errno.EWOULDBLOCK}
            if hasattr(errno, "WSAEWOULDBLOCK"):
                in_progress_codes.add(errno.WSAEWOULDBLOCK)
            if hasattr(errno, "WSAEINPROGRESS"):
                in_progress_codes.add(errno.WSAEINPROGRESS)

            if err in in_progress_codes:
                _, writable, exceptional = select.select([], [sock], [sock], timeout)
                if writable or exceptional:
                    so_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    err = so_error
                else:
                    err = getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            outcome, err_name = _normalize_errno(err)

            # Best effort ICMP errqueue inspection on failure
            icmp_type, icmp_code, icmp_src = None, None, None
            if outcome != "connected":
                # ECONNREFUSED alone cannot distinguish a TCP RST from an ICMP port-unreachable.
                icmp_type, icmp_code, icmp_src = _read_icmp_errqueue(sock)

            return outcome, err, err_name, elapsed_ms, icmp_type, icmp_code, icmp_src

        except socket.gaierror as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return "other", exc.errno or -1, "EGAIERROR", elapsed_ms, None, None, None
        finally:
            sock.close()

    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Record raw TCP socket connection timing, successes, and OS error codes.

        Retries: honours ctx.retries on failure with short delays between attempts,
        recording each attempt as its own independent Observation.
        """
        if target.port is None:
            raise ValueError(f"TCPConnectProbe requires target with explicit port: {target}")

        observations: list[Observation] = []
        max_attempts = 1 + max(0, ctx.retries)

        for attempt in range(1, max_attempts + 1):
            outcome, err, err_name, elapsed_ms, icmp_type, icmp_code, icmp_src = (
                self._attempt_connect(
                    host=target.host,
                    port=target.port,
                    timeout=ctx.timeout,
                )
            )

            raw_fields: dict[str, Any] = {
                "outcome": outcome,
                "errno": err,
                "errno_name": err_name,
                "rtt_ms": round(elapsed_ms, 3),
                "attempt": attempt,
                "expect_open": target.expect_open,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "icmp_src": icmp_src,
                "reply_received": outcome in ("connected", "refused"),
            }

            obs = Observation(
                probe_name=self.name,
                target=target,
                timestamp=time.time(),
                success=(outcome == "connected"),
                raw=raw_fields,
            )
            observations.append(obs)

            # If connection succeeded, no need to retry
            if outcome == "connected":
                break

            # Short delay between retry attempts
            if attempt < max_attempts:
                time.sleep(min(0.05, ctx.timeout / 10.0))

        return observations


# Backwards compatibility alias
TCPConnectProbe = TcpConnectProbe
