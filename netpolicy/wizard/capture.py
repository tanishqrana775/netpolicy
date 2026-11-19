"""Optional packet capture for Wireshark analysis with hard resource bounds (Stage 5)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CaptureResult:
    """Artifact metadata of a completed packet capture."""

    pcap_path: str
    packet_count: int
    byte_count: int
    sha256: str
    bpf_filter: str
    interface: str | None


def build_bpf_filter(target: str | None, dns_resolvers: list[str] | None = None) -> str:
    """Builds a strict BPF filter scoped to the target and DNS servers."""
    clauses: list[str] = []
    if target:
        clauses.append(f"host {target}")

    resolvers = dns_resolvers or ["1.1.1.1", "8.8.8.8"]
    dns_clause = " or ".join(f"host {r}" for r in resolvers)
    clauses.append(f"(port 53 and ({dns_clause}))")

    return " or ".join(f"({c})" for c in clauses)


def generate_wireshark_filters(target: str | None, findings: list[str] | None = None) -> list[str]:
    """Generates tailored Wireshark display filters combined with the target IP."""
    target_clause = f"ip.addr == {target}" if target else ""
    filters: list[str] = []

    def combine(expr: str) -> str:
        if target_clause:
            return f"{expr} and {target_clause}"
        return expr

    findings_text = " ".join(findings or []).lower()

    # 1. TCP Resets
    if "reset" in findings_text or not findings:
        filters.append(combine("tcp.flags.reset == 1"))

    # 2. ICMP Destination Unreachable
    if "icmp" in findings_text or "unreachable" in findings_text or not findings:
        filters.append(combine("icmp.type == 3"))

    # 3. DNS
    if "dns" in findings_text or not findings:
        filters.append(combine("udp.port == 53"))

    # 4. HTTP / Web
    if "http" in findings_text or "proxy" in findings_text or not findings:
        filters.append(combine("http"))

    return filters


class PacketCapture:
    """Scoped packet capture context manager enforcing packet count and file size bounds."""

    def __init__(
        self,
        target: str | None,
        run_id: str,
        output_dir: Path | str = "reports",
        max_packets: int = 50000,
        max_bytes: int = 50 * 1024 * 1024,
        sniffer_factory: Any | None = None,
    ) -> None:
        self.target = target
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.max_packets = max_packets
        self.max_bytes = max_bytes
        self.sniffer_factory = sniffer_factory

        self.pcap_path = self.output_dir / f"capture-{run_id}.pcap"
        self.bpf_filter = build_bpf_filter(target)
        self.sniffer: Any = None
        self.result: CaptureResult | None = None
        self.packet_count = 0
        self.byte_count = 0

    def __enter__(self) -> PacketCapture:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            if self.sniffer_factory:
                try:
                    self.sniffer = self.sniffer_factory(self.bpf_filter)
                except TypeError:
                    self.sniffer = self.sniffer_factory(filter=self.bpf_filter)
                self.sniffer.start()
                return self

            # Real Scapy sniffer
            from scapy.config import conf
            from scapy.sendrecv import AsyncSniffer

            iface = None
            if self.target:
                try:
                    route = conf.route.route(self.target)
                    if route and len(route) > 0:
                        iface = route[0]
                except Exception:
                    iface = None

            self.sniffer = AsyncSniffer(
                filter=self.bpf_filter,
                iface=iface,
                count=self.max_packets,
                store=True,
            )
            self.sniffer.start()
        except Exception:
            # Graceful degradation if capture cannot start (e.g. non-root or missing sniffer)
            self.sniffer = None

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.sniffer is None:
            return

        try:
            self.sniffer.stop()
            packets = getattr(self.sniffer, "results", []) or []

            # Write pcap
            from scapy.utils import PcapWriter

            writer = PcapWriter(str(self.pcap_path), append=False, sync=True)
            total_bytes = 0
            count = 0

            for pkt in packets:
                raw_bytes = bytes(pkt)
                if total_bytes + len(raw_bytes) > self.max_bytes:
                    break
                to_write = pkt if hasattr(pkt, "build") else raw_bytes
                writer.write(to_write)
                total_bytes += len(raw_bytes)
                count += 1
            writer.close()

            self.packet_count = count
            self.byte_count = total_bytes

            # SHA-256
            hasher = hashlib.sha256()
            if self.pcap_path.exists():
                hasher.update(self.pcap_path.read_bytes())
            sha = hasher.hexdigest()

            self.result = CaptureResult(
                pcap_path=str(self.pcap_path),
                packet_count=count,
                byte_count=total_bytes,
                sha256=sha,
                bpf_filter=self.bpf_filter,
                interface=getattr(self.sniffer, "iface", None),
            )
        except Exception:
            self.result = None
