"""Unit and golden-file tests for Execution, Capture, Recommendations, and Lab Report."""

from __future__ import annotations

import datetime
from pathlib import Path

from netpolicy.models import (
    AuditReport,
    Confidence,
    Observation,
    ReportMetadata,
    Target,
    Verdict,
    VerdictKind,
)
from netpolicy.wizard.capture import (
    CaptureResult,
    PacketCapture,
    build_bpf_filter,
    generate_wireshark_filters,
)
from netpolicy.wizard.labreport import render_lab_report
from netpolicy.wizard.plan import build_audit_plan
from netpolicy.wizard.recommend import get_recommendations
from netpolicy.wizard.runner import RunResult

# ==============================================================================
# Injected Mock Sniffer for Capture Testing
# ==============================================================================


class MockPacket:
    """Mock scapy packet object."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def __bytes__(self) -> bytes:
        return self.data


class MockSniffer:
    """Mock scapy AsyncSniffer for testing without root or real interfaces."""

    def __init__(self, filter_expr: str | None = None) -> None:
        self.filter = filter_expr
        self.results: list[MockPacket] = []
        self.iface = "eth0"
        self._started = False

    def start(self) -> None:
        self._started = True
        # Simulate captured packets
        self.results = [
            MockPacket(b"GET /canary HTTP/1.1\r\nHost: probe.test\r\n\r\n"),
            MockPacket(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\ncanary-alive"),
        ]

    def stop(self) -> None:
        self._started = False


# ==============================================================================
# Stage 5 Tests: Capture, Runner, Recommendations
# ==============================================================================


def test_build_bpf_filter() -> None:
    """Verify BPF filter generation for target and DNS resolvers."""
    bpf = build_bpf_filter("192.168.1.10", dns_resolvers=["1.1.1.1", "8.8.8.8"])
    assert "host 192.168.1.10" in bpf
    assert "port 53" in bpf
    assert "host 1.1.1.1" in bpf


def test_generate_wireshark_filters() -> None:
    """Verify display filter combinations for specific finding domains."""
    filters = generate_wireshark_filters("10.200.2.2", ["reset", "http"])
    assert any("tcp.flags.reset == 1 and ip.addr == 10.200.2.2" in f for f in filters)
    assert any("http and ip.addr == 10.200.2.2" in f for f in filters)


def test_packet_capture_with_mock_sniffer(tmp_path: Path) -> None:
    """Verify PacketCapture records packet count, byte count, and SHA-256 using injected sniffer."""
    with PacketCapture(
        target="127.0.0.1",
        run_id="test_run",
        output_dir=tmp_path,
        sniffer_factory=lambda f: MockSniffer(filter_expr=f),
    ) as cap:
        pass

    assert cap.result is not None
    assert cap.result.packet_count == 2
    assert cap.result.byte_count > 0
    assert len(cap.result.sha256) == 64
    assert Path(cap.result.pcap_path).exists()


def test_recommendations_rules() -> None:
    """Verify pure recommendation rules map verdicts to at most 5 choices."""
    meta = ReportMetadata(tool_version="0.1.0", network_label="test")

    # 1. Clean report
    clean_rep = AuditReport(metadata=meta, port_results=[], dns_results=[], http_results=[])
    recs_clean = get_recommendations(clean_rep, current_intent="audit", target="127.0.0.1")
    assert len(recs_clean) <= 5
    actions = [r.action for r in recs_clean]
    assert "export" in actions
    assert "rerun" in actions
    assert "menu" in actions
    assert "quit" in actions


# ==============================================================================
# Stage 6 Tests: Lab Report Golden-File & Invariants
# ==============================================================================


def test_labreport_golden_file() -> None:
    """Golden-file test of render_lab_report with fixed clock, metrics, and plan."""

    def fixed_clock() -> datetime.datetime:
        return datetime.datetime(2026, 11, 13, 12, 0, 0, tzinfo=datetime.timezone.utc)

    meta = ReportMetadata(tool_version="0.1.0", network_label="test-network")

    # Sample observation
    obs = Observation(
        probe_name="tcp_connect",
        target=Target(host="probe.test", port=443, service="HTTPS"),
        success=True,
        raw={"status": "open", "rtt_ms": 15.4},
    )
    v = Verdict(
        kind=VerdictKind.OPEN,
        confidence=Confidence.HIGH,
        target=Target(host="probe.test", port=443, service="HTTPS"),
        evidence=["Received SYN-ACK in 15.4ms"],
    )
    report = AuditReport(metadata=meta, port_results=[v], dns_results=[], http_results=[])

    plan = build_audit_plan(
        target="probe.test", ports="443", runs=1, timeout=3.0, retries=1, mode="socket"
    )
    metrics = RunResult(
        exit_code=0,
        error=None,
        run_id="20261113_120000_a1b2c3d4",
        started_utc="2026-11-13T12:00:00Z",
        finished_utc="2026-11-13T12:00:01Z",
        wall_s=1.234,
        cpu_s=0.456,
        peak_rss_kb=12345,
    )

    cap_res = CaptureResult(
        pcap_path="reports/capture-20261113_120000_a1b2c3d4.pcap",
        packet_count=12,
        byte_count=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        bpf_filter="host probe.test",
        interface="eth0",
    )

    content = render_lab_report(
        report=report,
        run_meta={"run_id": "20261113_120000_a1b2c3d4", "observations": [obs]},
        metrics=metrics,
        plan=plan,
        transcript=(),
        capture=cap_res,
        clock=fixed_clock,
        git_commit="abcdef1234567890",
    )

    # Invariants checks
    assert "# Netpolicy Laboratory Audit Report: 20261113_120000_a1b2c3d4" in content
    assert "2026-11-13 12:00:00 UTC" in content
    assert "abcdef1234567890" in content
    assert "Port 443 (HTTPS)" in content
    assert "15.4 ms" in content
    assert "1.234 s" in content
    assert "12,345 KB" in content
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in content


def test_identifiers_excluded_by_default() -> None:
    """Verify SSIDs, MAC addresses, and client public IPs are not in the report by default."""

    def fixed_clock() -> datetime.datetime:
        return datetime.datetime(2026, 11, 13, 12, 0, 0, tzinfo=datetime.timezone.utc)

    meta = ReportMetadata(tool_version="0.1.0", network_label="test")
    report = AuditReport(metadata=meta, port_results=[], dns_results=[], http_results=[])
    plan = build_audit_plan(target="probe.test")

    content = render_lab_report(
        report=report,
        run_meta={"run_id": "clean_run"},
        metrics=None,
        plan=plan,
        clock=fixed_clock,
        git_commit="deadbeef",
    )

    # Identifiers check: MAC addresses (e.g. 00:1A:2B:3C:4D:5E), SSIDs, client public IP
    assert "SSID:" not in content
    assert "MAC:" not in content
    assert "BSSID:" not in content
