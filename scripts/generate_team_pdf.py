#!/usr/bin/env python3
"""Netpolicy Project Study Guide - PDF Generator.

Generates a publication-grade, beautifully formatted PDF project study guide
for new engineering team members. Documents the problem space, architectural
solution, cyber-range lab topology, bootstrapping setup, and CLI manual.

Adheres strictly to local file storage rules to prevent binary stream corruption
on Windows /mnt/c/ filesystem mounts.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ------------------------------------------------------------------------------
# Professional Color Palette
# ------------------------------------------------------------------------------
PRIMARY = colors.HexColor("#1A365D")      # Deep Navy
SECONDARY = colors.HexColor("#2B6CB0")    # Slate Blue
ACCENT = colors.HexColor("#0D9488")       # Dark Teal
TEXT_DARK = colors.HexColor("#2D3748")    # Charcoal
TEXT_MUTED = colors.HexColor("#718096")   # Slate Gray
BG_LIGHT = colors.HexColor("#F7FAFC")     # Off-white / light slate
BG_CODE = colors.HexColor("#EDF2F7")      # Cool light gray for code blocks
BORDER = colors.HexColor("#CBD5E0")       # Light border gray
WARN_COLOR = colors.HexColor("#C53030")   # Crimson Red
SUCCESS_COLOR = colors.HexColor("#2F855A")# Forest Green


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()

        # Suppress headers & footers on Page 1 (Cover Page)
        if self._pageNumber > 1:
            # Running Header
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(SECONDARY)
            self.drawString(36, 756, "NETPOLICY")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(TEXT_MUTED)
            self.drawString(88, 756, "— Engineering Team Project Study Guide")

            self.drawRightString(
                576, 756, "Internal Technical Manual • Version 0.1.0"
            )
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)

            # Running Footer
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.5)
            self.line(36, 42, 576, 42)

            self.setFont("Helvetica", 7.5)
            self.setFillColor(TEXT_MUTED)
            self.drawString(
                36, 30, "Confidential • Network Security Engineering Team • Tanishq Rana"
            )
            page_text = f"Page {self._pageNumber} of {total_pages}"
            self.drawRightString(576, 30, page_text)

        self.restoreState()


def build_pdf(filename: str):
    """Compile the entire study guide document into the target PDF path."""
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=48,
    )

    base_styles = getSampleStyleSheet()

    # Document Styles
    styles = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle",
            parent=base_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=32,
            textColor=PRIMARY,
            alignment=TA_LEFT,
            spaceAfter=6,
        ),
        "CoverSubtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=SECONDARY,
            alignment=TA_LEFT,
            spaceAfter=14,
        ),
        "CoverMeta": ParagraphStyle(
            "CoverMeta",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=TEXT_DARK,
            spaceAfter=3,
        ),
        "CoverAbstract": ParagraphStyle(
            "CoverAbstract",
            parent=base_styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9.5,
            leading=14.5,
            textColor=TEXT_DARK,
            alignment=TA_JUSTIFY,
        ),
        "H1": ParagraphStyle(
            "H1",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=PRIMARY,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "H2": ParagraphStyle(
            "H2",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=SECONDARY,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "H3": ParagraphStyle(
            "H3",
            parent=base_styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=PRIMARY,
            spaceBefore=7,
            spaceAfter=3,
            keepWithNext=True,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base_styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=TEXT_DARK,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        ),
        "Bullet": ParagraphStyle(
            "Bullet",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=TEXT_DARK,
            leftIndent=14,
            firstLineIndent=-9,
            spaceAfter=3,
        ),
        "CodeBlock": ParagraphStyle(
            "CodeBlock",
            parent=base_styles["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=10.5,
            textColor=colors.HexColor("#1A202C"),
            spaceBefore=2,
            spaceAfter=2,
        ),
        "CalloutText": ParagraphStyle(
            "CalloutText",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=PRIMARY,
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "TableCell": ParagraphStyle(
            "TableCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10.5,
            textColor=TEXT_DARK,
        ),
        "TableCellBold": ParagraphStyle(
            "TableCellBold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.8,
            leading=10.5,
            textColor=PRIMARY,
        ),
        "TableCellMono": ParagraphStyle(
            "TableCellMono",
            parent=base_styles["Normal"],
            fontName="Courier-Bold",
            fontSize=7.2,
            leading=9.5,
            textColor=colors.HexColor("#742A2A"),
        ),
    }

    story = []

    # ==========================================================================
    # COVER / HEADER BANNER
    # ==========================================================================
    story.append(Paragraph("NETPOLICY", styles["CoverTitle"]))
    story.append(
        Paragraph(
            "Deterministic Network Policy & Middlebox Tampering Auditor",
            styles["CoverSubtitle"],
        )
    )

    # Document Metadata Box
    meta_data = [
        [
            Paragraph("<b>Project Version:</b> v0.1.0 (Production Core)", styles["CoverMeta"]),
            Paragraph("<b>Target Audience:</b> Engineering Team & Onboarding", styles["CoverMeta"]),
        ],
        [
            Paragraph("<b>Author / Lead:</b> Tanishq Rana", styles["CoverMeta"]),
            Paragraph("<b>Platform:</b> Linux & Windows WSL2 (Kali/Ubuntu)", styles["CoverMeta"]),
        ],
        [
            Paragraph("<b>Core Stack:</b> Python 3.10+, Scapy, Typer, Rich", styles["CoverMeta"]),
            Paragraph("<b>Lab Engine:</b> Linux Network Namespaces (veth)", styles["CoverMeta"]),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[270, 270])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Abstract Callout Box
    abstract_text = (
        "<b>Executive Purpose:</b> When deploying applications or working across heterogeneous networks "
        "(enterprise guest Wi-Fi, campus networks, cellular hotspots, hotel portals), network middleboxes "
        "frequently enforce silent blocking, forged TCP resets, ICMP rejections, DNS redirection, and HTTP "
        "header tampering. Standard utilities like <i>ping</i> and speed tests fail to expose these transport- "
        "and application-layer disruptions. <b>netpolicy</b> provides an automated, deterministic CLI auditor "
        "paired with an isolated 3-node cyber-range testbed (Linux network namespaces) to measure, classify, "
        "and document network policies with absolute precision and zero host pollution."
    )
    abstract_table = Table(
        [[Paragraph(abstract_text, styles["CoverAbstract"])]],
        colWidths=[540],
    )
    abstract_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
                ("BOX", (0, 0), (-1, -1), 1, SUCCESS_COLOR),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(abstract_table)
    story.append(Spacer(1, 12))

    # ==========================================================================
    # SECTION 1: PROBLEM STATEMENT
    # ==========================================================================
    story.append(
        Paragraph("1. Problem Statement: Silent Network Tampering", styles["H1"])
    )
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    story.append(
        Paragraph(
            "Modern computer networking fundamentally depends on the <b>End-to-End Principle</b> (Saltzer et al., 1984), "
            "which dictates that reliability and policy checks belong at endpoints, while the network merely forwards packets. "
            "However, commercial networks deploy intermediate appliances—collectively termed <b>middleboxes</b> (RFC 3234)—such "
            "as stateful firewalls, Carrier-Grade NATs, captive portals, and transparent proxies. These entities silently alter "
            "or kill transport traffic without notifying client applications, violating standard protocol semantics.",
            styles["Body"],
        )
    )

    story.append(
        Paragraph("The Five Primary Middlebox Tampering Signatures:", styles["H2"])
    )

    story.append(
        Paragraph(
            "• <b>Silent Firewall Drops (BLOCKED_DROP):</b> Firewalls drop outbound TCP SYN packets targeting specific ports "
            "(e.g., SMTP 25, custom databases) with <code>-j DROP</code>. The OS retransmits exponentially until socket timeout "
            "(<code>ETIMEDOUT</code>), causing long hangs without explaining if the server is down or filtered.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "• <b>TCP Reset Injection (BLOCKED_RESET):</b> Middleboxes forge TCP RST packets matching the client sequence number, "
            "terminating connections immediately (<code>ECONNREFUSED</code>). This creates acute ambiguity: did the target server "
            "actively refuse connection, or did an intermediate firewall forge the reset?",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "• <b>ICMP Administrative Prohibitions (BLOCKED_ICMP):</b> Security gateways emit ICMP Type 3 error packets "
            "(Code 13: <i>Communication Administratively Prohibited</i>; Code 3: <i>Port Unreachable</i>). Standard OS socket APIs "
            "frequently collapse these rich error signals into generic refusal errors, hiding the true administrative blocker.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "• <b>DNS Interception & NXDOMAIN Hijacking (INTERCEPTED / REWRITTEN):</b> Gateways capture cleartext UDP/53 queries directed "
            "at trusted resolvers (8.8.8.8, 1.1.1.1) and transparently DNAT them to local resolvers. For nonexistent domains (<code>.invalid</code>), "
            "middleboxes rewrite the authentic <code>NXDOMAIN</code> into an IP pointing to an ISP advertising or search portal.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "• <b>HTTP Transparent Proxying & Header Tampering (HEADERS_INJECTED / BODY_MODIFIED):</b> In-path web proxies intercept "
            "unencrypted port 80 traffic, injecting proxy tracing headers (<code>Via</code>, <code>X-Cache</code>, <code>X-Forwarded-For</code>), "
            "stripping client tokens, modifying payload bodies, or redirecting to captive portals.",
            styles["Bullet"],
        )
    )

    story.append(Spacer(1, 4))
    story.append(
        Paragraph("Why Standard Tools Fail to Expose Middlebox Tampering:", styles["H2"])
    )

    tool_comparison = [
        [
            Paragraph("Diagnostic Tool", styles["TableHeader"]),
            Paragraph("Protocol Layer", styles["TableHeader"]),
            Paragraph("What It Tests", styles["TableHeader"]),
            Paragraph("Why It Fails to Expose Tampering", styles["TableHeader"]),
        ],
        [
            Paragraph("<b>ping (ICMP Echo)</b>", styles["TableCellBold"]),
            Paragraph("Layer 3 (IP)", styles["TableCell"]),
            Paragraph("Basic host reachability and round-trip time.", styles["TableCell"]),
            Paragraph("Carries zero transport-layer port context. Returns flawless 15ms replies even when ports 22, 25, or 587 are blocked.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>traceroute / tracert</b>", styles["TableCellBold"]),
            Paragraph("Layer 3 / 4", styles["TableCell"]),
            Paragraph("Hop-by-hop IP path via TTL expiration.", styles["TableCell"]),
            Paragraph("Routers drop or rate-limit ICMP TTL-exceeded packets (producing * * *). Completely blind to Layer 4/7 firewall rules.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Speedtest (Ookla/Fast)</b>", styles["TableCellBold"]),
            Paragraph("Layer 7 (HTTP/HTTPS)", styles["TableCell"]),
            Paragraph("Bulk throughput on ports 80/443 to optimized CDNs.", styles["TableCell"]),
            Paragraph("Tests only open web ports. Fails to detect outbound mail drops, SSH blocks, DNS interception, or proxy tampering.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>netpolicy</b>", styles["TableCellBold"]),
            Paragraph("Layer 4 (TCP/UDP) & Layer 7 (DNS/HTTP)", styles["TableCell"]),
            Paragraph("Active multi-port SYN probing, DNS integrity, and HTTP canary.", styles["TableCellBold"]),
            Paragraph("<b>Differentiates drops, forged resets, ICMP codes, UDP DNAT, and proxy headers using deterministic decision tables.</b>", styles["TableCell"]),
        ],
    ]
    t_comp = Table(tool_comparison, colWidths=[95, 75, 145, 225])
    t_comp.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ]
        )
    )
    story.append(t_comp)
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECTION 2: SOLUTION
    # ==========================================================================
    story.append(
        Paragraph("2. Solution: Deterministic Heuristic Probing & Classification", styles["H1"])
    )
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    story.append(
        Paragraph(
            "<b>netpolicy</b> solves the network observability gap by replacing blind assumptions with structured, "
            "heuristic transport-layer probing and mathematically pure, stateless classifiers. The tool adheres strictly "
            "to four core engineering principles:",
            styles["Body"],
        )
    )

    story.append(
        Paragraph(
            "1. <b>Strict Measurement / Verdict Separation:</b> Probes never evaluate policy. They record only raw physical wire "
            "observations (TCP flags, TTL, IP ID, ICMP type/code, latency, headers). Classifiers evaluate observations offline as pure functions.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "2. <b>The Baseline Control Probe Guard:</b> Every audit dispatches a control probe to a known reachable target (port 443). "
            "If the control probe fails, the entire destination is marked <code>CONTROL_FAILED</code>, converting all timeouts to <code>UNKNOWN</code> "
            "rather than misattributing transient network loss to firewall blocking.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "3. <b>Multi-Run Sampling & Packet Loss Resilience:</b> A single timeout is classified as network packet loss (<code>LOSSY</code>), "
            "never a block. An unequivocal <code>BLOCKED_DROP</code> verdict requires all retries across all sample runs ($N=5$) to time out "
            "while the control port remains healthy.",
            styles["Bullet"],
        )
    )
    story.append(
        Paragraph(
            "4. <b>TTL Discrepancy Heuristic for RST Injection:</b> When a port known to be open (<code>expect_open=True</code>) receives an RST, "
            "the classifier computes the difference between the RST TTL and the control SYN-ACK TTL: $\\Delta\\text{TTL} = |\\text{TTL}_{\\text{rst}} - \\text{TTL}_{\\text{ctrl}}|$. "
            "A $\\Delta\\text{TTL} > 2$ confirms middlebox injection with HIGH confidence, proving the RST was synthesized by an in-path gateway.",
            styles["Bullet"],
        )
    )

    story.append(Spacer(1, 4))
    story.append(Paragraph("Normalized Classifier Verdict Decision Matrix:", styles["H2"]))

    verdict_matrix = [
        [
            Paragraph("Domain", styles["TableHeader"]),
            Paragraph("Verdict Kind", styles["TableHeader"]),
            Paragraph("Detection Criteria & Packet Evidence", styles["TableHeader"]),
            Paragraph("Confidence", styles["TableHeader"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("OPEN", styles["TableCellBold"]),
            Paragraph("SYN-ACK received (raw mode) or socket connected across sample runs.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("BLOCKED_DROP", styles["TableCellMono"]),
            Paragraph("0/N replies received (all timeouts) while control port 443 connects cleanly.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("BLOCKED_RESET", styles["TableCellMono"]),
            Paragraph("TCP RST received on expect_open=True port; |TTL_rst - TTL_ctrl| > 2.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("CLOSED_OR_RESET", styles["TableCell"]),
            Paragraph("TCP RST received on uncontrolled port (expect_open=False). Ambiguous state.", styles["TableCell"]),
            Paragraph("LOW", styles["TableCell"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("BLOCKED_ICMP", styles["TableCellMono"]),
            Paragraph("ICMP Type 3 received (Code 13 admin prohibited; Code 3 port unreachable).", styles["TableCell"]),
            Paragraph("HIGH / MED", styles["TableCell"]),
        ],
        [
            Paragraph("TCP Port", styles["TableCellBold"]),
            Paragraph("LOSSY", styles["TableCell"]),
            Paragraph("Mixed replies and timeouts, but control port healthy. Loss rate calculated.", styles["TableCell"]),
            Paragraph("MEDIUM", styles["TableCell"]),
        ],
        [
            Paragraph("DNS", styles["TableCellBold"]),
            Paragraph("INTERCEPTED", styles["TableCellMono"]),
            Paragraph("Replies received for blackhole IPs (192.0.2.1), or reply source IP mismatch.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("DNS", styles["TableCellBold"]),
            Paragraph("REWRITTEN", styles["TableCellMono"]),
            Paragraph(".invalid query returned valid A record instead of authentic NXDOMAIN.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("HTTP", styles["TableCellBold"]),
            Paragraph("HEADERS_INJECTED", styles["TableCellMono"]),
            Paragraph("Response contains proxy headers: Via, X-Cache, X-Forwarded-For, etc.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
        [
            Paragraph("HTTP", styles["TableCellBold"]),
            Paragraph("BODY_MODIFIED", styles["TableCellMono"]),
            Paragraph("Payload SHA-256 differs from expected canary manifest hash.", styles["TableCell"]),
            Paragraph("HIGH", styles["TableCellBold"]),
        ],
    ]
    t_verd = Table(verdict_matrix, colWidths=[65, 95, 310, 70])
    t_verd.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ]
        )
    )
    story.append(t_verd)
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECTION 3: HOW IT WORKS
    # ==========================================================================
    story.append(
        Paragraph("3. How It Works: Architecture & Cyber-Range Lab", styles["H1"])
    )
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    story.append(
        Paragraph(
            "<b>netpolicy</b> is organized into four strictly isolated functional layers, ensuring robust execution, "
            "instant crash recovery, and offline re-classification capability:",
            styles["Body"],
        )
    )

    # Architecture Overview Callout
    arch_box_text = (
        "<b>System Data Pipeline:</b><br/>"
        "1. <b>Active Probing Layer:</b> TcpSynProbe (Scapy raw packet crafting) & TcpConnectProbe (socket connect + MSG_ERRQUEUE).<br/>"
        "2. <b>Durable Telemetry Storage:</b> Flushes observations immediately to append-only JSONL (<code>reports/&lt;run_id&gt;.jsonl</code>).<br/>"
        "3. <b>Pure Inference Engine:</b> Groups observations by target/probe $\\to$ runs pure classifiers $\\to$ synthesizes findings.<br/>"
        "4. <b>Presentation Layer:</b> Renders Rich terminal ANSI tables, structured JSON (<code>--json</code>), or Markdown (<code>--output</code>)."
    )
    arch_table = Table([[Paragraph(arch_box_text, styles["CalloutText"])]], colWidths=[540])
    arch_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_CODE),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(arch_table)
    story.append(Spacer(1, 8))

    story.append(
        Paragraph("The 3-Node Cyber-Range Lab Topology (Linux Namespaces):", styles["H2"])
    )
    story.append(
        Paragraph(
            "To rigorously validate detection accuracy against ground-truth middlebox policies without affecting host networking, "
            "the project provides an automated 3-node cyber-range testbed using <b>Linux Network Namespaces</b> (<code>ip netns</code>):",
            styles["Body"],
        )
    )

    # ASCII Lab Diagram in Monospace Box
    lab_ascii = (
        "+-------------------------+                 +-------------------------+                 +-------------------------+\n"
        "|        np-client        |                 |          np-gw          |                 |        np-server        |\n"
        "|   (Audit Origin Node)   |                 |   (Middlebox Router)    |                 |  (Mock Target Daemons)  |\n"
        "|                         |                 |                         |                 |                         |\n"
        "|   10.200.1.2/24         |                 |   10.200.1.1/24         |                 |   10.200.2.2/24         |\n"
        "|   [veth-client] <=======|==== veth 1 =====|=> [veth-gw-c]           |                 |   [veth-server]         |\n"
        "|                         |                 |                         |                 |        ^                |\n"
        "|   Default Route:        |                 |   IPv4 Forwarding = 1   |                 |        |                |\n"
        "|     via 10.200.1.1      |                 |   Blackholes: 192.0.2.0 |                 |     veth 2              |\n"
        "|                         |                 |   10.200.2.1/24         |                 |        |                |\n"
        "|   DNS: /etc/netns/      |                 |   [veth-gw-s] <=========|==== veth 2 =====|=>      v                |\n"
        "|   np-client/resolv.conf |                 |                         |                 |   Default Route:        |\n"
        "|                         |                 |                         |                 |     via 10.200.2.1      |\n"
        "+-------------------------+                 +-------------------------+                 +-------------------------+\n"
        "       Subnet 1: 10.200.1.0/24 (Client Subnet)                                     Subnet 2: 10.200.2.0/24 (Server Subnet)"
    )
    t_ascii = Table([[Paragraph(lab_ascii.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeBlock"])]], colWidths=[540])
    t_ascii.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1A202C")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(t_ascii)
    story.append(Spacer(1, 6))

    story.append(
        Paragraph("Why Namespaces Guarantee 100% Host Isolation & Safety:", styles["H3"])
    )
    story.append(
        Paragraph(
            "• <b>Direct Veth Creation:</b> Both ends of each veth link are created directly in their destination namespaces "
            "(<code>ip link add veth-client netns np-client type veth peer name veth-gw-c netns np-gw</code>). Neither endpoint ever enters the host namespace.<br/>"
            "• <b>Confined Forwarding:</b> <code>sysctl net.ipv4.ip_forward=1</code> is enabled strictly inside <code>np-gw</code>. Host forwarding remains off.<br/>"
            "• <b>No Internet Uplink / No Host Routes:</b> Closed testbed with no NAT or routing to physical adapters.<br/>"
            "• <b>Preserved Host DNS:</b> Host <code>/etc/resolv.conf</code> is untouched; uses isolated per-namespace mounts under <code>/etc/netns/</code>.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 8))

    # ==========================================================================
    # SECTION 4: SETUP GUIDE
    # ==========================================================================
    story.append(
        Paragraph("4. Setup Guide: Prerequisites & Automated Bootstrapping", styles["H1"])
    )
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    story.append(
        Paragraph(
            "<b>Prerequisites:</b> Linux OS (Ubuntu, Kali, Debian, Fedora, Arch) or <b>Windows 11 with WSL2</b>. "
            "<i>Note: WSL1 is not supported because it lacks native Linux network namespaces and Scapy raw sockets. "
            "Always store the repository inside Linux ext4 storage (e.g. <code>~/netpolicy</code>), never under <code>/mnt/c/</code>.</i>",
            styles["Body"],
        )
    )

    story.append(Paragraph("Three-Step Automated Bootstrap Sequence:", styles["H2"]))

    setup_table_data = [
        [
            Paragraph("Step & Script", styles["TableHeader"]),
            Paragraph("Execution Command", styles["TableHeader"]),
            Paragraph("What It Does & Issues It Solves", styles["TableHeader"]),
        ],
        [
            Paragraph("<b>1. System Packages</b><br/><code>scripts/bootstrap-system.sh</code>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash scripts/bootstrap-system.sh</code>", styles["TableCellMono"]),
            Paragraph("Installs core OS packages via apt/dnf/pacman: <code>python3</code>, <code>python3-venv</code>, <code>iproute2</code>, <code>iptables</code>, <code>curl</code>, <code>iputils-ping</code>, <code>psmisc</code>, and <code>procps</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>2. Python Virtualenv</b><br/><code>scripts/bootstrap-python.sh</code>", styles["TableCellBold"]),
            Paragraph("<code>bash scripts/bootstrap-python.sh</code><br/><i>(Run as regular user!)</i>", styles["TableCellMono"]),
            Paragraph("<b>Fixes Debian/Kali broken pip bug</b> (<code>ModuleNotFoundError: No module named 'pip._internal.utils'</code>). Creates <code>.linux-venv</code> with <code>--without-pip</code>, bootstraps via official <code>get-pip.py</code>, and installs <code>.[lab]</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>3. Diagnostics</b><br/><code>scripts/doctor.sh</code>", styles["TableCellBold"]),
            Paragraph("<code>bash scripts/doctor.sh</code><br/><i>(or <code>sudo bash scripts/doctor.sh</code>)</i>", styles["TableCellMono"]),
            Paragraph("Verifies OS virtualization (WSL2), checks Python >= 3.10, audits tooling in PATH, and runs an isolated firewall self-test inside throwaway namespaces (<code>np-doctor-&lt;pid&gt;</code>).", styles["TableCell"]),
        ],
    ]
    t_setup = Table(setup_table_data, colWidths=[130, 160, 250])
    t_setup.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ]
        )
    )
    story.append(t_setup)
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECTION 5: USING MANUAL
    # ==========================================================================
    story.append(
        Paragraph("5. Using Manual: Step-by-Step CLI & Lab Operations", styles["H1"])
    )
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    story.append(
        Paragraph(
            "Follow this operational procedure to spin up the lab, audit baseline reachability, apply tampering policies, "
            "and detect changes with the differential comparison engine:",
            styles["Body"],
        )
    )

    ops_steps = [
        [
            Paragraph("Phase", styles["TableHeader"]),
            Paragraph("CLI Command", styles["TableHeader"]),
            Paragraph("Expected Output & Action Summary", styles["TableHeader"]),
        ],
        [
            Paragraph("<b>1. Provision Lab</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash lab/setup.sh</code>", styles["TableCellMono"]),
            Paragraph("Creates <code>np-client</code>, <code>np-gw</code>, <code>np-server</code>, binds veth pairs, sets IP routes, enables forwarding in <code>np-gw</code>, and verifies client-to-server ping.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>2. Start Daemons</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash lab/services.sh start</code>", styles["TableCellMono"]),
            Paragraph("Spawns mock background services inside <code>np-server</code> detached via <code>nohup</code>: Banner listeners (ports 21, 22, 25, 443, 587), Canary HTTP (port 80), and DNS server (port 53).", styles["TableCell"]),
        ],
        [
            Paragraph("<b>3. Baseline Audit</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo ip netns exec np-client \\<br/>&nbsp;&nbsp;netpolicy audit --target 10.200.2.2 \\<br/>&nbsp;&nbsp;--json &gt; baseline.json</code>", styles["TableCellMono"]),
            Paragraph("Runs full multi-probe audit from <code>np-client</code> across clean baseline network. All ports return <code>OPEN</code>; DNS and HTTP return <code>CLEAN</code>. Exit code: <code>0</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>4. Apply Scenario</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash lab/scenario.sh reset-smtp</code><br/><i>(or <code>campus</code>, <code>dns-dnat</code>)</i>", styles["TableCellMono"]),
            Paragraph("<b>Strictly flushes all existing iptables rules in np-gw</b>, then injects TCP RST on port 25 (<code>REJECT --reject-with tcp-reset</code>). Records state in <code>lab/run/active_scenario</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>5. Tampered Audit</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo ip netns exec np-client \\<br/>&nbsp;&nbsp;netpolicy audit --target 10.200.2.2 \\<br/>&nbsp;&nbsp;--json &gt; tampered.json</code>", styles["TableCellMono"]),
            Paragraph("Re-runs audit across tampered network. Detects port 25 <code>BLOCKED_RESET</code> with HIGH confidence (TTL discrepancy $\\Delta\\text{TTL} &gt; 2$). Emits warning findings. Exit code: <code>1</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>6. Diff Reports</b>", styles["TableCellBold"]),
            Paragraph("<code>netpolicy compare baseline.json tampered.json</code>", styles["TableCellMono"]),
            Paragraph("Highlights exact policy divergence table: Port 25 changed from <code>OPEN</code> to <code>BLOCKED_RESET</code> with evidence. Exit code: <code>1</code>.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>7. One-Step Demo</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash scripts/demo.sh</code>", styles["TableCellMono"]),
            Paragraph("Automated end-to-end smoke test: provisions lab, runs baseline, applies scenario, runs tampered audit, diffs reports, verifies exit codes, and cleans up.", styles["TableCell"]),
        ],
        [
            Paragraph("<b>8. Teardown</b>", styles["TableCellBold"]),
            Paragraph("<code>sudo bash lab/teardown.sh</code>", styles["TableCellMono"]),
            Paragraph("Kills background mock daemons, removes only <code>np-*</code> namespaces, cleans up <code>/etc/netns/</code>. Zero lingering state on host.", styles["TableCell"]),
        ],
    ]
    t_ops = Table(ops_steps, colWidths=[85, 185, 270])
    t_ops.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ]
        )
    )
    story.append(t_ops)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Scenario Catalogue Quick Reference:", styles["H2"]))
    scenarios_data = [
        [
            Paragraph("Scenario Name", styles["TableHeader"]),
            Paragraph("Enforcement Mechanism in np-gw", styles["TableHeader"]),
            Paragraph("Expected Audit Verdicts", styles["TableHeader"]),
        ],
        [
            Paragraph("<code>clean</code>", styles["TableCellMono"]),
            Paragraph("All tables flushed; policy FORWARD ACCEPT", styles["TableCell"]),
            Paragraph("All audited ports OPEN; DNS & HTTP CLEAN", styles["TableCell"]),
        ],
        [
            Paragraph("<code>drop-smtp</code>", styles["TableCellMono"]),
            Paragraph("iptables -A FORWARD -p tcp --dport 25 -j DROP", styles["TableCell"]),
            Paragraph("Port 25 BLOCKED_DROP (all timeouts); others OPEN", styles["TableCell"]),
        ],
        [
            Paragraph("<code>reset-smtp</code>", styles["TableCellMono"]),
            Paragraph("iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with tcp-reset", styles["TableCell"]),
            Paragraph("Port 25 BLOCKED_RESET (injected RST detected); others OPEN", styles["TableCell"]),
        ],
        [
            Paragraph("<code>icmp-admin</code>", styles["TableCellMono"]),
            Paragraph("iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-admin-prohibited", styles["TableCell"]),
            Paragraph("Port 25 BLOCKED_ICMP (Type 3 Code 13); others OPEN", styles["TableCell"]),
        ],
        [
            Paragraph("<code>dns-dnat</code>", styles["TableCellMono"]),
            Paragraph("iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53", styles["TableCell"]),
            Paragraph("DNS INTERCEPTED (UDP/53 redirected to gateway)", styles["TableCell"]),
        ],
        [
            Paragraph("<code>nxdomain-rewrite</code>", styles["TableCellMono"]),
            Paragraph("dns_server restarted with --rewrite flag inside np-server", styles["TableCell"]),
            Paragraph("DNS REWRITTEN (.invalid returns fixed A record)", styles["TableCell"]),
        ],
        [
            Paragraph("<code>http-proxy</code>", styles["TableCellMono"]),
            Paragraph("Tamper proxy on 8080; port 80 redirected to 8080 in np-gw", styles["TableCell"]),
            Paragraph("HTTP HEADERS_INJECTED (Via / X-Cache injected)", styles["TableCell"]),
        ],
        [
            Paragraph("<code>campus</code>", styles["TableCellMono"]),
            Paragraph("Composite: reset-smtp + dns-dnat + http-proxy applied together", styles["TableCellBold"]),
            Paragraph("Port 25 BLOCKED_RESET, DNS INTERCEPTED, HTTP HEADERS_INJECTED", styles["TableCell"]),
        ],
    ]
    t_scen = Table(scenarios_data, colWidths=[110, 210, 220])
    t_scen.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ]
        )
    )
    story.append(t_scen)

    # Build PDF with two-pass NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] Successfully generated PDF study guide at: {filename}")


if __name__ == "__main__":
    out_target = sys.argv[1] if len(sys.argv) > 1 else "./netpolicy_team_guide.pdf"
    build_pdf(out_target)
