#!/usr/bin/env python3
# ruff: noqa
"""Academic Project Report Generator for Netpolicy.

Generates a publication-quality Microsoft Word (.docx) project report for the
Netpolicy framework and Linux namespace cyber-range, following rigorous academic
specifications:
- A4 layout with 2.5 cm margins
- Formal typography (Calibri body, distinct heading hierarchy)
- Custom header and dynamic page numbering field in footer
- Native Word Table of Contents field code
- Formatted tables with shaded headers and explicit captions
- Embedded figures (accuracy.png, confusion.png)
- Monospaced code blocks for CLI commands and ASCII network topologies
- Strict adherence to ground-truth repository facts and specified reference list

Execution & Prevention of Corruption:
  Saves locally in Linux/repo first as './netpolicy_report.docx' before transferring
  to the Windows Downloads folder, preventing 9P / drvfs zip corruption.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import docx
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor


# ==============================================================================
# Helper Formatting Functions
# ==============================================================================


def set_cell_background(cell, hex_color: str) -> None:
    """Sets background shading of a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)


def set_cell_margins(
    cell, top: int = 100, bottom: int = 100, left: int = 150, right: int = 150
) -> None:
    """Sets internal padding for a table cell in dxa (1 pt = 20 dxa)."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f"<w:tcMar {nsdecls('w')}>"
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f"</w:tcMar>"
    )
    tcPr.append(tcMar)


def add_toc_field(doc: docx.Document) -> None:
    """Inserts a standard Microsoft Word Table of Contents field."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(18)
    run = p.add_run()

    fldChar1 = OxmlElement("w:fldChar")
    fldChar1.set(qn("w:fldCharType"), "begin")
    instrText = OxmlElement("w:instrText")
    instrText.set(qn("xml:space"), "preserve")
    instrText.text = 'TOC \\o "1-3" \\h \\z \\u'
    fldChar2 = OxmlElement("w:fldChar")
    fldChar2.set(qn("w:fldCharType"), "separate")
    fldChar3 = OxmlElement("w:fldChar")
    fldChar3.set(qn("w:fldCharType"), "end")

    p._p.append(fldChar1)
    p._p.append(instrText)
    p._p.append(fldChar2)
    p._p.append(fldChar3)


def add_header_footer(section, project_title: str) -> None:
    """Configures running header and page numbering footer."""
    # Running Header
    header = section.header
    hp = header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hp.paragraph_format.space_after = Pt(0)
    hrun = hp.add_run(project_title)
    hrun.font.name = "Calibri"
    hrun.font.size = Pt(8.5)
    hrun.font.color.rgb = RGBColor(120, 120, 120)

    # Running Footer with Page Numbers (Page X of Y)
    footer = section.footer
    fp = footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    fp.paragraph_format.space_before = Pt(0)
    frun1 = fp.add_run("Page ")
    frun1.font.name = "Calibri"
    frun1.font.size = Pt(9)
    frun1.font.color.rgb = RGBColor(120, 120, 120)

    fld1 = OxmlElement("w:fldChar")
    fld1.set(qn("w:fldCharType"), "begin")
    instr1 = OxmlElement("w:instrText")
    instr1.set(qn("xml:space"), "preserve")
    instr1.text = "PAGE"
    fld2 = OxmlElement("w:fldChar")
    fld2.set(qn("w:fldCharType"), "separate")
    fld3 = OxmlElement("w:fldChar")
    fld3.set(qn("w:fldCharType"), "end")
    fp._p.append(fld1)
    fp._p.append(instr1)
    fp._p.append(fld2)
    fp._p.append(fld3)

    frun2 = fp.add_run(" of ")
    frun2.font.name = "Calibri"
    frun2.font.size = Pt(9)
    frun2.font.color.rgb = RGBColor(120, 120, 120)

    fld4 = OxmlElement("w:fldChar")
    fld4.set(qn("w:fldCharType"), "begin")
    instr2 = OxmlElement("w:instrText")
    instr2.set(qn("xml:space"), "preserve")
    instr2.text = "NUMPAGES"
    fld5 = OxmlElement("w:fldChar")
    fld5.set(qn("w:fldCharType"), "separate")
    fld6 = OxmlElement("w:fldChar")
    fld6.set(qn("w:fldCharType"), "end")
    fp._p.append(fld4)
    fp._p.append(instr2)
    fp._p.append(fld5)
    fp._p.append(fld6)


def add_custom_heading(doc: docx.Document, text: str, level: int) -> None:
    """Adds a heading with consistent spacing and styling."""
    h = doc.add_heading(text, level=level)
    h.paragraph_format.keep_with_next = True
    if level == 1:
        h.paragraph_format.space_before = Pt(18)
        h.paragraph_format.space_after = Pt(8)
        for r in h.runs:
            r.font.name = "Calibri"
            r.font.size = Pt(16)
            r.font.bold = True
            r.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)  # Navy
    elif level == 2:
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(6)
        for r in h.runs:
            r.font.name = "Calibri"
            r.font.size = Pt(13)
            r.font.bold = True
            r.font.color.rgb = RGBColor(0x2B, 0x54, 0x7E)  # Slate Blue
    elif level == 3:
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(4)
        for r in h.runs:
            r.font.name = "Calibri"
            r.font.size = Pt(11.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(0x33, 0x33, 0x33)


def add_academic_paragraph(
    doc: docx.Document,
    text: str,
    space_after: float = 6.0,
    bold_prefix: str | None = None,
    italic_prefix: str | None = None,
) -> None:
    """Adds a justified body paragraph with optional bold or italic prefix."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.15
    p.paragraph_format.space_after = Pt(space_after)

    if bold_prefix:
        r_pre = p.add_run(bold_prefix)
        r_pre.font.name = "Calibri"
        r_pre.font.size = Pt(11)
        r_pre.font.bold = True
        r_pre.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    if italic_prefix:
        r_pre2 = p.add_run(italic_prefix)
        r_pre2.font.name = "Calibri"
        r_pre2.font.size = Pt(11)
        r_pre2.font.italic = True
        r_pre2.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    r_text = p.add_run(text)
    r_text.font.name = "Calibri"
    r_text.font.size = Pt(11)
    r_text.font.color.rgb = RGBColor(0x22, 0x22, 0x22)


def add_bullet_item(doc: docx.Document, text: str, bold_prefix: str | None = None) -> None:
    """Adds a stylized bullet list item."""
    p = doc.add_paragraph(style="List Bullet")
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.12
    p.paragraph_format.space_after = Pt(3.5)

    if bold_prefix:
        r_bold = p.add_run(bold_prefix)
        r_bold.font.name = "Calibri"
        r_bold.font.size = Pt(11)
        r_bold.font.bold = True
        r_bold.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    r_text = p.add_run(text)
    r_text.font.name = "Calibri"
    r_text.font.size = Pt(11)
    r_text.font.color.rgb = RGBColor(0x22, 0x22, 0x22)


def add_numbered_item(doc: docx.Document, text: str, bold_prefix: str | None = None) -> None:
    """Adds a stylized numbered list item."""
    p = doc.add_paragraph(style="List Number")
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.12
    p.paragraph_format.space_after = Pt(4.0)

    if bold_prefix:
        r_bold = p.add_run(bold_prefix)
        r_bold.font.name = "Calibri"
        r_bold.font.size = Pt(11)
        r_bold.font.bold = True

    r_text = p.add_run(text)
    r_text.font.name = "Calibri"
    r_text.font.size = Pt(11)


def add_code_block(doc: docx.Document, code_text: str) -> None:
    """Adds a formatted monospaced code or ASCII diagram block with light background shading."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F4F5F7")
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)

    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)

    run = p.add_run(code_text.rstrip())
    run.font.name = "Consolas"
    run.font.size = Pt(9.0)
    run.font.color.rgb = RGBColor(0x1E, 0x29, 0x3B)

    # Empty paragraph after table for spacing
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(2)
    p_sp.paragraph_format.space_after = Pt(4)


def add_academic_table(
    doc: docx.Document,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    caption: str,
    col_widths: Sequence[float] | None = None,
) -> None:
    """Adds a fully bordered, professional academic table with header shading and caption."""
    # Caption above table
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p_cap.paragraph_format.space_before = Pt(10)
    p_cap.paragraph_format.space_after = Pt(4)
    p_cap.paragraph_format.keep_with_next = True
    r_cap = p_cap.add_run(caption)
    r_cap.font.name = "Calibri"
    r_cap.font.size = Pt(10.0)
    r_cap.font.bold = True
    r_cap.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)

    tbl = doc.add_table(rows=len(rows) + 1, cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"

    # Header Row
    hdr_cells = tbl.rows[0].cells
    for idx, title in enumerate(headers):
        cell = hdr_cells[idx]
        set_cell_background(cell, "1B365D")  # Dark Navy
        set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(title)
        run.font.name = "Calibri"
        run.font.size = Pt(9.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    # Data Rows
    for r_idx, row_data in enumerate(rows):
        row_cells = tbl.rows[r_idx + 1].cells
        bg_color = "F8FAFC" if (r_idx % 2 == 1) else "FFFFFF"
        for c_idx, val in enumerate(row_data):
            cell = row_cells[c_idx]
            set_cell_background(cell, bg_color)
            set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.05
            run = p.add_run(str(val))
            run.font.name = "Calibri"
            run.font.size = Pt(9.0)
            run.font.color.rgb = RGBColor(0x1E, 0x29, 0x3B)

    # Set Column Widths if provided
    if col_widths:
        for row in tbl.rows:
            for idx, width in enumerate(col_widths):
                if idx < len(row.cells):
                    row.cells[idx].width = Inches(width)

    p_post = doc.add_paragraph()
    p_post.paragraph_format.space_before = Pt(0)
    p_post.paragraph_format.space_after = Pt(6)


def add_figure_if_exists(
    doc: docx.Document, img_path: Path, caption: str, width: float = 5.8
) -> bool:
    """Embeds an image figure if found on disk, adding an academic caption."""
    if not img_path.exists():
        return False

    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(10)
    p_img.paragraph_format.space_after = Pt(4)
    run_img = p_img.add_run()
    run_img.add_picture(str(img_path), width=Inches(width))

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(0)
    p_cap.paragraph_format.space_after = Pt(12)
    r_cap = p_cap.add_run(caption)
    r_cap.font.name = "Calibri"
    r_cap.font.size = Pt(9.5)
    r_cap.font.italic = True
    r_cap.font.color.rgb = RGBColor(0x47, 0x55, 0x69)
    return True


# ==============================================================================
# Dynamic Windows Downloads Destination Resolver
# ==============================================================================


def resolve_downloads_directory() -> Path:
    """Resolves the user's Downloads folder dynamically across Windows and WSL2."""
    if sys.platform == "win32":
        # Native Windows
        user_profile = os.environ.get("USERPROFILE")
        if user_profile and Path(user_profile).exists():
            downloads = Path(user_profile) / "Downloads"
            if downloads.exists():
                return downloads
        return Path.home() / "Downloads"

    # Running under WSL or Linux
    try:
        proc = subprocess.run(
            ["cmd.exe", "/c", "echo %USERPROFILE%"],
            capture_output=True,
            text=True,
            check=True,
        )
        win_profile_raw = proc.stdout.strip().replace("\r", "")
        if win_profile_raw and win_profile_raw != "%USERPROFILE%":
            proc2 = subprocess.run(
                ["wslpath", win_profile_raw],
                capture_output=True,
                text=True,
                check=True,
            )
            wsl_profile = Path(proc2.stdout.strip().replace("\r", ""))
            downloads = wsl_profile / "Downloads"
            if downloads.exists():
                return downloads
    except Exception:
        pass

    # Fallback to local user Downloads or repository docs
    fallback = Path.home() / "Downloads"
    if fallback.exists():
        return fallback
    return Path(__file__).resolve().parent.parent / "docs"


# ==============================================================================
# Main Report Assembly
# ==============================================================================


def build_project_report(output_path: Path, repo_root: Path) -> None:
    """Constructs the complete 16-section academic project report in Word (.docx) format."""
    doc = docx.Document()

    # Section & Page Geometry Setup (A4, 2.5 cm margins)
    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.top_margin = Inches(0.984)  # 2.5 cm
    section.bottom_margin = Inches(0.984)  # 2.5 cm
    section.left_margin = Inches(0.984)  # 2.5 cm
    section.right_margin = Inches(0.984)  # 2.5 cm

    # Running Header and Page Numbering
    add_header_footer(section, "netpolicy: Network Policy & Middlebox Auditing Framework")

    # ==========================================================================
    # SECTION 1: TITLE PAGE
    # ==========================================================================
    p_univ = doc.add_paragraph()
    p_univ.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_univ.paragraph_format.space_before = Pt(36)
    p_univ.paragraph_format.space_after = Pt(4)
    r_univ = p_univ.add_run("INDIRA GANDHI DELHI TECHNICAL UNIVERSITY FOR WOMEN (IGDTUW)")
    r_univ.font.name = "Calibri"
    r_univ.font.size = Pt(13)
    r_univ.font.bold = True
    r_univ.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)

    p_dept = doc.add_paragraph()
    p_dept.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_dept.paragraph_format.space_after = Pt(48)
    r_dept = p_dept.add_run(
        "Department of Computer Science and Engineering\nAcademic Term: 2026–2027"
    )
    r_dept.font.name = "Calibri"
    r_dept.font.size = Pt(11)
    r_dept.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(24)
    p_title.paragraph_format.space_after = Pt(12)
    r_title = p_title.add_run(
        "netpolicy: A Deterministic Network Policy and Middlebox Auditing Framework "
        "with an Isolated Linux Namespace Cyber-Range"
    )
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(22)
    r_title.font.bold = True
    r_title.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(72)
    r_sub = p_sub.add_run(
        "Computer Networks Course Project\n"
        "Technical Evaluation, Deterministic Inference, and Ground-Truth Validation"
    )
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(12)
    r_sub.font.italic = True
    r_sub.font.color.rgb = RGBColor(0x47, 0x55, 0x69)

    # Student & Evaluation Metadata Box
    meta_table = doc.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Author / Candidate:", "Tanishq"),
        ("Institution:", "Indira Gandhi Delhi Technical University for Women (IGDTUW)"),
        ("Course / Evaluation Code:", "[Course Code Placeholder: e.g., BCS-301 / CS-402]"),
        ("Faculty / Evaluator:", "[Professor / Evaluator Name Placeholder]"),
    ]
    for idx, (label, val) in enumerate(meta_data):
        c0, c1 = meta_table.rows[idx].cells
        c0.width, c1.width = Inches(2.2), Inches(4.2)
        set_cell_margins(c0, 60, 60, 80, 80)
        set_cell_margins(c1, 60, 60, 80, 80)
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_after = Pt(2)
        r0 = p0.add_run(label)
        r0.font.name = "Calibri"
        r0.font.size = Pt(10.5)
        r0.font.bold = True
        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_after = Pt(2)
        r1 = p1.add_run(val)
        r1.font.name = "Calibri"
        r1.font.size = Pt(10.5)

    p_date = doc.add_paragraph()
    p_date.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_date.paragraph_format.space_before = Pt(48)
    r_date = p_date.add_run(f"Report Generated: {datetime.date.today().strftime('%B %d, %Y')}")
    r_date.font.name = "Calibri"
    r_date.font.size = Pt(10)
    r_date.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    doc.add_page_break()

    # ==========================================================================
    # SECTION 2: ABSTRACT
    # ==========================================================================
    add_custom_heading(doc, "Abstract", level=1)
    add_academic_paragraph(
        doc,
        "Modern Internet communication relies upon intermediate networking devices—collectively known as middleboxes—to "
        "route transport-layer traffic faithfully according to standardized Internet Engineering Task Force (IETF) "
        "specifications. However, production access networks, including university campus Wi-Fi, enterprise guest networks, "
        "mobile cellular hotspots behind Carrier-Grade Network Address Translation (CGNAT), and hotel portals, frequently "
        "enforce unannounced, intrusive middlebox policies. These include silent packet drops, artificial Transmission Control "
        "Protocol (TCP) Reset (RST) packet injection, Internet Control Message Protocol (ICMP) administrative destination "
        "rejections, unencrypted Domain Name System (DNS) query interception, Non-Existent Domain (NXDOMAIN) hijacking, "
        "and transparent Hypertext Transfer Protocol (HTTP) proxy header and payload tampering. Standard network diagnostics, "
        "such as ICMP echo requests (ping) and bandwidth speed tests, operate at incongruent protocol layers and fail to reveal "
        "these impairments. This project designs, implements, and evaluates netpolicy, an open-source, deterministic Python 3.10+ "
        "auditing framework and Linux network-namespace cyber-range. By strictly decoupling measurement probes from pure, "
        "stateless inference classifiers, verifying destination reachability via a control probe, and validating verdicts "
        "against an isolated, three-node virtual network lab with zero host pollution, netpolicy provides high-confidence "
        "identification of middlebox interference without heuristics or artificial intelligence.",
    )

    # ==========================================================================
    # SECTION 3: TABLE OF CONTENTS
    # ==========================================================================
    add_custom_heading(doc, "Table of Contents", level=1)
    add_toc_field(doc)
    doc.add_page_break()

    # ==========================================================================
    # SECTION 4: PROBLEM STATEMENT
    # ==========================================================================
    add_custom_heading(doc, "1. Problem Statement", level=1)
    add_academic_paragraph(
        doc,
        "The end-to-end principle, fundamental to Internet architecture, presumes that intermediary network nodes act "
        "exclusively as packet forwarders, leaving connection state maintenance, transport reliability, and payload "
        "integrity to end hosts. In production deployments, however, network operators deploy diverse middlebox appliances "
        "—including stateful firewalls, deep packet inspection (DPI) engines, transparent web caches, and captive portals—that "
        "actively violate this design principle by modifying, intercepting, or terminating packets in flight.",
    )
    add_academic_paragraph(
        doc,
        "These middlebox actions manifest as five distinct classes of network impairment:",
        bold_prefix="Taxonomy of Middlebox Tampering: ",
    )
    add_bullet_item(
        doc,
        "In-path firewalls silently discard outbound TCP SYN packets targeting non-standard or restricted destination ports "
        "(most notably outbound Simple Mail Transfer Protocol port 25 or database ports) without returning error signaling. "
        "The initiating application hangs until its TCP retransmission timer expires, producing unbounded connection latency.",
        bold_prefix="Silent Packet Drops (BLOCKED_DROP): ",
    )
    add_bullet_item(
        doc,
        "Intermediaries forge and inject synthetic TCP RST packets into the transport stream, impersonating the remote destination "
        "to terminate the handshake immediately. While this eliminates prolonged timeout delays, it creates an ambiguous failure "
        "mode where the client cannot distinguish between a remote service that is closed and an in-path middlebox termination.",
        bold_prefix="TCP Reset Injection (BLOCKED_RESET): ",
    )
    add_bullet_item(
        doc,
        "Security gateways synthesize ICMP Destination Unreachable datagrams, such as Type 3 Code 13 (Communication Administratively "
        "Prohibited) or Type 3 Code 3 (Port Unreachable). Standard socket abstractions frequently obscure or drop these raw ICMP "
        "payloads, leaving client software with generic connection failure exceptions.",
        bold_prefix="ICMP Administrative Rejections (BLOCKED_ICMP): ",
    )
    add_bullet_item(
        doc,
        "Network gateways intercept unencrypted User Datagram Protocol port 53 (UDP/53) queries destined for public recursive resolvers "
        "(such as 8.8.8.8 or 1.1.1.1) and transparently redirect them to internal resolvers. Furthermore, when querying non-existent "
        "domains (.invalid), middleboxes frequently rewrite authentic NXDOMAIN responses into A records pointing to advertising "
        "search engines or captive portal landing pages.",
        bold_prefix="DNS Interception and NXDOMAIN Hijacking (INTERCEPTED, REWRITTEN): ",
    )
    add_bullet_item(
        doc,
        "Transparent web proxies intercept unencrypted port 80 traffic to inject tracing headers (such as Via, X-Cache, or "
        "X-Forwarded-For), strip client cryptographic nonces, or manipulate payload bodies in transit.",
        bold_prefix="Transparent HTTP Proxy Interception (HEADERS_INJECTED, BODY_MODIFIED): ",
    )

    add_custom_heading(doc, "1.1 Diagnostic Inadequacy of Standard Network Utilities", level=2)
    add_academic_paragraph(
        doc,
        "Commonly deployed diagnostic utilities fail completely to detect these middlebox interventions:",
        bold_prefix="Diagnostic Failure Modes: ",
    )
    add_bullet_item(
        doc,
        "ICMP Echo Requests (ping) test solely network-layer reachability to a designated IP address. They do not carry transport-layer "
        "port numbers and traverse separate middlebox routing queues. A network path may exhibit 100% ICMP ping reliability while "
        "simultaneously dropping or resetting outbound ports 25, 22, and 587.",
        bold_prefix="ICMP Echo (ping): ",
    )
    add_bullet_item(
        doc,
        "Commercial broadband speed tests (such as Ookla Speedtest or Fast.com) measure aggregate bandwidth over established HTTP/HTTPS "
        "sessions to optimized Content Delivery Network (CDN) edge nodes on ports 80 and 443. They evaluate neither egress port "
        "filtering nor DNS query rewriting, presenting a false impression of network health.",
        bold_prefix="Broadband Speed Tests: ",
    )

    add_custom_heading(doc, "1.2 Affected Populations and Operational Impact", level=2)
    add_academic_paragraph(
        doc,
        "Middlebox interference disproportionately affects technical professionals and academic researchers:",
        bold_prefix="Impacted User Groups: ",
    )
    add_bullet_item(
        doc,
        "Campus Wi-Fi networks routinely enforce aggressive egress filtering, silently blocking Secure Shell (SSH port 22), mail "
        "submission (ports 25 and 587), and direct database connections, disrupting academic coursework and remote laboratory access.",
        bold_prefix="Students and University Researchers: ",
    )
    add_bullet_item(
        doc,
        "Software engineers working on corporate guest networks or remote connections find that Git over SSH fails, webhooks break due "
        "to injected HTTP proxy headers, and direct API endpoints are silently redirected.",
        bold_prefix="Software Developers: ",
    )
    add_bullet_item(
        doc,
        "Mobile cellular networks behind CGNAT and hospitality Wi-Fi portals deploy transparent DNS proxies and captive redirection "
        "that break Virtual Private Network (VPN) tunnels and automated background services.",
        bold_prefix="Travellers and Remote Operators: ",
    )

    add_custom_heading(doc, "1.3 Shortcomings of Existing Tooling", level=2)
    add_academic_paragraph(
        doc,
        "While established network assessment tools exist, in the author's technical assessment they fall short of providing automated, "
        "deterministic policy auditing. General-purpose port scanners, such as Nmap [8], are designed primarily for comprehensive host "
        "reconnaissance and service fingerprinting. They require complex command-line parameterization to capture raw ICMP responses and "
        "do not synthesize multi-probe evidence into high-level policy findings. Furthermore, reconnaissance tools lack dedicated "
        "testbeds to validate their own classification logic against known, ground-truth middlebox configurations, frequently confusing "
        "transient network congestion with deliberate firewall intervention.",
    )

    # ==========================================================================
    # SECTION 5: OBJECTIVES AND SCOPE
    # ==========================================================================
    add_custom_heading(doc, "2. Objectives and Scope", level=1)
    add_academic_paragraph(
        doc,
        "The primary objective of this project is to architect, develop, and validate netpolicy—a lightweight, deterministic "
        "command-line framework capable of detecting silent egress filtering, DNS hijacking, and HTTP tampering across untrusted "
        "networks, supported by an isolated, reproducible virtual cyber-range.",
    )
    add_academic_paragraph(
        doc,
        "The project encompasses the following explicit technical goals:",
        bold_prefix="Specific Technical Objectives: ",
    )
    add_numbered_item(
        doc,
        "Implement non-intrusive active measurement probes covering outbound TCP reachability (supporting both raw TCP SYN packet crafting "
        "and unprivileged socket connects), DNS resolution integrity (RFC 5737 blackhole testing, TXT resolver identification, NXDOMAIN "
        "verification, and DNS-over-HTTPS cross-checking), and HTTP canary validation.",
        bold_prefix="Multi-Protocol Measurement: ",
    )
    add_numbered_item(
        doc,
        "Establish a control-probe architecture that verifies target server baseline reachability (on port 443) before classifying "
        "unresponsive ports, completely eliminating false-positive blocks caused by local link disconnections or remote server outages.",
        bold_prefix="Control-Probe Baseline Verification: ",
    )
    add_numbered_item(
        doc,
        "Construct a pure, stateless inference engine that maps multi-run observation vectors into discrete verdicts with explicit "
        "confidence ratings (high, medium, low) and human-readable evidence strings, entirely devoid of heuristic machine learning.",
        bold_prefix="Deterministic Verdict Classification: ",
    )
    add_numbered_item(
        doc,
        "Engineer an isolated Linux network namespace testbed (np-client, np-gw, np-server) connected via virtual Ethernet (veth) links, "
        "providing reproducible ground truth for packet drops, TCP resets, ICMP rejections, DNS DNAT, and HTTP proxying without modifying host settings.",
        bold_prefix="Ground-Truth Cyber-Range Lab: ",
    )
    add_numbered_item(
        doc,
        "Develop an automated statistical validation framework that computes classification accuracy, confusion matrices, and verifies a "
        "strict 0.0% false-positive rate across clean and degraded network conditions using traffic control emulation (tc netem).",
        bold_prefix="Empirical Ground-Truth Validation: ",
    )

    # ==========================================================================
    # SECTION 6: THEORETICAL BACKGROUND
    # ==========================================================================
    add_custom_heading(doc, "3. Theoretical Background", level=1)
    add_academic_paragraph(
        doc,
        "To interpret netpolicy's detection mechanisms, this section reviews the transport, internet, and application-layer protocols "
        "governing network traffic, alongside the Linux kernel virtualization primitives that underpin the laboratory environment.",
    )

    add_custom_heading(doc, "3.1 TCP Three-Way Handshake and Reset Mechanics", level=2)
    add_academic_paragraph(
        doc,
        "The Transmission Control Protocol, standardized in RFC 9293 [1], establishes bidirectional byte-stream communication via a "
        "three-way handshake. The client transmits a synchronization segment (SYN) containing an Initial Sequence Number (ISN). If the "
        "destination port is bound by an active listening process, the server returns a SYN-ACK segment acknowledging the client ISN and "
        "providing its own sequence number. The client completes the handshake with an ACK segment.",
    )
    add_academic_paragraph(
        doc,
        "If a client targets a closed port on an unfirewalled host, RFC 9293 mandates that the operating system return a TCP Reset (RST) "
        "segment with matching sequence numbers to refuse the connection. However, stateful firewalls can also forge and inject TCP RST "
        "segments into the data path to terminate unauthorized traffic. Because forged RST packets originate from intermediate hops rather "
        "than the destination endpoint, their IP Time-To-Live (TTL) field typically differs from authentic server segments (such as the SYN-ACK "
        "returned on a known open port). Evaluating the TTL delta (|TTL_control - TTL_target|) "
        "provides a deterministic mechanism to uncover middlebox spoofing.",
    )

    add_custom_heading(doc, "3.2 ICMP Destination Unreachable Diagnostics", level=2)
    add_academic_paragraph(
        doc,
        "The Internet Control Message Protocol, defined in RFC 792 [2], delivers network-layer diagnostic and control notifications. "
        "When an intermediate router or firewall refuses to forward an IP datagram due to policy constraints, it generates an ICMP Destination "
        "Unreachable datagram (Type 3). The Code field provides explicit diagnostic granularity:",
        bold_prefix="ICMP Diagnostic Codes: ",
    )
    add_bullet_item(
        doc,
        "Designates that intermediate routing tables have no path to the destination network.",
        bold_prefix="Type 3, Code 0 (Network Unreachable): ",
    )
    add_bullet_item(
        doc,
        "Indicates that the destination subnet was reached, but the specific target IP is unresponsive.",
        bold_prefix="Type 3, Code 1 (Host Unreachable): ",
    )
    add_bullet_item(
        doc,
        "Returned by the destination host when no process is listening on the targeted transport port.",
        bold_prefix="Type 3, Code 3 (Port Unreachable): ",
    )
    add_bullet_item(
        doc,
        "Explicitly generated by intermediate firewalls and access control lists (ACLs) to signal that traffic is prohibited by administrative policy.",
        bold_prefix="Type 3, Code 13 (Communication Administratively Prohibited): ",
    )

    add_custom_heading(doc, "3.3 DNS Architecture, Interception, and Encrypted Transports", level=2)
    add_academic_paragraph(
        doc,
        "The Domain Name System, formalized in RFC 1035 [3], maps human-readable domain names to numerical IP addresses. Standard DNS "
        "queries execute over unencrypted UDP port 53. Because UDP is stateless and unauthenticated, in-path middleboxes can intercept UDP/53 "
        "packets using Destination Network Address Translation (DNAT) and redirect queries to local resolvers without client consent [4]. "
        "To mitigate eavesdropping and tampering, modern standards define DNS over TLS (DoT, RFC 7858 [6]) and DNS over HTTPS (DoH, RFC 8484 [7]), "
        "which encapsulate queries inside authenticated TLS sessions on port 443, bypassing middlebox UDP inspection.",
    )
    add_academic_paragraph(
        doc,
        "In addition, RFC 5737 [5] reserves three IPv4 documentation address blocks (192.0.2.0/24 TEST-NET-1, 198.51.100.0/24 TEST-NET-2, "
        "and 203.0.113.0/24 TEST-NET-3) that are strictly unroutable on the global Internet. If a client transmits a UDP/53 query to an RFC 5737 "
        "destination and receives a response, it represents incontrovertible proof that a middlebox intercepted and answered the packet in flight.",
    )

    add_custom_heading(doc, "3.4 Linux Kernel Network Virtualization Primitives", level=2)
    add_academic_paragraph(
        doc,
        "To provide a realistic testing cyber-range without requiring physical hardware, netpolicy leverages Linux kernel virtualization:",
        bold_prefix="Kernel Virtualization Primitives: ",
    )
    add_bullet_item(
        doc,
        "Network namespaces, documented in ip-netns(8) [9], provide complete virtualization of the network stack. Each namespace possesses "
        "an independent set of network interfaces, routing tables, ARP caches, and iptables firewall rules. Processes assigned to a namespace "
        "execute inside an isolated virtual network environment.",
        bold_prefix="Linux Network Namespaces (netns): ",
    )
    add_bullet_item(
        doc,
        "Virtual Ethernet devices operate in interconnected pairs as bidirectional virtual cables. Packets transmitted into one endpoint "
        "immediately emerge from the peer endpoint. Placing each peer directly into distinct namespaces links them across an isolated virtual topology.",
        bold_prefix="Virtual Ethernet Pairs (veth): ",
    )
    add_bullet_item(
        doc,
        "The Linux kernel packet filtering framework, documented in iptables-extensions(8) [10], provides rule-based packet manipulation. "
        "Specific targets include DROP (silent discard), REJECT with --reject-with tcp-reset (TCP RST injection), REJECT with "
        "--reject-with icmp-admin-prohibited (ICMP Code 13), and DNAT in the nat table PREROUTING chain (transparent port redirection).",
        bold_prefix="iptables Subsystem: ",
    )

    # ==========================================================================
    # SECTION 7: SOLUTION AND ARCHITECTURE
    # ==========================================================================
    add_custom_heading(doc, "4. Solution and Architecture", level=1)
    add_academic_paragraph(
        doc,
        "netpolicy is architected around strict separation of concerns, ensuring that measurement, data persistence, deterministic "
        "classification, and report generation operate as isolated subsystems.",
    )

    add_custom_heading(doc, "4.1 Probe and Classifier Decoupling", level=2)
    add_academic_paragraph(
        doc,
        "A foundational design rule of netpolicy is that active probes perform pure measurement without interpreting policy intent. "
        "A probe records raw telemetry (such as packet flags, TTLs, elapsed RTT, or HTTP response headers) into an Observation object. "
        "Observation collections are then evaluated by pure, mathematical classification functions: "
        "Observations -> Verdict(Kind, Confidence, Evidence). Classifiers perform zero network I/O, ensuring that verdict determination "
        "is completely reproducible and testable offline.",
    )

    add_custom_heading(doc, "4.2 Control-Probe Baseline and Multi-Run Sampling", level=2)
    add_academic_paragraph(
        doc,
        "To prevent transient network instability from triggering false policy alarms, netpolicy enforces two safeguards:",
        bold_prefix="Verification Safeguards: ",
    )
    add_bullet_item(
        doc,
        "Every audit requires a designated control target (default: port 443). If the control probe fails, the entire network path or "
        "destination server is marked unhealthy. The system issues a CONTROL_FAILED verdict and suppresses all port-block conclusions.",
        bold_prefix="The Control Probe: ",
    )
    add_bullet_item(
        doc,
        "Checks execute across multiple iterations (default: 5 runs, configurable via --runs) with retries per check (default: 2 retries, "
        "configurable via --retries). A port is declared BLOCKED_DROP only when every retry times out across iterations while the control probe succeeds.",
        bold_prefix="Multi-Run Consensus: ",
    )

    add_custom_heading(doc, "4.3 Data-Flow Architecture", level=2)
    add_academic_paragraph(
        doc,
        "All raw observations are streamed immediately to an append-only JSON Lines (JSONL) file under reports/<run_id>.jsonl before "
        "classification passes occur. If an execution is interrupted, zero measurement data is lost. The pipeline aggregates observations "
        "by (probe_name, target), feeds them through domain classifiers, and generates a structured AuditReport.",
        bold_prefix="Telemetry Lifecycle: ",
    )

    add_code_block(
        doc,
        "+-----------------------------------------------------------------------------------+\n"
        "|                        NETPOLICY DATA-FLOW PIPELINE                               |\n"
        "+-----------------------------------------------------------------------------------+\n"
        "\n"
        "  [ Measurement Layer ]\n"
        "    * Control Probe (Port 443)  --> raw Observation (RTT, TTL, Flags)\n"
        "    * Outbound TCP Probes       --> raw Observation (SYN-ACK / RST / ICMP / Timeout)\n"
        "    * DNS UDP/53 & DoH Probes   --> raw Observation (RCode, Answers, Source IP)\n"
        "    * HTTP Canary Probes        --> raw Observation (Status, Headers, SHA-256, Nonce)\n"
        "                     |\n"
        "                     v  (Thread-Safe Immediate Flush)\n"
        "  [ Durable Telemetry Layer ]\n"
        "    * Append-Only JSONL Store (reports/<YYYYMMDD_HHMMSS>_<hex>.jsonl)\n"
        "                     |\n"
        "                     v  (Group by Probe & Target)\n"
        "  [ Inference & Aggregation Layer ]\n"
        "    * Pipeline Coordinator (engine/pipeline.py)\n"
        "    * Pure Classifiers (classify/tcp.py, classify/dns.py, classify/http.py)\n"
        "    * Rule-Based Findings Engine (findings.py)\n"
        "                     |\n"
        "                     v  (Assemble AuditReport Model)\n"
        "  [ Multi-Format Presentation Layer ]\n"
        "    * Rich Terminal Renderer (tables, badges, summary panel)\n"
        "    * Serialized JSON Output (--json / --output report.json)\n"
        "    * Standalone Markdown Report (--output report.md)\n",
    )

    add_custom_heading(doc, "4.4 Repository Module Architecture", level=2)
    module_rows = [
        (
            "netpolicy/cli.py",
            "Typer Command Line Interface",
            "Registers audit, ports, dns, http, compare, reclassify, lab commands.",
        ),
        (
            "netpolicy/config.py",
            "Pydantic Configuration Hierarchy",
            "Loads YAML configs, manages defaults, and handles CLI overrides.",
        ),
        (
            "netpolicy/models.py",
            "Core Domain Data Models",
            "Defines Target, Observation, Verdict, Finding, and AuditReport models.",
        ),
        (
            "netpolicy/findings.py",
            "Rule-Based Inference Engine",
            "Synthesizes multi-probe verdicts into info/warn/critical findings.",
        ),
        (
            "netpolicy/engine/context.py",
            "Environment Context Provider",
            "Discovers local IPs, gateways, resolvers, and computes SHA-256 fingerprint.",
        ),
        (
            "netpolicy/engine/runner.py",
            "Multithreaded Task Runner",
            "Dispatches probe jobs via ThreadPoolExecutor with timeout management.",
        ),
        (
            "netpolicy/engine/pipeline.py",
            "Data Aggregation Pipeline",
            "Groups raw observations, routes through classifiers, checks control health.",
        ),
        (
            "netpolicy/probes/base.py",
            "Abstract Probe Interface",
            "Defines probe execution, timing, and observation contracts.",
        ),
        (
            "netpolicy/probes/tcp_connect.py",
            "Socket TCP Probe",
            "Unprivileged outbound TCP reachability using OS socket connect().",
        ),
        (
            "netpolicy/probes/tcp_syn.py",
            "Raw Scapy TCP SYN Probe",
            "Privileged SYN packet crafting; detects SYN-ACK, RST, ICMP unreachable.",
        ),
        (
            "netpolicy/probes/dns.py",
            "DNS Probes Suite",
            "Implements Blackhole, Whoami, Nxdomain, DoH, and SourceMismatch probes.",
        ),
        (
            "netpolicy/probes/http.py",
            "HTTP Canary Probe",
            "Validates HTTP status, expected headers, payload hash, and echoed nonce.",
        ),
        (
            "netpolicy/classify/tcp.py",
            "TCP Pure Classifier",
            "Evaluates OPEN, BLOCKED_DROP, BLOCKED_RESET, BLOCKED_ICMP, LOSSY.",
        ),
        (
            "netpolicy/classify/dns.py",
            "DNS Pure Classifier",
            "Evaluates CLEAN, INTERCEPTED, REWRITTEN, MISMATCH.",
        ),
        (
            "netpolicy/classify/http.py",
            "HTTP Pure Classifier",
            "Evaluates CLEAN, HEADERS_INJECTED, BODY_MODIFIED, PROXIED, REDIRECTED.",
        ),
        (
            "netpolicy/store/raw.py",
            "Append-Only JSONL Store",
            "Persists raw telemetry immediately; manages sudo user ownership.",
        ),
        (
            "netpolicy/report/compare.py",
            "Report Diffing Engine",
            "Identifies verdict, reachability, and finding differences between two runs.",
        ),
        (
            "netpolicy/report/jsonout.py",
            "JSON Report Serializer",
            "Exports serialized AuditReport models; handles identifier redaction.",
        ),
        (
            "netpolicy/report/markdown.py",
            "Markdown Exporter",
            "Generates publication-ready Markdown reports with summary badges.",
        ),
        (
            "netpolicy/report/terminal.py",
            "Rich Terminal Renderer",
            "Formats stylized tables, confidence badges, and summary finding panels.",
        ),
    ]
    add_academic_table(
        doc,
        headers=["Module Path", "Subsystem Role", "Operational Responsibilities"],
        rows=module_rows,
        caption="Table 1: netpolicy Core Architecture and Module Responsibilities",
        col_widths=[1.8, 1.8, 3.2],
    )

    add_custom_heading(doc, "4.5 The Cyber-Range Laboratory Topology", level=2)
    add_academic_paragraph(
        doc,
        "To evaluate netpolicy against known ground truth, the framework provides an isolated, multi-node Linux network namespace lab "
        "(lab/setup.sh). The topology consists of three namespaces connected by virtual Ethernet pairs:",
        bold_prefix="Lab Network Topology: ",
    )

    add_code_block(
        doc,
        "+-----------------------------------------------------------------------------------+\n"
        "|                           NETPOLICY LAB NETWORK TOPOLOGY                          |\n"
        "+-----------------------------------------------------------------------------------+\n"
        "\n"
        " [ np-client Namespace ]               [ np-gw Namespace ]               [ np-server Namespace ]\n"
        " (Audit Probe Client)                  (Middlebox Gateway)               (Mock Target Server)\n"
        "\n"
        "   10.200.1.2/24                         10.200.1.1/24                     10.200.2.2/24\n"
        " +---------------+                     +---------------+                 +---------------+\n"
        " |  veth-client  | <=== veth pair 1 ==>|   veth-gw-c   |                 |  veth-server  |\n"
        " +---------------+                     +---------------+                 +---------------+\n"
        "         |                                     |                                 ^\n"
        "         | Default Route                       | IPv4 Forwarding = 1             | veth pair 2\n"
        "         v                                     | Blackholes: 192.0.2.0/24        |\n"
        "   via 10.200.1.1                              |             198.51.100.0/24     v\n"
        "                                               |                          +---------------+\n"
        "                                               | 10.200.2.1/24            |   veth-gw-s   |\n"
        "                                               +------------------------> +---------------+\n"
        "                                                                                 |\n"
        "                                                                                 | Default Route\n"
        "                                                                                 v\n"
        "                                                                           via 10.200.2.1\n"
        "\n"
        " Subnet: 10.200.1.0/24 (Client Subnet)                           Subnet: 10.200.2.0/24 (Server Subnet)\n",
    )

    add_custom_heading(doc, "4.6 Middlebox Scenarios Catalogue", level=2)
    scenarios_data = [
        (
            "clean",
            "All tables flushed; policy FORWARD ACCEPT",
            "np-gw",
            "All ports OPEN",
            "CLEAN",
            "CLEAN",
        ),
        (
            "drop-smtp",
            "iptables -A FORWARD -p tcp --dport 25 -j DROP",
            "np-gw",
            "Port 25 BLOCKED_DROP; others OPEN",
            "CLEAN",
            "CLEAN",
        ),
        (
            "reset-smtp",
            "iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with tcp-reset",
            "np-gw",
            "Port 25 BLOCKED_RESET; others OPEN",
            "CLEAN",
            "CLEAN",
        ),
        (
            "icmp-admin",
            "iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-admin-prohibited",
            "np-gw",
            "Port 25 BLOCKED_ICMP (code 13)",
            "CLEAN",
            "CLEAN",
        ),
        (
            "icmp-port-unreach",
            "iptables -A FORWARD -p tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable",
            "np-gw",
            "Port 25 BLOCKED_ICMP (code 3)",
            "CLEAN",
            "CLEAN",
        ),
        (
            "dns-dnat",
            "iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53",
            "np-gw",
            "All ports OPEN",
            "INTERCEPTED",
            "CLEAN",
        ),
        (
            "nxdomain-rewrite",
            "dns_server.py restarted in np-server with --rewrite flag",
            "np-server",
            "All ports OPEN",
            "REWRITTEN",
            "CLEAN",
        ),
        (
            "http-proxy",
            "Tamper proxy on 8080; iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT ...",
            "np-gw",
            "All ports OPEN",
            "CLEAN",
            "HEADERS_INJECTED",
        ),
        (
            "campus",
            "Composite: reset-smtp + dns-dnat + http-proxy",
            "np-gw",
            "Port 25 BLOCKED_RESET; others OPEN",
            "INTERCEPTED",
            "HEADERS_INJECTED",
        ),
    ]
    add_academic_table(
        doc,
        headers=[
            "Scenario",
            "Mechanism / Rule Applied",
            "Target NS",
            "Expected Ports",
            "Expected DNS",
            "Expected HTTP",
        ],
        rows=scenarios_data,
        caption="Table 2: Middlebox Policy Scenarios and Ground-Truth Verdict Expectations",
        col_widths=[1.1, 2.2, 0.8, 1.3, 0.9, 0.9],
    )

    add_custom_heading(doc, "4.7 Safety Design and Static Analysis Verification", level=2)
    add_academic_paragraph(
        doc,
        "Because laboratory middlebox rules manipulate firewall tables and traffic control queues, netpolicy enforces strict safety "
        "constraints: zero commands are permitted to execute in the host namespace, veth endpoints are placed directly into namespaces "
        "upon instantiation, and scripts never call sudo internally. To statically enforce these constraints, netpolicy includes a dedicated "
        "static safety linter (tests/test_lab_safety.py) that parses shell scripts and Python source files, verifying that all network mutations "
        "are strictly encapsulated within namespaces prefixed with np-.",
    )

    # ==========================================================================
    # SECTION 8: METHODOLOGY AND VALIDATION
    # ==========================================================================
    add_custom_heading(doc, "5. Methodology and Validation", level=1)
    add_academic_paragraph(
        doc,
        "The validation protocol follows a formal ground-truth evaluation methodology. By comparing netpolicy's automated verdict "
        "classifications against known, programmatic middlebox rules inside the cyber-range, the framework's precision, recall, and false-positive "
        "resistance are quantified under both clean and degraded channel conditions.",
    )

    add_custom_heading(doc, "5.1 Validation Protocol and Quality Gates", level=2)
    add_academic_paragraph(
        doc,
        "The automated validation harness (lab/validate.py) executes $N$ independent audit runs (default: 30 runs per scenario) inside "
        "np-client targeting mock listeners on np-server (10.200.2.2). The harness compares emitted verdicts against expectations in "
        "lab/scenarios.yaml across ports, DNS, and HTTP subsystems.",
        bold_prefix="Automated Evaluation: ",
    )
    add_academic_paragraph(
        doc,
        "Two mandatory quality gates govern validation acceptance:",
        bold_prefix="Acceptance Gates: ",
    )
    add_bullet_item(
        doc,
        "On the unfiltered clean scenario, the false-positive rate must remain exactly 0.0%. Any single unblocked port classified as "
        "blocked, or any authentic DNS/HTTP query classified as tampered, fails the validation suite.",
        bold_prefix="Zero False-Positive Rate (FPR = 0.0%): ",
    )
    add_bullet_item(
        doc,
        "Under baseline channel conditions, classification accuracy across all checks must meet or exceed 95.0%.",
        bold_prefix="Accuracy Threshold (Accuracy >= 95.0%): ",
    )

    add_custom_heading(doc, "5.2 Empirical Lab Artifacts and Validation Data", level=2)
    add_academic_paragraph(
        doc,
        "In strict accordance with the repository-only ground truth policy, experimental validation numbers are quoted exclusively from "
        "verified artifacts present in the repository:",
        bold_prefix="Repository Artifact Status: ",
    )
    add_bullet_item(
        doc,
        "results/validation.csv is not present in the current repository checkout. In accordance with project reporting rules, "
        "statistical multi-run CSV data is designated as: 'results to be inserted after running validate.py'.",
        bold_prefix="Validation Dataset (CSV): ",
    )
    add_bullet_item(
        doc,
        "demo-output/baseline.json confirms 100% agreement across 2/2 audit runs on the clean network, with ports 21, 22, 25, 80, 443, "
        "and 587 classified as OPEN with HIGH confidence, and an empty findings list (zero false positives).",
        bold_prefix="Verified Baseline Telemetry: ",
    )
    add_bullet_item(
        doc,
        "demo-output/tampered.json confirms that applying the reset-smtp scenario immediately produced a CLOSED_OR_RESET verdict on port 25 "
        "and generated the policy finding: 'Direct SMTP (Port 25) Blocked' (Summary: Direct SMTP port 25 is blocked; submission ports 465/587 remain accessible).",
        bold_prefix="Verified Tampered Telemetry: ",
    )

    # Embed figures if present on disk
    accuracy_img = repo_root / "results" / "accuracy.png"
    confusion_img = repo_root / "results" / "confusion.png"

    has_acc = add_figure_if_exists(
        doc,
        accuracy_img,
        caption="Figure 1: Classification Accuracy Across Middlebox Scenarios (Generated from lab/validate.py)",
    )
    if not has_acc:
        add_academic_paragraph(
            doc,
            "[Figure 1: results/accuracy.png not found on disk; placeholder for accuracy bar chart.]",
        )

    has_conf = add_figure_if_exists(
        doc,
        confusion_img,
        caption="Figure 2: Confusion Matrix Heatmap Across Port, DNS, and HTTP Classifications (Generated from lab/validate.py)",
    )
    if not has_conf:
        add_academic_paragraph(
            doc,
            "[Figure 2: results/confusion.png not found on disk; placeholder for confusion matrix heatmap.]",
        )

    # ==========================================================================
    # SECTION 9: DEVELOPMENT JOURNEY & CHALLENGES
    # ==========================================================================
    add_custom_heading(doc, "6. Development Journey & Portability Challenges", level=1)
    add_academic_paragraph(
        doc,
        "The implementation of netpolicy proceeded across four distinct architectural phases:",
        bold_prefix="Development Timeline: ",
    )
    add_numbered_item(
        doc,
        "Implementation of core CLI command parsers, Typer application structure, and Pydantic configuration schemas.",
        bold_prefix="Phase 1 (Front-End & Schema Architecture): ",
    )
    add_numbered_item(
        doc,
        "Development of active measurement workers across Scapy raw SYN sockets, unprivileged OS connect sockets, dnspython resolvers, and HTTPX canary clients.",
        bold_prefix="Phase 2 (Probing Layer): ",
    )
    add_numbered_item(
        doc,
        "Construction of pure, stateless classifier modules (tcp.py, dns.py, http.py) and rule-based findings synthesis in findings.py.",
        bold_prefix="Phase 3 (Deterministic Classification & Telemetry): ",
    )
    add_numbered_item(
        doc,
        "Engineering of the network namespace cyber-range (setup.sh, services.sh, scenario.sh) and automated ground-truth validation (validate.py).",
        bold_prefix="Phase 4 (Cyber-Range Lab & Statistical Validation): ",
    )

    add_custom_heading(doc, "6.1 Portability Challenges and Verified Root Causes", level=2)
    add_academic_paragraph(
        doc,
        "Cross-platform execution on Windows 11, WSL2 Kali Linux, and native Linux revealed eight concrete technical challenges. "
        "Each challenge was investigated directly within the codebase and permanently resolved:",
        bold_prefix="Empirical Challenges: ",
    )

    challenges = [
        (
            "1. ip netns in PowerShell",
            "Executing lab scripts in Windows PowerShell failed with command-not-found errors.",
            "Linux network namespaces and iproute2 are native Linux kernel primitives absent from the Windows NT kernel.",
            "Configured a WSL2 Linux environment (such as Kali Linux via 'wsl --install -d kali-linux'), maintaining the repo in ~/netpolicy. Prevented by scripts/doctor.sh.",
        ),
        (
            "2. Missing Tools on Fresh Distros",
            "Clean Debian/Ubuntu/Kali distributions failed executing scripts due to missing ip, iptables, tc, or ping.",
            "Minimal container and WSL base images intentionally omit networking utilities to reduce disk footprint.",
            "Automated system dependency provisioning (python3, iproute2, iptables, curl, iputils-ping, psmisc, procps) via scripts/bootstrap-system.sh.",
        ),
        (
            "3. Broken pip in python3-venv",
            "Creating a virtual environment succeeded, but pip crashed with 'ModuleNotFoundError: No module named pip._internal.utils'.",
            "Upstream packaging discrepancy between python3-venv and python3-pip in Debian/Kali. The exact underlying cause was not established.",
            "Automated venv creation with --without-pip, followed by bootstrapping official get-pip.py via scripts/bootstrap-python.sh.",
        ),
        (
            "4. No module named netpolicy.__main__",
            "Invoking 'python -m netpolicy' failed with 'No module named netpolicy.__main__'.",
            "'No module named netpolicy' means the package is absent from sys.path. 'No module named netpolicy.__main__' proves the package was found, but lacked the mandatory __main__.py file required for -m execution.",
            "Added netpolicy/__main__.py importing app from netpolicy.cli, and installed package in editable mode via 'pip install -e .[lab]'.",
        ),
        (
            "5. Apparent Terminal Freeze",
            "Starting background service listeners with '&' caused interactive terminal sessions to appear unresponsive.",
            "Normal shell job control behavior when unredirected processes share standard output and input streams with an active TTY.",
            "Refactored lab/services.sh to detach daemons using nohup, redirect output to lab/run/*.log, track PIDs in lab/run/pids, and display status with lab/status.sh.",
        ),
        (
            "6. Telemetry Format Incompatibility",
            "Running netpolicy compare failed because audit generates raw .jsonl telemetry, whereas compare required classified .json.",
            "Discrepancy between raw stream storage and pre-classified report schemas.",
            "Updated compare in netpolicy/cli.py to natively accept both .json and raw .jsonl files (automatically reclassifying .jsonl on the fly).",
        ),
        (
            "7. Non-Stacking Scenario Execution",
            "Applying multiple scenarios consecutively did not combine firewall rules.",
            "lab/scenario.sh is designed to be strictly exclusive, flushing all iptables rules before applying a scenario to preserve clean validation baselines.",
            "Added a startup exclusivity notice, a --list flag, and implemented the composite 'campus' scenario for simultaneous multi-policy testing.",
        ),
        (
            "8. Missing Validation Packages",
            "lab/validate.py crashed with ModuleNotFoundError for matplotlib and pandas. In some tests, rich and pyyaml were also missing.",
            "Plotting libraries are optional for CLI use. Missing rich and pyyaml indicated that the package had not been installed into that venv.",
            "Created the '.[lab]' optional dependency group in pyproject.toml, added a pre-flight dependency check in validate.py, and automated install in bootstrap-python.sh.",
        ),
    ]

    for item in challenges:
        add_academic_paragraph(doc, item[1], bold_prefix=f"{item[0]} — Symptom: ")
        add_academic_paragraph(doc, item[2], italic_prefix="Root Cause: ")
        add_academic_paragraph(doc, item[3], italic_prefix="Resolution: ")

    add_custom_heading(doc, "6.2 Portability Tooling Suite", level=2)
    add_academic_paragraph(
        doc,
        "To guarantee that a new developer can verify the entire framework with zero manual troubleshooting, four automation files were added:",
        bold_prefix="Final Portability Suite: ",
    )
    add_bullet_item(
        doc,
        "Root-only script automating system package installation across apt, dnf, and pacman.",
        bold_prefix="scripts/bootstrap-system.sh: ",
    )
    add_bullet_item(
        doc,
        "User-owned virtualenv manager creating .linux-venv, bootstrapping get-pip.py, and installing .[lab].",
        bold_prefix="scripts/bootstrap-python.sh: ",
    )
    add_bullet_item(
        doc,
        "Environment diagnostic scanner verifying OS, Python >= 3.10, tools, and executing throwaway namespace self-tests.",
        bold_prefix="scripts/doctor.sh: ",
    )
    add_bullet_item(
        doc,
        "Single-command end-to-end demo running doctor, lab setup, baseline audit, scenario tampering, and report comparison.",
        bold_prefix="scripts/demo.sh: ",
    )
    add_bullet_item(
        doc,
        "Standardized developer automation providing targets for setup, doctor, lab-up, lab-down, demo, test, and lint.",
        bold_prefix="Makefile: ",
    )

    # ==========================================================================
    # SECTION 10: TECHNOLOGY STACK
    # ==========================================================================
    add_custom_heading(doc, "7. Technology Stack", level=1)
    add_academic_paragraph(
        doc,
        "The technologies comprising netpolicy were selected to satisfy strict constraints: deterministic execution, minimal runtime "
        "overhead, zero reliance on external cloud services, and reproducible Linux kernel isolation.",
    )
    tech_stack_data = [
        (
            "Implementation Language",
            "Python 3.10+",
            "Core CLI application, probe engine, and classifiers.",
            "netpolicy/",
        ),
        (
            "CLI Framework",
            "Typer >= 0.12.0",
            "Command-line parsing, subcommands, and flag generation.",
            "netpolicy/cli.py",
        ),
        (
            "Terminal Rendering",
            "Rich >= 13.0.0",
            "ANSI styling, colored status tables, and progress bars.",
            "netpolicy/report/terminal.py",
        ),
        (
            "Packet Crafting",
            "Scapy >= 2.5.0",
            "Raw TCP SYN packet synthesis, sniffing, and ICMP decoding.",
            "netpolicy/probes/tcp_syn.py",
        ),
        (
            "DNS Protocol",
            "dnspython >= 2.6.0 [doh]",
            "Wire-format DNS encoding/decoding, UDP/53, and DoH queries.",
            "netpolicy/probes/dns.py",
        ),
        (
            "HTTP Client",
            "HTTPX >= 0.27.0",
            "Asynchronous and synchronous HTTP/1.1 and HTTP/2 canary queries.",
            "netpolicy/probes/http.py",
        ),
        (
            "Configuration",
            "PyYAML >= 6.0",
            "Parsing application configuration and scenario specifications.",
            "netpolicy/config.py",
        ),
        (
            "Schema Validation",
            "Pydantic >= 2.0.0",
            "Data model serialization, validation, and immutability.",
            "netpolicy/models.py",
        ),
        (
            "Test Harness",
            "pytest >= 8.0.0",
            "Unit testing and static safety rule enforcement.",
            "tests/",
        ),
        (
            "Linter & Formatter",
            "Ruff >= 0.4.0",
            "High-performance Python linting and code formatting.",
            "pyproject.toml",
        ),
        (
            "Static Type Checker",
            "Mypy >= 1.10.0",
            "Strict static type validation across all modules.",
            "pyproject.toml",
        ),
        (
            "Data & Plotting",
            "Matplotlib & Pandas",
            "Confusion matrix heatmaps, accuracy plots, and CSV exports.",
            "lab/validate.py",
        ),
        (
            "Document Generation",
            "python-docx 1.2.0",
            "Automated academic project report generation.",
            "scripts/generate_report_docx.py",
        ),
        (
            "Network Virtualization",
            "Linux Namespaces (netns)",
            "Virtual network stack isolation (np-client, np-gw, np-server).",
            "lab/setup.sh",
        ),
        (
            "Virtual Links",
            "Virtual Ethernet (veth)",
            "Bidirectional point-to-point links between namespaces.",
            "lab/setup.sh",
        ),
        (
            "Firewall Subsystem",
            "iptables (nft / legacy)",
            "Egress filtering, packet drops, TCP resets, and DNAT.",
            "lab/scenario.sh",
        ),
        (
            "Traffic Control",
            "tc netem",
            "Kernel-level packet loss and latency injection sweeps.",
            "lab/validate.py",
        ),
        (
            "Virtualization Layer",
            "WSL2 / Kali Linux",
            "Linux kernel virtualization on Windows 11 host.",
            "Environment",
        ),
        (
            "AI Coding Assistant",
            "Google Antigravity / Gemini CLI",
            "Assisted in code generation, testing, and documentation.",
            "Development",
        ),
    ]
    add_academic_table(
        doc,
        headers=[
            "Subsystem / Role",
            "Technology & Version",
            "Purpose in Architecture",
            "Repository Context",
        ],
        rows=tech_stack_data,
        caption="Table 3: Comprehensive Technology Stack and Dependency Specifications",
        col_widths=[1.5, 1.8, 2.5, 1.2],
    )

    # ==========================================================================
    # SECTION 11: LIMITATIONS AND THREATS TO VALIDITY
    # ==========================================================================
    add_custom_heading(doc, "8. Limitations and Threats to Validity", level=1)
    add_academic_paragraph(
        doc,
        "A rigorous engineering evaluation requires candid acknowledgment of architectural assumptions and limitations:",
        bold_prefix="Methodological Boundaries: ",
    )
    add_numbered_item(
        doc,
        "The laboratory cyber-range validates classifiers against software Linux network implementations (iptables, nftables, and Python proxies). "
        "Commercial enterprise middleboxes (such as Palo Alto Networks, Fortinet, or Cisco ASA appliances) perform deep packet inspection, "
        "stateful TCP stream reassembly, and active Layer 7 protocol validation. Real-world middlebox behaviors may exhibit protocol nuances "
        "not replicated by standard packet-filtering rules.",
        bold_prefix="Emulated vs Commercial Hardware Middleboxes: ",
    )
    add_numbered_item(
        doc,
        "When an audit targets a destination port that the user does not own or control, receiving a TCP RST packet is fundamentally "
        "ambiguous: without ground-truth knowledge of the target server, an authentic closed port and an in-path middlebox reset look "
        "identical. netpolicy conservatively classifies such events as CLOSED_OR_RESET with LOW confidence.",
        bold_prefix="Ambiguity of TCP Resets on Uncontrolled Ports: ",
    )
    add_numbered_item(
        doc,
        "Differentiating silent packet drops from transient network congestion relies on control probe responsiveness. Under conditions "
        "of severe path-wide packet loss, conclusions are marked LOSSY rather than definitive blocks.",
        bold_prefix="Heuristic Reliance on Control Probe Health: ",
    )
    add_numbered_item(
        doc,
        "When running audits against external Internet targets from a Windows Subsystem for Linux (WSL2) environment, packets traverse a "
        "virtual Hyper-V NAT switch. The Windows networking stack and Windows Defender Firewall may inspect, alter TTLs, or intercept raw "
        "TCP packets. Authoritative real-world audits require native Linux.",
        bold_prefix="WSL2 Virtual NAT Boundary Effects: ",
    )
    add_numbered_item(
        doc,
        "The cyber-range operates entirely on a single host machine via network namespaces. While this eliminates hardware overhead and "
        "guarantees zero host pollution, it does not introduce physical hardware transmission phenomena such as asymmetric routing or physical MTU fragmentation.",
        bold_prefix="Single-Machine Namespace Simulation: ",
    )

    # ==========================================================================
    # SECTION 12: ETHICS AND LEGAL CONSIDERATIONS
    # ==========================================================================
    add_custom_heading(doc, "9. Ethics and Legal Considerations", level=1)
    add_academic_paragraph(
        doc,
        "Active network probing can trigger intrusion detection systems (IDS) or violate Computer Fraud and Abuse policies if conducted "
        "without authorization. netpolicy incorporates strict ethical safeguards into its architecture:",
        bold_prefix="Ethical Design Safeguards: ",
    )
    add_bullet_item(
        doc,
        "netpolicy is strictly an audit tool, not a port scanner. It probes only explicitly designated ports and target hosts designated "
        "by the user via CLI flags or configuration files. It performs zero subnet sweeps, zero network CIDR discovery, and zero port range scans.",
        bold_prefix="Strict Authorization Scope: ",
    )
    add_bullet_item(
        doc,
        "All probes are rate-limited and multi-run iterations introduce inter-probe delays, preventing denial-of-service conditions on target servers.",
        bold_prefix="Rate-Limiting and Transmission Throttling: ",
    )
    add_bullet_item(
        doc,
        "Audit reports scrub client public IP addresses, MAC addresses, and network SSIDs by default. A privacy-preserving cryptographic "
        "SHA-256 fingerprint (fp:...) derived from the gateway and resolver IPs is generated for correlation without leaking identity.",
        bold_prefix="Privacy Preservation by Default: ",
    )

    # ==========================================================================
    # SECTION 13: FUTURE WORK
    # ==========================================================================
    add_custom_heading(doc, "10. Future Work", level=1)
    add_academic_paragraph(
        doc,
        "Derived from codebase analysis and experimental observations, the author proposes the following extensions:",
        bold_prefix="Proposed Technical Enhancements: ",
    )
    add_numbered_item(
        doc,
        "Extend the probing engine to evaluate IPv6 reachability, Hop-by-Hop extension header drops, and ICMPv6 Type 1 (Destination Unreachable) "
        "Code 1 (Communication with destination administratively prohibited) middlebox behavior.",
        bold_prefix="IPv6 Dual-Stack and Extension Header Auditing: ",
    )
    add_numbered_item(
        doc,
        "Incorporate an automated TLS certificate chain validator that queries a known control HTTPS endpoint, asserting that intermediate "
        "root Certificate Authorities (CAs) have not been injected by enterprise SSL inspection proxies.",
        bold_prefix="Automated TLS Certificate Chain Inspection: ",
    )
    add_numbered_item(
        doc,
        "Extend the probe runner to construct HTTP/3 (QUIC over UDP/443) probes to audit whether networks silently block or throttle "
        "emerging transport protocols while permitting legacy TCP HTTPS.",
        bold_prefix="QUIC and HTTP/3 Reachability Probing: ",
    )
    add_numbered_item(
        doc,
        "Implement interactive web dashboard export functionality to visualize temporal policy stability across multi-day continuous network auditing.",
        bold_prefix="Longitudinal Policy Tracking: ",
    )

    # ==========================================================================
    # SECTION 14: CONCLUSION
    # ==========================================================================
    add_custom_heading(doc, "11. Conclusion", level=1)
    add_academic_paragraph(
        doc,
        "This project successfully designed, implemented, and validated netpolicy, a deterministic network policy and middlebox auditor "
        "supported by a Linux network namespace cyber-range. By strictly decoupling measurement workers from pure mathematical classifiers, "
        "verifying reachability through a control probe, and enforcing multi-run consensus, netpolicy eliminates the false-positive alarms "
        "common to existing diagnostic utilities. The accompanying cyber-range laboratory proves that complex middlebox behaviors—including "
        "silent drops, TCP reset injection, ICMP administrative prohibitions, transparent DNS DNAT, and HTTP proxy tampering—can be rigorously "
        "evaluated and validated in an isolated, multi-node virtual topology with zero host mutation. netpolicy delivers a powerful, "
        "transparent diagnostic tool for computer science students, researchers, and network engineers operating in increasingly restrictive "
        "network environments.",
    )

    # ==========================================================================
    # SECTION 15: REFERENCES
    # ==========================================================================
    add_custom_heading(doc, "12. References", level=1)
    references = [
        (
            "1",
            "Eddy, W. (2022). Transmission Control Protocol (TCP). RFC 9293, Internet Engineering Task Force (IETF).",
        ),
        (
            "2",
            "Postel, J. (1981). Internet Control Message Protocol (ICMP). RFC 792, Internet Engineering Task Force (IETF).",
        ),
        (
            "3",
            "Mockapetris, P. (1987). Domain Names - Implementation and Specification. RFC 1035, Internet Engineering Task Force (IETF).",
        ),
        (
            "4",
            "Larson, M., & Barber, P. (2006). Observed DNS Resolution Misbehavior. RFC 4697, Internet Engineering Task Force (IETF).",
        ),
        (
            "5",
            "Cotton, M., Vegoda, L., & Meyer, D. (2010). IPv4 Address Blocks Reserved for Documentation. RFC 5737, Internet Engineering Task Force (IETF).",
        ),
        (
            "6",
            "Hu, Z., Zhu, L., Heidemann, J., Mankin, A., Wessels, D., & Hoffman, P. (2016). Specification for DNS over Transport Layer Security (TLS). RFC 7858, Internet Engineering Task Force (IETF).",
        ),
        (
            "7",
            "Hoffman, P., & McManus, P. (2018). DNS Queries over HTTPS (DoH). RFC 8484, Internet Engineering Task Force (IETF).",
        ),
        (
            "8",
            "Lyon, G. F. (2009). Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning. Insecure.Com LLC.",
        ),
        (
            "9",
            "ip-netns(8) - Linux man page. Process network namespace management. iproute2 Linux networking utilities.",
        ),
        (
            "10",
            "iptables-extensions(8) - Linux man page. Target and match extensions for iptables/ip6tables. Netfilter project.",
        ),
    ]
    for num, citation in references:
        add_academic_paragraph(doc, citation, bold_prefix=f"[{num}] ")

    # ==========================================================================
    # SECTION 16: APPENDICES
    # ==========================================================================
    add_custom_heading(doc, "Appendix A: CLI Command Reference", level=1)
    add_academic_paragraph(
        doc,
        "The following commands represent the verified command-line interface of netpolicy, extracted directly from CLI --help specifications:",
        bold_prefix="Verified CLI Operations: ",
    )

    add_code_block(
        doc,
        "# 1. Execute Full Network Policy Audit (ports + DNS + HTTP)\n"
        "netpolicy audit --target 10.200.2.2 --ports 21,22,25,80,443,587 --runs 5\n"
        "\n"
        "# 2. Execute Outbound Port Reachability Audit\n"
        "netpolicy ports --target 10.200.2.2 --ports 21,22,25,80,443,587 --runs 5\n"
        "\n"
        "# 3. Execute DNS Interception and Tampering Audit\n"
        "netpolicy dns --target 10.200.2.2 --runs 3\n"
        "\n"
        "# 4. Execute HTTP Canary Tampering Audit\n"
        "netpolicy http --target 10.200.2.2 --ports 80 --runs 3\n"
        "\n"
        "# 5. Compare Baseline and Tampered Audit Reports\n"
        "netpolicy compare baseline.json tampered.json\n"
        "\n"
        "# 6. Reclassify Persisted Raw Telemetry Offline\n"
        "netpolicy reclassify reports/20261113_140000_a1b2c3d4.jsonl\n",
    )

    add_custom_heading(doc, "Appendix B: Repository File Tree Structure", level=1)
    add_code_block(
        doc,
        "netpolicy/\n"
        "├── canary/\n"
        "│   ├── server.py              # Standalone HTTP canary server (port 80)\n"
        "│   └── tamper_proxy.py        # Re-export shim for test reverse proxy\n"
        "├── demo-output/\n"
        "│   ├── baseline.json          # Verified clean network audit report (exit 0)\n"
        "│   └── tampered.json          # Verified reset-smtp middlebox audit report (exit 1)\n"
        "├── docs/\n"
        "│   ├── internal/\n"
        "│   │   └── project_facts.md   # Ground-truth verified project technical facts\n"
        "│   ├── METHOD.md              # Experimental methodology and field test plan\n"
        "│   ├── netpolicy_master_guide.md # Comprehensive 7-section pedagogical master guide\n"
        "│   ├── PORTABILITY.md         # Final changes and cross-platform portability report\n"
        "│   └── report_notes.md        # Technical fact sheet for academic report\n"
        "├── lab/\n"
        "│   ├── banner_servers.py      # TCP mock daemon for ports 21, 22, 25, 443, 587\n"
        "│   ├── dns_server.py          # dnspython UDP DNS responder (port 53)\n"
        "│   ├── README.md              # Cyber-range lab network documentation\n"
        "│   ├── scenario.sh            # Exclusive middlebox scenario manager (np-gw)\n"
        "│   ├── scenarios.yaml         # Ground-truth scenario specifications and verdicts\n"
        "│   ├── services.sh            # Idempotent detached mock service manager (np-server)\n"
        "│   ├── setup.sh               # 3-node namespace lab provisioner (np-client, gw, server)\n"
        "│   ├── status.sh              # Read-only operational state inspector\n"
        "│   ├── teardown.sh            # Safe cleanup script removing only np-* namespaces\n"
        "│   └── validate.py            # Automated statistical ground-truth validation runner\n"
        "├── netpolicy/\n"
        "│   ├── canary/                # Canary re-export module namespace\n"
        "│   ├── classify/              # Pure mathematical verdict classifiers (tcp, dns, http)\n"
        "│   ├── engine/                # Context provider, runner, and aggregation pipeline\n"
        "│   ├── probes/                # Active measurement probes (TCP SYN/connect, DNS, HTTP)\n"
        "│   ├── report/                # Visual Rich terminal, JSON, Markdown, and compare diff\n"
        "│   ├── store/                 # Thread-safe append-only raw JSONL telemetry persistence\n"
        "│   ├── cli.py                 # Typer command-line application registering 7 subcommands\n"
        "│   ├── config.py              # Pydantic configuration hierarchy\n"
        "│   ├── demo.py                # Synthetic mock report generator\n"
        "│   ├── findings.py            # Rule-based policy inference engine\n"
        "│   ├── models.py              # Core Pydantic domain models\n"
        "│   ├── __init__.py            # Package root; exports __version__ = '0.1.0'\n"
        "│   └── __main__.py            # CLI module entrypoint for python -m netpolicy\n"
        "├── results/\n"
        "│   ├── accuracy.png           # Classifier accuracy bar chart across scenarios\n"
        "│   └── confusion.png          # Confusion matrix heatmap across check domains\n"
        "├── scripts/\n"
        "│   ├── bootstrap-python.sh    # Non-root user virtualenv bootstrap (.linux-venv)\n"
        "│   ├── bootstrap-system.sh    # Root package installer across apt/dnf/pacman\n"
        "│   ├── check_docs.py          # Static CLI documentation consistency checker\n"
        "│   ├── demo.sh                # End-to-end automated demo script with exit code assertions\n"
        "│   ├── doctor.sh              # Comprehensive environment and kernel diagnostics\n"
        "│   ├── export-docs.sh         # Unprivileged documentation exporter to Windows Downloads\n"
        "│   └── generate_report.py     # Academic Word project report generator\n"
        "├── tests/                     # 202 passing unit, functional, and safety tests\n"
        "├── .gitattributes             # Enforces LF line endings across *.sh, *.py, *.yaml, *.md\n"
        "├── CHANGELOG.md               # Version 0.1.0 release notes and feature log\n"
        "├── GEMINI.md                  # Project constitution, architecture, and safety rules\n"
        "├── Makefile                   # 10 phony developer automation targets\n"
        "└── pyproject.toml             # Project metadata, dependencies, and [lab] extra\n",
    )

    # Save Document
    doc.save(str(output_path))


def main() -> int:
    """Saves document locally first, copies to Windows Downloads, and prints final path."""
    import shutil

    repo_root = Path(__file__).resolve().parent.parent
    local_filename = "netpolicy_report.docx"
    local_path = repo_root / local_filename

    print("=== Netpolicy Academic Project Report Generator ===")
    print(f"[*] Repository root: {repo_root}")
    print(f"[*] Step 1: Generating document locally as ./{local_filename}")

    try:
        build_project_report(local_path, repo_root)
        print(f"[OK] Local document successfully built: {local_path}")
        print(f"     Size: {local_path.stat().st_size:,} bytes")
    except Exception as exc:
        print(f"[ERROR] Failed to build document: {exc}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1

    # Step 2: Copy to Windows Downloads without drvfs/9P corruption
    print("[*] Step 2: Transferring to Windows Downloads folder")
    final_win_path = ""

    if sys.platform != "win32":
        # Linux / WSL environment: execute exact required subprocess command
        cp_cmd = (
            "cp ./netpolicy_report.docx "
            "\"$(wslpath \"$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\\r')\")/Downloads/\""
        )
        print(f"[*] Executing WSL copy command:\n    {cp_cmd}")
        try:
            subprocess.run(["bash", "-c", cp_cmd], cwd=str(repo_root), check=True)
            # Resolve Windows path using cmd.exe
            proc = subprocess.run(
                ["cmd.exe", "/c", "echo %USERPROFILE%\\Downloads\\netpolicy_report.docx"],
                capture_output=True,
                text=True,
                check=True,
            )
            final_win_path = proc.stdout.strip().replace("\r", "")
            print("[OK] Subprocess copy completed successfully.")
        except Exception as exc:
            print(f"[!] Warning: WSL subprocess copy encountered error: {exc}", file=sys.stderr)
            downloads_dir = resolve_downloads_directory()
            dest_file = downloads_dir / local_filename
            shutil.copyfile(str(local_path), str(dest_file))
            final_win_path = str(dest_file)
    else:
        # Native Windows environment
        user_profile = os.environ.get("USERPROFILE")
        if user_profile and Path(user_profile).exists():
            downloads_dir = Path(user_profile) / "Downloads"
        else:
            downloads_dir = Path.home() / "Downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        dest_file = downloads_dir / local_filename

        # If file exists, create timestamped backup
        if dest_file.exists():
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = downloads_dir / f"{local_filename}.{timestamp}.bak"
            try:
                dest_file.rename(backup_file)
                print(f"[!] Existing report in Downloads backed up to: {backup_file}")
            except Exception as e:
                print(f"[-] Backup note: {e}")

        shutil.copyfile(str(local_path), str(dest_file))
        final_win_path = str(dest_file)
        print(f"[OK] Copied uncorrupted file to Windows Downloads: {dest_file}")

    # Step 3: Print final verification details
    print("\n" + "=" * 76)
    print("ACADEMIC REPORT GENERATION COMPLETE")
    print(f"Local Path:         {local_path}")
    print(f"File Size:          {local_path.stat().st_size:,} bytes")
    print(f"Final Windows Path: {final_win_path}")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
