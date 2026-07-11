"""
PDF report generator for BSS-Recon.

Reads the consolidated scan results dict (same structure that markdown_report.py
receives) and produces a branded PDF using ReportLab.

Usage from cli.py (mirrors the markdown report call):
    from bssrecon.reporting.pdf_report import generate_pdf_report
    pdf_path = generate_pdf_report(target, all_results, config)

Or standalone from the CLI report command:
    python -m bssrecon report output/target_20240101_120000.json --format pdf
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable


# ---------------------------------------------------------------------------
# Brand colours
# ---------------------------------------------------------------------------

_BSS_DARK   = colors.HexColor("#0D1B2A")   # near-black navy
_BSS_ACCENT = colors.HexColor("#1E88E5")   # BSS blue
_BSS_LIGHT  = colors.HexColor("#F5F7FA")   # off-white background rows
_BSS_TEXT   = colors.HexColor("#1A1A2E")   # body text

_SEV_COLOURS = {
    "critical": colors.HexColor("#D32F2F"),
    "high":     colors.HexColor("#E64A19"),
    "medium":   colors.HexColor("#F9A825"),
    "low":      colors.HexColor("#388E3C"),
    "info":     colors.HexColor("#455A64"),
}

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.index(sev.lower()) if sev.lower() in _SEV_ORDER else 99


def _sev_color(sev: str) -> colors.Color:
    return _SEV_COLOURS.get(sev.lower(), _BSS_TEXT)


def _sev_label(sev: str) -> str:
    return sev.upper()


# ---------------------------------------------------------------------------
# Collect and normalise findings from all module result dicts
# ---------------------------------------------------------------------------

def _collect_findings(all_results: list[dict]) -> list[dict]:
    """
    Flatten findings from every module result dict.
    Each finding gets a `module` field injected for traceability.
    """
    findings: list[dict] = []
    for result in all_results:
        module_name = result.get("module", result.get("domain", "unknown"))
        for f in result.get("findings", []):
            findings.append({
                "severity": f.get("severity", "info").lower(),
                "title":       f.get("title", "Untitled Finding"),
                "detail":      f.get("detail", ""),
                "owasp":       f.get("owasp", ""),
                "mitre":       f.get("mitre", ""),
                "remediation": f.get("remediation", ""),
                "module":      module_name,
            })
    return sorted(findings, key=lambda f: _sev_rank(f["severity"]))


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    base = getSampleStyleSheet()

    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        "cover_company": ps(
            "cover_company",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=colors.white,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "cover_title": ps(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=_BSS_ACCENT,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "cover_subtitle": ps(
            "cover_subtitle",
            fontName="Helvetica",
            fontSize=11,
            textColor=colors.HexColor("#B0BEC5"),
            alignment=TA_CENTER,
            spaceAfter=3,
        ),
        "h1": ps(
            "h1",
            fontName="Helvetica-Bold",
            fontSize=15,
            textColor=_BSS_DARK,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "h2": ps(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=_BSS_ACCENT,
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ps(
            "body",
            fontName="Helvetica",
            fontSize=9,
            textColor=_BSS_TEXT,
            leading=14,
            spaceAfter=4,
        ),
        "body_small": ps(
            "body_small",
            fontName="Helvetica",
            fontSize=8,
            textColor=_BSS_TEXT,
            leading=12,
        ),
        "label": ps(
            "label",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=_BSS_TEXT,
        ),
        "disclaimer": ps(
            "disclaimer",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=colors.HexColor("#78909C"),
            leading=12,
            spaceBefore=6,
        ),
        "finding_title": ps(
            "finding_title",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=_BSS_DARK,
            spaceBefore=8,
            spaceAfter=2,
        ),
        "tag": ps(
            "tag",
            fontName="Helvetica",
            fontSize=8,
            textColor=colors.HexColor("#546E7A"),
        ),
    }


# ---------------------------------------------------------------------------
# Page template (header / footer)
# ---------------------------------------------------------------------------

def _make_page_template(company_name: str, target: str, doc):
    """Return an onPage callback that draws the running header and footer."""

    def _draw(canvas, doc):
        canvas.saveState()
        w, h = A4

        # Running header bar (skip cover page)
        if doc.page > 1:
            canvas.setFillColor(_BSS_DARK)
            canvas.rect(0, h - 20 * mm, w, 20 * mm, fill=1, stroke=0)
            canvas.setFont("Helvetica-Bold", 9)
            canvas.setFillColor(colors.white)
            canvas.drawString(15 * mm, h - 13 * mm, company_name)
            canvas.setFont("Helvetica", 9)
            canvas.setFillColor(_BSS_ACCENT)
            canvas.drawRightString(w - 15 * mm, h - 13 * mm, f"Target: {target}")

        # Footer
        canvas.setFillColor(colors.HexColor("#CFD8DC"))
        canvas.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#546E7A"))
        canvas.drawString(15 * mm, 3.5 * mm, "CONFIDENTIAL — For authorized use only.")
        canvas.drawRightString(
            w - 15 * mm, 3.5 * mm,
            f"Page {doc.page} | Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )

        canvas.restoreState()

    return _draw


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------

def _cover_page(target: str, company_name: str, analyst_name: str, styles: dict) -> list:
    w, h = A4
    elements = []

    # Dark header band — simulated with a coloured table spanning full width
    cover_header = Table(
        [[Paragraph(company_name, styles["cover_company"])]],
        colWidths=[w - 40 * mm],
    )
    cover_header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _BSS_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 28),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
    ]))
    elements.append(cover_header)
    elements.append(Spacer(1, 18 * mm))

    # Logo placeholder box
    logo_table = Table(
        [[Paragraph("[ BSS LOGO ]", ParagraphStyle(
            "logo_ph",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=colors.HexColor("#B0BEC5"),
            alignment=TA_CENTER,
        ))]],
        colWidths=[60 * mm],
        rowHeights=[30 * mm],
    )
    logo_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#ECEFF1")),
        ("BOX",           (0, 0), (-1, -1), 1, colors.HexColor("#B0BEC5")),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))

    # To swap in a real logo: replace logo_table with Image("path/to/logo.png", width=60*mm, height=30*mm)

    logo_wrapper = Table([[logo_table]], colWidths=[w - 40 * mm])
    logo_wrapper.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    elements.append(logo_wrapper)
    elements.append(Spacer(1, 12 * mm))

    elements.append(Paragraph("Security Assessment Report", styles["cover_title"]))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(f"Target: {target}", styles["cover_subtitle"]))
    elements.append(Spacer(1, 2 * mm))
    elements.append(Paragraph(
        f"Prepared by: {analyst_name}",
        styles["cover_subtitle"],
    ))
    elements.append(Paragraph(
        f"Date: {datetime.now(timezone.utc).strftime('%B %d, %Y')}",
        styles["cover_subtitle"],
    ))
    elements.append(Spacer(1, 20 * mm))

    elements.append(HRFlowable(width="100%", thickness=1, color=_BSS_ACCENT))
    elements.append(Spacer(1, 6 * mm))
    elements.append(Paragraph(
        "CONFIDENTIAL — This report contains sensitive security information. "
        "Distribution is restricted to authorized personnel only.",
        styles["disclaimer"],
    ))

    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _executive_summary(
    target: str,
    findings: list[dict],
    counts: dict[str, int],
    styles: dict,
    scan_meta: dict,
) -> list:
    elements = []
    elements.append(Paragraph("Executive Summary", styles["h1"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=_BSS_ACCENT))
    elements.append(Spacer(1, 4 * mm))

    # Scan metadata block
    meta_rows = [
        ["Target Domain", target],
        ["Assessment Date", datetime.now(timezone.utc).strftime("%Y-%m-%d")],
        ["Total Findings", str(len(findings))],
        ["Modules Run", scan_meta.get("modules_run", "")],
    ]
    meta_table = Table(meta_rows, colWidths=[50 * mm, 110 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 0), (0, -1), _BSS_TEXT),
        ("TEXTCOLOR",     (1, 0), (1, -1), _BSS_TEXT),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [_BSS_LIGHT, colors.white]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#ECEFF1")),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8 * mm))

    # Severity count tiles
    elements.append(Paragraph("Finding Counts by Severity", styles["h2"]))

    sev_cells = []
    for sev in _SEV_ORDER:
        count = counts.get(sev, 0)
        c = _sev_color(sev)
        cell = Table(
            [[Paragraph(str(count), ParagraphStyle(
                f"tile_count_{sev}",
                fontName="Helvetica-Bold",
                fontSize=22,
                textColor=colors.white,
                alignment=TA_CENTER,
            ))],
            [Paragraph(_sev_label(sev), ParagraphStyle(
                f"tile_label_{sev}",
                fontName="Helvetica-Bold",
                fontSize=8,
                textColor=colors.white,
                alignment=TA_CENTER,
            ))]],
            colWidths=[28 * mm],
            rowHeights=[14 * mm, 8 * mm],
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), c),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ROUNDEDCORNERS", [3]),
        ]))
        sev_cells.append(cell)

    tile_row = Table([sev_cells], colWidths=[30 * mm] * 5)
    tile_row.setStyle(TableStyle([
        ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    elements.append(tile_row)
    elements.append(Spacer(1, 8 * mm))

    # Narrative paragraph
    critical_high = counts.get("critical", 0) + counts.get("high", 0)
    if critical_high:
        risk_stmt = (
            f"This assessment identified <b>{critical_high} critical or high-severity "
            f"finding(s)</b> requiring immediate remediation. "
        )
    else:
        risk_stmt = "No critical or high-severity findings were identified. "

    elements.append(Paragraph(
        risk_stmt +
        f"A total of <b>{len(findings)}</b> findings were recorded across all modules. "
        "Full details, OWASP category mappings, MITRE ATT&CK technique references, "
        "and remediation guidance are provided in the sections that follow.",
        styles["body"],
    ))

    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Findings table (summary — one row per finding)
# ---------------------------------------------------------------------------

def _findings_table(findings: list[dict], styles: dict) -> list:
    elements = []
    elements.append(Paragraph("Findings Summary", styles["h1"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=_BSS_ACCENT))
    elements.append(Spacer(1, 3 * mm))

    if not findings:
        elements.append(Paragraph("No findings were recorded.", styles["body"]))
        elements.append(PageBreak())
        return elements

    header = [
        Paragraph("#",        styles["label"]),
        Paragraph("Severity", styles["label"]),
        Paragraph("Title",    styles["label"]),
        Paragraph("OWASP",    styles["label"]),
        Paragraph("MITRE",    styles["label"]),
    ]
    col_widths = [8 * mm, 20 * mm, 72 * mm, 36 * mm, 34 * mm]

    rows = [header]
    row_styles = []

    for i, f in enumerate(findings, 1):
        sev = f["severity"].lower()
        sev_color = _sev_color(sev)

        sev_para = Paragraph(
            _sev_label(sev),
            ParagraphStyle(
                f"sev_cell_{i}",
                fontName="Helvetica-Bold",
                fontSize=8,
                textColor=colors.white,
                alignment=TA_CENTER,
            ),
        )
        # Wrap severity in a mini coloured table for the pill effect
        sev_pill = Table([[sev_para]], colWidths=[18 * mm])
        sev_pill.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_color),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        rows.append([
            Paragraph(str(i), styles["body_small"]),
            sev_pill,
            Paragraph(f["title"][:120], styles["body_small"]),
            Paragraph(f.get("owasp", "")[:50], styles["body_small"]),
            Paragraph(f.get("mitre", "")[:50], styles["body_small"]),
        ])

        # Alternate row shading
        bg = _BSS_LIGHT if i % 2 == 0 else colors.white
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        # Header
        ("BACKGROUND",    (0, 0), (-1, 0), _BSS_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("TOPPADDING",    (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        # Body
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#ECEFF1")),
        *row_styles,
    ]))

    elements.append(table)
    elements.append(PageBreak())
    return elements


# ---------------------------------------------------------------------------
# Detailed findings — one block per finding
# ---------------------------------------------------------------------------

def _detailed_findings(findings: list[dict], styles: dict) -> list:
    elements = []
    elements.append(Paragraph("Detailed Findings", styles["h1"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=_BSS_ACCENT))

    if not findings:
        elements.append(Paragraph("No findings to detail.", styles["body"]))
        return elements

    for i, f in enumerate(findings, 1):
        sev = f["severity"].lower()
        sev_color = _sev_color(sev)

        # Title bar with severity badge
        title_text = f"<font color='#{sev_color.hexval()[2:8]}'>[{_sev_label(sev)}]</font>  {i}. {f['title']}"
        block = [
            Spacer(1, 5 * mm),
            Paragraph(title_text, styles["finding_title"]),
            HRFlowable(width="100%", thickness=0.4, color=sev_color),
        ]

        # Detail
        if f.get("detail"):
            block.append(Spacer(1, 2 * mm))
            block.append(Paragraph("<b>Detail:</b>", styles["label"]))
            block.append(Paragraph(f["detail"], styles["body"]))

        # OWASP / MITRE tags
        tags = []
        if f.get("owasp"):
            tags.append(f"<b>OWASP:</b> {f['owasp']}")
        if f.get("mitre"):
            tags.append(f"<b>MITRE ATT&CK:</b> {f['mitre']}")
        if f.get("module"):
            tags.append(f"<b>Module:</b> {f['module']}")
        if tags:
            block.append(Paragraph("  ·  ".join(tags), styles["tag"]))

        # Remediation
        if f.get("remediation"):
            block.append(Spacer(1, 2 * mm))
            block.append(Paragraph("<b>Remediation:</b>", styles["label"]))
            block.append(Paragraph(f["remediation"], styles["body"]))

        elements.append(KeepTogether(block))

    return elements


# ---------------------------------------------------------------------------
# Disclaimer page
# ---------------------------------------------------------------------------

def _disclaimer_page(company_name: str, analyst_name: str, styles: dict) -> list:
    elements = [PageBreak()]
    elements.append(Paragraph("Disclaimer & Scope", styles["h1"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=_BSS_ACCENT))
    elements.append(Spacer(1, 4 * mm))

    text_blocks = [
        (
            "Authorized Use",
            "This report has been prepared exclusively for the client organization "
            "under an authorized security assessment engagement. All testing was "
            "conducted within the agreed scope and with explicit written authorization. "
            "Unauthorized reproduction or distribution is strictly prohibited."
        ),
        (
            "Scope Limitations",
            "The findings in this report reflect the security posture of the assessed "
            "target at the time of testing only. The absence of a finding does not "
            "guarantee the absence of a vulnerability. New vulnerabilities may emerge "
            "after the assessment date due to changes in software, configuration, or "
            "the threat landscape."
        ),
        (
            "Passive vs. Active Testing",
            "Passive (OSINT) modules rely solely on publicly available information "
            "and do not interact directly with the target's systems. Active modules "
            "send network requests to the target and require written authorization "
            "before use. The client is responsible for ensuring that all active "
            "testing is explicitly authorized under applicable laws and agreements."
        ),
        (
            "No Warranty",
            f"{company_name} provides this report as-is. The findings represent "
            "professional judgement based on information available at the time of "
            "the assessment. No warranty, express or implied, is made regarding "
            "completeness or fitness for any particular purpose."
        ),
        (
            "Analyst",
            analyst_name,
        ),
        (
            "Report Generated",
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ),
    ]

    for heading, body in text_blocks:
        elements.append(Paragraph(heading, styles["h2"]))
        elements.append(Paragraph(body, styles["disclaimer"]))
        elements.append(Spacer(1, 3 * mm))

    return elements


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def generate_pdf_report(
    target: str,
    all_results: list[dict],
    config: dict,
    output_path: str | None = None,
) -> str:
    """
    Generate a branded PDF security assessment report.

    Args:
        target:       Domain name that was scanned.
        all_results:  List of module result dicts (each with a 'findings' key).
        config:       Parsed config.yaml dict.
        output_path:  Where to save the PDF. Defaults to
                      <report_dir>/<target>_<timestamp>.pdf

    Returns:
        Absolute path to the generated PDF file.
    """
    reporting_cfg = config.get("reporting", {})
    company_name  = reporting_cfg.get("company_name", "Burgohy Security Solutions")
    analyst_name  = reporting_cfg.get("analyst_name", "Emilio Burgohy")
    report_dir    = Path(reporting_cfg.get("report_dir", "./reports"))
    report_dir.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(report_dir / f"{target}_{ts}.pdf")

    findings = _collect_findings(all_results)
    counts   = _severity_counts(findings)

    modules_run = ", ".join(
        r.get("module", r.get("domain", ""))
        for r in all_results
        if r.get("module") or r.get("domain")
    )
    scan_meta = {"modules_run": modules_run or "unknown"}

    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=28 * mm,
        bottomMargin=18 * mm,
        title=f"Security Assessment — {target}",
        author=company_name,
        subject="Confidential Security Assessment Report",
    )

    on_page = _make_page_template(company_name, target, doc)

    story = []
    story += _cover_page(target, company_name, analyst_name, styles)
    story += _executive_summary(target, findings, counts, styles, scan_meta)
    story += _findings_table(findings, styles)
    story += _detailed_findings(findings, styles)
    story += _disclaimer_page(company_name, analyst_name, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return str(Path(output_path).resolve())


# ---------------------------------------------------------------------------
# CLI entry point — called from bssrecon/cli.py report command
# ---------------------------------------------------------------------------

def generate_from_json(json_path: str, config: dict) -> str:
    """
    Load a saved scan JSON file and generate a PDF from it.
    The JSON must be the output written by cli.py (contains 'domain' + per-module results).

    Called by:
        python -m bssrecon report output/target_20240101.json --format pdf
    """
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    target = data.get("domain", Path(json_path).stem)
    # The top-level JSON is a dict of module_name -> result_dict
    all_results = []
    for module_name, result in data.items():
        if isinstance(result, dict) and "findings" in result:
            result = dict(result)
            result.setdefault("module", module_name)
            all_results.append(result)
    return generate_pdf_report(target, all_results, config)
