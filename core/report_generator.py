
import logging
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

logger = logging.getLogger(__name__)

DARK_BG      = colors.HexColor("#1a1a2e")
ACCENT       = colors.HexColor("#e94560")
LIGHT_GREY   = colors.HexColor("#f5f5f5")
MID_GREY     = colors.HexColor("#cccccc")
TEXT_DARK    = colors.HexColor("#1a1a1a")
FOFA_BG      = colors.HexColor("#fff3cd")
FOFA_BORDER  = colors.HexColor("#e6a817")
WHITE        = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc3545"),
    "high":     colors.HexColor("#fd7e14"),
    "medium":   colors.HexColor("#ffc107"),
    "low":      colors.HexColor("#28a745"),
    "unknown":  colors.HexColor("#6c757d"),
}


def _severity_color(severity: str) -> colors.Color:
    return SEVERITY_COLORS.get((severity or "unknown").lower(), SEVERITY_COLORS["unknown"])


def _styles():
    base = getSampleStyleSheet()

    custom = {
        "ReportTitle": ParagraphStyle(
            "ReportTitle",
            fontSize=22, leading=28,
            textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=4,
        ),
        "ReportSubtitle": ParagraphStyle(
            "ReportSubtitle",
            fontSize=11, leading=14,
            textColor=MID_GREY, fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=2,
        ),
        "SectionHeader": ParagraphStyle(
            "SectionHeader",
            fontSize=12, leading=16,
            textColor=ACCENT, fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6,
        ),
        "BodyText": ParagraphStyle(
            "BodyText",
            fontSize=10, leading=15,
            textColor=TEXT_DARK, fontName="Helvetica",
            spaceAfter=4,
        ),
        "FOFAQuery": ParagraphStyle(
            "FOFAQuery",
            fontSize=11, leading=16,
            textColor=colors.HexColor("#7d4e00"),
            fontName="Courier-Bold",
            spaceAfter=4,
        ),
        "BulletItem": ParagraphStyle(
            "BulletItem",
            fontSize=10, leading=14,
            textColor=TEXT_DARK, fontName="Helvetica",
            leftIndent=12, spaceAfter=2,
        ),
        "ArticleTitle": ParagraphStyle(
            "ArticleTitle",
            fontSize=9, leading=13,
            textColor=colors.HexColor("#0056b3"),
            fontName="Helvetica-Bold",
            spaceAfter=1,
        ),
        "ArticleURL": ParagraphStyle(
            "ArticleURL",
            fontSize=8, leading=11,
            textColor=colors.HexColor("#666666"),
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "Footer": ParagraphStyle(
            "Footer",
            fontSize=8, leading=10,
            textColor=MID_GREY, fontName="Helvetica",
            alignment=TA_CENTER,
        ),
    }
    return custom


def _header_block(story, styles, enriched: dict):
    cve_id   = enriched.get("cve_id", "UNKNOWN")
    severity = enriched.get("severity", "Unknown")
    sev_col  = _severity_color(severity)

    header_data = [[
        Paragraph(f"<b>{cve_id}</b>", styles["ReportTitle"]),
        Paragraph(
            f'<font color="white"><b> {severity.upper()} </b></font>',
            ParagraphStyle("Badge", fontSize=13, fontName="Helvetica-Bold",
                           alignment=TA_CENTER, textColor=WHITE,
                           backColor=sev_col, leading=18)
        ),
    ]]
    t = Table(header_data, colWidths=[12*cm, 4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), DARK_BG),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (0, -1),  18),
        ("RIGHTPADDING", (-1,0), (-1, -1), 18),
        ("TOPPADDING",   (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 18),
        ("BACKGROUND",   (1, 0), (1,  0),  sev_col),
    ]))
    story.append(t)

    subtitle = (
        f"CVE Intelligence Report  •  "
        f"Generated {datetime.now().strftime('%d %b %Y, %H:%M')}  • "
    )
    story.append(Spacer(1, 6))
    story.append(Paragraph(subtitle, styles["ReportSubtitle"]))
    story.append(Spacer(1, 10))


def _fmt_list(lst):
    """Format a list nicely, one item per line if long."""
    if not lst:
        return "—"
    if len(lst) <= 3:
        return ", ".join(lst)
    return "\n".join(lst)

def _summary_table(story, styles, enriched: dict):
    story.append(Paragraph("Summary", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))

    def fmt(lst):
        if not lst:
            return "—"
        if len(lst) <= 3:
            return ", ".join(lst)
        return "\n".join(lst)

    rows = [
        ["CVE ID",            enriched.get("cve_id", "—")],
        ["Severity",          enriched.get("severity", "—")],
        ["Products",          fmt(enriched.get("products"))],
        ["Affected Versions", fmt(enriched.get("affected_versions"))],
        ["Fixed Versions",    fmt(enriched.get("fixed_versions"))],
    ]

    t = Table(rows, colWidths=[4.5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1),  "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("TEXTCOLOR",     (0, 0), (-1, -1), TEXT_DARK),
        ("BACKGROUND",    (0, 0), (0, -1),  LIGHT_GREY),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0, 0), (-1, -1), 0.5, MID_GREY),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("WORDWRAP",      (0, 0), (-1, -1), True),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))


def _description_section(story, styles, enriched: dict):
    story.append(Paragraph("Description", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))
    desc = enriched.get("description") or "No description available."
    story.append(Paragraph(desc, styles["BodyText"]))
    story.append(Spacer(1, 6))


def _mitigation_section(story, styles, enriched: dict):
    story.append(Paragraph("Mitigation", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))
    mit = enriched.get("mitigation") or "No mitigation information available."
    story.append(Paragraph(mit, styles["BodyText"]))
    story.append(Spacer(1, 6))


def _fofa_section(story, styles, fofa_query: str):
    story.append(Paragraph("FOFA Search Query", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))

    intro = (
        "Use the query below on <b>fofa.info</b> to identify potentially vulnerable "
        "Indian infrastructure. Copy and paste directly into the FOFA search bar."
    )
    story.append(Paragraph(intro, styles["BodyText"]))
    story.append(Spacer(1, 6))

    query_data = [[Paragraph(fofa_query, styles["FOFAQuery"])]]
    qt = Table(query_data, colWidths=[16.5*cm])
    qt.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), FOFA_BG),
        ("BOX",           (0, 0), (-1, -1), 2,  FOFA_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(KeepTogether([qt]))
    story.append(Spacer(1, 10))


def _sources_section(story, styles, ddg_results: list):
    if not ddg_results:
        return

    story.append(Paragraph("Intelligence Sources", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=8))
    story.append(Paragraph(
        "The following articles were used to enrich this CVE report:",
        styles["BodyText"]
    ))
    story.append(Spacer(1, 4))

    for i, r in enumerate(ddg_results, 1):
        title   = r.get("title", "Unknown title")
        url     = r.get("href", "")
        snippet = r.get("body", "").strip()[:180]
        if snippet and not snippet.endswith("."):
            snippet += "…"

        story.append(Paragraph(f"{i}. {title}", styles["ArticleTitle"]))
        story.append(Paragraph(f'<a href="{url}" color="#0056b3">{url}</a>', styles["ArticleURL"]))
        if snippet:
            story.append(Paragraph(snippet, styles["BulletItem"]))
        story.append(Spacer(1, 4))


def generate_cve_report(
    enriched: dict,
    fofa_query: str,
    ddg_results: Optional[list] = None,
    output_path: str = "cve_report.pdf",
) -> str:

    styles = _styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )

    story = []
    _header_block(story, styles, enriched)
    story.append(Spacer(1, 12))
    _summary_table(story, styles, enriched)
    _description_section(story, styles, enriched)
    _mitigation_section(story, styles, enriched)
    _fofa_section(story, styles, fofa_query)
    _sources_section(story, styles, ddg_results or [])

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY))
    story.append(Spacer(1, 4))
   

    doc.build(story)
    logger.info(f"[Report] PDF saved to {output_path}")
    return output_path