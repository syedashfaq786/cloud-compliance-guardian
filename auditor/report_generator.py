"""
PDF Report Generator — Creates professional, well-structured compliance audit reports.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ─── Color Palette ───────────────────────────────────────────────────────────

BRAND_ORANGE = colors.HexColor("#F97316")
BRAND_DARK = colors.HexColor("#1a1a2e")
HEADER_BG = colors.HexColor("#F97316")
PASS_GREEN = colors.HexColor("#22c55e")
FAIL_RED = colors.HexColor("#ef4444")
CRITICAL_RED = colors.HexColor("#dc2626")
HIGH_ORANGE = colors.HexColor("#ea580c")
MEDIUM_AMBER = colors.HexColor("#d97706")
LOW_BLUE = colors.HexColor("#3b82f6")
LIGHT_GRAY = colors.HexColor("#f8f9fa")
BORDER_GRAY = colors.HexColor("#e5e7eb")
TEXT_DARK = colors.HexColor("#1f2937")
TEXT_MUTED = colors.HexColor("#6b7280")

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL_RED,
    "HIGH": HIGH_ORANGE,
    "MEDIUM": MEDIUM_AMBER,
    "LOW": LOW_BLUE,
}


def _get_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontSize=22,
        leading=28,
        textColor=TEXT_DARK,
        fontName="Helvetica-Bold",
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        fontSize=11,
        leading=16,
        textColor=TEXT_MUTED,
        fontName="Helvetica",
        spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontSize=15,
        leading=20,
        textColor=BRAND_ORANGE,
        fontName="Helvetica-Bold",
        spaceBefore=20,
        spaceAfter=10,
        borderPadding=(0, 0, 4, 0),
    ))
    styles.add(ParagraphStyle(
        name="SubSection",
        fontSize=12,
        leading=16,
        textColor=TEXT_DARK,
        fontName="Helvetica-Bold",
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontSize=9,
        leading=13,
        textColor=TEXT_DARK,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        name="SmallMuted",
        fontSize=8,
        leading=11,
        textColor=TEXT_MUTED,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        name="CodeBlock",
        fontSize=8,
        leading=11,
        textColor=TEXT_DARK,
        fontName="Courier",
        backColor=LIGHT_GRAY,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="ScoreGrade",
        fontSize=36,
        leading=40,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    ))
    return styles


def _header_footer(canvas, doc):
    """Add header and footer to each page."""
    canvas.saveState()

    # Header line
    canvas.setStrokeColor(BRAND_ORANGE)
    canvas.setLineWidth(2)
    canvas.line(30, A4[1] - 30, A4[0] - 30, A4[1] - 30)

    # Header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(BRAND_ORANGE)
    canvas.drawString(30, A4[1] - 25, "CLOUD COMPLIANCE GUARDIAN")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawRightString(A4[0] - 30, A4[1] - 25, "Confidential — Audit Report")

    # Footer
    canvas.setStrokeColor(BORDER_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(30, 35, A4[0] - 30, 35)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(30, 22, f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawRightString(A4[0] - 30, 22, f"Page {doc.page}")

    canvas.restoreState()


def _score_grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _score_color(score: float):
    if score >= 75: return PASS_GREEN
    if score >= 50: return MEDIUM_AMBER
    return FAIL_RED


def generate_pdf_report(audit_data: Dict[str, Any], findings_data: List[Dict[str, Any]]) -> bytes:
    """Generate a professional PDF audit report.

    Returns the PDF as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=45,
        bottomMargin=50,
        leftMargin=30,
        rightMargin=30,
    )

    styles = _get_styles()
    story = []

    # ═══════════════════════════════════════════════════════════════════════
    # COVER / TITLE SECTION
    # ═══════════════════════════════════════════════════════════════════════

    story.append(Spacer(1, 30))
    story.append(Paragraph("Cloud Compliance Guardian", styles["ReportTitle"]))
    story.append(Paragraph("Infrastructure Compliance Audit Report", styles["ReportSubtitle"]))

    # Report metadata table
    audit_id = audit_data.get("audit_id", "N/A")
    directory = audit_data.get("directory", "N/A")
    created = audit_data.get("created_at", "")
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            created = dt.strftime("%B %d, %Y at %H:%M UTC")
        except Exception:
            pass

    meta_data = [
        ["Audit ID", audit_id],
        ["Directory", Paragraph(str(directory), styles["BodyText2"])],
        ["Date", created or datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")],
        ["Files Scanned", str(audit_data.get("files_scanned", 0))],
        ["Resources Scanned", str(audit_data.get("resources_scanned", 0))],
        ["Triggered By", audit_data.get("triggered_by", "manual").title()],
    ]
    meta_table = Table(meta_data, colWidths=[120, 400])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), TEXT_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), TEXT_DARK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, BORDER_GRAY),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # ═══════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════

    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
    story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))

    score = audit_data.get("compliance_score", 0)
    grade = _score_grade(score)
    grade_color = _score_color(score)

    failed = [f for f in findings_data if f.get("status") == "FAIL"]
    passed = [f for f in findings_data if f.get("status") == "PASS"]
    total_checks = len(findings_data)

    # Score + summary table side by side
    score_text = f'<font color="{grade_color.hexval()}" size="28"><b>{score:.1f}%</b></font>'
    grade_text = f'<font color="{grade_color.hexval()}" size="14">Grade: {grade}</font>'

    summary_items = [
        f"<b>Total Checks:</b> {total_checks}",
        f'<b>Passed:</b> <font color="{PASS_GREEN.hexval()}">{len(passed)}</font>',
        f'<b>Failed:</b> <font color="{FAIL_RED.hexval()}">{len(failed)}</font>',
        f"<b>Resources Scanned:</b> {audit_data.get('resources_scanned', 0)}",
    ]

    score_para = Paragraph(score_text + "<br/>" + grade_text, ParagraphStyle(
        "ScoreInline", fontSize=28, alignment=TA_CENTER, leading=36,
    ))

    summary_para = Paragraph("<br/>".join(summary_items), styles["BodyText2"])

    score_table = Table([[score_para, summary_para]], colWidths=[150, 380])
    score_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, 0), LIGHT_GRAY),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    # Severity breakdown
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in failed:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    sev_header = [
        Paragraph("<b>Severity</b>", styles["BodyText2"]),
        Paragraph("<b>Count</b>", styles["BodyText2"]),
        Paragraph("<b>Action Required</b>", styles["BodyText2"]),
    ]
    sev_rows = [sev_header]
    action_map = {
        "CRITICAL": "Immediate remediation required (within 24h)",
        "HIGH": "Remediate promptly (within 1 week)",
        "MEDIUM": "Plan remediation in next sprint (within 30 days)",
        "LOW": "Address during routine maintenance (within 90 days)",
    }
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts[sev_name]
        if count > 0:
            color = SEVERITY_COLORS[sev_name].hexval()
            sev_rows.append([
                Paragraph(f'<font color="{color}"><b>{sev_name}</b></font>', styles["BodyText2"]),
                Paragraph(str(count), styles["BodyText2"]),
                Paragraph(action_map[sev_name], styles["SmallMuted"]),
            ])

    if len(sev_rows) > 1:
        story.append(Paragraph("Severity Breakdown", styles["SubSection"]))
        sev_table = Table(sev_rows, colWidths=[80, 50, 400])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GRAY),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(sev_table)
    story.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════════════════════
    # FAILED FINDINGS (DETAILED)
    # ═══════════════════════════════════════════════════════════════════════

    if failed:
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
        story.append(Paragraph(f"2. Failed Checks ({len(failed)})", styles["SectionHeader"]))

        for i, f in enumerate(failed, 1):
            sev = f.get("severity", "MEDIUM").upper()
            sev_color = SEVERITY_COLORS.get(sev, MEDIUM_AMBER)
            provider = f.get("cloud_provider", "AWS")

            finding_elements = []

            # Finding header
            header_text = (
                f'<font color="{sev_color.hexval()}"><b>[{sev}]</b></font> '
                f'<b>{f.get("rule_id", "N/A")} — {f.get("rule_title", "Unknown")}</b>'
            )
            finding_elements.append(Paragraph(header_text, styles["BodyText2"]))
            finding_elements.append(Spacer(1, 4))

            # Details table
            detail_rows = [
                ["Resource", f.get("resource_address", "N/A")],
                ["Type", f.get("resource_type", "N/A")],
                ["Cloud Provider", provider],
                ["File", f.get("file_path", "N/A")],
            ]
            detail_table = Table(detail_rows, colWidths=[90, 440])
            detail_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), TEXT_MUTED),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            finding_elements.append(detail_table)
            finding_elements.append(Spacer(1, 4))

            # Description
            desc = f.get("description", "")
            if desc:
                finding_elements.append(Paragraph(f"<b>Description:</b> {desc}", styles["BodyText2"]))
                finding_elements.append(Spacer(1, 2))

            # Reasoning
            reasoning = f.get("reasoning", "")
            if reasoning:
                finding_elements.append(Paragraph(f"<b>Analysis:</b> {reasoning}", styles["BodyText2"]))
                finding_elements.append(Spacer(1, 2))

            # Expected vs Actual
            expected = f.get("expected", "")
            actual = f.get("actual", "")
            if expected or actual:
                ea_rows = []
                if expected:
                    ea_rows.append([
                        Paragraph('<font color="#22c55e"><b>Expected</b></font>', styles["BodyText2"]),
                        Paragraph(str(expected), styles["CodeBlock"]),
                    ])
                if actual:
                    ea_rows.append([
                        Paragraph('<font color="#ef4444"><b>Actual</b></font>', styles["BodyText2"]),
                        Paragraph(str(actual), styles["CodeBlock"]),
                    ])
                ea_table = Table(ea_rows, colWidths=[70, 460])
                ea_table.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                ]))
                finding_elements.append(ea_table)

            # Recommendation
            rec = f.get("recommendation", "")
            if rec:
                finding_elements.append(Paragraph(
                    f'<font color="{BRAND_ORANGE.hexval()}"><b>Recommendation:</b></font> {rec}',
                    styles["BodyText2"]
                ))
                finding_elements.append(Spacer(1, 2))

            # Remediation HCL
            hcl = f.get("remediation_hcl", "")
            if hcl:
                finding_elements.append(Paragraph("<b>Remediation Code:</b>", styles["SmallMuted"]))
                # Escape special chars for ReportLab
                safe_hcl = hcl.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                finding_elements.append(Paragraph(safe_hcl, styles["CodeBlock"]))

            finding_elements.append(Spacer(1, 8))

            # Wrap in a bordered box
            finding_table = Table([[finding_elements]], colWidths=[530])
            finding_table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))

            # Use KeepTogether to avoid page breaks mid-finding
            story.append(KeepTogether([finding_table, Spacer(1, 8)]))

    # ═══════════════════════════════════════════════════════════════════════
    # PASSED CHECKS
    # ═══════════════════════════════════════════════════════════════════════

    if passed:
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
        story.append(Paragraph(f"3. Passed Checks ({len(passed)})", styles["SectionHeader"]))

        pass_header = [
            Paragraph("<b>Rule</b>", styles["BodyText2"]),
            Paragraph("<b>Resource</b>", styles["BodyText2"]),
            Paragraph("<b>Provider</b>", styles["BodyText2"]),
            Paragraph("<b>Status</b>", styles["BodyText2"]),
        ]
        pass_rows = [pass_header]
        for f in passed:
            pass_rows.append([
                Paragraph(f'{f.get("rule_id", "")} — {f.get("rule_title", "")}', styles["SmallMuted"]),
                Paragraph(f.get("resource_address", ""), styles["SmallMuted"]),
                Paragraph(f.get("cloud_provider", "AWS"), styles["SmallMuted"]),
                Paragraph('<font color="#22c55e"><b>PASS</b></font>', styles["SmallMuted"]),
            ])

        pass_table = Table(pass_rows, colWidths=[200, 180, 60, 50])
        pass_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GRAY),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, BORDER_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(pass_table)

    # ═══════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS SUMMARY
    # ═══════════════════════════════════════════════════════════════════════

    if failed:
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
        section_num = 4 if passed else 3
        story.append(Paragraph(f"{section_num}. Remediation Priorities", styles["SectionHeader"]))

        story.append(Paragraph(
            "The following is a prioritized list of remediation actions based on severity. "
            "Address CRITICAL and HIGH findings first, as they represent the greatest risk to your infrastructure.",
            styles["BodyText2"]
        ))
        story.append(Spacer(1, 8))

        prio_rows = [[
            Paragraph("<b>#</b>", styles["BodyText2"]),
            Paragraph("<b>Priority</b>", styles["BodyText2"]),
            Paragraph("<b>Finding</b>", styles["BodyText2"]),
            Paragraph("<b>Recommendation</b>", styles["BodyText2"]),
        ]]

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_failed = sorted(failed, key=lambda x: sev_order.get(x.get("severity", "LOW").upper(), 4))

        for idx, f in enumerate(sorted_failed, 1):
            sev = f.get("severity", "MEDIUM").upper()
            sev_color = SEVERITY_COLORS.get(sev, MEDIUM_AMBER)
            prio_rows.append([
                Paragraph(str(idx), styles["BodyText2"]),
                Paragraph(f'<font color="{sev_color.hexval()}"><b>{sev}</b></font>', styles["BodyText2"]),
                Paragraph(f'{f.get("rule_id", "")} — {f.get("resource_address", "")}', styles["SmallMuted"]),
                Paragraph(f.get("recommendation", f.get("description", "")), styles["SmallMuted"]),
            ])

        prio_table = Table(prio_rows, colWidths=[25, 65, 180, 260])
        prio_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GRAY),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, BORDER_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(prio_table)

    # ═══════════════════════════════════════════════════════════════════════
    # FOOTER / DISCLAIMER
    # ═══════════════════════════════════════════════════════════════════════

    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_GRAY))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<i>This report was automatically generated by Cloud Compliance Guardian. "
        "Findings are based on static analysis of Terraform configurations against "
        "CIS Benchmark and NIST 800-53 controls. Always validate findings against your "
        "organization's specific security requirements and risk tolerance.</i>",
        styles["SmallMuted"]
    ))

    # Build
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
