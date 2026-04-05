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

# ─── Framework Metadata ───────────────────────────────────────────────────────

FRAMEWORK_META = {
    "CIS": {
        "full_name": "CIS Benchmarks",
        "version": "v3.0.0 (2024)",
        "org": "Center for Internet Security",
        "description": "CIS Benchmark controls for AWS, Azure, and GCP infrastructure hardening",
        "disclaimer": (
            "Findings are based on analysis against CIS Benchmark controls "
            "(AWS v3.0.0, Azure v2.1.0, GCP v2.0.0). "
            "CIS Benchmarks are consensus-based configuration guidelines. "
            "Always validate findings against your organization's risk tolerance."
        ),
    },
    "NIST": {
        "full_name": "NIST SP 800-53 Rev 5",
        "version": "Rev 5 (2020)",
        "org": "National Institute of Standards and Technology",
        "description": "NIST 800-53 security and privacy controls for information systems",
        "disclaimer": (
            "Findings are mapped to NIST SP 800-53 Revision 5 security controls. "
            "NIST 800-53 provides a catalog of security and privacy controls for federal "
            "information systems and organizations. Validate against your ATO requirements."
        ),
    },
    "CCM": {
        "full_name": "CSA Cloud Controls Matrix v4.1",
        "version": "v4.1 (2021)",
        "org": "Cloud Security Alliance",
        "description": "CSA CCM v4.1 controls across 17 domains for cloud security assurance",
        "disclaimer": (
            "Findings are mapped to the CSA Cloud Controls Matrix (CCM) v4.1. "
            "CCM v4.1 covers 207 controls across 17 domains designed for cloud environments. "
            "Refer to the CSA CAIQ and STAR program for customer-facing assurance."
        ),
    },
    "All": {
        "full_name": "All Frameworks",
        "version": "CIS + NIST + CCM",
        "org": "CIS · NIST · CSA",
        "description": "Combined CIS Benchmarks, NIST 800-53, and CSA CCM v4.1 controls",
        "disclaimer": (
            "Findings are based on analysis against CIS Benchmark, NIST SP 800-53 Rev 5, "
            "and CSA Cloud Controls Matrix v4.1 controls. "
            "Always validate findings against your organization's specific security requirements."
        ),
    },
}


def _framework_meta(framework: str) -> dict:
    """Return display metadata for a given framework key."""
    return FRAMEWORK_META.get(framework, FRAMEWORK_META["All"])


def _compute_score(findings: list) -> float:
    """Compute compliance score from a findings list (passed / total * 100)."""
    if not findings:
        return 0.0
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    return round((passed / len(findings)) * 100, 1)


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
    canvas.drawString(30, A4[1] - 25, "INVECTO COMPLIANCE GUARD")
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


def generate_pdf_report(audit_data: Dict[str, Any], findings_data: List[Dict[str, Any]], framework_label: str = "", framework: str = "All") -> bytes:
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
    fw = _framework_meta(framework)

    # ═══════════════════════════════════════════════════════════════════════
    # COVER / TITLE SECTION
    # ═══════════════════════════════════════════════════════════════════════

    story.append(Spacer(1, 30))
    story.append(Paragraph("Invecto Compliance Guard", styles["ReportTitle"]))
    subtitle = f"Infrastructure Compliance Audit Report — {fw['full_name']}"
    story.append(Paragraph(subtitle, styles["ReportSubtitle"]))
    # Framework badge row
    story.append(Paragraph(
        f'<b>Framework:</b> {fw["full_name"]} &nbsp;|&nbsp; '
        f'<b>Version:</b> {fw["version"]} &nbsp;|&nbsp; '
        f'<b>Published by:</b> {fw["org"]}',
        styles["SmallMuted"]
    ))
    story.append(Spacer(1, 8))

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

    # Always compute score from the (already-filtered) findings_data
    failed = [f for f in findings_data if f.get("status") == "FAIL"]
    passed = [f for f in findings_data if f.get("status") == "PASS"]
    total_checks = len(findings_data)
    score = _compute_score(findings_data) if total_checks > 0 else float(audit_data.get("compliance_score", 0))
    grade = _score_grade(score)
    grade_color = _score_color(score)

    # Score + summary table side by side
    score_text = f'<font color="{grade_color.hexval()}" size="28"><b>{score:.1f}%</b></font>'
    grade_text = f'<font color="{grade_color.hexval()}" size="14">Grade: {grade}</font>'

    summary_items = [
        f"<b>Framework:</b> {fw['full_name']}",
        f"<b>Total Checks ({framework}):</b> {total_checks}",
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
        f"<i>This report was automatically generated by Invecto Compliance Guard. "
        f"{fw['disclaimer']}</i>",
        styles["SmallMuted"]
    ))

    # Build
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()


def generate_aws_pdf_report(scan_cache: Dict[str, Any]) -> bytes:
    """Generate a PDF report for AWS live cloud audit results."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=45, bottomMargin=50, leftMargin=30, rightMargin=30,
    )
    styles = _get_styles()
    story = []

    audit = scan_cache.get("audit", {})
    scan = scan_cache.get("scan", {})
    region = scan_cache.get("region", "unknown")
    scan_time = scan_cache.get("scan_time", "")
    framework = scan_cache.get("framework", "All")
    fw = _framework_meta(framework)
    findings = audit.get("findings", [])
    # Always compute score from the filtered findings passed in
    total_checks = len(findings)
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed_count = sum(1 for f in findings if f.get("status") == "FAIL")
    failed = [f for f in findings if f.get("status") == "FAIL"]
    passed_findings = [f for f in findings if f.get("status") == "PASS"]
    health = _compute_score(findings) if total_checks > 0 else float(audit.get("health_score", 0))

    # ═════════════════════════════════════════════════════════════════════
    # TITLE
    # ═════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 30))
    story.append(Paragraph("Invecto Compliance Guard", styles["ReportTitle"]))
    subtitle = f"AWS Live Infrastructure Audit Report — {fw['full_name']}"
    story.append(Paragraph(subtitle, styles["ReportSubtitle"]))
    # Framework badge row
    story.append(Paragraph(
        f'<b>Framework:</b> {fw["full_name"]} &nbsp;|&nbsp; '
        f'<b>Version:</b> {fw["version"]} &nbsp;|&nbsp; '
        f'<b>Published by:</b> {fw["org"]}',
        styles["SmallMuted"]
    ))
    story.append(Spacer(1, 8))

    meta = [
        ["Cloud Provider", "Amazon Web Services (AWS)"],
        ["Region", region],
        ["Scan Time", scan_time or datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")],
        ["Compliance Framework", f"{fw['full_name']} ({fw['version']})"],
        ["Resources Scanned", f"S3: {scan.get('s3_buckets', 0)}, Security Groups: {scan.get('security_groups', 0)}, IAM Policies: {scan.get('iam_policies', 0)}, IAM Users: {scan.get('iam_users', 0)}"],
    ]
    meta_table = Table(meta, colWidths=[120, 400])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), TEXT_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), TEXT_DARK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, BORDER_GRAY),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # ═════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═════════════════════════════════════════════════════════════════════
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
    story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))

    grade = _score_grade(health)
    grade_color = _score_color(health)

    score_text = f'<font color="{grade_color.hexval()}" size="28"><b>{health:.1f}%</b></font>'
    grade_label = f'<font color="{grade_color.hexval()}" size="14">Grade: {grade}</font>'
    summary_items = [
        f"<b>Framework:</b> {fw['full_name']}",
        f"<b>Total Checks ({framework}):</b> {total_checks}",
        f'<b>Passed:</b> <font color="{PASS_GREEN.hexval()}">{passed}</font>',
        f'<b>Failed:</b> <font color="{FAIL_RED.hexval()}">{failed_count}</font>',
    ]

    score_para = Paragraph(score_text + "<br/>" + grade_label, ParagraphStyle(
        "ScoreInlineAWS", fontSize=28, alignment=TA_CENTER, leading=36,
    ))
    summary_para = Paragraph("<br/>".join(summary_items), styles["BodyText2"])

    score_table = Table([[score_para, summary_para]], colWidths=[150, 380])
    score_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, 0), LIGHT_GRAY),
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

    action_map = {
        "CRITICAL": "Immediate remediation required (within 24h)",
        "HIGH": "Remediate promptly (within 1 week)",
        "MEDIUM": "Plan remediation in next sprint (within 30 days)",
        "LOW": "Address during routine maintenance (within 90 days)",
    }

    sev_rows = [[
        Paragraph("<b>Severity</b>", styles["BodyText2"]),
        Paragraph("<b>Count</b>", styles["BodyText2"]),
        Paragraph("<b>Action Required</b>", styles["BodyText2"]),
    ]]
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
        ]))
        story.append(sev_table)

    # ═════════════════════════════════════════════════════════════════════
    # FAILED FINDINGS (DETAILED — matches Terraform report format)
    # ═════════════════════════════════════════════════════════════════════
    if failed:
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
        story.append(Paragraph(f"2. Failed Checks ({len(failed)})", styles["SectionHeader"]))

        for i, f in enumerate(failed, 1):
            sev = f.get("severity", "MEDIUM").upper()
            sev_color = SEVERITY_COLORS.get(sev, MEDIUM_AMBER)

            elems = []

            # Finding header
            rule_id = f.get("cis_rule_id", f.get("rule_id", "N/A"))
            title = f.get("title", f.get("rule_title", "Unknown"))
            header = (
                f'<font color="{sev_color.hexval()}"><b>[{sev}]</b></font> '
                f'<b>{rule_id} — {title}</b>'
            )
            elems.append(Paragraph(header, styles["BodyText2"]))
            elems.append(Spacer(1, 4))

            # Details table
            resource_name = f.get("resource_name", f.get("resource", "N/A"))
            detail_rows = [
                ["Resource", str(resource_name)],
                ["Type", f.get("resource_type", "N/A")],
                ["Cloud Provider", "AWS"],
            ]
            dt = Table(detail_rows, colWidths=[90, 440])
            dt.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), TEXT_MUTED),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            elems.append(dt)
            elems.append(Spacer(1, 4))

            # Description
            desc = f.get("description", "")
            if desc:
                elems.append(Paragraph(f"<b>Description:</b> {desc}", styles["BodyText2"]))
                elems.append(Spacer(1, 2))

            # Reasoning / Analysis
            reasoning = f.get("reasoning", "")
            if reasoning:
                elems.append(Paragraph(f"<b>Analysis:</b> {reasoning}", styles["BodyText2"]))
                elems.append(Spacer(1, 2))

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
                elems.append(ea_table)

            # Recommendation
            rec = f.get("recommendation", "")
            if rec:
                elems.append(Paragraph(
                    f'<font color="{BRAND_ORANGE.hexval()}"><b>Recommendation:</b></font> {rec}',
                    styles["BodyText2"]
                ))
                elems.append(Spacer(1, 2))

            # Remediation Command
            remediation = f.get("remediation_step", "")
            if remediation:
                elems.append(Paragraph("<b>Remediation:</b>", styles["SmallMuted"]))
                safe_cmd = remediation.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elems.append(Paragraph(safe_cmd, styles["CodeBlock"]))

            elems.append(Spacer(1, 6))

            # Wrap in bordered box
            box = Table([[elems]], colWidths=[530])
            box.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(KeepTogether([box, Spacer(1, 8)]))

    # ═════════════════════════════════════════════════════════════════════
    # PASSED CHECKS
    # ═════════════════════════════════════════════════════════════════════
    if passed_findings:
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE, spaceAfter=4))
        section_num = 3 if failed else 2
        story.append(Paragraph(f"{section_num}. Passed Checks ({len(passed_findings)})", styles["SectionHeader"]))

        pass_rows = [[
            Paragraph("<b>Rule</b>", styles["BodyText2"]),
            Paragraph("<b>Resource</b>", styles["BodyText2"]),
            Paragraph("<b>Status</b>", styles["BodyText2"]),
        ]]
        for f in passed_findings:
            resource_name = f.get("resource", f.get("resource_name", ""))
            pass_rows.append([
                Paragraph(f'{f.get("rule_id", "")} — {f.get("rule_title", "")}', styles["SmallMuted"]),
                Paragraph(str(resource_name), styles["SmallMuted"]),
                Paragraph('<font color="#22c55e"><b>PASS</b></font>', styles["SmallMuted"]),
            ])

        pass_table = Table(pass_rows, colWidths=[230, 210, 50])
        pass_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GRAY),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, BORDER_GRAY),
        ]))
        story.append(pass_table)

    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_GRAY))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<i>This report was generated by Invecto Compliance Guard from a live AWS scan. "
        f"Findings reflect the real-time state of your AWS infrastructure at the time of scanning. "
        f"{fw['disclaimer']}</i>",
        styles["SmallMuted"]
    ))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
