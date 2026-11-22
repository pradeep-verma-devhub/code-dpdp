import os
from pathlib import Path
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from ..core.models import ScanResult, Finding

class PdfGenerator:
    """Generates official DPDP Act 2023 & DPDP Rules 2025 Compliance Audit PDF Reports."""

    @classmethod
    def generate(cls, scan_result: ScanResult, output_path: str) -> str:
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(dest),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom Palette: Dark Navy & Saffron / Indian Privacy Theme
        c_primary = colors.HexColor("#0F2B5C")
        c_accent = colors.HexColor("#FF8C00")
        c_critical = colors.HexColor("#DC2626")
        c_high = colors.HexColor("#EA580C")
        c_medium = colors.HexColor("#D97706")
        c_low = colors.HexColor("#2563EB")
        c_dark = colors.HexColor("#1E293B")
        c_light = colors.HexColor("#F8FAFC")
        c_border = colors.HexColor("#E2E8F0")

        # Typography Styles
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=26,
            leading=32,
            textColor=c_primary,
            alignment=1,
            spaceAfter=12
        )
        subtitle_style = ParagraphStyle(
            'CoverSubTitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#475569"),
            alignment=1,
            spaceAfter=24
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=c_primary,
            spaceBefore=14,
            spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading3'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=c_primary,
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=c_dark
        )
        code_style = ParagraphStyle(
            'CodeSnippet',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0F172A")
        )

        story = []

        # ==========================================
        # 1. COVER PAGE
        # ==========================================
        story.append(Spacer(1, 1.2 * inch))
        story.append(Paragraph("DPDP-AUDIT COMPLIANCE REPORT", title_style))
        story.append(Paragraph(
            "Statutory Privacy Assessment under India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025",
            subtitle_style
        ))
        story.append(HRFlowable(width="80%", thickness=3, color=c_accent, spaceBefore=10, spaceAfter=20))

        # Metadata Card
        meta_data = [
            [Paragraph("<b>Target Application:</b>", body_style), Paragraph(scan_result.target_path, body_style)],
            [Paragraph("<b>Audit Date:</b>", body_style), Paragraph(scan_result.timestamp, body_style)],
            [Paragraph("<b>Overall Compliance Score:</b>", body_style), Paragraph(f"<b>{scan_result.summary.compliance_score} / 100</b>", body_style)],
            [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(scan_result.summary.findings_count), body_style)],
            [Paragraph("<b>Audited By:</b>", body_style), Paragraph("DPDP-Audit Automated Engine v1.0", body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[2.2 * inch, 4.3 * inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_light),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, c_border),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 0.8 * inch))

        # Severity Summary Pills
        sev_counts = scan_result.summary.by_severity
        pill_data = [
            [
                Paragraph("<font color='#DC2626'><b>CRITICAL</b></font><br/><b>" + str(sev_counts.get("critical", 0)) + "</b>", ParagraphStyle('C', alignment=1)),
                Paragraph("<font color='#EA580C'><b>HIGH</b></font><br/><b>" + str(sev_counts.get("high", 0)) + "</b>", ParagraphStyle('H', alignment=1)),
                Paragraph("<font color='#D97706'><b>MEDIUM</b></font><br/><b>" + str(sev_counts.get("medium", 0)) + "</b>", ParagraphStyle('M', alignment=1)),
                Paragraph("<font color='#2563EB'><b>LOW</b></font><br/><b>" + str(sev_counts.get("low", 0)) + "</b>", ParagraphStyle('L', alignment=1)),
            ]
        ]
        pill_table = Table(pill_data, colWidths=[1.6 * inch, 1.6 * inch, 1.6 * inch, 1.6 * inch])
        pill_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#FEE2E2")),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#FFEDD5")),
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor("#FEF3C7")),
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor("#DBEAFE")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(pill_table)

        story.append(PageBreak())

        # ==========================================
        # 2. EXECUTIVE SUMMARY
        # ==========================================
        story.append(Paragraph("1. Executive Summary & Legal Exposure Analysis", h1_style))
        story.append(Paragraph(
            "This audit evaluated source code, infrastructure declarations, and data pipelines for compliance "
            "with statutory obligations mandated under the <b>Digital Personal Data Protection Act 2023</b> "
            "and <b>DPDP Rules 2025</b>. India's Data Protection Board may impose penalties up to <b>₹250 Crore</b> "
            "for failures in taking reasonable security safeguards under Section 8(6), up to <b>₹200 Crore</b> for "
            "failing to notify personal data breaches under Section 8(4), and up to <b>₹200 Crore</b> for child data "
            "non-compliance under Section 9.",
            body_style
        ))
        story.append(Spacer(1, 8))

        # Metrics Breakdown Table
        summary_rows = [
            [Paragraph("<b>Compliance Metric</b>", body_style), Paragraph("<b>Observed Result</b>", body_style), Paragraph("<b>Statutory Reference</b>", body_style)],
            [Paragraph("Application Health Score", body_style), Paragraph(f"<b>{scan_result.summary.compliance_score}/100</b>", body_style), Paragraph("Act 2023 Posture", body_style)],
            [Paragraph("Critical Severity Findings", body_style), Paragraph(f"<font color='#DC2626'><b>{sev_counts.get('critical', 0)}</b></font>", body_style), Paragraph("Schedule Item 1 (Up to ₹250 Cr)", body_style)],
            [Paragraph("High Severity Findings", body_style), Paragraph(f"<font color='#EA580C'><b>{sev_counts.get('high', 0)}</b></font>", body_style), Paragraph("Schedule Item 2/3 (Up to ₹200 Cr)", body_style)],
            [Paragraph("Total Scanned Source Files", body_style), Paragraph(str(scan_result.summary.scanned_files_count), body_style), Paragraph("Scope Boundary", body_style)],
            [Paragraph("Audit Execution Time", body_style), Paragraph(f"{scan_result.summary.scan_duration_ms:.1f} ms", body_style), Paragraph("Deterministic Scan", body_style)],
        ]
        sum_table = Table(summary_rows, colWidths=[2.5 * inch, 1.8 * inch, 2.2 * inch])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sum_table)

        story.append(Spacer(1, 14))

        # ==========================================
        # 3. CONSENT SCORECARD (BONUS A)
        # ==========================================
        if scan_result.consent_scorecard:
            cs = scan_result.consent_scorecard
            story.append(Paragraph("2. Consent Flow Assessment Scorecard (Sections 5 & 6)", h1_style))
            story.append(Paragraph(
                f"Overall Consent Maturity Grade: <b>Grade {cs.grade} ({cs.overall_score}/100)</b>. "
                f"Evaluated across the 5 statutory pillars of lawful consent management.",
                body_style
            ))
            story.append(Spacer(1, 6))

            consent_rows = [
                [Paragraph("<b>Pillar</b>", body_style), Paragraph("<b>Score</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Audit Finding</b>", body_style)],
            ]
            for p_name, p_data in cs.pillars.items():
                st_color = "#16A34A" if p_data["passed"] else "#DC2626"
                st_label = "PASSED" if p_data["passed"] else "GAP"
                consent_rows.append([
                    Paragraph(f"<b>{p_name.replace('_', ' ').title()}</b>", body_style),
                    Paragraph(f"{p_data['score']}/20", body_style),
                    Paragraph(f"<font color='{st_color}'><b>{st_label}</b></font>", body_style),
                    Paragraph(p_data['details'], body_style),
                ])
            c_table = Table(consent_rows, colWidths=[1.5 * inch, 0.9 * inch, 1.1 * inch, 3.0 * inch])
            c_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(c_table)

        story.append(Spacer(1, 14))

        # ==========================================
        # 4. DPDP STATUTORY PROVISION COVERAGE
        # ==========================================
        story.append(Paragraph("3. DPDP Act & Rules Provision Coverage", h1_style))
        cov_rows = [
            [Paragraph("<b>Provision</b>", body_style), Paragraph("<b>Law</b>", body_style), Paragraph("<b>Title & Summary</b>", body_style), Paragraph("<b>Audit Status</b>", body_style)]
        ]
        for cov in scan_result.summary.dpdp_coverage[:12]:  # Show top key provisions
            st_col = "#DC2626" if cov["status"] == "VIOLATION" else "#16A34A"
            cov_rows.append([
                Paragraph(f"<b>{cov['provision']}</b>", body_style),
                Paragraph(cov['law'], body_style),
                Paragraph(f"<b>{cov['title']}</b>", body_style),
                Paragraph(f"<font color='{st_col}'><b>{cov['status']} ({cov['findingCount']})</b></font>", body_style),
            ])
        cov_table = Table(cov_rows, colWidths=[1.4 * inch, 1.0 * inch, 2.7 * inch, 1.4 * inch])
        cov_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(cov_table)

        story.append(PageBreak())

        # ==========================================
        # 5. DETAILED AUDIT FINDINGS
        # ==========================================
        story.append(Paragraph("4. Detailed Technical Findings & Remediation Guidance", h1_style))
        story.append(Paragraph(
            "Each finding links to an official DPDP statutory provision with a documented risk justification "
            "and recommended remediation diff.",
            body_style
        ))
        story.append(Spacer(1, 10))

        # Limit per-finding cards to prevent gigantic PDFs on huge target apps
        for idx, f in enumerate(scan_result.findings[:25], 1):
            sev_c = c_critical if f.severity == "critical" else (c_high if f.severity == "high" else c_medium)

            card_data = [
                [
                    Paragraph(f"<b>#{idx} [{f.id}] {f.title}</b>", ParagraphStyle('FTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)),
                    Paragraph(f"<b>{f.severity.upper()}</b>", ParagraphStyle('FSev', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white, alignment=2)),
                ],
                [
                    Paragraph(f"<b>Location:</b> {f.file}:{f.line} &nbsp;|&nbsp; <b>Flow:</b> {f.data_flow.upper()} &nbsp;|&nbsp; <b>PII:</b> {', '.join(f.pii_types) if f.pii_types else 'Infrastructure'}", body_style),
                    "",
                ],
                [
                    Paragraph(f"<b>DPDP Provision:</b> {f.dpdp_ref.get('sectionOrRule', '')} &mdash; <i>{f.dpdp_ref.get('explanation', '')}</i>", body_style),
                    "",
                ],
                [
                    Paragraph(f"<b>Risk Scoring:</b> {f.justification}", body_style),
                    "",
                ],
                [
                    Paragraph(f"<b>Code Snippet (Redacted):</b><br/><font face='Courier' color='#0F172A'>{f.snippet[:120]}</font>", body_style),
                    "",
                ],
                [
                    Paragraph(f"<b>Recommended Fix:</b> {f.fix}", body_style),
                    "",
                ],
            ]
            f_table = Table(card_data, colWidths=[5.0 * inch, 1.5 * inch])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), sev_c),
                ('SPAN', (0, 1), (1, 1)),
                ('SPAN', (0, 2), (1, 2)),
                ('SPAN', (0, 3), (1, 3)),
                ('SPAN', (0, 4), (1, 4)),
                ('SPAN', (0, 5), (1, 5)),
                ('BACKGROUND', (0, 1), (-1, -1), c_light),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(KeepTogether([f_table, Spacer(1, 10)]))

        # Build Document
        doc.build(story)
        return str(dest)
