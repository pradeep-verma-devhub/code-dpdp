import os
import re
import html
import textwrap
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from ..core.models import ScanResult, Finding
from ..core.rag_pipeline import RagPipeline
from ..core.statutory_resolver import StatutoryResolver

class NumberedCanvas(canvas.Canvas):

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
        if self._pageNumber == 1:
            return

        self.saveState()

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#0A192F"))
        self.drawString(32, 762, "CODE-DPDP // STATUTORY COMPLIANCE & CYBER DEFENSE AUDIT")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(580, 762, "INDIA DPDP ACT 2023 & DPDP RULES 2025")

        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(32, 755, 580, 755)

        self.line(32, 38, 580, 38)
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#BE123C"))
        self.drawString(32, 27, "CONFIDENTIAL // STATUTORY AUDIT & LEGAL PRIVILEGE")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(580, 27, f"Page {self._pageNumber} of {total_pages}")

        self.restoreState()

class PdfGenerator:

    PAGE_WIDTH = 548

    SEV_PALETTE = {
        "critical": {
            "hex": "#BE123C",
            "tint_hex": "#FFF1F2",
            "border_hex": "#F43F5E",
            "header": colors.HexColor("#BE123C"),
            "tint": colors.HexColor("#FFF1F2"),
            "border": colors.HexColor("#F43F5E"),
        },
        "high": {
            "hex": "#EA580C",
            "tint_hex": "#FFF7ED",
            "border_hex": "#FB923C",
            "header": colors.HexColor("#EA580C"),
            "tint": colors.HexColor("#FFF7ED"),
            "border": colors.HexColor("#FB923C"),
        },
        "medium": {
            "hex": "#D97706",
            "tint_hex": "#FFFBEB",
            "border_hex": "#FBBF24",
            "header": colors.HexColor("#D97706"),
            "tint": colors.HexColor("#FFFBEB"),
            "border": colors.HexColor("#FBBF24"),
        },
        "low": {
            "hex": "#0284C7",
            "tint_hex": "#F0F9FF",
            "border_hex": "#38BDF8",
            "header": colors.HexColor("#0284C7"),
            "tint": colors.HexColor("#F0F9FF"),
            "border": colors.HexColor("#38BDF8"),
        },
    }

    @classmethod
    def calculate_statutory_penalty(cls, findings: List[Finding]) -> Tuple[str, str, str]:
        if not findings:
            return "Rs. 0", "Compliant - No statutory violations detected", "#16A34A"

        has_critical_safeguards = any(
            f.severity == "critical" and ("8(5)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 6" in str(f.dpdp_ref.get("sectionOrRule", "")))
            for f in findings
        )
        has_child = any("9" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 8" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
        has_breach_notice = any("8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 7" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
        has_sdf = any("10" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
        has_consent = any(("6(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "5(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Section 6" in str(f.dpdp_ref.get("sectionOrRule", ""))) for f in findings)

        if has_critical_safeguards:
            return "Up to Rs. 250 Crore", "DPDP Act Schedule Item 1: Failure to take reasonable security safeguards (Sec 8(5) & Rule 6)", "#BE123C"
        elif has_child:
            return "Up to Rs. 200 Crore", "DPDP Act Schedule Item 3: Breach in relation to children data obligations (Sec 9 & Rule 8)", "#EA580C"
        elif has_breach_notice:
            return "Up to Rs. 200 Crore", "DPDP Act Schedule Item 2: Failure to notify personal data breach (Sec 8(6) & Rule 7)", "#EA580C"
        elif has_sdf:
            return "Up to Rs. 150 Crore", "DPDP Act Schedule Item 4: Failure in Significant Data Fiduciary obligations (Sec 10)", "#D97706"
        elif has_consent:
            return "Up to Rs. 50 Crore", "DPDP Act Schedule Item 7: Breach of consent or notice obligations (Sec 5/6)", "#D97706"
        else:
            return "Up to Rs. 50 Crore", "DPDP Act Schedule Item 7: General statutory non-compliance", "#D97706"

    @classmethod
    def format_code_snippet(cls, snippet: str) -> str:
        if not snippet:
            return "<i>No code snippet available</i>"
        lines = snippet.strip().split("\n")
        formatted = []
        for line in lines[:10]:
            wrapped_sublines = textwrap.wrap(line, width=78) if len(line) > 78 else [line]
            for sub in wrapped_sublines:
                esc = html.escape(sub)
                formatted.append(esc)
        return "<br/>".join(formatted)

    @classmethod
    def format_diff(cls, diff_text: str) -> str:
        if not diff_text:
            return ""
        lines = diff_text.strip().split("\n")
        formatted = []
        for line in lines[:12]:
            esc = html.escape(line)
            if line.startswith("---") or line.startswith("+++"):
                formatted.append(f"<font color='#64748B'><b>{esc}</b></font>")
            elif line.startswith("-"):
                formatted.append(f"<font color='#DC2626'><b>{esc}</b></font>")
            elif line.startswith("+"):
                formatted.append(f"<font color='#16A34A'><b>{esc}</b></font>")
            elif line.startswith("@@"):
                formatted.append(f"<font color='#0284C7'>{esc}</font>")
            else:
                formatted.append(f"<font color='#334155'>{esc}</font>")
        return "<br/>".join(formatted)

    @classmethod
    def generate(cls, scan_result: ScanResult, output_path: str) -> str:
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(dest),
            pagesize=letter,
            rightMargin=32,
            leftMargin=32,
            topMargin=46,
            bottomMargin=46,
        )

        styles = getSampleStyleSheet()

        c_navy = colors.HexColor("#0A192F")
        c_dark_slate = colors.HexColor("#0F172A")
        c_gold = colors.HexColor("#F59E0B")
        c_critical = colors.HexColor("#BE123C")
        c_high = colors.HexColor("#EA580C")
        c_medium = colors.HexColor("#D97706")
        c_low = colors.HexColor("#0284C7")
        c_light = colors.HexColor("#F8FAFC")
        c_border = colors.HexColor("#CBD5E1")
        c_border_light = colors.HexColor("#E2E8F0")

        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=27,
            textColor=c_navy,
            alignment=1,
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'CoverSubTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=c_gold,
            alignment=1,
            spaceAfter=4
        )
        sub_desc_style = ParagraphStyle(
            'CoverSubDesc',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#475569"),
            alignment=1,
            spaceAfter=14
        )
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=c_navy,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading3'],
            fontName='Helvetica-Bold',
            fontSize=10.5,
            leading=14,
            textColor=c_navy,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=c_dark_slate
        )
        body_small = ParagraphStyle(
            'BodySmall',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#334155")
        )
        card_header_style = ParagraphStyle(
            'CardHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=12,
            textColor=colors.white
        )

        max_fine, fine_desc, fine_color = cls.calculate_statutory_penalty(scan_result.findings)

        story = []

        badge_table = Table([[
            Paragraph(
                "<font color='#0A192F'><b>CONFIDENTIAL // STATUTORY CYBER DEFENSE & COMPLIANCE ASSESSMENT REPORT</b></font>",
                ParagraphStyle('Bdg', fontName='Helvetica-Bold', fontSize=7.5, alignment=1, textColor=c_navy)
            )
        ]], colWidths=[cls.PAGE_WIDTH])
        badge_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
            ('BOX', (0, 0), (-1, -1), 0.75, c_gold),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(badge_table)
        story.append(Spacer(1, 12))

        story.append(Paragraph("CODE-DPDP STATUTORY COMPLIANCE & CYBER DEFENSE AUDIT", title_style))
        story.append(Paragraph("DIGITAL PERSONAL DATA PROTECTION ACT 2023 & NOTIFIED DPDP RULES 2025", subtitle_style))
        story.append(Paragraph(
            "Integrated Semgrep AST Taint Analysis, OWASP Top 10 Real Vulnerabilities, Statutory Consent Architecture & Penalty Dossier",
            sub_desc_style
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=c_gold, spaceBefore=0, spaceAfter=14))

        score_val = scan_result.summary.compliance_score
        score_bg = colors.HexColor("#FEE2E2") if score_val < 50 else (colors.HexColor("#FEF3C7") if score_val < 80 else colors.HexColor("#DCFCE7"))
        score_txt = "#BE123C" if score_val < 50 else ("#D97706" if score_val < 80 else "#16A34A")
        score_status = "CRITICAL NON-COMPLIANCE" if score_val < 50 else ("NEEDS REMEDIATION" if score_val < 80 else "COMPLIANT POSTURE")

        score_num_style = ParagraphStyle(
            'ScoreNum',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            alignment=1,
            textColor=colors.HexColor(score_txt)
        )
        fine_num_style = ParagraphStyle(
            'FineNum',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=17,
            leading=21,
            alignment=1,
            textColor=colors.HexColor(fine_color)
        )

        kpi_data = [
            [
                [
                    Paragraph("<b>OVERALL STATUTORY COMPLIANCE SCORE</b>", ParagraphStyle('KpiT1', fontName='Helvetica-Bold', fontSize=8, leading=10, alignment=1, textColor=c_navy)),
                    Spacer(1, 3),
                    Paragraph(f"<b>{score_val} / 100</b>", score_num_style),
                    Spacer(1, 3),
                    Paragraph(f"<b>STATUS: {score_status}</b>", ParagraphStyle('KpiS1', fontName='Helvetica-Bold', fontSize=7.5, leading=9, alignment=1, textColor=colors.HexColor(score_txt))),
                ],
                [
                    Paragraph("<b>MAXIMUM STATUTORY PENALTY EXPOSURE</b>", ParagraphStyle('KpiT2', fontName='Helvetica-Bold', fontSize=8, leading=10, alignment=1, textColor=c_navy)),
                    Spacer(1, 3),
                    Paragraph(f"<b>{max_fine}</b>", fine_num_style),
                    Spacer(1, 3),
                    Paragraph(f"<i>{fine_desc}</i>", ParagraphStyle('KpiS2', fontName='Helvetica', fontSize=7, leading=9, alignment=1, textColor=colors.HexColor("#475569"))),
                ],
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[270, 278])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), score_bg),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#F8FAFC")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 1, c_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 12))

        semgrep_findings_count = sum(1 for f in scan_result.findings if getattr(f, "engine", None) and "Semgrep" in f.engine)
        meta_data = [
            [Paragraph("<b>Target Codebase Scope:</b>", body_style), Paragraph(f"<font face='Courier' size='7.5'>{html.escape(scan_result.target_path)}</font>", body_style)],
            [Paragraph("<b>Audit Execution Timestamp:</b>", body_style), Paragraph(scan_result.timestamp, body_style)],
            [Paragraph("<b>Static Analysis Engines:</b>", body_style), Paragraph(f"<b>Semgrep OSS Engine v1.186.0</b> ({semgrep_findings_count} AST/Taint detections) + <b>code-dpdp AST SAST Engine</b>", body_style)],
            [Paragraph("<b>Active Rules & Standards:</b>", body_style), Paragraph("46 DPDP Act Rules, OWASP Top 10 (A01-A10), CWE-89/79/78/22/918/328, Verhoeff & Luhn Checksums", body_style)],
            [Paragraph("<b>Scanned Scope & Files:</b>", body_style), Paragraph(f"<b>{scan_result.summary.scanned_files_count} files</b> inspected in {scan_result.summary.scan_duration_ms:.1f}ms", body_style)],
            [Paragraph("<b>Total Compliance Findings:</b>", body_style), Paragraph(f"<b>{scan_result.summary.findings_count} total violations</b> documented across codebase", body_style)],
            [Paragraph("<b>Code Malfunctions & Crash Hazards:</b>", body_style), Paragraph(f"<b>{len(scan_result.malfunctions)} software defects</b> (Silent error swallowings, unhandled rejections)", body_style)],
            [Paragraph("<b>Third-Party Tracker Egress:</b>", body_style), Paragraph(f"<b>{len(scan_result.third_party_egress)} external integrations</b> transmitting behavioral data without consent", body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[170, 378])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_light),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, c_border_light),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        sev_counts = scan_result.summary.by_severity
        pill_data = [
            [
                [
                    Paragraph("<font color='#BE123C'><b>CRITICAL</b></font>", ParagraphStyle('CT1', fontName='Helvetica-Bold', fontSize=8, alignment=1)),
                    Spacer(1, 2),
                    Paragraph(f"<b><font size='14'>{sev_counts.get('critical', 0)}</font></b>", ParagraphStyle('CV1', fontName='Helvetica-Bold', alignment=1)),
                    Spacer(1, 2),
                    Paragraph("<font size='6.5' color='#64748B'>Immediate Fine Risk</font>", ParagraphStyle('CS1', alignment=1)),
                ],
                [
                    Paragraph("<font color='#EA580C'><b>HIGH</b></font>", ParagraphStyle('CT2', fontName='Helvetica-Bold', fontSize=8, alignment=1)),
                    Spacer(1, 2),
                    Paragraph(f"<b><font size='14'>{sev_counts.get('high', 0)}</font></b>", ParagraphStyle('CV2', fontName='Helvetica-Bold', alignment=1)),
                    Spacer(1, 2),
                    Paragraph("<font size='6.5' color='#64748B'>Severe Hazard</font>", ParagraphStyle('CS2', alignment=1)),
                ],
                [
                    Paragraph("<font color='#D97706'><b>MEDIUM</b></font>", ParagraphStyle('CT3', fontName='Helvetica-Bold', fontSize=8, alignment=1)),
                    Spacer(1, 2),
                    Paragraph(f"<b><font size='14'>{sev_counts.get('medium', 0)}</font></b>", ParagraphStyle('CV3', fontName='Helvetica-Bold', alignment=1)),
                    Spacer(1, 2),
                    Paragraph("<font size='6.5' color='#64748B'>Statutory Deficiency</font>", ParagraphStyle('CS3', alignment=1)),
                ],
                [
                    Paragraph("<font color='#0284C7'><b>LOW / INFO</b></font>", ParagraphStyle('CT4', fontName='Helvetica-Bold', fontSize=8, alignment=1)),
                    Spacer(1, 2),
                    Paragraph(f"<b><font size='14'>{sev_counts.get('low', 0)}</font></b>", ParagraphStyle('CV4', fontName='Helvetica-Bold', alignment=1)),
                    Spacer(1, 2),
                    Paragraph("<font size='6.5' color='#64748B'>Advisory Flag</font>", ParagraphStyle('CS4', alignment=1)),
                ],
            ]
        ]
        pill_table = Table(pill_data, colWidths=[137, 137, 137, 137])
        pill_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#FFF1F2")),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#FFF7ED")),
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor("#FFFBEB")),
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor("#F0F9FF")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 1, c_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(pill_table)

        story.append(PageBreak())

        story.append(Paragraph("1. Statutory Compliance & Cyber Defense Executive Summary", h1_style))
        story.append(Paragraph(
            "This statutory audit evaluates the target application codebase against India's <b>Digital Personal Data "
            "Protection Act, 2023 (Act No. 22 of 2023)</b> and the notified <b>DPDP Rules 2025</b>. "
            "The audit combines <b>Semgrep AST &amp; Taint Flow static analysis</b> with statutory rules, verified PII regex algorithms "
            "(Verhoeff 10-digit Aadhaar, Luhn credit cards, PAN), configuration analyzers, and consent architecture auditing. "
            "Under DPDP Act Section 8(6), data fiduciaries are under mandatory legal obligation to protect personal data "
            "by taking reasonable security safeguards. Every violation identified below represents an actionable compliance liability.",
            body_style
        ))
        story.append(Spacer(1, 8))

        flow_counts = scan_result.summary.by_data_flow
        matrix_data = [
            [Paragraph("<b>Data Flow Lifecycle Stage</b>", body_style), Paragraph("<b>Violations</b>", body_style), Paragraph("<b>Statutory Impact & Legal Obligations</b>", body_style)],
            [Paragraph("<b>Storage (At-Rest)</b>", body_style), Paragraph(f"<b>{flow_counts.get('stored', 0)}</b>", body_style), Paragraph("DPDP Sec 8(6) & Sec 12: Unencrypted personal data in database schemas, flat files, or source code.", body_style)],
            [Paragraph("<b>Transit (In-Transit)</b>", body_style), Paragraph(f"<b>{flow_counts.get('transit', 0) + flow_counts.get('transferred', 0)}</b>", body_style), Paragraph("DPDP Sec 8(6) & Rule 6: Cleartext HTTP endpoints, TLS verification bypass, or insecure transport cookies.", body_style)],
            [Paragraph("<b>Exposure (Logging / Exceptions)</b>", body_style), Paragraph(f"<b>{flow_counts.get('exposed', 0)}</b>", body_style), Paragraph("DPDP Sec 8(6): Personal data leaked in debug logs, console output, stack traces, or URL params.", body_style)],
            [Paragraph("<b>Transmission (Third-Party Egress)</b>", body_style), Paragraph(f"<b>{len(scan_result.third_party_egress)}</b>", body_style), Paragraph("DPDP Sec 6 & 16: External SDK tracker data transmission without verified affirmative consent.", body_style)],
        ]
        matrix_table = Table(matrix_data, colWidths=[150, 68, 330])
        matrix_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(matrix_table)
        story.append(Spacer(1, 10))

        story.append(Paragraph("Vulnerability Classification & Threat Breakdown", h2_style))
        cat_counts = scan_result.summary.by_category
        cat_data = [
            [Paragraph("<b>Category / Vulnerability Type</b>", body_style), Paragraph("<b>Findings</b>", body_style), Paragraph("<b>Industry Standard & Statutory Mapping</b>", body_style)],
            [Paragraph("Injection & Real Flaws (SQLi, RCE, XSS, SSRF)", body_style), Paragraph(str(cat_counts.get("injection", 0) + cat_counts.get("xss", 0) + cat_counts.get("rce", 0) + cat_counts.get("traversal", 0) + cat_counts.get("ssrf", 0)), body_style), Paragraph("OWASP Top 10 (A03, A01, A10) | DPDP Act Sec 8(6) Reasonable Safeguards", body_style)],
            [Paragraph("Cryptographic Failures (MD5/SHA1, Weak PRNG)", body_style), Paragraph(str(cat_counts.get("crypto", 0) + cat_counts.get("storage", 0)), body_style), Paragraph("OWASP A02:2021 | DPDP Rules 2025 Rule 6 Encryption Mandate", body_style)],
            [Paragraph("Sensitive Data Exposure & Logging", body_style), Paragraph(str(cat_counts.get("exposure", 0) + cat_counts.get("logging", 0)), body_style), Paragraph("OWASP A09:2021 | DPDP Act Sec 8(6) Data Breach Prevention", body_style)],
            [Paragraph("Configuration & Insecure Cookies", body_style), Paragraph(str(cat_counts.get("config", 0)), body_style), Paragraph("OWASP A05:2021 | DPDP Rules 2025 Rule 6 Access Safeguards", body_style)],
        ]
        cat_table = Table(cat_data, colWidths=[200, 68, 280])
        cat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(cat_table)

        story.append(Spacer(1, 10))

        story.append(Paragraph("2. DPDP Consent Architecture Scorecard (Sections 5 & 6, Rules 3 & 4)", h1_style))
        cs = scan_result.consent_scorecard
        if cs:
            grade_color = "#16A34A" if cs.grade in ("A+", "A") else ("#D97706" if cs.grade == "B" else "#BE123C")
            story.append(Paragraph(
                f"Consent Maturity Evaluation: <font color='{grade_color}'><b>Grade {cs.grade} ({cs.overall_score}/100)</b></font>. "
                "Assessed across the 5 statutory pillars of lawful consent management under DPDP Act 2023.",
                body_style
            ))
            story.append(Spacer(1, 6))

            consent_rows = [
                [Paragraph("<b>Pillar</b>", body_style), Paragraph("<b>Score</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Audit Finding & Technical Evidence</b>", body_style)],
            ]
            for p_name, p_data in cs.pillars.items():
                st_color = "#16A34A" if p_data["passed"] else "#BE123C"
                st_label = "PASSED" if p_data["passed"] else "NON-COMPLIANT"
                consent_rows.append([
                    Paragraph(f"<b>{p_name.replace('_', ' ').title()}</b>", body_style),
                    Paragraph(f"{p_data['score']}/20", body_style),
                    Paragraph(f"<font color='{st_color}'><b>{st_label}</b></font>", body_style),
                    Paragraph(html.escape(p_data['details']), body_style),
                ])
            c_table = Table(consent_rows, colWidths=[110, 58, 85, 295])
            c_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(c_table)

        story.append(Spacer(1, 10))

        story.append(Paragraph("3. DPDP Act 2023 & DPDP Rules 2025 Provision Coverage", h1_style))
        cov_rows = [
            [Paragraph("<b>Provision</b>", body_style), Paragraph("<b>Governing Law</b>", body_style), Paragraph("<b>Statutory Title & Scope</b>", body_style), Paragraph("<b>Audit Status</b>", body_style)]
        ]
        for cov in scan_result.summary.dpdp_coverage:
            st_col = "#BE123C" if cov["status"] == "VIOLATION" else "#16A34A"
            cov_rows.append([
                Paragraph(f"<b>{cov['provision']}</b>", body_style),
                Paragraph(cov['law'], body_style),
                Paragraph(f"<b>{cov['title']}</b>", body_style),
                Paragraph(f"<font color='{st_col}'><b>{cov['status']} ({cov['findingCount']})</b></font>", body_style),
            ])
        cov_table = Table(cov_rows, colWidths=[110, 85, 245, 108])
        cov_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ('BOX', (0, 0), (-1, -1), 1, c_border),
            ('GRID', (0, 0), (-1, -1), 0.5, c_border),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(cov_table)

        story.append(PageBreak())

        story.append(Paragraph("4. Master Inventory of All Detected Bugs, Vulnerabilities & Violations", h1_style))
        story.append(Paragraph(
            "Every vulnerability, defect, and compliance violation detected across the codebase is sequentially indexed below. "
            "Full technical dossiers with exact code lines, hazard analyses, and remediation diffs follow in Section 5.",
            body_style
        ))
        story.append(Spacer(1, 8))

        if not scan_result.findings:
            story.append(Paragraph(
                "<font color='#16A34A'><b>✓ No compliance violations detected in the codebase.</b></font>",
                body_style
            ))
        else:
            inv_rows = [
                [
                    Paragraph("<b>#</b>", body_style),
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Vulnerability Title & Engine</b>", body_style),
                    Paragraph("<b>Location (File:Line)</b>", body_style),
                    Paragraph("<b>DPDP Provision / Penalty</b>", body_style)
                ]
            ]
            for idx, f in enumerate(scan_result.findings, 1):
                sev_key = f.severity.lower()
                sev_pal = cls.SEV_PALETTE.get(sev_key, cls.SEV_PALETTE["medium"])
                sev_col = sev_pal["hex"]
                is_semgrep = (getattr(f, "engine", None) and "Semgrep" in f.engine)
                engine_badge = "<font color='#6366F1'><b>[Semgrep AST]</b></font>" if is_semgrep else "<font color='#0284C7'><b>[code-dpdp SAST]</b></font>"
                dossier = StatutoryResolver.resolve_dossier(
                    rule_id=f.rule_id,
                    title=f.title,
                    pii_types=f.pii_types,
                    snippet=f.snippet,
                    file_path=f.file
                )
                short_law = dossier["law"].split("read with")[0].strip()
                short_pen = dossier["penalty"].split(" under ")[0].strip()
                inv_rows.append([
                    Paragraph(f"<b>#{idx}</b>", body_style),
                    Paragraph(f"<font color='{sev_col}'><b>{f.severity.upper()}</b></font>", body_style),
                    Paragraph(f"{engine_badge} {html.escape(f.title)}", body_style),
                    Paragraph(f"<font face='Courier' size='7'>{html.escape(f.file)}:{f.line}</font>", body_style),
                    Paragraph(f"{html.escape(short_law)}<br/><font color='#BE123C' size='6.5'>{html.escape(short_pen)}</font>", body_small),
                ])
            inv_table = Table(inv_rows, colWidths=[36, 60, 186, 170, 96])
            inv_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 4),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]))
            story.append(inv_table)

        story.append(PageBreak())

        story.append(Paragraph("5. Detailed Technical Code Breakdown & Remediation Guidance", h1_style))
        story.append(Paragraph(
            "This section provides an exhaustive, line-by-line technical breakdown of <b>every single vulnerability and bug</b> "
            "detected in the target application. It documents <b>which code</b> is vulnerable, <b>where</b> it is located, "
            "<b>what mistake</b> was made, the <b>exact source lines</b>, the <b>underlying AST/taint mechanics</b>, and "
            "<b>concrete remediation patches</b>.",
            body_style
        ))
        story.append(Spacer(1, 10))

        if not scan_result.findings:
            story.append(Paragraph(
                "<font color='#16A34A'><b>✓ No technical code flaws detected. All files adhere to statutory standards.</b></font>",
                body_style
            ))
        else:
            for idx, f in enumerate(scan_result.findings, 1):
                sev_key = f.severity.lower()
                sev_pal = cls.SEV_PALETTE.get(sev_key, cls.SEV_PALETTE["medium"])
                sev_c = sev_pal["header"]
                card_border = sev_pal["border"]
                snippet_tint = sev_pal["tint"]
                engine_tag = getattr(f, "engine", "code-dpdp AST Engine") or "code-dpdp AST Engine"

                dossier = StatutoryResolver.resolve_dossier(
                    rule_id=f.rule_id,
                    title=f.title,
                    pii_types=f.pii_types,
                    snippet=f.snippet,
                    file_path=f.file
                )

                cwe_tag = getattr(f, "cwe", None) or dossier["cwe"]
                owasp_tag = getattr(f, "owasp", None) or dossier["owasp"]
                statute_citation = dossier["law"]
                penalty_ceiling = dossier["penalty"]
                official_mandate = dossier["mandate"]

                defect_raw = f.justification
                defect_clean = re.sub(
                    r'Risk Score \d+/\d+:.*?\.\s*Evaluated against DPDP Act 2023 impact thresholds\.?',
                    '',
                    defect_raw
                ).strip()
                if not defect_clean:
                    defect_clean = f.dpdp_ref.get("explanation") or f.title or "Statutory security safeguards missing or improperly configured."

                card_data = [
                    [
                        Paragraph(f"<b>Finding #{idx}: [{f.id}] {f.title}</b>", card_header_style),
                        Paragraph(
                            f"<b>{f.severity.upper()}</b> &nbsp;|&nbsp; <font size='7'><i>{engine_tag.split()[0]}</i></font>",
                            ParagraphStyle('FSev', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white, alignment=2)
                        ),
                    ],
                    [
                        Paragraph(
                            f"<b>[LOCATION] Exact Code Coordinates:</b> <font face='Courier' color='#0A192F'><b>{html.escape(f.file)}</b> (Line {f.line}{f':{f.column}' if f.column else ''})</font><br/>"
                            f"<b>Analysis Engine:</b> {engine_tag} &nbsp;|&nbsp; <b>Data Flow:</b> {f.data_flow.upper()}"
                            f"{f' &nbsp;|&nbsp; <b>PII Leaked:</b> {html.escape(chr(44).join(f.pii_types))}' if f.pii_types else ''}",
                            body_style
                        ),
                        "",
                    ],
                    [
                        Paragraph(
                            f"<b>[LAW BROKEN] Statutory Law:</b> <font color='#0A192F'><b>{html.escape(statute_citation)}</b></font><br/>"
                            f"<b>[PENALTY CEILING] Maximum Statutory Fine:</b> <font color='#BE123C'><b>{html.escape(penalty_ceiling)}</b></font> &nbsp;|&nbsp; "
                            f"<b>Standard:</b> <font color='#0284C7'><b>{cwe_tag}</b></font> &nbsp;|&nbsp; <b>{owasp_tag}</b><br/>"
                            f"<b>[GAZETTE MANDATE] Official DPDP Rulebook Provision:</b> <i>\"{html.escape(official_mandate)}\"</i>",
                            body_style
                        ),
                        "",
                    ],
                    [
                        Paragraph(
                            f"<b>Vulnerable Code (Line {f.line}):</b><br/>"
                            f"<font face='Courier' size='7.5' color='#991B1B'>{cls.format_code_snippet(f.snippet)}</font>",
                            body_style
                        ),
                        "",
                    ],
                    [
                        Paragraph(
                            f"<b>Defect &amp; Non-Compliance:</b> {html.escape(defect_clean)}",
                            body_style
                        ),
                        "",
                    ],
                    [
                        Paragraph(
                            f"<b>Remediation:</b> {html.escape(f.fix)}<br/>"
                            f"<b>Mandate Implementation:</b> <font color='#065F46'>{html.escape(dossier['implication'])}</font>",
                            body_style
                        ),
                        "",
                    ],
                ]

                if f.patch_unified_diff:
                    card_data.append([
                        Paragraph(
                            f"<b>Auto-Fix Unified Patch:</b><br/>"
                            f"<font face='Courier' size='7'>{cls.format_diff(f.patch_unified_diff)}</font>",
                            body_style
                        ),
                        "",
                    ])

                if getattr(f, "ai_remediation", None):
                    card_data.append([
                        Paragraph(
                            f"<b>Local Ollama AI Defense Advisory:</b><br/>"
                            f"<font color='#065F46'>{html.escape(f.ai_remediation).replace(chr(10), '<br/>')}</font>",
                            body_style
                        ),
                        "",
                    ])

                f_table = Table(card_data, colWidths=[418, 130])
                table_styles = [
                    ('BACKGROUND', (0, 0), (-1, 0), sev_c),
                    ('SPAN', (0, 1), (1, 1)),
                    ('SPAN', (0, 2), (1, 2)),
                    ('SPAN', (0, 3), (1, 3)),
                    ('SPAN', (0, 4), (1, 4)),
                    ('SPAN', (0, 5), (1, 5)),
                    ('BACKGROUND', (0, 1), (-1, -1), c_light),
                    ('BACKGROUND', (0, 3), (1, 3), snippet_tint),
                    ('BOX', (0, 0), (-1, -1), 1.2, card_border),
                    ('LINEBELOW', (0, 0), (-1, -1), 0.5, c_border_light),
                    ('PADDING', (0, 0), (-1, -1), 5),
                ]
                current_row = 6
                if f.patch_unified_diff:
                    table_styles.append(('SPAN', (0, current_row), (1, current_row)))
                    table_styles.append(('BACKGROUND', (0, current_row), (1, current_row), colors.HexColor("#F0FDF4")))
                    current_row += 1
                if getattr(f, "ai_remediation", None):
                    table_styles.append(('SPAN', (0, current_row), (1, current_row)))
                    table_styles.append(('BACKGROUND', (0, current_row), (1, current_row), colors.HexColor("#ECFDF5")))
                    current_row += 1

                f_table.setStyle(TableStyle(table_styles))
                story.append(KeepTogether([f_table, Spacer(1, 10)]))

        if scan_result.malfunctions:
            story.append(PageBreak())
            story.append(Paragraph("6. Code Malfunctions & Concurrency Hazards", h1_style))
            story.append(Paragraph(
                "Software malfunctions, silent error swallowings, and unhandled failure modes identified during static analysis. "
                "Under DPDP Act Section 8(6), system malfunctions that jeopardize personal data integrity constitute actionable violations.",
                body_style
            ))
            story.append(Spacer(1, 8))

            malf_rows = [
                [Paragraph("<b>#</b>", body_style), Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Malfunction Type</b>", body_style), Paragraph("<b>Location</b>", body_style), Paragraph("<b>Defect & Recommended Fix</b>", body_style)]
            ]
            for midx, m in enumerate(scan_result.malfunctions, 1):
                m_sev = m.get("severity", "medium").lower()
                m_col = "#BE123C" if m_sev == "critical" else ("#EA580C" if m_sev == "high" else "#D97706")
                malf_rows.append([
                    Paragraph(str(midx), body_style),
                    Paragraph(f"<font color='{m_col}'><b>{m_sev.upper()}</b></font>", body_style),
                    Paragraph(f"<b>{html.escape(m.get('title', 'Malfunction'))}</b>", body_style),
                    Paragraph(f"<font face='Courier' size='7'>{html.escape(m.get('file', ''))}:{m.get('line', '')}</font>", body_style),
                    Paragraph(f"{html.escape(m.get('description', ''))}<br/><b>Fix:</b> {html.escape(m.get('fix', ''))}", body_style),
                ])
            malf_table = Table(malf_rows, colWidths=[28, 62, 140, 140, 178])
            malf_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#FEE2E2")),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(malf_table)

        if scan_result.third_party_egress:
            story.append(PageBreak())
            story.append(Paragraph("7. Third-Party Tracker & Data Egress Analysis", h1_style))
            story.append(Paragraph(
                "Third-party SDK integrations transmitting telemetry or user behavioral data without "
                "affirmative consent mechanisms (Sections 6 & 16, Rule 6) are detailed below.",
                body_style
            ))
            story.append(Spacer(1, 8))

            egress_rows = [
                [Paragraph("<b>#</b>", body_style), Paragraph("<b>Service / SDK</b>", body_style), Paragraph("<b>Category</b>", body_style), Paragraph("<b>Code Location</b>", body_style), Paragraph("<b>Statutory Egress Hazard</b>", body_style)]
            ]
            for eidx, e in enumerate(scan_result.third_party_egress, 1):
                egress_rows.append([
                    Paragraph(str(eidx), body_style),
                    Paragraph(f"<b>{html.escape(e.get('service', 'Unknown'))}</b>", body_style),
                    Paragraph(html.escape(e.get("category", "Analytics")), body_style),
                    Paragraph(f"<font face='Courier' size='7'>{html.escape(e.get('file', ''))}:{e.get('line', '')}</font>", body_style),
                    Paragraph(html.escape(e.get("description", "Potential external data transmission without consent")), body_style),
                ])
            egress_table = Table(egress_rows, colWidths=[28, 120, 110, 130, 160])
            egress_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#FEF3C7")),
                ('BOX', (0, 0), (-1, -1), 1, c_border),
                ('GRID', (0, 0), (-1, -1), 0.5, c_border),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(egress_table)

        doc.build(story, canvasmaker=NumberedCanvas)
        return str(dest)
