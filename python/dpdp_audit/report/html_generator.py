from pathlib import Path
from typing import List, Dict, Any
from ..core.models import ScanResult

class HtmlGenerator:

    @classmethod
    def generate(cls, scan_result: ScanResult, output_path: str) -> str:
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        sev = scan_result.summary.by_severity
        crit_cnt = sev.get("critical", 0)
        high_cnt = sev.get("high", 0)
        med_cnt = sev.get("medium", 0)
        low_cnt = sev.get("low", 0)

        cs = scan_result.consent_scorecard

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DPDP-Audit Compliance Report</title>
  <style>
    :root {{
      --primary: #0F2B5C;
      --accent: #FF8C00;
      --critical: #DC2626;
      --high: #EA580C;
      --medium: #D97706;
      --low: #2563EB;
      --bg: #F8FAFC;
      --card-bg: #FFFFFF;
      --text: #1E293B;
      --text-muted: #64748B;
      --border: #E2E8F0;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 32px 16px;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    header {{
      background: linear-gradient(135deg, var(--primary) 0%, #1E3A8A 100%);
      color: white;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
      margin-bottom: 24px;
    }}
    header h1 {{ font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
    header p {{ color: #93C5FD; font-size: 14px; margin-top: 6px; }}
    .badge-bar {{
      display: flex;
      gap: 16px;
      margin-top: 20px;
      flex-wrap: wrap;
    }}
    .badge {{
      background: rgba(255,255,255,0.15);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
    }}
    .grid-stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--card-bg);
      padding: 20px;
      border-radius: 10px;
      border: 1px solid var(--border);
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .stat-label {{ font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; }}
    .stat-val {{ font-size: 32px; font-weight: 800; margin-top: 4px; }}
    .val-critical {{ color: var(--critical); }}
    .val-high {{ color: var(--high); }}
    .val-medium {{ color: var(--medium); }}
    .val-low {{ color: var(--low); }}
    .val-score {{ color: var(--primary); }}

    section {{
      background: var(--card-bg);
      padding: 28px;
      border-radius: 10px;
      border: 1px solid var(--border);
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    h2 {{ font-size: 20px; font-weight: 700; margin-bottom: 16px; color: var(--primary); border-bottom: 2px solid var(--border); padding-bottom: 8px; }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 12px;
    }}
    th, td {{
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{ background: #F1F5F9; color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 11px; }}
    tr:hover {{ background: #F8FAFC; }}

    .finding-card {{
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 14px;
      overflow: hidden;
    }}
    .finding-header {{
      padding: 12px 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 700;
      color: white;
    }}
    .bg-critical {{ background: var(--critical); }}
    .bg-high {{ background: var(--high); }}
    .bg-medium {{ background: var(--medium); }}
    .bg-low {{ background: var(--low); }}

    .finding-body {{ padding: 16px; background: white; font-size: 13px; }}
    .code-box {{
      background: #0F172A;
      color: #38BDF8;
      padding: 12px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      overflow-x: auto;
      margin: 8px 0;
    }}
    .fix-box {{
      background: #F0FDF4;
      border-left: 4px solid #16A34A;
      padding: 10px;
      margin-top: 8px;
      color: #166534;
      font-size: 12px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>DPDP-Audit Compliance Report</h1>
      <p>Automated Statutory Assessment under India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025</p>
      <div class="badge-bar">
        <span class="badge">Target: {scan_result.target_path}</span>
        <span class="badge">Audited: {scan_result.timestamp}</span>
        <span class="badge">Health Score: {scan_result.summary.compliance_score}/100</span>
      </div>
    </header>

    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-label">Compliance Score</div>
        <div class="stat-val val-score">{scan_result.summary.compliance_score}<span style="font-size:16px;">/100</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical Findings</div>
        <div class="stat-val val-critical">{crit_cnt}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">High Findings</div>
        <div class="stat-val val-high">{high_cnt}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Findings</div>
        <div class="stat-val">{scan_result.summary.findings_count}</div>
      </div>
    </div>
"""

        if cs:
            html += f"""
    <section>
      <h2>Consent Flow Assessment Scorecard (Sections 5 & 6)</h2>
      <p style="font-size:14px; margin-bottom:12px;">
        Overall Consent Maturity: <b>Grade {cs.grade} ({cs.overall_score}/100)</b>
      </p>
      <table>
        <thead>
          <tr>
            <th>Statutory Pillar</th>
            <th>Score</th>
            <th>Status</th>
            <th>Audit Assessment</th>
          </tr>
        </thead>
        <tbody>
"""
            for pname, pdata in cs.pillars.items():
                st_color = "#16A34A" if pdata["passed"] else "#DC2626"
                st_badge = "PASSED" if pdata["passed"] else "GAP"
                html += f"""
          <tr>
            <td><b>{pname.replace('_', ' ').title()}</b></td>
            <td>{pdata['score']}/20</td>
            <td><span style="color:{st_color}; font-weight:700;">{st_badge}</span></td>
            <td>{pdata['details']}</td>
          </tr>
"""
            html += """
        </tbody>
      </table>
    </section>
"""

        html += """
    <section>
      <h2>DPDP Act 2023 & Rules 2025 Statutory Provision Coverage</h2>
      <table>
        <thead>
          <tr>
            <th>Provision</th>
            <th>Law</th>
            <th>Title & Scope</th>
            <th>Status</th>
            <th>Penalty Clause</th>
          </tr>
        </thead>
        <tbody>
"""
        for cov in scan_result.summary.dpdp_coverage:
            st_color = "#DC2626" if cov["status"] == "VIOLATION" else "#16A34A"
            html += f"""
          <tr>
            <td><b>{cov['provision']}</b></td>
            <td>{cov['law']}</td>
            <td><b>{cov['title']}</b></td>
            <td><span style="color:{st_color}; font-weight:700;">{cov['status']} ({cov['findingCount']})</span></td>
            <td><small>{cov['penaltyClause']}</small></td>
          </tr>
"""
        html += """
        </tbody>
      </table>
    </section>
"""

        html += f"""
    <section>
      <h2>Detailed Findings & Remediation Instructions ({len(scan_result.findings)})</h2>
"""
        for idx, f in enumerate(scan_result.findings, 1):
            bg_cls = f"bg-{f.severity}"
            html += f"""
      <div class="finding-card">
        <div class="finding-header {bg_cls}">
          <span>#{idx} [{f.id}] {f.title}</span>
          <span>{f.severity.upper()}</span>
        </div>
        <div class="finding-body">
          <p><b>Location:</b> <code>{f.file}:{f.line}</code> &nbsp;|&nbsp; <b>Flow:</b> <code>{f.data_flow.upper()}</code> &nbsp;|&nbsp; <b>PII:</b> {', '.join(f.pii_types) if f.pii_types else 'Infrastructure'}</p>
          <p style="margin-top:4px;"><b>Statutory Provision:</b> {f.dpdp_ref.get('sectionOrRule', '')} &mdash; <i>{f.dpdp_ref.get('explanation', '')}</i></p>
          <p style="margin-top:4px; color:#475569;"><b>Risk Logic:</b> {f.justification}</p>
          <div class="code-box">{f.snippet}</div>
          <div class="fix-box"><b>Recommended Fix:</b> {f.fix}</div>
        </div>
      </div>
"""
        html += """
    </section>
  </div>
</body>
</html>
"""

        with open(dest, "w", encoding="utf-8") as out_f:
            out_f.write(html)
        return str(dest)
