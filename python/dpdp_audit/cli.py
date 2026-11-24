import sys
import os
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .core.rules_engine import RulesEngine
from .core.pii_detector import PiiDetector
from .core.dpdp_mapper import DpdpMapper
from .core.file_walker import FileWalker
from .core.ollama_service import OllamaService
from .analyzers.consent_analyzer import ConsentAnalyzer
from .analyzers.third_party_analyzer import ThirdPartyAnalyzer
from .analyzers.patch_generator import PatchGenerator
from .analyzers.live_tester import LiveTester
from .report.pdf_generator import PdfGenerator
from .report.html_generator import HtmlGenerator

console = Console()

VERSION = "1.0.0"
KNOWN_COMMANDS = {
    "scan", "pii", "consent", "egress", "live", "rules", "list-rules",
    "penalty", "patch", "coderabbit", "info", "version", "ai", "explain", "rag",
    "-h", "--help", "-v", "--version"
}

def print_banner():
    banner_text = Text()
    banner_text.append("🛡️  CODE-DPDP", style="bold cyan")
    banner_text.append(" | Automated Compliance & Security Scanner\n", style="bold white")
    banner_text.append("India Digital Personal Data Protection Act 2023 & DPDP Rules 2025", style="italic yellow")
    console.print(Panel(banner_text, box=box.ROUNDED, border_style="cyan"))

def calculate_penalty_details(findings: List[Any]) -> Dict[str, Any]:
    if not findings:
        return {
            "tier": "Tier 0 (Compliant)",
            "maxFine": "Rs. 0",
            "statutoryClause": "Compliant - No violations identified",
            "severityColor": "green"
        }

    has_safeguards_8_5 = any(
        f.severity == "critical" and ("8(5)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 6" in str(f.dpdp_ref.get("sectionOrRule", "")))
        for f in findings
    )
    has_child_9 = any("9" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 8" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
    has_breach_8_6 = any("8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 7" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
    has_sdf_10 = any("10" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)
    has_consent_notice = any("6(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "5(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Section 6" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in findings)

    if has_safeguards_8_5:
        return {
            "tier": "Tier 1: Maximum Statutory Ceiling",
            "maxFine": "Rs. 250 Crore",
            "statutoryClause": "Schedule Item 1: Failure to take reasonable security safeguards (Sec 8(5) & Rule 6)",
            "severityColor": "bold red"
        }
    elif has_child_9:
        return {
            "tier": "Tier 2: Child Privacy Hazard",
            "maxFine": "Rs. 200 Crore",
            "statutoryClause": "Schedule Item 3: Child data tracking or parental consent violation (Sec 9)",
            "severityColor": "bold bright_red"
        }
    elif has_breach_8_6:
        return {
            "tier": "Tier 2: Breach Notification Hazard",
            "maxFine": "Rs. 200 Crore",
            "statutoryClause": "Schedule Item 2: Failure to notify personal data breach (Sec 8(6) & Rule 7)",
            "severityColor": "bold bright_red"
        }
    elif has_sdf_10:
        return {
            "tier": "Tier 3: Significant Data Fiduciary Non-Compliance",
            "maxFine": "Rs. 150 Crore",
            "statutoryClause": "Schedule Item 4: Failure to appoint DPO or conduct DPIA (Sec 10)",
            "severityColor": "bold yellow"
        }
    elif has_consent_notice:
        return {
            "tier": "Tier 4: Consent & Notice Violation",
            "maxFine": "Rs. 50 Crore",
            "statutoryClause": "Schedule Item 7: Breach of consent or notice obligations (Sec 5 & 6)",
            "severityColor": "bold yellow"
        }
    else:
        return {
            "tier": "Tier 4: Statutory Non-Compliance",
            "maxFine": "Rs. 50 Crore",
            "statutoryClause": "Schedule Item 7: General statutory non-compliance with Act or Rules",
            "severityColor": "bold yellow"
        }

def run_scan(args):
    target = os.path.abspath(args.path)
    use_ai = getattr(args, "ollama", False) or getattr(args, "ai", False) or (getattr(args, "command", "") == "ai")

    console.print(f"\n[bold cyan][*][/bold cyan] Initiating DPDP compliance scan on: [bold]{target}[/bold]...")

    result = RulesEngine.scan_target(target, run_consent=True)
    summary = result.summary
    penalty = calculate_penalty_details(result.findings)

    if use_ai:
        if OllamaService.is_available():
            from .core.rag_pipeline import RagPipeline
            active_model = OllamaService.get_active_model()
            console.print(f"[bold green][*] RAG & Local Ollama Pipeline Active:[/bold green] Retrieving DPDP Act 2023 statutes and synthesizing defenses via [cyan]{active_model}[/cyan]...")
            critical_findings = [f for f in result.findings if f.severity == "critical"]
            for f in critical_findings[:10]:
                rag_res = RagPipeline.augment_finding_remediation(f.title, f.snippet, f.file, f.fix)
                if rag_res.get("ai_remediation"):
                    f.ai_remediation = rag_res["ai_remediation"]
            console.print(f"[bold green][✓] RAG Statutory Citations & Ollama Defenses attached to findings.[/bold green]")
        else:
            console.print(f"[dim yellow][!] Local Ollama is not active on http://localhost:11434. Continuing without LLM enrichment.[/dim yellow]")

    score_color = "bold green" if summary.compliance_score >= 80 else ("bold yellow" if summary.compliance_score >= 50 else "bold red")

    summary_table = Table(box=box.SIMPLE_HEAVY, show_header=False)
    summary_table.add_row("[bold]Scanned Files[/bold]", f"{summary.scanned_files_count} files ({summary.scan_duration_ms:.1f}ms)")
    summary_table.add_row("[bold]Compliance Posture Score[/bold]", f"[{score_color}]{summary.compliance_score} / 100[/{score_color}]")
    summary_table.add_row("[bold]Statutory Penalty Exposure[/bold]", f"[{penalty['severityColor']}]{penalty['maxFine']}[/{penalty['severityColor']}] &mdash; {penalty['statutoryClause']}")
    summary_table.add_row(
        "[bold]Findings Breakdown[/bold]",
        f"[bold red]Critical: {summary.by_severity['critical']}[/bold red] | "
        f"[bold bright_red]High: {summary.by_severity['high']}[/bold bright_red] | "
        f"[bold yellow]Medium: {summary.by_severity['medium']}[/bold yellow] | "
        f"[bold cyan]Low: {summary.by_severity['low']}[/bold cyan]"
    )
    if use_ai and OllamaService.is_available():
        summary_table.add_row("[bold]AI Copilot[/bold]", f"[bold green]Ollama Local ({OllamaService.get_active_model()})[/bold green]")

    console.print(Panel(summary_table, title="[bold white]Audit Executive Summary[/bold white]", border_style="cyan"))

    if result.findings:
        findings_to_show = result.findings
        if getattr(args, "severity", None):
            sev_filter = args.severity.lower()
            findings_to_show = [f for f in findings_to_show if f.severity.lower() == sev_filter]

        table = Table(title=f"All Real Compliance & Security Violations ({len(result.findings)} Total)", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("#", style="dim", width=5)
        table.add_column("Severity", width=10)
        table.add_column("Violation", style="bold white", width=28)
        table.add_column("File:Line", style="cyan", width=26)
        table.add_column("DPDP Section", style="magenta", width=14)
        table.add_column("Risk Justification", style="dim", width=36)

        for idx, f in enumerate(findings_to_show[:20], 1):
            sev_style = (
                "bold red" if f.severity == "critical"
                else ("bold bright_red" if f.severity == "high"
                else ("bold yellow" if f.severity == "medium"
                else "bold cyan"))
            )
            table.add_row(
                str(idx),
                f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
                f.title,
                f"{f.file}:{f.line}",
                f.dpdp_ref.get("sectionOrRule", ""),
                f.justification[:60] + "..." if len(f.justification) > 60 else f.justification
            )

        console.print(table)
        if len(findings_to_show) > 20:
            console.print(f"[dim](Showing top 20 of {len(findings_to_show)} findings. ALL {len(result.findings)} findings are fully documented in the PDF report!)[/dim]\n")
    else:
        console.print("\n[bold green][✓] Perfect Score! No DPDP Act 2023 or DPDP Rules 2025 non-compliance violations detected.[/bold green]\n")

    pdf_target = getattr(args, "pdf", None) or getattr(args, "out", None)
    if pdf_target:
        pdf_path = os.path.abspath(pdf_target)
        console.print(f"[bold cyan][*][/bold cyan] Compiling complete audit report into PDF: [bold]{pdf_path}[/bold]...")
        PdfGenerator.generate(result, pdf_path)
        console.print(f"[bold green][✓] Official PDF Compliance Report Generated:[/bold green] [bold cyan]{pdf_path}[/bold cyan] ({len(result.findings)} total findings included)")

    if getattr(args, "json", None):
        json_path = os.path.abspath(args.json)
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(result.to_dict(), jf, indent=2)
        console.print(f"[bold green][✓] JSON Findings Exported:[/bold green] [bold cyan]{json_path}[/bold cyan]")

    if getattr(args, "html", None):
        html_path = os.path.abspath(args.html)
        HtmlGenerator.generate(result, html_path)
        console.print(f"[bold green][✓] HTML Interactive Report Generated:[/bold green] [bold cyan]{html_path}[/bold cyan]")

    if getattr(args, "patches", None):
        patch_res = PatchGenerator.generate_patches(
            result.findings,
            args.patches,
            target,
            apply=getattr(args, "apply", False)
        )
        console.print(f"[bold green][✓] Generated {patch_res['generated_count']} Auto-Fix Patches in:[/bold green] [bold cyan]{patch_res['patches_dir']}[/bold cyan]")
        if patch_res["applied"]:
            console.print(f"[bold green][✓] Applied Fixes to Branch:[/bold green] {patch_res['pr_info']['branch']}")

    if not pdf_target:
        console.print("[dim]💡 Tip: Run `code-dpdp --pdf result.pdf` to generate an official PDF containing all findings.[/dim]\n")

    if getattr(args, "fail_on", None):
        fail_sev = args.fail_on.lower()
        severities = ["low", "medium", "high", "critical"]
        if fail_sev in severities:
            threshold_idx = severities.index(fail_sev)
            for f in result.findings:
                if f.severity.lower() in severities[threshold_idx:]:
                    console.print(f"[bold red][!] CI Failure: Found violation matching --fail-on {fail_sev}[/bold red]")
                    sys.exit(1)

def run_pii(args):
    target = os.path.abspath(args.path)
    console.print(f"\n[bold cyan][*][/bold cyan] Scanning for Indian PII & Credentials in: [bold]{target}[/bold]...")

    root = Path(target)
    pii_records = []

    for file_path in FileWalker.walk(str(root)):
        rel_path = str(file_path.relative_to(root))
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, 1):
                    detections = PiiDetector.scan_text(line, line_no=line_idx)
                    for d in detections:
                        pii_records.append({
                            "file": rel_path,
                            "line": line_idx,
                            "type": d.type,
                            "term": d.value_snippet if getattr(args, "redact", True) else d.matched_term,
                            "confidence": f"{int(d.confidence * 100)}%"
                        })
        except Exception:
            continue

    if pii_records:
        table = Table(title=f"Indian PII & Sensitive Data Detected ({len(pii_records)} occurrences)", box=box.ROUNDED, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", style="bold yellow", width=14)
        table.add_column("File:Line", style="cyan", width=36)
        table.add_column("Confidence", style="green", width=12)
        table.add_column("Value (Masked)", style="bold white")

        for idx, p in enumerate(pii_records[:25], 1):
            table.add_row(str(idx), p["type"].upper(), f"{p['file']}:{p['line']}", p["confidence"], p["term"])

        console.print(table)
        if len(pii_records) > 25:
            console.print(f"[dim](Showing top 25 of {len(pii_records)} personal data occurrences)[/dim]\n")
    else:
        console.print("\n[bold green][✓] No unmasked Indian personal data (Aadhaar, PAN, Cards, Passwords) detected![/bold green]\n")

    if getattr(args, "json", None):
        json_path = os.path.abspath(args.json)
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(pii_records, jf, indent=2)
        console.print(f"[bold green][✓] Exported PII results to:[/bold green] {json_path}")

def run_consent(args):
    target = os.path.abspath(args.path)
    console.print(f"\n[bold cyan][*][/bold cyan] Auditing Consent Architecture on: [bold]{target}[/bold]...")
    scorecard = ConsentAnalyzer.assess_project(target)

    grade_style = "bold green" if scorecard.grade in ("A+", "A") else ("bold yellow" if scorecard.grade == "B" else "bold red")
    console.print(Panel(
        f"Overall Maturity: [{grade_style}]Grade {scorecard.grade} ({scorecard.overall_score}/100)[/{grade_style}]\n"
        "Statutory Reference: DPDP Act 2023 Sections 5 & 6 and DPDP Rules 2025 Rules 3 & 4",
        title="[bold white]DPDP 5-Pillar Consent Scorecard[/bold white]",
        border_style="cyan"
    ))

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Statutory Pillar", style="bold white", width=22)
    table.add_column("Score", style="yellow", width=10)
    table.add_column("Status", width=12)
    table.add_column("Technical Evaluation", style="dim")

    for p_name, p_data in scorecard.pillars.items():
        st_style = "[bold green]PASSED[/bold green]" if p_data["passed"] else "[bold red]GAP [FAIL][/bold red]"
        table.add_row(
            p_name.replace("_", " ").title(),
            f"{p_data['score']}/20",
            st_style,
            p_data["details"]
        )

    console.print(table)

    if scorecard.recommendations:
        console.print("\n[bold yellow]Statutory Remediation Steps:[/bold yellow]")
        for idx, rec in enumerate(scorecard.recommendations, 1):
            console.print(f"  [cyan]{idx}.[/cyan] {rec}")
    console.print()

def run_egress(args):
    target = os.path.abspath(args.path)
    console.print(f"\n[bold cyan][*][/bold cyan] Auditing Third-Party Trackers & Data Egress in: [bold]{target}[/bold]...")

    root = Path(target)
    egress_items = []
    for file_path in FileWalker.walk(str(root)):
        if file_path.suffix.lower() in (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".py", ".html"):
            items = ThirdPartyAnalyzer.analyze_file(file_path, root)
            egress_items.extend(items)

    if egress_items:
        table = Table(title=f"Third-Party SDK & Data Egress Streams ({len(egress_items)} detected)", box=box.ROUNDED, header_style="bold red")
        table.add_column("#", style="dim", width=4)
        table.add_column("Service / Tracker", style="bold yellow", width=20)
        table.add_column("Location", style="cyan", width=30)
        table.add_column("Category", style="magenta", width=16)
        table.add_column("DPDP Statutory Risk", style="dim")

        for idx, it in enumerate(egress_items[:20], 1):
            table.add_row(
                str(idx),
                it.get("service", "Unknown"),
                f"{it.get('file', '')}:{it.get('line', '')}",
                it.get("category", "Analytics"),
                it.get("description", "Potential transmission without verified affirmative consent")
            )

        console.print(table)
    else:
        console.print("\n[bold green][✓] No un-gated third-party tracking or egress SDKs detected.[/bold green]\n")

def run_live(args):
    print_banner()
    res = LiveTester.run_tests(args.baseUrl)

    summary_panel = Panel(
        f"Endpoints Tested: [bold]{res.endpoints_tested}[/bold]\n"
        f"Passed: [bold green]{res.summary['passed']}[/bold green] | "
        f"Failed: [bold red]{res.summary['failed']}[/bold red] | "
        f"Warnings: [bold yellow]{res.summary['warnings']}[/bold yellow]",
        title=f"[bold white]Live API Audit: {res.base_url}[/bold white]",
        border_style="cyan"
    )
    console.print(summary_panel)

    if res.findings:
        table = Table(title="Live Endpoint Observations", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Status", width=10)
        table.add_column("Check / Probe", style="bold white", width=26)
        table.add_column("Endpoint", style="cyan", width=24)
        table.add_column("Severity", width=10)
        table.add_column("DPDP Reference", style="magenta", width=14)
        table.add_column("Details", style="dim")

        for f in res.findings:
            st_style = "bold green" if f.status == "PASS" else ("bold red" if f.status == "FAIL" else "yellow")
            table.add_row(
                f"[{st_style}]{f.status}[/{st_style}]",
                f.test_name,
                f.endpoint,
                f.severity.upper(),
                f.dpdp_ref,
                f.details
            )
        console.print(table)
    console.print()

def run_penalty(args):
    target = os.path.abspath(args.path)
    console.print(f"\n[bold cyan][*][/bold cyan] Computing statutory financial penalty exposure for: [bold]{target}[/bold]...")

    result = RulesEngine.scan_target(target, run_consent=True)
    penalty = calculate_penalty_details(result.findings)

    pen_table = Table(box=box.ROUNDED, header_style="bold red")
    pen_table.add_column("Schedule Item", style="bold white", width=18)
    pen_table.add_column("Statutory Offense", width=34)
    pen_table.add_column("Statutory Penalty Ceiling", style="bold red", width=18)
    pen_table.add_column("Project Audit Status", width=22)

    crit_safeguards = any(
        f.severity == "critical" and ("8(5)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 6" in str(f.dpdp_ref.get("sectionOrRule", "")))
        for f in result.findings
    )
    breach = any("8(6)" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 7" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in result.findings)
    child = any("9" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Rule 8" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in result.findings)
    sdf = any("10" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in result.findings)
    consent = any("6(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "5(" in str(f.dpdp_ref.get("sectionOrRule", "")) or "Section 6" in str(f.dpdp_ref.get("sectionOrRule", "")) for f in result.findings)

    pen_table.add_row(
        "Item 1 (Sec 8(5) / Rule 6)",
        "Failure to take reasonable security safeguards to prevent personal data breach",
        "Up to Rs. 250 Crore",
        "[bold red]EXPOSED (Critical Risk)[/bold red]" if crit_safeguards else "[bold green]Compliant[/bold green]"
    )
    pen_table.add_row(
        "Item 2 (Sec 8(6) / Rule 7)",
        "Failure to notify personal data breach to DPB and Data Principals",
        "Up to Rs. 200 Crore",
        "[bold red]EXPOSED (High Risk)[/bold red]" if breach else "[bold green]Compliant[/bold green]"
    )
    pen_table.add_row(
        "Item 3 (Sec 9 / Rule 8)",
        "Breach of obligations regarding processing data of children",
        "Up to Rs. 200 Crore",
        "[bold red]EXPOSED (High Risk)[/bold red]" if child else "[bold green]Compliant[/bold green]"
    )
    pen_table.add_row(
        "Item 4 (Sec 10)",
        "Breach of Significant Data Fiduciary obligations (DPO, DPIA, Audits)",
        "Up to Rs. 150 Crore",
        "[bold yellow]EXPOSED (Medium Risk)[/bold yellow]" if sdf else "[bold green]Compliant[/bold green]"
    )
    pen_table.add_row(
        "Item 7 (Sec 5, 6, 8(7), 16)",
        "Breach in respect of consent, notice, storage limitation, or cross-border rules",
        "Up to Rs. 50 Crore",
        "[bold yellow]EXPOSED (Medium Risk)[/bold yellow]" if consent else ("[bold yellow]EXPOSED[/bold yellow]" if result.findings else "[bold green]Compliant[/bold green]")
    )

    console.print(Panel(
        f"Maximum Financial Liability: [{penalty['severityColor']}]{penalty['maxFine']}[/{penalty['severityColor']}]\n"
        f"Risk Category: [bold]{penalty['tier']}[/bold]\n"
        f"Key Trigger: {penalty['statutoryClause']}",
        title="[bold white]DPDP Act 2023 Statutory Penalty Verdict[/bold white]",
        border_style="red"
    ))
    console.print(pen_table)
    console.print()

def run_explain(args):
    print_banner()
    query = args.query.strip()
    if not OllamaService.is_available():
        console.print("[bold red][!] Local Ollama is not active on http://localhost:11434.[/bold red]")
        console.print("Ensure Ollama daemon is running (`ollama serve`) and try again.")
        return

    model = OllamaService.get_active_model()
    console.print(f"[bold cyan][*][/bold cyan] Consulting local Ollama ([bold]{model}[/bold]) for: [bold white]{query}[/bold white]...\n")

    prompt = (
        f"You are an expert cybersecurity defense engineer and India DPDP Act 2023 compliance auditor. "
        f"Provide a structured technical defense brief for: '{query}'.\n"
        f"Cover:\n"
        f"1. How this vulnerability or defect compromises system security/privacy.\n"
        f"2. Which India DPDP Act 2023 provision applies (e.g. Section 8(6) security safeguards, Section 6 consent).\n"
        f"3. Concrete secure code remediation example with before/after code."
    )
    res = OllamaService.generate(prompt)
    if res:
        console.print(Panel(res, title=f"[bold green]Ollama Defensive Intelligence ({model})[/bold green]", border_style="green"))
    else:
        console.print("[bold red]Failed to receive response from local Ollama.[/bold red]")

def run_rag(args):
    print_banner()
    query = args.query.strip()
    console.print(f"[bold cyan][*] RAG Statutory Rulebook Search:[/bold cyan] [bold white]{query}[/bold white]\n")
    from .core.rag_pipeline import RagPipeline
    res = RagPipeline.query_rulebook(query)

    table = Table(title="DPDP Act 2023 & DPDP Rules 2025 Statutory Provisions", box=box.ROUNDED)
    table.add_column("Provision / Section", style="bold cyan", width=26)
    table.add_column("Statutory Title & Penalty", style="bold yellow", width=34)
    table.add_column("Official Gazette Text", style="white")

    for item in res["retrieved_provisions"]:
        table.add_row(
            item["statutory_citation"],
            f"[bold]{item['title']}[/bold]\n[bold red]{item['penalty']}[/bold red]",
            f"\"{item['official_text']}\"\n\n[dim italic]Technical Mandate: {item['technical_implication']}[/dim italic]"
        )
    console.print(table)
    console.print()

    if res.get("ai_synthesis"):
        console.print(Panel(
            res["ai_synthesis"],
            title="[bold green]Local Ollama Legal-Technical Defense Synthesis (RAG Grounded)[/bold green]",
            border_style="green",
            box=box.ROUNDED
        ))
        console.print()

def run_patch(args):
    target = os.path.abspath(args.path)
    output_dir = getattr(args, "patches_dir", "patches")
    console.print(f"\n[bold cyan][*][/bold cyan] Generating unified remediation patches for: [bold]{target}[/bold]...")

    result = RulesEngine.scan_target(target, run_consent=False)
    patch_res = PatchGenerator.generate_patches(
        result.findings,
        output_dir,
        target,
        apply=getattr(args, "apply", False)
    )
    console.print(f"[bold green][✓] Generated {patch_res['generated_count']} patch files in:[/bold green] [bold cyan]{patch_res['patches_dir']}[/bold cyan]")
    if patch_res["applied"]:
        console.print(f"[bold green][✓] Applied fixes to branch:[/bold green] {patch_res['pr_info']['branch']}")

def run_coderabbit(args):
    target = os.path.abspath(args.path)
    cfg_path = Path(target) / ".coderabbit.yaml"
    content = """language: "en-US"
reviews:
  profile: "assertive"
  request_changes_workflow: true
knowledge_base:
  instructions: |
    Audit all code changes against India DPDP Act 2023 & Rules 2025:
    1. Reject unencrypted personal data (Aadhaar, PAN, phone, email, health records).
    2. Require affirmative consent checks before third-party data egress (Sec 6 & 16).
    3. Block logging of credentials or personal data in console/syslog (Sec 8(6)).
    4. Mandate data erasure endpoints (Right to be Forgotten - Sec 12).
    5. Block behavioural tracking of minors (Sec 9).
"""
    cfg_path.write_text(content, encoding="utf-8")
    console.print(f"\n[bold green][✓] Generated CodeRabbit AI PR Gating Contract:[/bold green] [bold cyan]{cfg_path}[/bold cyan]\n")

def run_list_rules():
    rules = RulesEngine.load_rules()
    dpdp_map = DpdpMapper.load_map()

    table = Table(title=f"DPDP Act 2023 Statutory Rules Registry ({len(rules)} Rules)", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Rule ID", style="bold white", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Category", style="yellow", width=12)
    table.add_column("DPDP Section", style="magenta", width=16)
    table.add_column("Statutory Penalty", style="bold red", width=22)
    table.add_column("Description", style="dim")

    for r in sorted(rules, key=lambda x: (x.category, x.id)):
        prov = dpdp_map.get(r.dpdp_ref)
        prov_str = prov.provision if prov else r.dpdp_ref
        pen_str = prov.penalty_clause if prov else "Schedule Item 5: Up to Rs. 50 Cr"
        sev_style = "bold red" if r.severity == "critical" else ("bold yellow" if r.severity == "high" else "yellow")

        table.add_row(
            r.id,
            f"[{sev_style}]{r.severity.upper()}[/{sev_style}]",
            r.category,
            prov_str,
            pen_str[:22],
            r.title
        )

    console.print(table)
    console.print()

def run_info():
    print_banner()
    rules = RulesEngine.load_rules()
    dpdp_map = DpdpMapper.load_map()

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_row("[bold]CLI Command[/bold]", "code-dpdp")
    table.add_row("[bold]Version[/bold]", VERSION)
    table.add_row("[bold]Statutory Provisions[/bold]", f"{len(dpdp_map)} sections mapped (DPDP Act 2023 & DPDP Rules 2025)")
    table.add_row("[bold]Active Security & SAST Rules[/bold]", f"{len(rules)} statutory rules + OWASP Top 10 real vulnerability engine")
    table.add_row("[bold]Semgrep SAST Engine[/bold]", "[bold green]Active (v1.186.0)[/bold green] with DPDP Act & OWASP AST Rules")
    table.add_row("[bold]Maximum Statutory Penalty[/bold]", "Rs. 250 Crore (Schedule Item 1 / Sec 8(6))")

    if OllamaService.is_available():
        ollama_status = f"[bold green]Connected ({OllamaService.get_active_model()})[/bold green] at {OllamaService.get_base_url()}"
    else:
        ollama_status = "[dim yellow]Not running (start with `ollama serve`)[/dim yellow]"
    table.add_row("[bold]Local Ollama LLM[/bold]", ollama_status)

    table.add_row("[bold]Python Runtime[/bold]", sys.executable)
    console.print(table)
    console.print()

def main():
    raw_args = sys.argv[1:]

    if not raw_args:
        raw_args = ["scan", "."]
    elif raw_args[0] not in KNOWN_COMMANDS and not raw_args[0].startswith("-"):
        raw_args = ["scan"] + raw_args
    elif raw_args[0].startswith("-") and raw_args[0] not in ("-h", "--help", "-v", "--version"):
        raw_args = ["scan", "."] + raw_args

    parser = argparse.ArgumentParser(
        prog="code-dpdp",
        description="Automated Compliance & Security Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025"
    )
    parser.add_argument("-v", "--version", action="version", version=f"code-dpdp v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan code and configs for DPDP compliance & security violations")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target directory to scan (default: current directory)")
    scan_parser.add_argument("--pdf", "-o", "--out", default=None, help="Output path for PDF compliance report (e.g. result.pdf)")
    scan_parser.add_argument("--json", "-j", default=None, help="Output path for JSON report (e.g. out.json)")
    scan_parser.add_argument("--html", default=None, help="Output path for interactive HTML report (e.g. report.html)")
    scan_parser.add_argument("--patches", "-p", default=None, help="Directory to output auto-fix patch files")
    scan_parser.add_argument("--apply", action="store_true", help="Apply generated patches to a new branch")
    scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter findings by minimum severity")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Exit with non-zero status code if findings match")
    scan_parser.add_argument("--ollama", "--ai", dest="ollama", action="store_true", help="Use local Ollama LLM (localhost:11434) for AI remediation analysis")

    ai_parser = subparsers.add_parser("ai", help="Scan with local Ollama LLM defensive remediation analysis")
    ai_parser.add_argument("path", nargs="?", default=".", help="Target directory to scan")
    ai_parser.add_argument("--pdf", "-o", "--out", default=None, help="Output path for PDF compliance report (e.g. result.pdf)")
    ai_parser.add_argument("--json", "-j", default=None, help="Output path for JSON report")

    explain_parser = subparsers.add_parser("explain", help="Consult local Ollama LLM about a security flaw or DPDP requirement")
    explain_parser.add_argument("query", help="Vulnerability name, CWE, or DPDP provision (e.g. 'SQL injection' or 'Aadhaar masking')")

    rag_parser = subparsers.add_parser("rag", help="Query DPDP Act 2023 & Rules 2025 rulebook via RAG pipeline")
    rag_parser.add_argument("query", help="Compliance question, vulnerability, or statutory section to query")

    pii_parser = subparsers.add_parser("pii", help="Scan for Indian PII (Aadhaar, PAN, phone, cards, passwords)")
    pii_parser.add_argument("path", nargs="?", default=".", help="Target directory to scan")
    pii_parser.add_argument("--no-redact", dest="redact", action="store_false", default=True, help="Display unredacted values in terminal")
    pii_parser.add_argument("--json", "-j", default=None, help="Export PII detections to JSON")

    consent_parser = subparsers.add_parser("consent", help="Assess 5-pillar consent architecture (DPDP Sec 5 & 6)")
    consent_parser.add_argument("path", nargs="?", default=".", help="Target directory to audit")

    egress_parser = subparsers.add_parser("egress", help="Detect third-party SDK and tracking egress without consent")
    egress_parser.add_argument("path", nargs="?", default=".", help="Target directory to audit")

    live_parser = subparsers.add_parser("live", help="Non-destructive live API privacy and security probe")
    live_parser.add_argument("baseUrl", help="Target base URL (e.g. http://localhost:3000)")

    penalty_parser = subparsers.add_parser("penalty", help="Calculate statutory penalty exposure under DPDP Act Schedule")
    penalty_parser.add_argument("path", nargs="?", default=".", help="Target directory to evaluate")

    patch_parser = subparsers.add_parser("patch", help="Generate auto-fix remediation patches")
    patch_parser.add_argument("path", nargs="?", default=".", help="Target directory to patch")
    patch_parser.add_argument("--patches-dir", default="patches", help="Directory for patch files")
    patch_parser.add_argument("--apply", action="store_true", help="Apply patches directly")

    coderabbit_parser = subparsers.add_parser("coderabbit", help="Generate DPDP Act .coderabbit.yaml rule contract")
    coderabbit_parser.add_argument("path", nargs="?", default=".", help="Target directory to generate contract into")

    subparsers.add_parser("rules", help="List all statutory DPDP rules and statutory penalty ceilings")
    subparsers.add_parser("list-rules", help="List all statutory DPDP rules and statutory penalty ceilings")

    subparsers.add_parser("info", help="Display system information, active rules count, and Ollama status")
    subparsers.add_parser("version", help="Display code-dpdp version")

    args = parser.parse_args(raw_args)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print(f"code-dpdp v{VERSION}")
        sys.exit(0)
    elif args.command in ("scan", "ai"):
        print_banner()
        run_scan(args)
    elif args.command == "explain":
        run_explain(args)
    elif args.command == "rag":
        run_rag(args)
    elif args.command == "pii":
        print_banner()
        run_pii(args)
    elif args.command == "consent":
        print_banner()
        run_consent(args)
    elif args.command == "egress":
        print_banner()
        run_egress(args)
    elif args.command == "live":
        run_live(args)
    elif args.command == "penalty":
        print_banner()
        run_penalty(args)
    elif args.command == "patch":
        print_banner()
        run_patch(args)
    elif args.command == "coderabbit":
        print_banner()
        run_coderabbit(args)
    elif args.command in ("rules", "list-rules"):
        print_banner()
        run_list_rules()
    elif args.command == "info":
        run_info()

if __name__ == "__main__":
    main()
