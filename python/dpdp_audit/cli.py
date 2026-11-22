import sys
import os
import json
import argparse
from pathlib import Path

from .core.rules_engine import RulesEngine
from .analyzers.consent_analyzer import ConsentAnalyzer
from .analyzers.patch_generator import PatchGenerator
from .analyzers.live_tester import LiveTester
from .report.pdf_generator import PdfGenerator
from .report.html_generator import HtmlGenerator
from .core.dpdp_mapper import DpdpMapper

def main():
    parser = argparse.ArgumentParser(
        prog="dpdp-audit",
        description="Automated Compliance Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # Command 1: scan
    scan_parser = subparsers.add_parser("scan", help="Scan code and configurations for DPDP non-compliance")
    scan_parser.add_argument("path", help="Target project root directory to scan")
    scan_parser.add_argument("--out", "-o", default=None, help="Output path for PDF compliance report (e.g. report.pdf)")
    scan_parser.add_argument("--json", "-j", default=None, help="Output path for JSON report (e.g. out.json)")
    scan_parser.add_argument("--html", default=None, help="Output path for interactive HTML report (e.g. report.html)")
    scan_parser.add_argument("--patches", "-p", default=None, help="Directory to output unified diff auto-fix patches")
    scan_parser.add_argument("--apply", action="store_true", help="Apply patches to target repository and create PR branch")

    # Command 2: consent
    consent_parser = subparsers.add_parser("consent", help="Assess consent architecture against DPDP Sections 5 & 6 and Rules 3 & 4")
    consent_parser.add_argument("path", help="Target project directory")

    # Command 3: live
    live_parser = subparsers.add_parser("live", help="Execute non-destructive live API compliance tests against running endpoint")
    live_parser.add_argument("baseUrl", help="Target base URL (e.g. http://localhost:3000)")

    # Command 4: list-rules
    subparsers.add_parser("list-rules", help="Print all registered checks, rules, and DPDP provisions")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        run_scan(args)
    elif args.command == "consent":
        run_consent(args)
    elif args.command == "live":
        run_live(args)
    elif args.command == "list-rules":
        run_list_rules()

def run_scan(args):
    target = os.path.abspath(args.path)
    print(f"\n[*] Starting DPDP-Audit Compliance Scan on: {target}")

    result = RulesEngine.scan_target(target, run_consent=True)
    summary = result.summary

    print(f"[+] Scanned {summary.scanned_files_count} files in {summary.scan_duration_ms:.1f}ms")
    print(f"[+] Findings Detected: {summary.findings_count}")
    print(f"    - Critical: {summary.by_severity['critical']}")
    print(f"    - High:     {summary.by_severity['high']}")
    print(f"    - Medium:   {summary.by_severity['medium']}")
    print(f"    - Low:      {summary.by_severity['low']}")
    print(f"[+] Overall Compliance Posture Score: {summary.compliance_score}/100\n")

    # Display Top 5 Findings in Terminal
    if result.findings:
        print("[!] Top Compliance Violations:")
        for idx, f in enumerate(result.findings[:5], 1):
            print(f"  {idx}. [{f.severity.upper()}] {f.title} ({f.file}:{f.line})")
            print(f"     Provision: {f.dpdp_ref.get('sectionOrRule', '')}")
            print(f"     Risk Logic: {f.justification}")
        print()

    # Generate JSON report if requested
    if args.json:
        json_path = os.path.abspath(args.json)
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(result.to_dict(), jf, indent=2)
        print(f"[+] Exported JSON report to: {json_path}")

    # Generate HTML report if requested
    if args.html:
        html_path = os.path.abspath(args.html)
        HtmlGenerator.generate(result, html_path)
        print(f"[+] Generated HTML report at: {html_path}")

    # Generate PDF report if requested (or default if --out passed)
    if args.out:
        pdf_path = os.path.abspath(args.out)
        PdfGenerator.generate(result, pdf_path)
        print(f"[+] Generated PDF report at: {pdf_path}")

    # Generate patches if requested
    if args.patches:
        patch_res = PatchGenerator.generate_patches(
            result.findings,
            args.patches,
            target,
            apply=args.apply
        )
        print(f"[+] Generated {patch_res['generated_count']} auto-fix patch files in: {patch_res['patches_dir']}")
        if patch_res["applied"]:
            print(f"[+] Applied fixes to branch: {patch_res['pr_info']['branch']}")
            print(f"[+] Created PR summary at: {patch_res['pr_info']['pr_summary_file']}")

def run_consent(args):
    target = os.path.abspath(args.path)
    print(f"\n[*] Evaluating Consent Architecture on: {target}\n")
    scorecard = ConsentAnalyzer.assess_project(target)

    print(f"============================================================")
    print(f" CONSENT MATURITY SCORECARD: Grade {scorecard.grade} ({scorecard.overall_score}/100)")
    print(f"============================================================")
    for p_name, p_data in scorecard.pillars.items():
        st = "PASSED [OK]" if p_data["passed"] else "GAP [FAIL]"
        print(f"  * {p_name.replace('_', ' ').title():<15}: {p_data['score']:>2}/20  [{st}]  {p_data['details']}")
    print()

    if scorecard.recommendations:
        print("Remediation Recommendations:")
        for r in scorecard.recommendations:
            print(f"  - {r}")
        print()

def run_live(args):
    res = LiveTester.run_tests(args.baseUrl)
    print(f"\n[*] Tested {res.endpoints_tested} requests against {res.base_url}")
    print(f"    - Passed:   {res.summary['passed']}")
    print(f"    - Failed:   {res.summary['failed']}")
    print(f"    - Warnings: {res.summary['warnings']}\n")

    if res.findings:
        print("[!] Live Compliance Observations:")
        for f in res.findings:
            print(f"  [{f.status}] {f.test_name} ({f.endpoint})")
            print(f"      Severity: {f.severity.upper()} | DPDP: {f.dpdp_ref}")
            print(f"      Details:  {f.details}")
        print()

def run_list_rules():
    rules = RulesEngine.load_rules()
    dpdp_map = DpdpMapper.load_map()

    print(f"\nRegistered DPDP-Audit Compliance Rules ({len(rules)} total):\n")
    print(f"{'RULE ID':<15} | {'SEVERITY':<8} | {'CATEGORY':<10} | {'DPDP PROVISION':<16} | {'RULE TITLE'}")
    print("-" * 90)
    for r in sorted(rules, key=lambda x: (x.category, x.id)):
        prov = dpdp_map.get(r.dpdp_ref)
        prov_str = prov.provision if prov else r.dpdp_ref
        print(f"{r.id:<15} | {r.severity.upper():<8} | {r.category:<10} | {prov_str:<16} | {r.title}")
    print()

if __name__ == "__main__":
    main()
