"""
DPDP-Audit Central Execution Pipeline
Systematically extracts, reads codebase files in-memory, triggers all analyzers,
and generates structured compliance results without terminal print clutter.
"""

import sys
import os
import json
import argparse
import time
from pathlib import Path
from typing import Dict, Any, Optional

from dpdp_audit.core.models import ScanResult
from dpdp_audit.core.rules_engine import RulesEngine
from dpdp_audit.analyzers.patch_generator import PatchGenerator
from dpdp_audit.report.pdf_generator import PdfGenerator

class CompliancePipeline:
    """Central orchestration pipeline for code analysis and report compilation."""

    @classmethod
    def execute(
        cls,
        target_path: str,
        session_dir: str,
        generate_pdf: bool = True,
        generate_patches: bool = True
    ) -> Dict[str, Any]:
        target = Path(target_path).resolve()
        session = Path(session_dir).resolve()
        session.mkdir(parents=True, exist_ok=True)

        pdf_path = session / "report.pdf"
        json_path = session / "out.json"
        patches_dir = session / "patches"

        # 1. Execute full scanning & code reading engine
        scan_result: ScanResult = RulesEngine.scan_target(str(target), run_consent=True)

        # 2. Compile Vector PDF Report
        if generate_pdf:
            PdfGenerator.generate(scan_result, str(pdf_path))

        # 3. Generate Unified Diff Patches
        if generate_patches:
            PatchGenerator.generate_patches(
                scan_result.findings,
                str(patches_dir),
                str(target),
                apply=False
            )

        # 4. Serialize to out.json
        result_dict = scan_result.to_dict()
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(result_dict, jf, indent=2)

        return result_dict

def main():
    parser = argparse.ArgumentParser(description="DPDP-Audit Pipeline Runner")
    parser.add_argument("--target", required=True, help="Path to target codebase")
    parser.add_argument("--session-dir", required=True, help="Path to session output directory")
    args = parser.parse_args()

    try:
        res = CompliancePipeline.execute(args.target, args.session_dir)
        # Output clean JSON on stdout for Node IPC
        print(json.dumps({"success": True, "data": res}))
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
