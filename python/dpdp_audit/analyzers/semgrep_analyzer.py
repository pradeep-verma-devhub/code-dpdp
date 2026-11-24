import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.models import Finding, Severity, DataFlow
from ..core.rag_pipeline import RagPipeline

class SemgrepAnalyzer:
    """Invokes and parses Semgrep static code analysis with DPDP Act & OWASP rules."""

    @classmethod
    def find_semgrep_binary(cls) -> Optional[str]:
        # 1. Check current virtualenv
        venv_bin = Path(sys.prefix) / "bin" / "semgrep"
        if venv_bin.exists() and os.access(venv_bin, os.X_OK):
            return str(venv_bin)

        # 2. Check local project .venv
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        proj_venv = project_root / ".venv" / "bin" / "semgrep"
        if proj_venv.exists() and os.access(proj_venv, os.X_OK):
            return str(proj_venv)

        # 3. Check system PATH
        which_path = shutil.which("semgrep")
        if which_path:
            return which_path

        return None

    @classmethod
    def find_rules_path(cls) -> Optional[Path]:
        curr = Path(__file__).resolve()
        for parent in [curr.parent, curr.parent.parent, curr.parent.parent.parent, curr.parent.parent.parent.parent]:
            candidate = parent / "src" / "rules" / "semgrep_dpdp_rules.yaml"
            if candidate.exists():
                return candidate
        cwd_cand = Path(os.getcwd()) / "src" / "rules" / "semgrep_dpdp_rules.yaml"
        if cwd_cand.exists():
            return cwd_cand
        return None

    @classmethod
    def scan_target(cls, target_path: str, root_path: Optional[str] = None) -> List[Finding]:
        semgrep_bin = cls.find_semgrep_binary()
        rules_path = cls.find_rules_path()

        if not semgrep_bin or not rules_path:
            return []

        target = Path(target_path).resolve()
        root = Path(root_path).resolve() if root_path else target

        cmd = [
            semgrep_bin,
            "scan",
            "--config", str(rules_path),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--exclude=node_modules",
            "--exclude=.venv",
            "--exclude=.git",
            str(target)
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90,
                cwd=str(root)
            )
            stdout = res.stdout.strip()
            if not stdout:
                return []

            # Extract json object from stdout (ignoring any warning banners)
            brace_start = stdout.find("{")
            brace_end = stdout.rfind("}")
            if brace_start == -1 or brace_end == -1:
                return []

            json_str = stdout[brace_start:brace_end + 1]
            data = json.loads(json_str)
            raw_results = data.get("results", [])

            findings: List[Finding] = []
            for item in raw_results:
                f = cls._parse_finding(item, root)
                if f:
                    findings.append(f)
            return findings

        except Exception:
            return []

    @classmethod
    def _parse_finding(cls, item: Dict[str, Any], root: Path) -> Optional[Finding]:
        check_id = item.get("check_id", "semgrep-unknown")
        raw_path = item.get("path", "")
        try:
            rel_path = str(Path(raw_path).resolve().relative_to(root))
        except Exception:
            rel_path = raw_path

        # Ignore results in internal vendor dependencies or environment directories
        if "node_modules" in rel_path or ".venv" in rel_path or "/.git/" in rel_path or rel_path.startswith(".git"):
            return None

        start = item.get("start", {})
        line_num = start.get("line", 1)
        col_num = start.get("col", 1)

        extra = item.get("extra", {})
        msg = extra.get("message", "Semgrep security check failure")
        metadata = extra.get("metadata", {})
        lines = extra.get("lines", "").strip()

        # Severity mapping
        raw_sev = extra.get("severity", "ERROR").upper()
        if raw_sev == "ERROR":
            severity: Severity = "critical"
        elif raw_sev == "WARNING":
            severity = "high"
        else:
            severity = "medium"

        cwe = metadata.get("cwe", "CWE-693: Protection Mechanism Failure")
        owasp = metadata.get("owasp", "A03:2021-Injection")
        dpdp_sec = metadata.get("dpdp_section", "Sec 8(6)")
        penalty = metadata.get("penalty_clause", "Up to Rs. 250 Crore under DPDP Act Schedule Item 1")
        category = metadata.get("category", "storage")
        remediation = metadata.get("remediation", "Implement strict input validation and defense-in-depth security safeguards.")

        # Data flow mapping
        if "transit" in category or "tls" in check_id.lower() or "ssl" in check_id.lower():
            df: DataFlow = "transferred"
        elif "logging" in category or "exposure" in category or "xss" in category:
            df = "exposed"
        else:
            df = "stored"

        short_name = check_id.split(".")[-1].replace("semgrep-dpdp-", "").replace("-", " ").title()
        title = f"{short_name} ({cwe.split(':')[0].strip() if ':' in cwe else 'Security Flaw'})"

        # Unique ID
        fid = f"DPDP-SEM-{line_num:04d}"

        # Generate a patch diff if possible
        patch_diff = cls._build_patch(lines, rel_path, line_num, check_id)

        finding = Finding(
            id=fid,
            rule_id=check_id,
            title=title,
            file=rel_path,
            line=line_num,
            column=col_num,
            snippet=lines if lines else f"# Line {line_num} in {rel_path}",
            pii_types=[],
            data_flow=df,
            dpdp_ref=(lambda s: {
                "provision": s["sectionOrRule"],
                "sectionOrRule": s["sectionOrRule"],
                "law": "DPDP Act 2023",
                "title": s["title"],
                "explanation": msg or s["explanation"],
                "penaltyClause": s["penaltyClause"],
                "statutory_citation": s["statutory_citation"]
            })(RagPipeline.resolve_statutory_reference(title=title, category=category, snippet=lines, fallback_ref=dpdp_sec)),
            severity=severity,
            justification=f"Semgrep AST Analysis [{cwe} | {owasp}]: {msg}",
            fix=remediation,
            patch_available=True,
            patch_unified_diff=patch_diff,
            cwe=cwe,
            owasp=owasp,
            engine="Semgrep SAST Engine v1.186.0"
        )
        return finding

    @classmethod
    def _build_patch(cls, snippet: str, file_path: str, line: int, check_id: str) -> Optional[str]:
        if not snippet:
            return None
        safe_snippet = snippet
        if "md5" in snippet or "sha1" in snippet:
            safe_snippet = snippet.replace("'md5'", "'sha256'").replace('"md5"', '"sha256"').replace("'sha1'", "'sha256'").replace('"sha1"', '"sha256"')
        elif "eval(" in snippet:
            safe_snippet = snippet.replace("eval(", "JSON.parse(")
        elif "rejectUnauthorized: false" in snippet:
            safe_snippet = snippet.replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        elif "verify=False" in snippet:
            safe_snippet = snippet.replace("verify=False", "verify=True")
        elif "innerHTML" in snippet:
            safe_snippet = snippet.replace(".innerHTML =", ".textContent =")
        elif "Math.random()" in snippet:
            safe_snippet = snippet.replace("Math.random()", "crypto.randomBytes(16).toString('hex')")
        else:
            safe_snippet = f"// Safe parameterization recommended\n// {snippet}"

        return (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{line},1 +{line},1 @@\n"
            f"- {snippet}\n"
            f"+ {safe_snippet}\n"
        )
