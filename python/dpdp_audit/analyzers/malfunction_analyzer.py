import re
from pathlib import Path
from typing import List, Dict, Any

MALFUNCTION_CHECKS = [
    {
        "id": "MALF-001",
        "title": "Silent Exception Swallowing / Empty Catch Block",
        "category": "Code Malfunction",
        "severity": "medium",
        "pattern": r"""catch\s*\([^)]*\)\s*\{\s*\}""",
        "description": "Empty catch block silently suppresses runtime errors, causing unexpected application halts and data inconsistencies.",
        "fix": "Log the caught exception using a structured logger or rethrow with proper context.",
    },
    {
        "id": "MALF-002",
        "title": "SQL Injection Vulnerability via String Concatenation",
        "category": "Security Vulnerability",
        "severity": "critical",
        "pattern": r"""(?:query|execute)\s*\(\s*['\"][^'\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'\"]*['\"]\s*\+""",
        "description": "SQL query built via string concatenation with dynamic inputs, allowing unauthorized database extraction.",
        "fix": "Use parameterized queries or prepared statements (e.g., db.query('SELECT * FROM users WHERE id = $1', [userId])).",
    },
    {
        "id": "MALF-003",
        "title": "Dangerous Dynamic Code Execution (eval/Function)",
        "category": "Security Vulnerability",
        "severity": "critical",
        "pattern": r"""\b(?:eval|new\s+Function)\s*\(""",
        "description": "Use of eval() or dynamic Function constructor allows arbitrary code execution and memory tampering.",
        "fix": "Avoid eval. Use safe JSON.parse or strict schema validation.",
    },
    {
        "id": "MALF-004",
        "title": "Prototype Pollution Risk (Unvalidated Object Merge)",
        "category": "Security Vulnerability",
        "severity": "high",
        "pattern": r"""(?:Object\.assign|_\.merge|_\.extend)\s*\([^)]*req\.body""",
        "description": "Merging unvalidated request body directly into target objects can overwrite Object.prototype properties.",
        "fix": "Validate and whitelist object properties before merging, or use Object.create(null).",
    },
    {
        "id": "MALF-005",
        "title": "Missing Error Handling in Promise Chain",
        "category": "Code Malfunction",
        "severity": "medium",
        "pattern": r"""\.(?:then)\s*\([^)]+\)\s*(?:;|\n)(?!\s*\.catch)""",
        "description": "Promise chain without a terminating .catch() handler causes UnhandledPromiseRejection errors in Node.js.",
        "fix": "Always append a .catch(err => ...) handler or refactor to async/await with try/catch.",
    },
    {
        "id": "MALF-006",
        "title": "Hardcoded Cryptographic Secret / JWT Key",
        "category": "Security Vulnerability",
        "severity": "critical",
        "pattern": r"""(?:jwtSecret|secretOrKey|api_secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-!@#$%^&*+=]{6,}['\"]""",
        "description": "Cryptographic signing key hardcoded in application source files.",
        "fix": "Load keys securely from environment variables (process.env.JWT_SECRET) or a secret manager.",
    },
]

class MalfunctionAnalyzer:

    @classmethod
    def analyze_file(cls, file_path: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel_path = str(file_path.relative_to(root))

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or not clean:
                continue

            for check in MALFUNCTION_CHECKS:
                if re.search(check["pattern"], line):
                    findings.append({
                        "id": f"{check['id']}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                        "checkId": check["id"],
                        "title": check["title"],
                        "category": check["category"],
                        "severity": check["severity"],
                        "file": rel_path,
                        "line": idx,
                        "snippet": clean[:140],
                        "description": check["description"],
                        "fix": check["fix"],
                    })

        return findings
