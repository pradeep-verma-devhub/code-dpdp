import re
from pathlib import Path
from typing import List, Optional
from ..core.models import Finding, RuleDefinition
from ..core.pii_detector import PiiDetector
from ..core.risk_scorer import RiskScorer
from ..core.dpdp_mapper import DpdpMapper
from ..core.file_walker import FileWalker

class AstAnalyzer:
    """
    Code AST and semantic flow analyzer for TypeScript and JavaScript files.
    Identifies dangerous function calls, unsafe configurations, and personal data leakage.
    """

    @classmethod
    def analyze_file(cls, file_path: Path, rules: List[RuleDefinition], root: Path) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(root))

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return findings

        content = "".join(lines)

        # Iterate through all active code rules
        for rule in rules:
            if rule.category in ("config",) and not rule.target_type == "regex":
                continue

            # 1. Regex-based pattern matching on code
            if rule.pattern:
                try:
                    pat = re.compile(rule.pattern, re.IGNORECASE)
                except Exception:
                    continue

                for idx, line in enumerate(lines, 1):
                    if FileWalker.has_ignore_comment(line, rule.id):
                        continue
                    m = pat.search(line)
                    if m:
                        clean_line = line.strip()
                        masked_snippet = PiiDetector.mask_snippet(clean_line)
                        piis = [p for p in rule.pii_types] or []
                        sev, just = RiskScorer.calculate_risk(piis, rule.data_flow, rule.category, rule.severity)
                        prov = DpdpMapper.get_provision(rule.dpdp_ref)

                        # Generate unified diff patch if patch template available
                        patch_diff = cls._generate_patch(rule, rel_path, idx, clean_line)

                        findings.append(Finding(
                            id=f"{rule.id}-{abs(hash(rel_path + str(idx) + rule.id)) % 10000:04d}",
                            rule_id=rule.id,
                            title=rule.title,
                            file=rel_path,
                            line=idx,
                            snippet=masked_snippet,
                            pii_types=piis,
                            data_flow=rule.data_flow,
                            dpdp_ref={
                                "sectionOrRule": prov.provision if prov else rule.dpdp_ref,
                                "explanation": prov.summary if prov else rule.description,
                                "penaltyClause": prov.penalty_clause if prov else None,
                            },
                            severity=sev,
                            justification=just,
                            fix=rule.remediation,
                            patch_available=bool(patch_diff),
                            patch_unified_diff=patch_diff,
                        ))

            # 2. Semantic AST-level checks for logging & request bodies
            elif rule.id == "DPDP-LOG-001":
                cls._check_pii_logging(lines, rel_path, rule, findings)

            elif rule.id == "DPDP-LOG-002":
                cls._check_req_body_logging(lines, rel_path, rule, findings)

            elif rule.id == "DPDP-STO-001":
                cls._check_plaintext_passwords(lines, rel_path, rule, findings)

            elif rule.id == "DPDP-EXP-001":
                cls._check_entity_response_leak(lines, rel_path, rule, findings)

        return findings

    @classmethod
    def _check_pii_logging(cls, lines: List[str], rel_path: str, rule: RuleDefinition, findings: List[Finding]):
        """Detect console.log(piiVar) or logger.info(user.email)."""
        log_pattern = re.compile(r"""(?:console|logger|winston)\.(?:log|info|warn|error|debug)\s*\(([^)]+)\)""")
        for idx, line in enumerate(lines, 1):
            if FileWalker.has_ignore_comment(line, rule.id):
                continue
            m = log_pattern.search(line)
            if m:
                args = m.group(1)
                # Check if arguments reference known PII keywords
                tokens = re.split(r"[,+.\s\"'()\[\]{}]+", args)
                detected_pii = []
                for tok in tokens:
                    p = PiiDetector.match_identifier(tok)
                    if p:
                        detected_pii.append(p)
                if detected_pii:
                    clean = line.strip()
                    sev, just = RiskScorer.calculate_risk(detected_pii, "logged", "logging", rule.severity)
                    prov = DpdpMapper.get_provision(rule.dpdp_ref)
                    findings.append(Finding(
                        id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                        rule_id=rule.id,
                        title=f"Direct logging of sensitive PII ({', '.join(set(detected_pii))})",
                        file=rel_path,
                        line=idx,
                        snippet=PiiDetector.mask_snippet(clean),
                        pii_types=list(set(detected_pii)),
                        data_flow="logged",
                        dpdp_ref={
                            "sectionOrRule": prov.provision if prov else rule.dpdp_ref,
                            "explanation": prov.summary if prov else rule.description,
                            "penaltyClause": prov.penalty_clause if prov else None,
                        },
                        severity=sev,
                        justification=just,
                        fix=rule.remediation,
                        patch_available=True,
                        patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+// [DPDP-LOG-001] Redacted PII logging call",
                    ))

    @classmethod
    def _check_req_body_logging(cls, lines: List[str], rel_path: str, rule: RuleDefinition, findings: List[Finding]):
        """Detect console.log(req.body)."""
        pattern = re.compile(r"""(?:console|logger|winston)\.(?:log|info|warn|error|debug)\s*\([^)]*req\.body[^)]*\)""")
        for idx, line in enumerate(lines, 1):
            if FileWalker.has_ignore_comment(line, rule.id):
                continue
            if pattern.search(line):
                clean = line.strip()
                sev, just = RiskScorer.calculate_risk(["password", "email", "phone"], "logged", "logging", rule.severity)
                prov = DpdpMapper.get_provision(rule.dpdp_ref)
                findings.append(Finding(
                    id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                    rule_id=rule.id,
                    title=rule.title,
                    file=rel_path,
                    line=idx,
                    snippet=clean,
                    pii_types=["password", "email", "phone"],
                    data_flow="logged",
                    dpdp_ref={
                        "sectionOrRule": prov.provision if prov else rule.dpdp_ref,
                        "explanation": prov.summary if prov else rule.description,
                        "penaltyClause": prov.penalty_clause if prov else None,
                    },
                    severity=sev,
                    justification=just,
                    fix=rule.remediation,
                    patch_available=True,
                    patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+// [DPDP-LOG-002] Redacted unmasked req.body logging",
                ))

    @classmethod
    def _check_plaintext_passwords(cls, lines: List[str], rel_path: str, rule: RuleDefinition, findings: List[Finding]):
        """Detect user.password = req.body.password without bcrypt/hash."""
        pattern = re.compile(r"""(?:user|account)\.password\s*=\s*(?:req\.body\.password|password\b)(?!\s*hash)""")
        for idx, line in enumerate(lines, 1):
            if FileWalker.has_ignore_comment(line, rule.id):
                continue
            if pattern.search(line):
                clean = line.strip()
                sev, just = RiskScorer.calculate_risk(["password"], "stored", "storage", rule.severity)
                prov = DpdpMapper.get_provision(rule.dpdp_ref)
                findings.append(Finding(
                    id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                    rule_id=rule.id,
                    title=rule.title,
                    file=rel_path,
                    line=idx,
                    snippet=clean,
                    pii_types=["password"],
                    data_flow="stored",
                    dpdp_ref={
                        "sectionOrRule": prov.provision if prov else rule.dpdp_ref,
                        "explanation": prov.summary if prov else rule.description,
                        "penaltyClause": prov.penalty_clause if prov else None,
                    },
                    severity=sev,
                    justification=just,
                    fix=rule.remediation,
                    patch_available=True,
                    patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+{clean.replace('req.body.password', 'await bcrypt.hash(req.body.password, 12)')}",
                ))

    @classmethod
    def _check_entity_response_leak(cls, lines: List[str], rel_path: str, rule: RuleDefinition, findings: List[Finding]):
        """Detect res.json(user) returning raw DB entity."""
        pattern = re.compile(r"""res\.(?:json|send)\s*\(\s*(?:user|userData|account)\s*\)""")
        for idx, line in enumerate(lines, 1):
            if FileWalker.has_ignore_comment(line, rule.id):
                continue
            if pattern.search(line):
                clean = line.strip()
                sev, just = RiskScorer.calculate_risk(["email", "phone", "password"], "exposed", "exposure", rule.severity)
                prov = DpdpMapper.get_provision(rule.dpdp_ref)
                findings.append(Finding(
                    id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                    rule_id=rule.id,
                    title=rule.title,
                    file=rel_path,
                    line=idx,
                    snippet=clean,
                    pii_types=["email", "phone", "password"],
                    data_flow="exposed",
                    dpdp_ref={
                        "sectionOrRule": prov.provision if prov else rule.dpdp_ref,
                        "explanation": prov.summary if prov else rule.description,
                        "penaltyClause": prov.penalty_clause if prov else None,
                    },
                    severity=sev,
                    justification=just,
                    fix=rule.remediation,
                    patch_available=True,
                    patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+res.json(sanitizeUser(user))",
                ))

    @classmethod
    def _generate_patch(cls, rule: RuleDefinition, rel_path: str, line_no: int, original_line: str) -> Optional[str]:
        """Generate targeted unified diff patches for fixable findings."""
        if not rule.patch_template:
            return None

        fixed_line = None
        if rule.patch_template == "replace_md5_sha1":
            fixed_line = re.sub(r"""createHash\s*\(\s*['\"](md5|sha1)['\"]\s*\)""", "createHash('sha256')", original_line)
        elif rule.patch_template == "set_cookie_httponly":
            fixed_line = re.sub(r"""httpOnly\s*:\s*false""", "httpOnly: true", original_line)
        elif rule.patch_template == "set_cookie_secure":
            fixed_line = re.sub(r"""secure\s*:\s*false""", "secure: true", original_line)
        elif rule.patch_template == "set_cookie_samesite":
            fixed_line = re.sub(r"""sameSite\s*:\s*['\"]none['\"]""", "sameSite: 'lax'", original_line)
        elif rule.patch_template == "enforce_https":
            fixed_line = re.sub(r"""['\"]http://""", "'https://", original_line)
        elif rule.patch_template == "fix_tls_verification":
            fixed_line = re.sub(r"""rejectUnauthorized\s*:\s*false""", "rejectUnauthorized: true", original_line)
        elif rule.patch_template == "generic_error_response":
            fixed_line = re.sub(r"""res\.(?:status\(\d+\)\.)?(?:send|json)\s*\([^)]*\)""", 'res.status(500).json({ error: "Internal Server Error" })', original_line)
        elif rule.patch_template == "fix_cors_origin":
            fixed_line = re.sub(r"""origin\s*:\s*['\"]\*(['\"])""", "origin: process.env.ALLOWED_ORIGIN || false", original_line)

        if fixed_line and fixed_line != original_line:
            return f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{line_no},1 +{line_no},1 @@\n-{original_line}\n+{fixed_line}"

        return None
