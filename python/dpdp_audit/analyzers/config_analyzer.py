import re
from pathlib import Path
from typing import List
from ..core.models import Finding, RuleDefinition
from ..core.pii_detector import PiiDetector
from ..core.risk_scorer import RiskScorer
from ..core.dpdp_mapper import DpdpMapper
from ..core.file_walker import FileWalker

class ConfigAnalyzer:
    """Specialized analyzer for .env, Dockerfile, docker-compose, and cloud configs."""

    @classmethod
    def analyze_file(cls, file_path: Path, rules: List[RuleDefinition], root: Path) -> List[Finding]:
        findings: List[Finding] = []
        fname = file_path.name.lower()
        rel_path = str(file_path.relative_to(root))

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return findings

        # 1. Analyze .env files for committed secrets (DPDP-CFG-001)
        if fname.startswith(".env"):
            rule = next((r for r in rules if r.id == "DPDP-CFG-001"), None)
            if rule:
                for idx, line in enumerate(lines, 1):
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    if FileWalker.has_ignore_comment(line, rule.id):
                        continue
                    if "=" in clean:
                        key, _, val = clean.partition("=")
                        key = key.strip()
                        val = val.strip().strip("'\"")
                        # Check for sensitive secret keys
                        if re.search(r"(SECRET|PASSWORD|PASSWD|KEY|TOKEN|API_KEY|AUTH)", key, re.IGNORECASE) and len(val) > 4:
                            # Not dummy/placeholder
                            if val.lower() not in ("dummy", "change_me", "placeholder", "your_secret_here"):
                                sev, just = RiskScorer.calculate_risk(["password"], "stored", "config", rule.severity)
                                prov = DpdpMapper.get_provision(rule.dpdp_ref)
                                findings.append(Finding(
                                    id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                                    rule_id=rule.id,
                                    title=rule.title,
                                    file=rel_path,
                                    line=idx,
                                    snippet=f"{key}=[REDACTED_SECRET]",
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
                                    patch_available=False,
                                ))

        # 2. Analyze Dockerfile for USER root and HEALTHCHECK (DPDP-CFG-002, DPDP-CFG-003)
        if "dockerfile" in fname:
            has_user = False
            has_healthcheck = False
            content = "".join(lines)

            for idx, line in enumerate(lines, 1):
                clean = line.strip()
                if re.match(r"^USER\s+", clean, re.IGNORECASE):
                    has_user = True
                    if re.match(r"^USER\s+root\b", clean, re.IGNORECASE):
                        rule = next((r for r in rules if r.id == "DPDP-CFG-002"), None)
                        if rule and not FileWalker.has_ignore_comment(line, rule.id):
                            sev, just = RiskScorer.calculate_risk([], "exposed", "config", rule.severity)
                            prov = DpdpMapper.get_provision(rule.dpdp_ref)
                            findings.append(Finding(
                                id=f"{rule.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                                rule_id=rule.id,
                                title=rule.title,
                                file=rel_path,
                                line=idx,
                                snippet=clean,
                                pii_types=[],
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
                                patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+USER node",
                            ))
                if re.match(r"^HEALTHCHECK\s+", clean, re.IGNORECASE):
                    has_healthcheck = True

            # If no USER instruction found at all in Dockerfile
            if not has_user:
                rule = next((r for r in rules if r.id == "DPDP-CFG-002"), None)
                if rule:
                    sev, just = RiskScorer.calculate_risk([], "exposed", "config", rule.severity)
                    prov = DpdpMapper.get_provision(rule.dpdp_ref)
                    findings.append(Finding(
                        id=f"{rule.id}-{abs(hash(rel_path + '_nouser')) % 10000:04d}",
                        rule_id=rule.id,
                        title="Dockerfile missing non-root USER instruction",
                        file=rel_path,
                        line=len(lines),
                        snippet="<end of Dockerfile without USER instruction>",
                        pii_types=[],
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
                        patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{len(lines)},0 +{len(lines)+1},1 @@\n+USER node",
                    ))

            # Missing HEALTHCHECK
            if not has_healthcheck:
                rule = next((r for r in rules if r.id == "DPDP-CFG-003"), None)
                if rule:
                    sev, just = RiskScorer.calculate_risk([], "exposed", "config", rule.severity)
                    prov = DpdpMapper.get_provision(rule.dpdp_ref)
                    findings.append(Finding(
                        id=f"{rule.id}-{abs(hash(rel_path + '_nohealth')) % 10000:04d}",
                        rule_id=rule.id,
                        title=rule.title,
                        file=rel_path,
                        line=1,
                        snippet="<missing HEALTHCHECK instruction>",
                        pii_types=[],
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
                        patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -1,0 +1,1 @@\n+HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:3000/health || exit 1",
                    ))

        # 3. Analyze docker-compose files for open ports and privileged containers
        if "docker-compose" in fname or fname.endswith((".yml", ".yaml")):
            content = "".join(lines)
            # Open DB ports (DPDP-EXP-007)
            rule_port = next((r for r in rules if r.id == "DPDP-EXP-007"), None)
            if rule_port:
                for idx, line in enumerate(lines, 1):
                    if re.search(r"""['"]?(?:0\.0\.0\.0:)?(?:5432:5432|27017:27017|3306:3306|6379:6379)['"]?""", line):
                        if not FileWalker.has_ignore_comment(line, rule_port.id):
                            sev, just = RiskScorer.calculate_risk(["financial", "aadhaar"], "exposed", "exposure", rule_port.severity)
                            prov = DpdpMapper.get_provision(rule_port.dpdp_ref)
                            clean = line.strip()
                            fix_line = re.sub(r"""['"]?(?:0\.0\.0\.0:)?(\d+:\1)['"]?""", r'"127.0.0.1:\1"', clean)
                            findings.append(Finding(
                                id=f"{rule_port.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                                rule_id=rule_port.id,
                                title=rule_port.title,
                                file=rel_path,
                                line=idx,
                                snippet=clean,
                                pii_types=["financial", "aadhaar"],
                                data_flow="exposed",
                                dpdp_ref={
                                    "sectionOrRule": prov.provision if prov else rule_port.dpdp_ref,
                                    "explanation": prov.summary if prov else rule_port.description,
                                    "penaltyClause": prov.penalty_clause if prov else None,
                                },
                                severity=sev,
                                justification=just,
                                fix=rule_port.remediation,
                                patch_available=True,
                                patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+{fix_line}",
                            ))

            # Privileged mode (DPDP-CFG-004)
            rule_priv = next((r for r in rules if r.id == "DPDP-CFG-004"), None)
            if rule_priv:
                for idx, line in enumerate(lines, 1):
                    if re.search(r"privileged\s*:\s*true", line, re.IGNORECASE):
                        if not FileWalker.has_ignore_comment(line, rule_priv.id):
                            sev, just = RiskScorer.calculate_risk(["password"], "exposed", "config", rule_priv.severity)
                            prov = DpdpMapper.get_provision(rule_priv.dpdp_ref)
                            clean = line.strip()
                            findings.append(Finding(
                                id=f"{rule_priv.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                                rule_id=rule_priv.id,
                                title=rule_priv.title,
                                file=rel_path,
                                line=idx,
                                snippet=clean,
                                pii_types=["password"],
                                data_flow="exposed",
                                dpdp_ref={
                                    "sectionOrRule": prov.provision if prov else rule_priv.dpdp_ref,
                                    "explanation": prov.summary if prov else rule_priv.description,
                                    "penaltyClause": prov.penalty_clause if prov else None,
                                },
                                severity=sev,
                                justification=just,
                                fix=rule_priv.remediation,
                                patch_available=True,
                                patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{idx},1 +{idx},1 @@\n-{clean}\n+privileged: false",
                            ))

        return findings
