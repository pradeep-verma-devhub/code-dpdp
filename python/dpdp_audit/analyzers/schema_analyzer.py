import re
from pathlib import Path
from typing import List
from ..core.models import Finding, RuleDefinition
from ..core.pii_detector import PiiDetector
from ..core.risk_scorer import RiskScorer
from ..core.dpdp_mapper import DpdpMapper
from ..core.file_walker import FileWalker

class SchemaAnalyzer:

    SENSITIVE_COLUMNS = {
        "aadhaar": ["aadhaar", "aadhar", "uidai"],
        "pan": ["pan", "pan_card", "pancard"],
        "financial": ["credit_card", "card_number", "cvv", "bank_account", "account_number", "upi_id"],
        "health": ["medical_history", "diagnosis", "prescription", "blood_group"],
    }

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

        if fname.endswith(".prisma"):
            cls._scan_prisma(lines, rel_path, rules, findings)

        elif fname.endswith(".sql"):
            cls._scan_sql(lines, rel_path, rules, findings)

        elif any(k in fname for k in ("model", "schema")):
            cls._scan_js_ts_schema(lines, rel_path, rules, findings)

        return findings

    @classmethod
    def _scan_prisma(cls, lines: List[str], rel_path: str, rules: List[RuleDefinition], findings: List[Finding]):
        rule_sto = next((r for r in rules if r.id == "DPDP-STO-005"), None)
        in_model = False
        model_name = ""

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or not clean:
                continue

            model_match = re.match(r"^model\s+([A-Za-z0-9_]+)\s*\{", clean)
            if model_match:
                in_model = True
                model_name = model_match.group(1)
                continue
            if clean.startswith("}"):
                in_model = False
                continue

            if in_model and rule_sto:
                parts = clean.split()
                if len(parts) >= 2:
                    field_name = parts[0]
                    pii_type = PiiDetector.match_identifier(field_name)
                    if pii_type in ("aadhaar", "pan", "financial", "health"):
                        if "@encrypted" not in clean and "@hash" not in clean:
                            if not FileWalker.has_ignore_comment(line, rule_sto.id):
                                sev, just = RiskScorer.calculate_risk([pii_type], "stored", "storage", rule_sto.severity)
                                prov = DpdpMapper.get_provision(rule_sto.dpdp_ref)
                                findings.append(Finding(
                                    id=f"{rule_sto.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                                    rule_id=rule_sto.id,
                                    title=f"Unencrypted {pii_type.upper()} field '{field_name}' in Prisma model '{model_name}'",
                                    file=rel_path,
                                    line=idx,
                                    snippet=clean,
                                    pii_types=[pii_type],
                                    data_flow="stored",
                                    dpdp_ref={
                                        "sectionOrRule": prov.provision if prov else rule_sto.dpdp_ref,
                                        "explanation": prov.summary if prov else rule_sto.description,
                                        "penaltyClause": prov.penalty_clause if prov else None,
                                    },
                                    severity=sev,
                                    justification=just,
                                    fix=f"Apply transparent column encryption to '{field_name}' using AES-256-GCM envelope encryption.",
                                    patch_available=False,
                                ))

    @classmethod
    def _scan_sql(cls, lines: List[str], rel_path: str, rules: List[RuleDefinition], findings: List[Finding]):
        rule_sto = next((r for r in rules if r.id == "DPDP-STO-005"), None)
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("--") or not clean:
                continue

            col_match = re.search(r"^\s*([`\"[\]a-zA-Z0-9_]+)\s+(VARCHAR|TEXT|CHAR|INT|BIGINT)", clean, re.IGNORECASE)
            if col_match and rule_sto:
                col_name = col_match.group(1).strip("`\"[] ")
                pii_type = PiiDetector.match_identifier(col_name)
                if pii_type in ("aadhaar", "pan", "financial", "health"):
                    if not FileWalker.has_ignore_comment(line, rule_sto.id):
                        sev, just = RiskScorer.calculate_risk([pii_type], "stored", "storage", rule_sto.severity)
                        prov = DpdpMapper.get_provision(rule_sto.dpdp_ref)
                        findings.append(Finding(
                            id=f"{rule_sto.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                            rule_id=rule_sto.id,
                            title=f"Unencrypted {pii_type.upper()} column '{col_name}' in SQL schema",
                            file=rel_path,
                            line=idx,
                            snippet=clean,
                            pii_types=[pii_type],
                            data_flow="stored",
                            dpdp_ref={
                                "sectionOrRule": prov.provision if prov else rule_sto.dpdp_ref,
                                "explanation": prov.summary if prov else rule_sto.description,
                                "penaltyClause": prov.penalty_clause if prov else None,
                            },
                            severity=sev,
                            justification=just,
                            fix=f"Ensure '{col_name}' column is stored with pgcrypto / column-level encryption.",
                            patch_available=False,
                        ))

    @classmethod
    def _scan_js_ts_schema(cls, lines: List[str], rel_path: str, rules: List[RuleDefinition], findings: List[Finding]):
        rule_sto = next((r for r in rules if r.id == "DPDP-STO-005"), None)
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*"):
                continue

            field_match = re.search(r"^([a-zA-Z0-9_]+)\s*:\s*\{", clean)
            if field_match and rule_sto:
                field_name = field_match.group(1)
                pii_type = PiiDetector.match_identifier(field_name)
                if pii_type in ("aadhaar", "pan", "financial", "health"):
                    if not FileWalker.has_ignore_comment(line, rule_sto.id):
                        sev, just = RiskScorer.calculate_risk([pii_type], "stored", "storage", rule_sto.severity)
                        prov = DpdpMapper.get_provision(rule_sto.dpdp_ref)
                        findings.append(Finding(
                            id=f"{rule_sto.id}-{abs(hash(rel_path + str(idx))) % 10000:04d}",
                            rule_id=rule_sto.id,
                            title=f"Unencrypted {pii_type.upper()} property '{field_name}' in Mongoose/ORM schema",
                            file=rel_path,
                            line=idx,
                            snippet=clean,
                            pii_types=[pii_type],
                            data_flow="stored",
                            dpdp_ref={
                                "sectionOrRule": prov.provision if prov else rule_sto.dpdp_ref,
                                "explanation": prov.summary if prov else rule_sto.description,
                                "penaltyClause": prov.penalty_clause if prov else None,
                            },
                            severity=sev,
                            justification=just,
                            fix=f"Use mongoose-field-encryption or encrypt getter/setter for '{field_name}'.",
                            patch_available=False,
                        ))
