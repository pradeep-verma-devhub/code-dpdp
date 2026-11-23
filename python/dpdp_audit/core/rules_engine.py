import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from .models import RuleDefinition, Finding, ScanSummary, ScanResult
from .dpdp_mapper import DpdpMapper
from .file_walker import FileWalker
from ..analyzers.config_analyzer import ConfigAnalyzer
from ..analyzers.schema_analyzer import SchemaAnalyzer
from ..analyzers.ast_analyzer import AstAnalyzer
from ..analyzers.consent_analyzer import ConsentAnalyzer
from ..analyzers.third_party_analyzer import ThirdPartyAnalyzer
from ..analyzers.malfunction_analyzer import MalfunctionAnalyzer

class RulesEngine:
    """Core rules orchestration, evaluation, and aggregation engine."""

    _cached_rules: Optional[List[RuleDefinition]] = None

    @classmethod
    def load_rules(cls) -> List[RuleDefinition]:
        if cls._cached_rules:
            return cls._cached_rules

        # Find rules directory
        curr = Path(__file__).resolve()
        rules_dir = None
        for parent in [curr.parent, curr.parent.parent, curr.parent.parent.parent, curr.parent.parent.parent.parent]:
            candidate = parent / "src" / "rules"
            if candidate.exists() and (candidate / "dpdp-map.yaml").exists():
                rules_dir = candidate
                break
        if not rules_dir:
            cwd_cand = Path(os.getcwd()) / "src" / "rules"
            if cwd_cand.exists():
                rules_dir = cwd_cand

        if not rules_dir:
            raise FileNotFoundError("Could not find src/rules directory")

        rules: List[RuleDefinition] = []
        for f in rules_dir.iterdir():
            if f.suffix in (".yaml", ".yml") and f.name != "dpdp-map.yaml":
                with open(f, "r", encoding="utf-8") as rf:
                    items = yaml.safe_load(rf)
                    if isinstance(items, list):
                        for it in items:
                            rules.append(RuleDefinition(
                                id=it["id"],
                                title=it["title"],
                                category=it["category"],
                                severity=it["severity"],
                                dpdp_ref=it["dpdpRef"],
                                description=it["description"],
                                pii_types=it.get("piiTypes", []),
                                data_flow=it.get("dataFlow", "exposed"),
                                target_files=it.get("targetFiles", []),
                                target_type=it.get("targetType", "regex"),
                                remediation=it.get("remediation", ""),
                                pattern=it.get("pattern"),
                                patch_template=it.get("patchTemplate"),
                                ast_query=it.get("astQuery"),
                            ))

        cls._cached_rules = rules
        return rules

    @classmethod
    def scan_target(cls, target_path: str, run_consent: bool = True) -> ScanResult:
        start_time = time.time()
        root = Path(target_path).resolve()
        rules = cls.load_rules()

        all_findings: List[Finding] = []
        all_third_party: List[Dict[str, Any]] = []
        all_malfunctions: List[Dict[str, Any]] = []
        scanned_count = 0

        for file_path in FileWalker.walk(str(root)):
            scanned_count += 1
            fname = file_path.name.lower()
            ext = file_path.suffix.lower()

            # 1. Config & Infrastructure
            if (
                fname.startswith(".env")
                or "dockerfile" in fname
                or "docker-compose" in fname
                or ext in (".tf", ".k8s.yaml", ".k8s.yml")
            ):
                all_findings.extend(ConfigAnalyzer.analyze_file(file_path, rules, root))

            # 2. Database schemas & models
            elif ext in (".prisma", ".sql") or "model" in fname or "schema" in fname:
                all_findings.extend(SchemaAnalyzer.analyze_file(file_path, rules, root))

            # 3. Code (TS, JS, JSX, TSX)
            if ext in (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs"):
                all_findings.extend(AstAnalyzer.analyze_file(file_path, rules, root))
                all_third_party.extend(ThirdPartyAnalyzer.analyze_file(file_path, root))
                all_malfunctions.extend(MalfunctionAnalyzer.analyze_file(file_path, root))

        # Deduplicate findings by (file, line, rule_id)
        deduped_findings: List[Finding] = []
        seen = set()
        for f in all_findings:
            key = (f.file, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped_findings.append(f)

        # Sort findings: critical -> high -> medium -> low
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduped_findings.sort(key=lambda x: (sev_rank.get(x.severity, 4), x.file, x.line))

        # Compute statistics
        by_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_cat: Dict[str, int] = {}
        by_flow: Dict[str, int] = {}
        violation_counts: Dict[str, Dict[str, Any]] = {}

        for f in deduped_findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            rule = next((r for r in rules if r.id == f.rule_id), None)
            cat = rule.category if rule else "general"
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_flow[f.data_flow] = by_flow.get(f.data_flow, 0) + 1

            if f.rule_id not in violation_counts:
                violation_counts[f.rule_id] = {"ruleId": f.rule_id, "title": f.title, "count": 0}
            violation_counts[f.rule_id]["count"] += 1

        top_violations = sorted(violation_counts.values(), key=lambda v: v["count"], reverse=True)[:5]
        compliance_score = DpdpMapper.compute_compliance_score(deduped_findings)
        coverage = DpdpMapper.compute_coverage(deduped_findings)

        duration_ms = (time.time() - start_time) * 1000

        summary = ScanSummary(
            scanned_files_count=scanned_count,
            scan_duration_ms=duration_ms,
            findings_count=len(deduped_findings),
            by_severity=by_sev,
            by_category=by_cat,
            by_data_flow=by_flow,
            top_violations=top_violations,
            compliance_score=compliance_score,
            dpdp_coverage=coverage,
        )

        consent_sc = None
        if run_consent:
            consent_sc = ConsentAnalyzer.assess_project(str(root))

        return ScanResult(
            target_path=str(root),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            summary=summary,
            findings=deduped_findings,
            consent_scorecard=consent_sc,
            third_party_egress=all_third_party,
            malfunctions=all_malfunctions,
        )
