import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml
from .models import DPDPRef, Finding, Severity

class DpdpMapper:
    """Manages legal mappings to DPDP Act 2023 and DPDP Rules 2025."""

    _cached_map: Optional[Dict[str, DPDPRef]] = None

    @classmethod
    def get_map_path(cls) -> Path:
        curr = Path(__file__).resolve()
        # Look upwards for src/rules/dpdp-map.yaml
        for parent in [curr.parent, curr.parent.parent, curr.parent.parent.parent, curr.parent.parent.parent.parent]:
            candidate = parent / "src" / "rules" / "dpdp-map.yaml"
            if candidate.exists():
                return candidate
        # Fallback to local working directory
        cwd_candidate = Path(os.getcwd()) / "src" / "rules" / "dpdp-map.yaml"
        if cwd_candidate.exists():
            return cwd_candidate
        raise FileNotFoundError("Could not find src/rules/dpdp-map.yaml")

    @classmethod
    def load_map(cls) -> Dict[str, DPDPRef]:
        if cls._cached_map:
            return cls._cached_map
        map_path = cls.get_map_path()
        with open(map_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        dpdp_map: Dict[str, DPDPRef] = {}
        for key, val in raw.items():
            dpdp_map[key] = DPDPRef(
                provision=val.get("provision", key),
                law=val.get("law", "Act 2023"),
                title=val.get("title", ""),
                summary=val.get("summary", ""),
                penalty_clause=val.get("penaltyClause", "Schedule Item 4: Up to ₹50 Crore"),
            )
        cls._cached_map = dpdp_map
        return dpdp_map

    @classmethod
    def get_provision(cls, key: str) -> Optional[DPDPRef]:
        m = cls.load_map()
        return m.get(key)

    @classmethod
    def compute_compliance_score(cls, findings: List[Finding]) -> int:
        """
        Compute compliance health score (0 - 100).
        Deductions:
          - Critical finding: -15 pts
          - High finding:     -7 pts
          - Medium finding:   -3 pts
          - Low finding:      -1 pt
        """
        score = 100
        for f in findings:
            if f.severity == "critical":
                score -= 15
            elif f.severity == "high":
                score -= 7
            elif f.severity == "medium":
                score -= 3
            elif f.severity == "low":
                score -= 1
        return max(0, min(100, score))

    @classmethod
    def compute_coverage(cls, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Compute status for each statutory provision in dpdp-map.yaml."""
        dpdp_map = cls.load_map()
        counts_by_ref: Dict[str, int] = {}
        for f in findings:
            ref_str = f.dpdp_ref.get("sectionOrRule", "")
            counts_by_ref[ref_str] = counts_by_ref.get(ref_str, 0) + 1

        coverage: List[Dict[str, Any]] = []
        for key, ref in dpdp_map.items():
            cnt = counts_by_ref.get(ref.provision, 0)
            status = "VIOLATION" if cnt > 0 else "COMPLIANT"
            coverage.append({
                "key": key,
                "provision": ref.provision,
                "law": ref.law,
                "title": ref.title,
                "status": status,
                "findingCount": cnt,
                "penaltyClause": ref.penalty_clause,
            })
        return coverage
