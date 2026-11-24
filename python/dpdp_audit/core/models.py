from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Literal

Severity = Literal["critical", "high", "medium", "low"]
DataFlow = Literal["collected", "stored", "logged", "transferred", "exposed"]
PiiType = Literal[
    "name", "email", "phone", "aadhaar", "pan", "dob", "address",
    "ip", "geolocation", "health", "financial", "password",
    "device_id", "biometrics", "children_data"
]

@dataclass
class PiiDetection:
    type: PiiType
    confidence: float
    matched_term: str
    data_flow: DataFlow
    line: int
    column: Optional[int] = None
    value_snippet: Optional[str] = None
    is_redacted: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class DPDPRef:
    provision: str
    law: str
    title: str
    summary: str
    penalty_clause: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RuleDefinition:
    id: str
    title: str
    category: str
    severity: Severity
    dpdp_ref: str
    description: str
    pii_types: List[PiiType]
    data_flow: DataFlow
    target_files: List[str]
    target_type: str
    remediation: str
    pattern: Optional[str] = None
    patch_template: Optional[str] = None
    ast_query: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    file: str
    line: int
    snippet: str
    pii_types: List[PiiType]
    data_flow: DataFlow
    dpdp_ref: Dict[str, Any]
    severity: Severity
    justification: str
    fix: str
    column: Optional[int] = None
    patch_available: bool = False
    patch_unified_diff: Optional[str] = None
    ai_remediation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    engine: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ScanSummary:
    scanned_files_count: int
    scan_duration_ms: float
    findings_count: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_data_flow: Dict[str, int]
    top_violations: List[Dict[str, Any]]
    compliance_score: int
    dpdp_coverage: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ConsentCheck:
    id: str
    pillar: str
    name: str
    description: str
    passed: bool
    recommendation: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ConsentScorecard:
    overall_score: int
    grade: str
    pillars: Dict[str, Dict[str, Any]]
    checks: List[ConsentCheck]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "pillars": self.pillars,
            "checks": [c.to_dict() for c in self.checks],
            "recommendations": self.recommendations,
        }

@dataclass
class ScanResult:
    target_path: str
    timestamp: str
    summary: ScanSummary
    findings: List[Finding]
    consent_scorecard: Optional[ConsentScorecard] = None
    third_party_egress: List[Dict[str, Any]] = field(default_factory=list)
    malfunctions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "consent_scorecard": self.consent_scorecard.to_dict() if self.consent_scorecard else None,
            "third_party_egress": self.third_party_egress,
            "malfunctions": self.malfunctions,
        }

@dataclass
class LiveTestFinding:
    id: str
    test_name: str
    endpoint: str
    method: str
    status: str  # FAIL, PASS, WARN
    details: str
    dpdp_ref: str
    severity: Severity
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class LiveTestResult:
    base_url: str
    timestamp: str
    endpoints_tested: int
    summary: Dict[str, int]
    findings: List[LiveTestFinding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "timestamp": self.timestamp,
            "endpoints_tested": self.endpoints_tested,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
