import re
from pathlib import Path
from typing import List, Dict, Any
from ..core.models import ConsentCheck, ConsentScorecard
from ..core.file_walker import FileWalker

class ConsentAnalyzer:
    """
    Evaluates consent mechanisms against DPDP Act 2023 (Sections 5 & 6) and DPDP Rules 2025 (Rules 3 & 4).
    Assesses 5 pillars: Recorded, Withdrawable, Enforced, Granular, Plain Notice.
    """

    @classmethod
    def assess_project(cls, target_path: str) -> ConsentScorecard:
        root = Path(target_path).resolve()
        all_code_files: List[Path] = []
        for p in FileWalker.walk(str(root)):
            if p.suffix.lower() in (".ts", ".js", ".tsx", ".jsx", ".prisma", ".sql", ".html", ".md", ".json"):
                all_code_files.append(p)

        checks: List[ConsentCheck] = []

        # Pillar 1: Recorded with timestamp, purpose, and notice version
        p1_res = cls._check_recorded(all_code_files)
        checks.extend(p1_res["checks"])

        # Pillar 2: Withdrawable via endpoint / UI
        p2_res = cls._check_withdrawable(all_code_files)
        checks.extend(p2_res["checks"])

        # Pillar 3: Enforced in backend before processing
        p3_res = cls._check_enforced(all_code_files)
        checks.extend(p3_res["checks"])

        # Pillar 4: Granular per purpose (discrete checkboxes/flags)
        p4_res = cls._check_granular(all_code_files)
        checks.extend(p4_res["checks"])

        # Pillar 5: Plain language notice with itemised disclosure
        p5_res = cls._check_plain_notice(all_code_files)
        checks.extend(p5_res["checks"])

        # Calculate scores
        pillars = {
            "recorded": {"score": p1_res["score"], "passed": p1_res["score"] >= 12, "details": p1_res["summary"]},
            "withdrawable": {"score": p2_res["score"], "passed": p2_res["score"] >= 12, "details": p2_res["summary"]},
            "enforced": {"score": p3_res["score"], "passed": p3_res["score"] >= 12, "details": p3_res["summary"]},
            "granular": {"score": p4_res["score"], "passed": p4_res["score"] >= 12, "details": p4_res["summary"]},
            "plain_notice": {"score": p5_res["score"], "passed": p5_res["score"] >= 12, "details": p5_res["summary"]},
        }

        total_score = sum(p["score"] for p in pillars.values())

        if total_score >= 85:
            grade = "A"
        elif total_score >= 70:
            grade = "B"
        elif total_score >= 55:
            grade = "C"
        elif total_score >= 40:
            grade = "D"
        else:
            grade = "F"

        recommendations: List[str] = []
        for c in checks:
            if not c.passed:
                recommendations.append(c.recommendation)

        return ConsentScorecard(
            overall_score=total_score,
            grade=grade,
            pillars=pillars,
            checks=checks,
            recommendations=recommendations,
        )

    @classmethod
    def _check_recorded(cls, files: List[Path]) -> Dict[str, Any]:
        has_timestamp = False
        has_purpose = False
        has_version = False
        evidence = []

        time_pat = re.compile(r"""(?:consentTimestamp|consentedAt|consent_date|granted_at)""", re.IGNORECASE)
        purpose_pat = re.compile(r"""(?:consentPurpose|purposeId|consentedPurposes|consent_type)""", re.IGNORECASE)
        version_pat = re.compile(r"""(?:noticeVersion|policyVersion|consentVersion|version_id)""", re.IGNORECASE)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if time_pat.search(content):
                    has_timestamp = True
                    evidence.append(f"Timestamp in {f.name}")
                if purpose_pat.search(content):
                    has_purpose = True
                    evidence.append(f"Purpose in {f.name}")
                if version_pat.search(content):
                    has_version = True
                    evidence.append(f"Version in {f.name}")
            except Exception:
                continue

        score = (8 if has_timestamp else 0) + (6 if has_purpose else 0) + (6 if has_version else 0)
        checks = [
            ConsentCheck(
                id="CONSENT-REC-01",
                pillar="recorded",
                name="Consent Recordation & Provenance",
                description="Verifies that consent logs capture timestamp, purpose identifier, and active privacy notice version.",
                passed=score >= 14,
                evidence=", ".join(evidence) if evidence else "No structured consent provenance schema found.",
                recommendation="Store an immutable consent audit record containing { userId, purposeId, noticeVersion, timestamp, ipAddress } on every grant.",
            )
        ]
        return {
            "score": score,
            "summary": "Consent captured with timestamp and purpose metadata" if score >= 14 else "Missing structured timestamp or versioning in consent records",
            "checks": checks,
        }

    @classmethod
    def _check_withdrawable(cls, files: List[Path]) -> Dict[str, Any]:
        has_withdraw_endpoint = False
        has_withdraw_ui = False
        evidence = []

        endpoint_pat = re.compile(r"""(?:app|router)\.(?:post|delete|put)\s*\(\s*['\"][^'\"]*consent/(?:withdraw|revoke|opt-out)""", re.IGNORECASE)
        ui_pat = re.compile(r"""(?:withdrawConsent|revokeConsent|optOutMarketing|handleConsentWithdrawal)""", re.IGNORECASE)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if endpoint_pat.search(content):
                    has_withdraw_endpoint = True
                    evidence.append(f"Withdrawal route in {f.name}")
                if ui_pat.search(content):
                    has_withdraw_ui = True
                    evidence.append(f"Withdrawal handler in {f.name}")
            except Exception:
                continue

        score = (12 if has_withdraw_endpoint else 0) + (8 if has_withdraw_ui else 0)
        checks = [
            ConsentCheck(
                id="CONSENT-WDR-01",
                pillar="withdrawable",
                name="Ease of Consent Withdrawal (Section 6(4))",
                description="Ensures Data Principals have automated endpoints and UI controls to revoke consent as easily as it was given.",
                passed=score >= 12,
                evidence=", ".join(evidence) if evidence else "No dedicated consent revocation endpoints found.",
                recommendation="Expose DELETE /api/consent or POST /api/consent/withdraw with cascading signals to downstream processors.",
            )
        ]
        return {
            "score": score,
            "summary": "Automated consent revocation mechanisms detected" if score >= 12 else "Absence of programmatic consent withdrawal endpoints",
            "checks": checks,
        }

    @classmethod
    def _check_enforced(cls, files: List[Path]) -> Dict[str, Any]:
        has_enforcement_middleware = False
        evidence = []

        middleware_pat = re.compile(r"""(?:requireConsent|checkConsent|hasConsent|verifyConsent|consentMiddleware)\s*\(""", re.IGNORECASE)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if middleware_pat.search(content):
                    has_enforcement_middleware = True
                    evidence.append(f"Consent middleware in {f.name}")
            except Exception:
                continue

        score = 20 if has_enforcement_middleware else 0
        checks = [
            ConsentCheck(
                id="CONSENT-ENF-01",
                pillar="enforced",
                name="Backend Pre-Processing Consent Enforcement",
                description="Checks whether backend middleware gates personal data processing against active consent state before execution.",
                passed=has_enforcement_middleware,
                evidence=", ".join(evidence) if evidence else "No backend consent verification middleware detected.",
                recommendation="Implement a requireConsent(purpose) middleware to block processing if the Data Principal has not opted in.",
            )
        ]
        return {
            "score": score,
            "summary": "Backend middleware actively verifies consent prior to processing" if has_enforcement_middleware else "Backend processes personal data without proactive consent check",
            "checks": checks,
        }

    @classmethod
    def _check_granular(cls, files: List[Path]) -> Dict[str, Any]:
        has_granular_purposes = False
        evidence = []

        granular_pat = re.compile(r"""(?:marketingConsent|analyticsConsent|profilingConsent|communicationConsent|purposes\s*:\s*\[)""", re.IGNORECASE)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if granular_pat.search(content):
                    has_granular_purposes = True
                    evidence.append(f"Discrete purposes in {f.name}")
            except Exception:
                continue

        score = 20 if has_granular_purposes else 0
        checks = [
            ConsentCheck(
                id="CONSENT-GRN-01",
                pillar="granular",
                name="Granular Purpose Separation (Section 6(1))",
                description="Verifies that consent requests are split per discrete processing purpose rather than bundled into an all-or-nothing checkbox.",
                passed=has_granular_purposes,
                evidence=", ".join(evidence) if evidence else "Single bundled or binary consent model detected.",
                recommendation="Separate consent toggles by discrete purpose (Essential, Analytics, Marketing, Third-party Sharing).",
            )
        ]
        return {
            "score": score,
            "summary": "Distinct purpose-level consent preferences implemented" if has_granular_purposes else "Bundled or all-or-nothing consent model",
            "checks": checks,
        }

    @classmethod
    def _check_plain_notice(cls, files: List[Path]) -> Dict[str, Any]:
        has_privacy_notice = False
        has_dpo_contact = False
        evidence = []

        notice_pat = re.compile(r"""(?:privacy\s+notice|privacy\s+policy|itemised\s+notice|data\s+protection\s+notice)""", re.IGNORECASE)
        dpo_pat = re.compile(r"""(?:dpo|grievance|data\s+protection\s+officer)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}""", re.IGNORECASE)

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                if notice_pat.search(content):
                    has_privacy_notice = True
                    evidence.append(f"Notice in {f.name}")
                if dpo_pat.search(content):
                    has_dpo_contact = True
                    evidence.append(f"DPO contact in {f.name}")
            except Exception:
                continue

        score = (12 if has_privacy_notice else 0) + (8 if has_dpo_contact else 0)
        checks = [
            ConsentCheck(
                id="CONSENT-NTC-01",
                pillar="plain_notice",
                name="Plain Language Itemised Notice (Section 5 & Rule 3)",
                description="Checks for accessible privacy notices specifying personal data items, specific purposes, and Grievance Officer details.",
                passed=score >= 12,
                evidence=", ".join(evidence) if evidence else "No accessible privacy notice with statutory disclosures found.",
                recommendation="Publish an itemised privacy notice in clear language with contact info of the Data Protection Officer.",
            )
        ]
        return {
            "score": score,
            "summary": "Accessible privacy notice and contact channels detected" if score >= 12 else "Missing comprehensive itemised privacy notice",
            "checks": checks,
        }
