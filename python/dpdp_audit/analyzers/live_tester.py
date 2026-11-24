import time
import urllib.request
import urllib.error
import json
from typing import List, Dict, Any, Optional
from ..core.models import LiveTestFinding, LiveTestResult
from ..core.pii_detector import PiiDetector

DISCOVERY_ROUTES = [
    ("/", "GET"),
    ("/api", "GET"),
    ("/api-docs", "GET"),
    ("/swagger.json", "GET"),
    ("/api/users", "GET"),
    ("/rest/user", "GET"),
    ("/api/profile", "GET"),
    ("/api/user/export", "GET"),
    ("/api/user/delete", "DELETE"),
    ("/api/consent", "GET"),
]

MANDATORY_HEADERS = [
    ("Strict-Transport-Security", "Enforces HTTPS connections to prevent MitM eavesdropping (Rule 6)."),
    ("Content-Security-Policy", "Prevents unauthorized cross-site data exfiltration (Rule 6)."),
    ("X-Content-Type-Options", "Prevents MIME-sniffing attacks exposing user data (Rule 6)."),
    ("X-Frame-Options", "Prevents clickjacking and unauthorized form hijacking (Rule 6)."),
]

class LiveTester:
    """
    Non-destructive live API compliance tester for DPDP Act 2023 & Rules 2025.
    Evaluates running application endpoints for transport security, missing auth, PII leaks, and headers.
    """

    WARNING_NOTICE = (
        "================================================================================\n"
        "[SECURITY NOTICE] DPDP-Audit Live API Testing Suite\n"
        "This tool executes safe, non-destructive compliance checks.\n"
        "You MUST only test systems that you own or have explicit written authorization to evaluate.\n"
        "================================================================================"
    )

    @classmethod
    def run_tests(cls, base_url: str, custom_routes: Optional[List[str]] = None) -> LiveTestResult:
        print(cls.WARNING_NOTICE)

        clean_url = base_url.rstrip("/")
        findings: List[LiveTestFinding] = []
        tested_count = 0

        # 1. Transport Security Check: HTTP vs HTTPS
        if clean_url.startswith("http://") and "localhost" not in clean_url and "127.0.0.1" not in clean_url:
            findings.append(LiveTestFinding(
                id="LIVE-TRN-01",
                test_name="Insecure Plaintext HTTP Transport",
                endpoint=clean_url,
                method="CONN",
                status="FAIL",
                details="Target API serves traffic over plaintext HTTP without mandatory TLS encryption.",
                dpdp_ref="Rule 6 (Reasonable Security Safeguards)",
                severity="critical",
                evidence=f"Base URL: {clean_url}",
            ))

        # 2. Probe Base URL for Security Headers
        resp_headers, status_code, body = cls._probe_endpoint(clean_url, "GET")
        tested_count += 1

        if resp_headers:
            for hdr, explanation in MANDATORY_HEADERS:
                if hdr.lower() not in [k.lower() for k in resp_headers.keys()]:
                    findings.append(LiveTestFinding(
                        id=f"LIVE-HDR-{hdr.upper()[:3]}",
                        test_name=f"Missing Security Header: {hdr}",
                        endpoint=clean_url,
                        method="GET",
                        status="FAIL",
                        details=f"Missing HTTP header '{hdr}'. {explanation}",
                        dpdp_ref="Rule 6 (Reasonable Security Safeguards)",
                        severity="medium",
                        evidence=f"Status: {status_code}",
                    ))

        # 3. Rate Limiting Check
        rate_limit_headers = [k for k in resp_headers.keys() if "ratelimit" in k.lower()]
        if not rate_limit_headers:
            findings.append(LiveTestFinding(
                id="LIVE-RAT-01",
                test_name="Absence of Rate-Limiting Telemetry Headers",
                endpoint=clean_url,
                method="GET",
                status="WARN",
                details="Response lacks standard RateLimit-* headers. Services handling personal data should limit brute-force enumeration.",
                dpdp_ref="Rule 6 (Reasonable Security Safeguards)",
                severity="low",
                evidence="No RateLimit headers detected in response.",
            ))

        # 4. Probe Discovery Routes
        routes_to_test = list(DISCOVERY_ROUTES)
        if custom_routes:
            for cr in custom_routes:
                routes_to_test.append((cr, "GET"))

        has_export = False
        has_delete = False

        for route, method in routes_to_test:
            target_ep = clean_url + route
            r_hdrs, r_status, r_body = cls._probe_endpoint(target_ep, method)
            tested_count += 1

            # Check for PII leakage in unauthenticated responses
            if r_status in (200, 201) and r_body:
                pii_detections = PiiDetector.scan_text(r_body)
                if pii_detections:
                    types = list(set(d.type for d in pii_detections))
                    findings.append(LiveTestFinding(
                        id="LIVE-PII-01",
                        test_name="Personal Data Leaked in Public HTTP Response",
                        endpoint=target_ep,
                        method=method,
                        status="FAIL",
                        details=f"Unauthenticated endpoint returned sensitive personal data: {', '.join(types)}.",
                        dpdp_ref="Section 8(5) & Rule 6",
                        severity="critical",
                        evidence=f"Detections: {len(pii_detections)} PII items",
                    ))

                # Check if sensitive route allowed unauthenticated access
                if any(k in route.lower() for k in ("users", "profile", "account")) and r_status == 200:
                    findings.append(LiveTestFinding(
                        id="LIVE-AUT-01",
                        test_name="Unauthenticated Access to User Resource",
                        endpoint=target_ep,
                        method=method,
                        status="FAIL",
                        details=f"Route '{route}' returned HTTP 200 OK without requiring authentication tokens.",
                        dpdp_ref="Section 8(5) & Rule 6",
                        severity="critical",
                        evidence=f"Response status: {r_status}",
                    ))

            # Statutory Right to Access / Export
            if "export" in route.lower() and r_status not in (404, 502, 503):
                has_export = True

            # Statutory Right to Erasure / Deletion
            if "delete" in route.lower() and r_status not in (404, 502, 503):
                has_delete = True

        # 5. Check Verbose Error Disclosure
        err_ep = clean_url + "/api/users/non_existent_invalid_%27%22"
        _, err_status, err_body = cls._probe_endpoint(err_ep, "GET")
        tested_count += 1
        if err_body and any(s in err_body.lower() for s in ("stack", "syntaxerror", "sequelizestatusexception", "mongodb error")):
            findings.append(LiveTestFinding(
                id="LIVE-ERR-01",
                test_name="Verbose Error Stack Leakage in Error Response",
                endpoint=err_ep,
                method="GET",
                status="FAIL",
                details="API returned database internals or execution stack trace on malformed input.",
                dpdp_ref="Rule 6 (Reasonable Security Safeguards)",
                severity="medium",
                evidence=f"Status: {err_status}, leaked stack indicators.",
            ))

        # Statutory Endpoints Verdict
        if not has_export:
            findings.append(LiveTestFinding(
                id="LIVE-LIF-EXP",
                test_name="Absence of Data Export Endpoint (Right to Access)",
                endpoint=clean_url + "/api/user/export",
                method="GET",
                status="WARN",
                details="Automated probe could not locate personal data export endpoints.",
                dpdp_ref="Section 11 (Right to Access Information)",
                severity="medium",
                evidence="HTTP 404 Not Found on standard export routes.",
            ))

        if not has_delete:
            findings.append(LiveTestFinding(
                id="LIVE-LIF-DEL",
                test_name="Absence of Data Erasure Endpoint (Right to Erasure)",
                endpoint=clean_url + "/api/user/delete",
                method="DELETE",
                status="WARN",
                details="Automated probe could not locate personal data erasure endpoints.",
                dpdp_ref="Section 12 (Right to Correction and Erasure)",
                severity="medium",
                evidence="HTTP 404 Not Found on standard deletion routes.",
            ))

        fails = sum(1 for f in findings if f.status == "FAIL")
        warns = sum(1 for f in findings if f.status == "WARN")
        passed = max(0, tested_count - fails - warns)

        return LiveTestResult(
            base_url=clean_url,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            endpoints_tested=tested_count,
            summary={"passed": passed, "failed": fails, "warnings": warns},
            findings=findings,
        )

    @classmethod
    def _probe_endpoint(cls, url: str, method: str) -> tuple[Dict[str, str], int, str]:
        """Execute a safe, non-destructive probe request with timeout."""
        try:
            req = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": "DPDP-Audit-Compliance-Scanner/1.0", "Accept": "*/*"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="ignore")
                return headers, status, body
        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if hasattr(e, "headers") else {}
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            return headers, e.code, body
        except Exception:
            return {}, 0, ""
