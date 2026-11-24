import pytest
from dpdp_audit.core.statutory_resolver import StatutoryResolver
from dpdp_audit.core.rag_pipeline import RagPipeline

def test_aadhaar_statutory_dossier():
    d = StatutoryResolver.resolve_dossier(
        rule_id="DPDP-PII-AADHAAR",
        title="Unencrypted Sensitive Personal Data Leak (AADHAAR)",
        pii_types=["aadhaar"],
        snippet='<p class="meta">Aadhaar: 2345 6789 0124</p>',
        file_path="void_hack.8.0/data/case_diary.html"
    )
    assert "Aadhaar Act 2016" in d["law"]
    assert "Section 29(4)" in d["law"]
    assert "Section 4 & Section 8(5)" in d["law"]
    assert "CWE-312" in d["cwe"]
    assert "A04:2021" in d["owasp"]
    assert "Rs. 250 Crore" in d["penalty"]
    assert "No entity shall publish, display or post" in d["mandate"]

def test_sql_injection_statutory_dossier():
    d = StatutoryResolver.resolve_dossier(
        rule_id="SEC-SQLI-001",
        title="Direct SQL Query String Concatenation",
        snippet='db.query("SELECT * FROM users WHERE id = " + req.query.id)'
    )
    assert "Rule 6(1)(b)" in d["law"]
    assert "Section 8(5)" in d["law"]
    assert "CWE-89" in d["cwe"]
    assert "A03:2021" in d["owasp"]
    assert "parameterized" in d["mandate"]

def test_cookie_security_statutory_dossier():
    d = StatutoryResolver.resolve_dossier(
        rule_id="SEC-AUTH-001",
        title="Missing HttpOnly flag on Session Cookie",
        snippet='res.cookie("session_id", sid, { secure: true })'
    )
    assert "Rule 6(1)(d)" in d["law"]
    assert "CWE-1004" in d["cwe"]
    assert "HttpOnly" in d["mandate"]

def test_child_tracking_and_consent_dossiers():
    track = StatutoryResolver.resolve_dossier(
        rule_id="DPDP-CHD-002",
        title="Tracking and Behavioural Profiling of Minor",
        pii_types=["children_data"]
    )
    assert "Section 9(3)" in track["law"]
    assert "Rs. 200 Crore under Schedule Item 3" in track["penalty"]
    assert "CWE-359" in track["cwe"]

    consent = StatutoryResolver.resolve_dossier(
        rule_id="DPDP-CHD-001",
        title="Processing Child Data Without Verifiable Parental Consent",
        pii_types=["children_data"]
    )
    assert "Section 9(1)" in consent["law"]
    assert "Rs. 200 Crore under Schedule Item 3" in consent["penalty"]
    assert "CWE-285" in consent["cwe"]

def test_pii_logging_statutory_dossier():
    d = StatutoryResolver.resolve_dossier(
        rule_id="DPDP-LOG-001",
        title="Logging of Personal Data in Cleartext",
        snippet='console.log("User payload:", req.body)'
    )
    assert "Section 8(3)" in d["law"]
    assert "Rs. 50 Crore under Schedule Item 7" in d["penalty"]
    assert "CWE-532" in d["cwe"]
    assert "A09:2021" in d["owasp"]

def test_consent_withdrawal_statutory_dossier():
    d = StatutoryResolver.resolve_dossier(
        rule_id="DPDP-CNS-004",
        title="Lack of Asymmetric Consent Withdrawal Mechanism",
        snippet='// No revocation handler provided'
    )
    assert "Section 6(1)" in d["law"]
    assert "Section 6(4)" in d["law"]
    assert "Rs. 50 Crore" in d["penalty"]
    assert "CWE-285" in d["cwe"]

def test_rag_pipeline_resolves_via_statutory_resolver():
    res = RagPipeline.resolve_statutory_reference(
        title="Unencrypted Sensitive Personal Data Leak (AADHAAR)",
        category="storage",
        snippet='Aadhaar: 2345 6789 0124',
        pii_types=["aadhaar"],
        fallback_ref="DPDP-PII-AADHAAR"
    )
    assert "Aadhaar Act 2016" in res["statutory_citation"]
    assert "CWE-312" in res["cwe"]
    assert "No entity shall publish" in res["explanation"]
