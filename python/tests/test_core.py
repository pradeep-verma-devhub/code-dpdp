import pytest
import os
import tempfile
from pathlib import Path

from dpdp_audit.core.pii_detector import PiiDetector, validate_verhoeff, validate_luhn
from dpdp_audit.core.risk_scorer import RiskScorer
from dpdp_audit.core.dpdp_mapper import DpdpMapper
from dpdp_audit.core.rules_engine import RulesEngine
from dpdp_audit.analyzers.consent_analyzer import ConsentAnalyzer
from dpdp_audit.analyzers.patch_generator import PatchGenerator
from dpdp_audit.report.pdf_generator import PdfGenerator
from dpdp_audit.report.html_generator import HtmlGenerator

def test_verhoeff_aadhaar():
    assert validate_verhoeff("234567890124") is True
    assert validate_verhoeff("234567890120") is False
    assert validate_verhoeff("012345678901") is False

def test_pan_detection():
    detections = PiiDetector.scan_text("Employee tax PAN is ABCPE1234F registered.")
    assert any(d.type == "pan" for d in detections)

def test_luhn_credit_card():
    assert validate_luhn("4532015112830366") is True
    assert validate_luhn("4532015112830367") is False

def test_pii_identifier_matching():
    assert PiiDetector.match_identifier("user_email") == "email"
    assert PiiDetector.match_identifier("phoneNumber") == "phone"
    assert PiiDetector.match_identifier("aadhaar_no") == "aadhaar"
    assert PiiDetector.match_identifier("pan_card") == "pan"
    assert PiiDetector.match_identifier("medical_history") == "health"
    assert PiiDetector.match_identifier("unrelated_foo") is None

def test_pii_masking():
    masked_email = PiiDetector.mask_value("email", "john.doe@example.com")
    assert masked_email != "john.doe@example.com"
    assert "example.com" in masked_email

    snippet = 'const apiKey = "secret_12345"; console.log(user.email);'
    masked_snippet = PiiDetector.mask_snippet(snippet)
    assert "[REDACTED_SECRET]" in masked_snippet

def test_risk_scorer_formula():
    sev, just = RiskScorer.calculate_risk(["aadhaar", "financial"], "exposed", "exposure", "critical")
    assert sev == "critical"
    assert "Risk Score" in just
    assert "Sensitivity (5/5" in just

def test_rules_loading():
    rules = RulesEngine.load_rules()
    assert len(rules) >= 40
    dpdp_map = DpdpMapper.load_map()
    for r in rules:
        assert r.dpdp_ref in dpdp_map

def test_consent_analyzer():
    with tempfile.TemporaryDirectory() as tmpdir:
        consent_file = Path(tmpdir) / "consent.ts"
        consent_file = Path(tmpdir) / "consent.ts"
        consent_file.write_text("""
        export function saveConsent(userId: string) {
            return db.consent.create({
                userId,
                consentedAt: new Date(),
                consentPurpose: 'marketing',
                noticeVersion: '2.1'
            });
        }
        router.post('/api/consent/withdraw', handleWithdrawal);
        """)
        scorecard = ConsentAnalyzer.assess_project(tmpdir)
        assert scorecard.overall_score > 0
        assert "recorded" in scorecard.pillars

def test_scan_and_pdf_generation():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "app.js"
        test_file.write_text("""
        const express = require('express');
        const app = express();
        app.post('/login', (req, res) => {
            console.log(req.body);
            res.cookie('token', 'xyz', { httpOnly: false });
        });
        """)
        result = RulesEngine.scan_target(tmpdir)
        assert result.summary.findings_count > 0

        pdf_out = Path(tmpdir) / "test_report.pdf"
        PdfGenerator.generate(result, str(pdf_out))
        assert pdf_out.exists()
        assert pdf_out.stat().st_size > 1000

        html_out = Path(tmpdir) / "test_report.html"
        HtmlGenerator.generate(result, str(html_out))
        assert html_out.exists()
        assert html_out.stat().st_size > 500
