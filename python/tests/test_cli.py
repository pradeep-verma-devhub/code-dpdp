import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from dpdp_audit.cli import main
from dpdp_audit.core.ollama_service import OllamaService

def test_cli_help(capsys):
    with patch.object(sys, "argv", ["code-dpdp", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "code-dpdp" in captured.out or "Automated Compliance" in captured.out

def test_cli_scan_with_pdf(tmp_path):
    sample_file = tmp_path / "app.js"
    sample_file.write_text("""
    const express = require('express');
    const app = express();
    app.post('/login', (req, res) => {
        console.log("Password is: " + req.body.password);
    });
    """)
    pdf_out = tmp_path / "result.pdf"

    with patch.object(sys, "argv", ["code-dpdp", str(tmp_path), "--pdf", str(pdf_out)]):
        main()

    assert pdf_out.exists()
    assert pdf_out.stat().st_size > 1000

def test_cli_pii_scanner(tmp_path):
    pii_file = tmp_path / "users.js"
    pii_file.write_text("""
    const userPan = "ABCDE1234F";
    const userPhone = "9876543210";
    """)

    with patch.object(sys, "argv", ["code-dpdp", "pii", str(tmp_path)]):
        main()

def test_cli_consent(tmp_path):
    with patch.object(sys, "argv", ["code-dpdp", "consent", str(tmp_path)]):
        main()

def test_cli_penalty(tmp_path):
    with patch.object(sys, "argv", ["code-dpdp", "penalty", str(tmp_path)]):
        main()

def test_cli_coderabbit(tmp_path):
    with patch.object(sys, "argv", ["code-dpdp", "coderabbit", str(tmp_path)]):
        main()
    cr_file = tmp_path / ".coderabbit.yaml"
    assert cr_file.exists()
    assert "DPDP Act 2023" in cr_file.read_text()

def test_cli_rules():
    with patch.object(sys, "argv", ["code-dpdp", "rules"]):
        main()

def test_cli_info():
    with patch.object(sys, "argv", ["code-dpdp", "info"]):
        main()

def test_ollama_service_mock():
    with patch.object(OllamaService, "is_available", return_value=True):
        with patch.object(OllamaService, "generate", return_value="Use parameterized queries."):
            res = OllamaService.explain_vulnerability("SQLi", "db.js", 10, "query()", "Sec 8(6)")
            assert "parameterized" in res

def test_cli_explain():
    with patch.object(OllamaService, "is_available", return_value=True):
        with patch.object(OllamaService, "generate", return_value="Defense guidance from Ollama"):
            with patch.object(sys, "argv", ["code-dpdp", "explain", "SQL injection"]):
                main()

def test_rag_retrieval_and_cli():
    from dpdp_audit.core.rag_pipeline import RagPipeline
    kb = RagPipeline.load_knowledge_base()
    assert len(kb) >= 30

    # Test Section 9 for children
    child_matches = RagPipeline.retrieve_statutory_context("children minor tracking targeted ads", top_k=2)
    assert any("9" in m["section"] for m in child_matches)

    # Test Section 8(5) for security safeguards / sql injection
    sqli_matches = RagPipeline.retrieve_statutory_context("sql injection parameterized query safeguards", top_k=2)
    assert any("8(5)" in m["section"] or "Rule 6" in m["section"] for m in sqli_matches)

    # Test Section 6(4) for withdrawal
    withdraw_matches = RagPipeline.retrieve_statutory_context("withdraw consent opt-out comparable ease", top_k=2)
    assert any("6(4)" in m["section"] or "Rule 4" in m["section"] for m in withdraw_matches)

    # Test CLI rag command
    with patch.object(sys, "argv", ["code-dpdp", "rag", "parental consent for child"]):
        main()
