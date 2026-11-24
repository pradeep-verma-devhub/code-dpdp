import os
import re
import json
import math
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from .ollama_service import OllamaService

class RagPipeline:
    """
    Advanced Retrieval-Augmented Generation (RAG) pipeline for DPDP Act 2023 & DPDP Rules 2025.
    Connects code findings and natural language compliance queries directly to the official
    statutory rulebook and Gazette provisions.
    """

    _knowledge_base: Optional[List[Dict[str, Any]]] = None
    _kb_by_key: Optional[Dict[str, Dict[str, Any]]] = None

    @classmethod
    def _get_knowledge_base_path(cls) -> Path:
        curr = Path(__file__).resolve()
        for parent in [curr.parent, curr.parent.parent, curr.parent.parent.parent, curr.parent.parent.parent.parent]:
            cand = parent / "data" / "knowledge_base" / "dpdp_rulebook.json"
            if cand.exists():
                return cand
        cwd_cand = Path(os.getcwd()) / "data" / "knowledge_base" / "dpdp_rulebook.json"
        if cwd_cand.exists():
            return cwd_cand
        return cand

    @classmethod
    def load_knowledge_base(cls) -> List[Dict[str, Any]]:
        if cls._knowledge_base is not None:
            return cls._knowledge_base

        kb_path = cls._get_knowledge_base_path()
        if not kb_path.exists():
            cls._knowledge_base = []
            cls._kb_by_key = {}
            return []

        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                cls._knowledge_base = data
                
                # Build lookup indices for fast exact matching
                by_key: Dict[str, Dict[str, Any]] = {}
                for item in data:
                    item_id = item.get("id", "").upper()
                    sec = item.get("section", "").upper()
                    by_key[item_id] = item
                    by_key[sec] = item
                    
                    # Also map standard normalization keys
                    # e.g., DPDP-ACT-SEC-8-5 -> ACT_SEC_8_5, Section 8(5) -> SEC_8_5
                    clean_id = re.sub(r'[^A-Z0-9]', '_', item_id)
                    by_key[clean_id] = item
                    if "SEC" in clean_id:
                        short_key = clean_id.replace("DPDP_", "").replace("ACT_", "")
                        by_key[short_key] = item
                        by_key["ACT_" + short_key] = item
                    if "RULE" in clean_id:
                        short_rule = clean_id.replace("DPDP_RULES_2025_", "")
                        by_key[short_rule] = item
                        
                cls._kb_by_key = by_key
                return data
        except Exception:
            cls._knowledge_base = []
            cls._kb_by_key = {}
            return []

    @classmethod
    def tokenize(cls, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r'\b[a-zA-Z0-9_\-]{2,}\b', text)]

    @classmethod
    def retrieve_statutory_context(cls, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieves top matching statutory sections from the complete DPDP Act 2023 & Rules 2025 rulebook
        using multi-tier BM25/keyword/statute semantic scoring.
        """
        kb = cls.load_knowledge_base()
        if not kb:
            return []

        query_lower = query.lower()
        query_tokens = set(cls.tokenize(query))

        # Check for explicit section/rule mentions (e.g. "section 9", "sec 8(5)", "rule 6", "16")
        explicit_sec_match = re.search(r'\b(?:section|sec\.?)\s*([0-9]+(?:\([0-9]+\))?)', query_lower)
        explicit_rule_match = re.search(r'\b(?:rule)\s*([0-9]+(?:\s*(?:&|and)\s*[0-9]+)?)', query_lower)
        
        target_sec = explicit_sec_match.group(1) if explicit_sec_match else None
        target_rule = explicit_rule_match.group(1) if explicit_rule_match else None

        scored: List[Tuple[float, Dict[str, Any]]] = []

        for item in kb:
            score = 0.0
            sec_lower = item.get("section", "").lower()
            title_lower = item.get("title", "").lower()
            category_lower = item.get("category", "").lower()
            keywords = [k.lower() for k in item.get("keywords", [])]

            # 1. Direct explicit statute number match (Highest priority)
            if target_sec and target_sec in sec_lower:
                score += 50.0
            if target_rule and target_rule in sec_lower:
                score += 50.0

            # 2. Keyword exact & substring matches
            for q in query_tokens:
                if q in keywords:
                    score += 8.0
                elif any(q in kw or kw in q for kw in keywords if len(kw) > 3):
                    score += 3.0

            # 3. Category match
            if category_lower and category_lower in query_lower:
                score += 10.0

            # 4. Title & section token overlap
            title_tokens = set(cls.tokenize(title_lower))
            sec_tokens = set(cls.tokenize(sec_lower))
            score += len(query_tokens.intersection(title_tokens)) * 4.0
            score += len(query_tokens.intersection(sec_tokens)) * 5.0

            # 5. Technical implication & Official Gazette text overlap
            tech_tokens = set(cls.tokenize(item.get("technical_implication", "").lower()))
            score += len(query_tokens.intersection(tech_tokens)) * 2.0

            text_tokens = set(cls.tokenize(item.get("official_text", "").lower()))
            score += len(query_tokens.intersection(text_tokens)) * 1.0

            # 6. Specific Concept Anchors
            # Children / Minors
            if any(w in query_lower for w in ["child", "minor", "parent", "guardian", "under 18", "age"]):
                if "9" in sec_lower or item.get("category") == "children":
                    score += 25.0
            # SQLi / XSS / RCE / Security safeguards
            if any(w in query_lower for w in ["sql", "sqli", "injection", "xss", "rce", "ssrf", "eval", "safeguard", "vulnerability"]):
                if "8(5)" in sec_lower or "rule 6" in sec_lower:
                    score += 20.0
            # Plaintext / Password / Encryption / TLS / MD5 / Hashing
            if any(w in query_lower for w in ["password", "md5", "sha1", "crypto", "tls", "encryption", "hash", "argon2", "bcrypt", "cookie"]):
                if "rule 6" in sec_lower or "8(5)" in sec_lower:
                    score += 20.0
            # Data Breach Notice / Alerts / PagerDuty / 6 hours
            if any(w in query_lower for w in ["breach notice", "breach reporting", "intimation", "alerting", "telemetry", "incident"]):
                if "8(6)" in sec_lower or "rule 7" in sec_lower:
                    score += 25.0
            # Consent / Opt-in / Dark pattern
            if any(w in query_lower for w in ["consent", "affirmative", "checkbox", "pre-ticked", "opt-in", "unbundled"]):
                if "6(1)" in sec_lower or "rule 3" in sec_lower:
                    score += 20.0
            # Consent withdrawal / Opt-out
            if any(w in query_lower for w in ["withdraw", "opt-out", "revoke", "revocation"]):
                if "6(4)" in sec_lower or "rule 4" in sec_lower:
                    score += 25.0
            # Retention / Erasure / Purge / Delete account
            if any(w in query_lower for w in ["retention", "erasure", "deletion", "ttl", "purge", "soft delete", "forget"]):
                if "8(7)" in sec_lower or "12" in sec_lower:
                    score += 25.0
            # Notice / Languages / 8th schedule
            if any(w in query_lower for w in ["notice", "multilingual", "language", "eighth schedule", "itemised"]):
                if "5" in sec_lower:
                    score += 25.0
            # Grievance / DPO / Contact
            if any(w in query_lower for w in ["grievance", "dpo", "officer", "complaint", "redressal"]):
                if "8(10)" in sec_lower or "13" in sec_lower or "rule 9" in sec_lower:
                    score += 25.0
            # Egress / Cross-border / Third-party / Foreign
            if any(w in query_lower for w in ["egress", "cross-border", "transfer", "overseas", "foreign", "meta pixel", "analytics"]):
                if "16" in sec_lower or "rule 5" in sec_lower:
                    score += 20.0
            # Significant Data Fiduciary / DPIA
            if any(w in query_lower for w in ["significant", "sdf", "dpia", "audit"]):
                if "10" in sec_lower:
                    score += 20.0

            if score > 0:
                scored.append((score, item))

        scored.sort(key=lambda x: x[0], reverse=True)
        top_matches = [item for _, item in scored[:top_k]]
        return top_matches

    @classmethod
    def resolve_statutory_reference(
        cls,
        title: str,
        category: str = "",
        snippet: str = "",
        pii_types: Optional[List[str]] = None,
        data_flow: str = "",
        fallback_ref: str = ""
    ) -> Dict[str, Any]:
        """
        Dynamically connects a code finding or rule to its precise DPDP Act 2023 or Rules 2025 provision.
        Eliminates hardcoded repetitiveness by querying the full rulebook via semantic RAG.
        """
        cls.load_knowledge_base()

        # If fallback_ref directly names a specific section in KB, verify it
        cleaned_ref = fallback_ref.strip().upper().replace(" ", "_").replace("-", "_")
        if cls._kb_by_key and cleaned_ref in cls._kb_by_key:
            target = cls._kb_by_key[cleaned_ref]
            # Avoid generic default fallbacks if context shows a more specific requirement
            if not (cleaned_ref in ("ACT_SEC_8_6", "SEC_8_6") and any(w in (title + " " + category).lower() for w in ["child", "consent", "notice", "retention", "injection", "crypto"])):
                return {
                    "sectionOrRule": target["section"],
                    "statutory_citation": target["statutory_citation"],
                    "title": target["title"],
                    "explanation": target["official_text"][:250] + ("..." if len(target["official_text"]) > 250 else ""),
                    "penaltyClause": target["penalty"],
                    "official_text": target["official_text"],
                    "technical_implication": target["technical_implication"]
                }

        # Build dynamic RAG query
        pii_str = " ".join(pii_types or [])
        query = f"{title} {category} {data_flow} {pii_str} {snippet[:200]}"
        matches = cls.retrieve_statutory_context(query, top_k=1)

        if matches:
            statute = matches[0]
            return {
                "sectionOrRule": statute["section"],
                "statutory_citation": statute["statutory_citation"],
                "title": statute["title"],
                "explanation": statute["official_text"][:250] + ("..." if len(statute["official_text"]) > 250 else ""),
                "penaltyClause": statute["penalty"],
                "official_text": statute["official_text"],
                "technical_implication": statute["technical_implication"]
            }

        # Default standard fallback grounded in Section 8(5) Reasonable Security Safeguards
        return {
            "sectionOrRule": "Section 8(5)",
            "statutory_citation": "DPDP Act 2023, Section 8(5) read with Schedule Item 1",
            "title": "Obligation to take Reasonable Security Safeguards to Prevent Personal Data Breach",
            "explanation": "A Data Fiduciary shall protect personal data by taking reasonable security safeguards to prevent personal data breach.",
            "penaltyClause": "Schedule Item 1: Up to Rs. 250 Crore",
            "official_text": "A Data Fiduciary shall protect personal data in its possession or under its control, including in respect of any processing undertaken by it or on its behalf by a Data Processor, by taking reasonable security safeguards to prevent personal data breach.",
            "technical_implication": "Mandates parameterized queries, strict input validation, end-to-end encryption, and role-based access control."
        }

    @classmethod
    def augment_finding_remediation(
        cls,
        finding_title: str,
        snippet: str,
        file_path: str,
        current_fix: str
    ) -> Dict[str, Any]:
        """Enriches a finding using RAG statutory retrieval and local Ollama or expert synthesis."""
        query = f"{finding_title} {current_fix} {file_path}"
        matches = cls.retrieve_statutory_context(query, top_k=1)

        statute = matches[0] if matches else None
        statute_citation = statute["statutory_citation"] if statute else "DPDP Act 2023 Section 8(5)"
        penalty = statute["penalty"] if statute else "Up to Rs. 250 Crore under Schedule Item 1"
        official_text = statute["official_text"] if statute else ""
        tech_implication = statute.get("technical_implication", "") if statute else ""

        # Local Ollama RAG generation
        ai_advice = None
        if OllamaService.is_available():
            rag_prompt = (
                f"You are a Senior Cyber Defense & DPDP Statutory Compliance Auditor.\n\n"
                f"OFFICIAL STATUTORY LAW CITATION:\n"
                f"- Law & Section: {statute_citation}\n"
                f"- Statutory Text: {official_text}\n"
                f"- Maximum Fine Exposure: {penalty}\n\n"
                f"CODE VULNERABILITY DETECTED:\n"
                f"- Title: {finding_title}\n"
                f"- File: {file_path}\n"
                f"- Code Snippet: {snippet}\n\n"
                f"Provide a 2-sentence defensive engineering remediation instructing developers "
                f"how to fix this code to ensure full compliance with {statute_citation}."
            )
            ai_advice = OllamaService.generate_remediation(finding_title, snippet, rag_prompt)
        else:
            # Deterministic, expert engineering defense brief based on retrieved statute
            ai_advice = f"Mandate under {statute_citation}: {tech_implication}. Fix file {file_path}: {current_fix}"

        return {
            "statute_citation": statute_citation,
            "penalty": penalty,
            "official_text": official_text,
            "ai_remediation": ai_advice
        }

    @classmethod
    def query_rulebook(cls, user_query: str) -> Dict[str, Any]:
        """Interactive RAG query on DPDP Act 2023 & DPDP Rules 2025."""
        matches = cls.retrieve_statutory_context(user_query, top_k=3)

        if not matches:
            kb = cls.load_knowledge_base()
            matches = kb[:3] if kb else []

        context_blocks = []
        for idx, m in enumerate(matches, 1):
            context_blocks.append(
                f"[{idx}] {m['statutory_citation']}\n"
                f"    Title: {m['title']}\n"
                f"    Statutory Penalty: {m['penalty']}\n"
                f"    Official Gazette Provision: \"{m['official_text']}\"\n"
                f"    Technical Mandate: {m['technical_implication']}"
            )
        context_str = "\n\n".join(context_blocks)

        ai_response = None
        if OllamaService.is_available():
            prompt = (
                f"You are the official India DPDP Act 2023 & DPDP Rules 2025 Statutory Compliance Assistant.\n\n"
                f"RETRIEVED STATUTORY PROVISIONS FROM OFFICIAL GAZETTE:\n"
                f"{context_str}\n\n"
                f"USER COMPLIANCE QUESTION: {user_query}\n\n"
                f"Answer the question directly in 2-3 sentences, citing the exact DPDP section number, official wording, and penalty ceiling."
            )
            ai_response = OllamaService.generate(prompt)
        else:
            # High-grade offline synthesis from top match
            top_m = matches[0] if matches else {}
            ai_response = (
                f"According to {top_m.get('statutory_citation', 'the DPDP Act 2023')}, "
                f"{top_m.get('official_text', '')}\n\n"
                f"• Technical Obligation: {top_m.get('technical_implication', '')}\n"
                f"• Statutory Exposure: {top_m.get('penalty', '')}"
            )

        return {
            "query": user_query,
            "retrieved_provisions": matches,
            "context_str": context_str,
            "ai_synthesis": ai_response
        }
