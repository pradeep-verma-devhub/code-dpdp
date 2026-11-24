import re
from typing import Dict, Any, Optional, List

class StatutoryResolver:

    _REGISTRY: Dict[str, Dict[str, Any]] = {
        "AADHAAR": {
            "law": "The Aadhaar Act 2016, Section 29(4) read with DPDP Act 2023, Section 4 & Section 8(5)",
            "title": "Protection of Core Citizen Identity & Prohibition on Unmasked Aadhaar Publication",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "No entity shall publish, display or post an individual's Aadhaar number or demographic data without masked redaction, and Data Fiduciary shall enforce robust security safeguards under Section 8(5) to prevent demographic data compromise.",
            "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Mask first 8 digits of Aadhaar (e.g., XXXX-XXXX-1234), store only truncated representations, and isolate demographic databases behind access controls."
        },
        "PAN": {
            "law": "DPDP Act 2023, Section 8(5) read with Rule 6(1)(a)",
            "title": "Cryptographic Masking & Secure Handling of Financial Tax Identifiers",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "Permanent Account Numbers (PAN) and tax profile records constitute sensitive financial personal data and shall not be exposed in cleartext assets, logs, or unencrypted storage.",
            "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
            "owasp": "A02:2021-Cryptographic Failures",
            "implication": "Encrypt PAN fields at rest using AES-256 and mask values in customer-facing interfaces (e.g., ABCDE****F)."
        },
        "FINANCIAL": {
            "law": "DPDP Act 2023, Section 8(5) read with Rule 6(1)(a) & RBI Tokenisation Norms",
            "title": "Mandatory Encryption & Tokenisation of Payment Instruments",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall ensure complete masking of Primary Account Numbers and payment instruments, storing only cryptographic tokens to prevent financial data compromise.",
            "cwe": "CWE-311: Missing Encryption of Sensitive Data",
            "owasp": "A02:2021-Cryptographic Failures",
            "implication": "Do not store raw credit card numbers or CVV codes; integrate certified tokenisation gateways."
        },
        "PASSWORD_STORAGE": {
            "law": "DPDP Rules 2025, Rule 6(1)(a) read with Act Section 8(5)",
            "title": "Mandatory Salted Hashing & Protection of Authentication Secrets",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall implement state-of-the-art salted password hashing (bcrypt, argon2, scrypt) and cryptographic controls to ensure authentication secrets cannot be compromised.",
            "cwe": "CWE-256: Plaintext Storage of Password",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "implication": "Never assign or store plaintext passwords. Hash using bcrypt with minimum cost factor 12."
        },
        "SECRETS_HARDCODED": {
            "law": "DPDP Rules 2025, Rule 6(1)(a) & Act Section 8(5)",
            "title": "Secure Secret Management & Prohibition of Hardcoded Credentials",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall store API secrets, encryption keys, and private credentials in dedicated secret vaults or environment layers, never embedded directly in source repositories.",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "implication": "Extract secrets into environment variables (process.env) or secret management vaults (HashiCorp Vault, AWS Secrets Manager)."
        },
        "PII_LOGGING": {
            "law": "DPDP Act 2023, Section 8(3) & Section 8(5)",
            "title": "Minimization and Redaction of Personal Data in Application Logs",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "A Data Fiduciary shall ensure diagnostic traces and system event logs do not ingest unredacted personal identifiers, request bodies, or user authentication payloads.",
            "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
            "owasp": "A09:2021-Security Logging and Monitoring Failures",
            "implication": "Sanitize log arguments to strip sensitive fields (password, token, aadhaar, email) prior to log emission."
        },
        "ERROR_STACK_LEAK": {
            "law": "DPDP Act 2023, Section 8(5) & Rule 6(1)(f)",
            "title": "Information Disclosure Mitigation in Production Error Handlers",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall configure production error handlers to return generic messages and prevent internal stack traces or database schema fragments from leaking to clients.",
            "cwe": "CWE-209: Generation of Error Message Containing Sensitive Information",
            "owasp": "A05:2021-Security Misconfiguration",
            "implication": "Implement global exception filters returning clean error codes without dumping err.stack in responses."
        },
        "COOKIE_SECURITY": {
            "law": "DPDP Rules 2025, Rule 6(1)(d) read with Act Section 8(5)",
            "title": "Hardened Session Attributes & Client-Side Cookie Isolation",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "Authentication session cookies containing personal identity links must be marked HttpOnly, Secure, and SameSite to prevent script-based exfiltration and session hijacking.",
            "cwe": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
            "owasp": "A05:2021-Security Misconfiguration",
            "implication": "Set { httpOnly: true, secure: true, sameSite: 'strict' } on all authentication cookies."
        },
        "SQL_INJECTION": {
            "law": "DPDP Act 2023, Section 8(5) & Rule 6(1)(b)",
            "title": "Mandatory Parameterized Queries & Database Boundary Protection",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall protect personal data repositories by enforcing parameterized database queries and input validation to thwart injection and arbitrary database exfiltration.",
            "cwe": "CWE-89: SQL Injection",
            "owasp": "A03:2021-Injection",
            "implication": "Never concatenate user input into queries. Use parameterized placeholders ($1, %s, ?) or ORM query builders."
        },
        "XSS": {
            "law": "DPDP Act 2023, Section 8(5) & Rule 6(1)(e)",
            "title": "Contextual Output Encoding & DOM Injection Mitigation",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall employ contextual output encoding and sanitization libraries to prevent malicious script injection into client browsers accessing personal data.",
            "cwe": "CWE-79: Cross-Site Scripting (XSS)",
            "owasp": "A03:2021-Injection",
            "implication": "Replace innerHTML with textContent or sanitize inputs with DOMPurify."
        },
        "CHILD_TRACKING": {
            "law": "DPDP Act 2023, Section 9(3) read with Rule 8",
            "title": "Prohibition of Tracking and Behavioural Monitoring of Children",
            "penalty": "Up to Rs. 200 Crore under Schedule Item 3",
            "mandate": "A Data Fiduciary shall not undertake tracking or behavioural monitoring of children or targeted advertising directed at children, nor process child data detrimental to the well-being of a child.",
            "cwe": "CWE-359: Exposure of Private Personal Information",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Disable third-party analytics SDKs, session replay trackers, and advertising pixels when user is a minor."
        },
        "CHILD_CONSENT": {
            "law": "DPDP Act 2023, Section 9(1) read with Rule 8",
            "title": "Verifiable Consent of Parent or Lawful Guardian for Children",
            "penalty": "Up to Rs. 200 Crore under Schedule Item 3",
            "mandate": "The Data Fiduciary shall, before processing any personal data of a child, obtain verifiable consent of the parent or lawful guardian in such manner as may be prescribed.",
            "cwe": "CWE-285: Improper Authorization",
            "owasp": "A01:2021-Broken Access Control",
            "implication": "Implement age verification gate and parent/guardian verification flow prior to onboarding minor accounts."
        },
        "BREACH_NOTIFICATION": {
            "law": "DPDP Act 2023, Section 8(6) read with Rule 7",
            "title": "Mandatory Intimation of Personal Data Breach to Board & Principals",
            "penalty": "Up to Rs. 200 Crore under Schedule Item 2",
            "mandate": "In the event of a personal data breach, the Data Fiduciary shall give the Board and each affected Data Principal intimation of such breach in the prescribed form without delay.",
            "cwe": "CWE-778: Insufficient Logging",
            "owasp": "A09:2021-Security Logging and Monitoring Failures",
            "implication": "Configure automated security monitoring hooks that trigger immediate incident response workflows upon data exfiltration."
        },
        "PRIVACY_NOTICE": {
            "law": "DPDP Act 2023, Section 5(1) & Section 5(3)",
            "title": "Itemised Notice and Language Options Prior to Consent",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "Every request for consent shall be preceded by an itemised notice detailing personal data sought, specific purpose, and options to view in English or 22 Eighth Schedule languages.",
            "cwe": "CWE-1059: Incomplete Documentation",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Publish comprehensive notice specifying purposes, data categories, and DPO contact details."
        },
        "CONSENT_WITHDRAWAL": {
            "law": "DPDP Act 2023, Section 6(1) read with Section 6(4) & Rule 4",
            "title": "Free, Specific, Unbundled Consent and Comparable Ease of Withdrawal",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "The Data Principal shall have the right to withdraw consent at any time with the same ease with which consent was given, and processing must cease immediately upon withdrawal.",
            "cwe": "CWE-285: Improper Authorization",
            "owasp": "A01:2021-Broken Access Control",
            "implication": "Expose programmatic withdrawal endpoints and cease downstream processing upon consent revocation."
        },
        "DATA_RETENTION": {
            "law": "DPDP Act 2023, Section 8(7) read with Section 12(3)",
            "title": "Storage Limitation and Mandatory Erasure of Personal Data",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "A Data Fiduciary shall erase personal data as soon as the specified purpose is fulfilled or consent is withdrawn, and cause its Data Processors to erase all mirrored copies.",
            "cwe": "CWE-459: Incomplete Cleanup",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Implement automated data retention expiration policies and hard deletion jobs for inactive user data."
        },
        "INSECURE_TRANSPORT": {
            "law": "DPDP Act 2023, Section 16 read with Rule 6(1)(c)",
            "title": "Modern Cryptographic Transport Protocols (TLS 1.2 / TLS 1.3)",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "Personal data in transit across public or internal networks shall utilize modern cipher suites and TLS 1.2+ protocols to prevent eavesdropping and man-in-the-middle interception.",
            "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
            "owasp": "A02:2021-Cryptographic Failures",
            "implication": "Enforce HTTPS and configure minVersion: 'TLSv1.2' on all server and client connections."
        },
        "CROSS_BORDER_TRANSFER": {
            "law": "DPDP Act 2023, Section 16",
            "title": "Territorial Transfer Safeguards & Cross-Border Egress Restrictions",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "The Central Government may restrict the transfer of personal data by a Data Fiduciary for processing to any country or territory outside India as notified.",
            "cwe": "CWE-359: Exposure of Private Personal Information",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Audit server geographical endpoints to ensure sensitive data does not egress to restricted regions."
        },
        "ACCESS_CONTROL_IDOR": {
            "law": "DPDP Act 2023, Section 8(4) & Section 8(5)",
            "title": "Technical Access Control & Ownership Validation on Object References",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "A Data Fiduciary shall implement appropriate technical and organisational measures including granular role-based access control to ensure processing complies with the provisions of this Act.",
            "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
            "owasp": "A01:2021-Broken Access Control",
            "implication": "Verify user ownership of record IDs on all API endpoints before returning personal data."
        },
        "CORS_CLOUD_EXPOSURE": {
            "law": "DPDP Act 2023, Section 8(5) & Rule 6(1)(f)",
            "title": "Perimeter Isolation and Prevention of Wildcard Origin Access",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "Storage repositories housing personal data shall be isolated from public networks and unrestricted cross-origin requests through strict perimeter access filters.",
            "cwe": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
            "owasp": "A05:2021-Security Misconfiguration",
            "implication": "Disallow origin: '*' on authenticated API routes and enable private cloud bucket policies."
        },
        "PROCESSOR_CONTRACT": {
            "law": "DPDP Act 2023, Section 8(2)",
            "title": "Engagement of Data Processor under Valid Statutory Contract",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "A Data Fiduciary may engage, appoint, use or involve a Data Processor to process personal data on its behalf only under a valid statutory contract.",
            "cwe": "CWE-1059: Incomplete Documentation",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Execute Data Processing Addendums (DPAs) with all sub-processors prior to data transmission."
        },
        "GRIEVANCE_REDRESSAL": {
            "law": "DPDP Act 2023, Section 8(9) & Section 13",
            "title": "Publication and Operation of Grievance Redressal Mechanism",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "A Data Fiduciary shall establish an effective mechanism to redress the grievances of Data Principals and publish contact details of the Grievance Officer.",
            "cwe": "CWE-1059: Incomplete Documentation",
            "owasp": "A04:2021-Insecure Design",
            "implication": "Expose grievance submission portal or publish DPO email contact on public site."
        },
        "RIGHT_TO_ACCESS": {
            "law": "DPDP Act 2023, Section 11",
            "title": "Right of Data Principal to Obtain Information About Personal Data",
            "penalty": "Up to Rs. 50 Crore under Schedule Item 7",
            "mandate": "The Data Principal shall have the right to obtain from the Data Fiduciary a summary of personal data being processed and identities of all Data Fiduciaries and Processors with whom data has been shared.",
            "cwe": "CWE-285: Improper Authorization",
            "owasp": "A01:2021-Broken Access Control",
            "implication": "Implement a self-service data export / access endpoint (e.g. GET /api/user/export)."
        },
        "GENERAL_SAFEGUARDS": {
            "law": "DPDP Act 2023, Section 8(5) read with Schedule Item 1",
            "title": "Obligation to take Reasonable Security Safeguards to Prevent Personal Data Breach",
            "penalty": "Up to Rs. 250 Crore under Schedule Item 1",
            "mandate": "A Data Fiduciary shall protect personal data in its possession or under its control, including in respect of any processing undertaken by it or on its behalf by a Data Processor, by taking reasonable security safeguards to prevent personal data breach.",
            "cwe": "CWE-693: Protection Mechanism Failure",
            "owasp": "A05:2021-Security Misconfiguration",
            "implication": "Implement comprehensive technical safeguards, cryptographic validation, and perimeter defenses."
        }
    }

    @classmethod
    def resolve_dossier(
        cls,
        rule_id: str = "",
        title: str = "",
        category: str = "",
        pii_types: Optional[List[str]] = None,
        snippet: str = "",
        file_path: str = "",
        existing_ref: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        piis = [p.lower() for p in (pii_types or [])]
        combined = f"{rule_id} {title} {category} {' '.join(piis)} {file_path} {snippet[:150]}".lower()

        key = "GENERAL_SAFEGUARDS"

        if any(w in combined for w in ["sqli", "sql_injection", "rawquery", "sec-sqli", "sec-nosql"]):
            key = "SQL_INJECTION"
        elif any(w in combined for w in ["xss", "cross-site scripting", "innerhtml", "sec-xss"]):
            key = "XSS"
        elif any(w in combined for w in ["cookie", "httponly", "samesite", "sec-auth-001", "dpdp-str-005"]):
            key = "COOKIE_SECURITY"
        elif any(w in combined for w in ["dpdp-chd-002", "dpdp-chd-003", "behavioural tracking", "minor profile", "tracking minor"]):
            key = "CHILD_TRACKING"
        elif any(w in combined for w in ["dpdp-chd-001", "parental consent", "child consent", "guardian"]):
            key = "CHILD_CONSENT"
        elif any(w in combined for w in ["dpdp-log", "console.log", "logger.", "winston", "req.body", "pii_logging"]):
            key = "PII_LOGGING"
        elif any(w in combined for w in ["stack trace", "verbose error", "sec-exp-001", "dpdp-exp-004"]):
            key = "ERROR_STACK_LEAK"
        elif any(w in combined for w in ["breach notification", "dpdp-brc", "data breach intimation", "rule 7"]):
            key = "BREACH_NOTIFICATION"
        elif any(w in combined for w in ["withdraw", "consent architecture", "opt-out", "act_sec_6", "dpdp-cns"]):
            key = "CONSENT_WITHDRAWAL"
        elif any(w in combined for w in ["notice", "multilingual", "dpdp-not", "act_sec_5"]):
            key = "PRIVACY_NOTICE"
        elif any(w in combined for w in ["retention", "erasure", "ttl", "storage limitation", "dpdp-lfc-001", "act_sec_8_7", "act_sec_12"]):
            key = "DATA_RETENTION"
        elif any(w in combined for w in ["tls", "https", "minversion", "cleartext transmission", "sec-trn", "dpdp-trn-001"]):
            key = "INSECURE_TRANSPORT"
        elif any(w in combined for w in ["cross-border", "cross border", "egress", "act_sec_16", "dpdp-trn-002"]):
            key = "CROSS_BORDER_TRANSFER"
        elif any(w in combined for w in ["idor", "authorization gate", "missing route auth", "sec-auth-003", "sec-exp-003", "dpdp-exp-001"]):
            key = "ACCESS_CONTROL_IDOR"
        elif any(w in combined for w in ["cors", "wildcard", "s3 bucket", "sec-cfg-001", "sec-exp-002", "dpdp-cfg-001"]):
            key = "CORS_CLOUD_EXPOSURE"
        elif any(w in combined for w in ["processor contract", "dpa", "dpdp-prc", "act_sec_8_2"]):
            key = "PROCESSOR_CONTRACT"
        elif any(w in combined for w in ["grievance", "dpo contact", "dpdp-lfc-004", "act_sec_8_9", "act_sec_13"]):
            key = "GRIEVANCE_REDRESSAL"
        elif any(w in combined for w in ["right to access", "export data", "act_sec_11"]):
            key = "RIGHT_TO_ACCESS"
        elif any(w in combined for w in ["secret", "hardcoded_secret", "jwt_secret", "api_key", "sec-auth-002", "dpdp-str-003"]):
            key = "SECRETS_HARDCODED"
        elif "aadhaar" in piis or "aadhaar" in combined or "dpdp-pii-aadhaar" in combined:
            key = "AADHAAR"
        elif "pan" in piis or "pan" in combined or "dpdp-pii-pan" in combined:
            key = "PAN"
        elif "financial" in piis or any(w in combined for w in ["credit_card", "cvv", "upi", "card_number", "dpdp-pii-financial"]):
            key = "FINANCIAL"
        elif any(w in combined for w in ["password", "plaintext_password", "weak_hash", "bcrypt", "sec-cryp", "dpdp-str-001", "dpdp-pii-password"]):
            key = "PASSWORD_STORAGE"

        dossier = cls._REGISTRY[key].copy()
        dossier["key"] = key
        return dossier
