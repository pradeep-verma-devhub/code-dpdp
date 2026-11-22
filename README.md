# DPDP-Audit

**Automated Compliance Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg)](https://www.python.org/)
[![DPDP Act 2023](https://img.shields.io/badge/Compliance-DPDP%20Act%202023%20%26%20Rules%202025-FF9933.svg)](#)

---

## Overview

**DPDP-Audit** is an automated static and dynamic compliance scanner designed for privacy and security engineers. It identifies personal data mishandling, insecure cloud and container configurations, missing consent workflows, and API security gaps across modern application repositories, mapping every finding directly to provisions of the **Digital Personal Data Protection Act 2023 (Act No. 22 of 2023)** and **DPDP Rules 2025**.

### Stack & Architecture

- **CLI & Frontend Tooling**: Node.js + TypeScript (strict mode), Commander CLI, `@babel/parser` & TypeScript Compiler API.
- **Backend & Core Logic**: Python 3.12 (PII detection engine, Verhoeff/Luhn cryptographic validators, AST semantic evaluator, mathematical risk classification, ReportLab PDF report generation, consent flow analyzer, unified diff patch generator, and safe live API tester).
- **Rule Definitions**: 100% external YAML entries in `src/rules/*.yaml`, linked to a single master statutory mapping file `src/rules/dpdp-map.yaml`.

---

## Key Features

1. **Full-Spectrum Code & Config Scanning**:
   - **Frontend & Backend**: JavaScript, TypeScript, React, Express routes, controllers, middleware.
   - **Database Schemas & Models**: SQL DDL (`.sql`), Prisma (`.prisma`), Mongoose & Sequelize models (`*model*.ts`, `*schema*.ts`).
   - **Config & DevOps**: `.env`, `Dockerfile`, `docker-compose.ya?ml`, Terraform (`.tf`), Kubernetes manifests.
2. **Indian PII Dictionary & Cryptographic Pattern Engine**:
   - Validates **Aadhaar** numbers using the official **Verhoeff algorithm** (rejecting invalid checksums and disallowing leading 0/1).
   - Validates **PAN** cards (format + 4th character holder status: Individual `P`, Company `C`, etc.).
   - Validates **Credit/Debit Cards** via the **Luhn algorithm**.
   - Detects Indian mobile phone numbers (+91), Indian PIN codes (6-digit), UPI VPAs, IFSC codes, Passports, Voter IDs, Biometrics, Health records, Passwords, Geolocation coordinates, and Children's data.
   - Classifies data flow as `collected`, `stored`, `logged`, `transferred`, or `exposed`.
   - Automatic redaction/masking of sensitive values in terminal and report snippets.
3. **DPDP Statutory Mapping**:
   - Single source of truth: [`src/rules/dpdp-map.yaml`](src/rules/dpdp-map.yaml).
   - Maps each rule to Sections 4, 5, 6, 8, 9, 11, 12, 13, 16, and Rules 3, 4, 5, 6, 7, 8, 9, 10.
   - Tracks statutory financial penalty clauses (e.g. Section 8(6) up to ₹250 Cr, Section 9 child data violations up to ₹200 Cr).
4. **Documented Risk Classification**:
   - Severity: `critical`, `high`, `medium`, `low`.
   - Mathematical formula:
     $$\text{Risk Score} = \text{Data Sensitivity } (1-5) \times \text{Exposure Vector } (1-5) \times \text{Ease of Exploit } (1-5) \in [1, 125]$$
   - Critical ($\ge 60$), High ($30-59$), Medium ($12-29$), Low ($<12$).
5. **Executive PDF & HTML Reports**:
   - Cover page, Executive Summary, Severity breakdown, DPDP statutory provision coverage table, Consent Scorecard, and detailed finding cards with redacted snippets and remediation steps.
6. **Bonus A: 5-Pillar Consent Flow Assessment**:
   - Evaluates whether consent is (1) recorded with timestamp/purpose/version, (2) withdrawable via endpoint/UI, (3) enforced in backend before data use, (4) granular per purpose, and (5) accompanied by a plain language notice.
7. **Bonus B: Unified Diff Auto-Fix Patches**:
   - Generates standard `.patch` unified diffs.
   - `--apply` mode creates a clean git branch `dpdp-remediation-<timestamp>` and a PR-ready markdown summary (`PR_REMEDIATION.md`).
8. **Bonus C: Safe Live API Tester**:
   - Non-destructive probes verifying TLS, mandatory security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), rate limiting headers, unauthenticated PII leakage, verbose error disclosures, and statutory erasure/export endpoints.

---

## Directory Structure

```
dpdp-anti/
├── bin/
│   └── dpdp-audit.js              # Executable CLI wrapper
├── package.json
├── tsconfig.json                  # TypeScript strict mode configuration
├── vitest.config.ts               # Vitest test suite config
├── src/
│   ├── cli.ts                     # Commander CLI interface
│   ├── index.ts                   # Library exports
│   ├── types.ts                   # Core TypeScript type contracts
│   ├── pii/                       # PII dictionary, patterns & classifier
│   ├── rules/                     # External YAML rules & dpdp-map.yaml
│   └── docs/                      # Auto-generator for RULES.md
├── python/
│   └── dpdp_audit/
│       ├── cli.py                 # Core CLI entrypoint
│       ├── core/
│       │   ├── models.py          # Data models
│       │   ├── pii_detector.py    # Verhoeff, Luhn & PII regex engine
│       │   ├── risk_scorer.py     # Sensitivity x Exposure x Exploit scoring
│       │   ├── rules_engine.py    # Multi-analyzer scanner & deduplicator
│       │   ├── dpdp_mapper.py     # Legal provision mapper
│       │   └── file_walker.py     # High-speed file walker & comment ignore parser
│       ├── analyzers/
│       │   ├── config_analyzer.py # .env, Dockerfile, Compose, k8s, Terraform
│       │   ├── schema_analyzer.py # SQL, Prisma, Mongoose schemas
│       │   ├── ast_analyzer.py    # Code AST and flow analyzer
│       │   ├── consent_analyzer.py# 5-Pillar Consent Flow Evaluator
│       │   ├── patch_generator.py # Unified diff & git branch PR creator
│       │   └── live_tester.py     # Safe live API tester
│       └── report/
│           ├── pdf_generator.py   # Vector PDF Compliance Report
│           └── html_generator.py  # Interactive HTML Report
├── docs/
│   └── RULES.md                   # Auto-generated documentation of all 46 rules
├── tests/                         # Vitest test suite
└── target/                        # Benchmark target (OWASP Juice Shop)
```

---

## Installation & Setup

### Prerequisites
- Node.js >= 18.0.0
- Python >= 3.10
- Git

### Quick Setup

```bash
# 1. Install Node dependencies and compile TypeScript
npm install
npm run build

# 2. Setup Python backend virtual environment
python3 -m venv .venv
.venv/bin/pip install reportlab pyyaml requests pytest

# 3. Verify installation
./bin/dpdp-audit.js --help
```

---

## CLI Usage

### 1. Static & Config Compliance Scan
```bash
# Scan target directory and generate PDF, JSON, and Auto-Fix patches
./bin/dpdp-audit.js scan ./target --out report.pdf --json out.json --patches ./patches

# Automatically apply patches to a new git branch in the target repo
./bin/dpdp-audit.js scan ./target --patches ./patches --apply
```

### 2. Consent Flow Assessment (Bonus A)
```bash
./bin/dpdp-audit.js consent ./target
```

### 3. Safe Live API Testing (Bonus C)
```bash
./bin/dpdp-audit.js live http://localhost:3000
```

### 4. Catalog Registered Rules
```bash
./bin/dpdp-audit.js list-rules
```

---

## Benchmark Results: OWASP Juice Shop

Scanning **OWASP Juice Shop** (`./target`):

| Metric | Result |
| :--- | :--- |
| **Total Files Scanned** | **1,371 files** |
| **Execution Duration** | **5.6 seconds** |
| **Findings Identified** | **171 violations** |
| **Critical Severity** | **109 findings** (e.g. unencrypted transit, hardcoded secrets, open ports) |
| **High Severity** | **59 findings** (e.g. missing cookie flags, full user entity exposure) |
| **Medium Severity** | **3 findings** (e.g. verbose error disclosures) |
| **Overall Health Score** | **0 / 100** |
| **Consent Maturity** | **Grade F** (Missing purpose-level consent checks) |
| **Auto-Fix Patches** | **117 unified diffs generated** |

Generated Artifacts:
- [`report.pdf`](report.pdf): Full statutory compliance report.
- [`out.json`](out.json): Machine-readable scan export.
- [`patches/all_remediations.patch`](patches/all_remediations.patch): Unified diff patch bundle.
- [`docs/RULES.md`](docs/RULES.md): Exhaustive catalog of all 46 rules and statutory citations.

---

## Running Test Suites

Both Vitest (TypeScript) and Pytest (Python) suites run with 100% test passing:

```bash
# Run TypeScript Vitest suite
npm test

# Run Python Pytest suite
PYTHONPATH=python .venv/bin/pytest python/tests

# Run both in sequence
npm test && PYTHONPATH=python .venv/bin/pytest python/tests
```

---

## 5-Minute Hackathon Demo Script

Here is an effective 5-minute presentation script for pitching **DPDP-Audit** at a hackathon or executive demo:

### **Minute 0:00 - 1:00: The Problem & The Regulatory Stakes**
> *"India's Digital Personal Data Protection Act 2023 and the DPDP Rules 2025 introduce some of the strictest data privacy obligations in the world, with fines reaching up to ₹250 Crore per violation for failing to maintain reasonable security safeguards. Today, engineering teams have no automated tool to audit their code, database schemas, and cloud configs specifically against the DPDP Act. That is why we built **DPDP-Audit**."*

### **Minute 1:00 - 2:00: Scanning OWASP Juice Shop Live**
> *"Let's test DPDP-Audit against a complex application: OWASP Juice Shop. With one command:  
> `dpdp-audit scan ./target --out report.pdf --json out.json --patches ./patches`  
> In just 5 seconds, our hybrid TypeScript + Python engine walks 1,371 files—analyzing TypeScript ASTs, Prisma schemas, Dockerfiles, and `.env` configs. It identified 171 statutory non-compliance points with zero false positives on Aadhaar (using Verhoeff verification) and PAN cards."*

### **Minute 2:00 - 3:00: Executive PDF Compliance Report**
> *(Open `report.pdf`)*  
> *"Here is the generated Compliance Report. Notice the Cover Page with an overall compliance health score (0/100). The Executive Summary quantifies the legal fine exposure under the Act's Schedule. The statutory coverage matrix directly correlates each finding to Sections 6, 8, 9, 12 of the Act and Rules 6 and 8. Notice how sensitive passwords and PII values in code snippets are automatically masked to prevent secondary leaks."*

### **Minute 3:00 - 4:00: Consent Flow Assessment & Live API Testing**
> *"Compliance isn't just about static secrets—it's about user consent. Let's run:  
> `dpdp-audit consent ./target`  
> In seconds, it evaluates the 5 statutory pillars of consent: Recordation with timestamps, ease of withdrawal, backend pre-processing enforcement, granular purposes, and plain notice.  
> Next, our safe live tester (`dpdp-audit live http://localhost:3000`) probes running endpoints for missing HSTS headers, unauthenticated PII leakage, and statutory erasure endpoints."*

### **Minute 4:00 - 5:00: Auto-Fix Patches & PR Generation**
> *"Finding problems is good; fixing them automatically is great. DPDP-Audit generated 117 unified diff patches. When we pass `--apply`, it creates a new git branch in the repository, applies the fixes (adding `secure: true, httpOnly: true` to cookies, upgrading ciphers, and securing Docker configs), and generates a PR-ready `PR_REMEDIATION.md`.  
> DPDP-Audit turns compliance from a 6-month legal audit into a 5-second automated CI/CD privacy pipeline."*

---

## License

Distributed under the **Apache-2.0** License.
