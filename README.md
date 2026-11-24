# code-dpdp

> **Automated CLI Compliance & Security Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025 with Integrated Statutory RAG Engine**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/CLI-code--dpdp-00CED1.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://python.org/)
[![DPDP Act 2023](https://img.shields.io/badge/Compliance-DPDP%20Act%202023-FF9933.svg)](#)
[![DPDP Rules 2025](https://img.shields.io/badge/Compliance-DPDP%20Rules%202025-138808.svg)](#)
[![RAG Grounded](https://img.shields.io/badge/RAG-Statutory%20Knowledge%20Base-8A2BE2.svg)](#)
[![Demo Video](https://img.shields.io/badge/Project%20Demo-1080p%20Video-E11D48.svg)](code-dpdp-project-demo.mp4)

---

## 🎬 Project Submission Demo Video

A complete 1080p Full HD video presentation and live demonstration walkthrough is included directly in the root of this repository:
- **Video File**: [`code-dpdp-project-demo.mp4`](code-dpdp-project-demo.mp4)
- **Duration**: ~2 minutes 15 seconds
- **Resolution**: 1920x1080 Full HD (H.264 / AAC)
- **Content**:
  1. *Statutory Mandate & Risk*: Legal background on DPDP Act 2023 & DPDP Rules 2025 with ₹250 Crore penalty thresholds.
  2. *System Architecture*: Full Gazette knowledge base & hybrid RAG pipeline eliminating section repetition.
  3. *Live CLI RAG Demo*: Natural language legal queries mapped to official Gazette provisions.
  4. *Live Codebase Scan*: AST flow analysis, Verhoeff Aadhaar/PAN validation, and real penalty exposures.
  5. *Automated Remediation*: One-click `.patch` generation and executive PDF compliance reports.
  6. *Cross-Platform Setup*: Linux (`./setup.sh`) and Windows (`setup.bat` / `setup.ps1`) deployment.

---

## ⚡ Overview

`code-dpdp` is an automated, terminal-based compliance auditor and cybersecurity scanner designed specifically for India's **Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)** and notified **DPDP Rules 2025**.

It inspects source code, configuration files, database schemas, and live API endpoints to identify data protection violations, calculate statutory monetary penalties under the DPDP Act Schedule, generate publication-grade PDF audit reports, and provide automated `.patch` fixes.

### 🧠 Grounded in a Real Statutory RAG System
Unlike simple static tools that repeat generic section numbers, `code-dpdp` is directly powered by a **Retrieval-Augmented Generation (RAG) engine** connected to the official DPDP Act 2023 rulebook:
- Covers all **44 Sections across all 9 Chapters**, the **Statutory Penalties Schedule (Items 1 to 7)**, and **DPDP Rules 2025 (Rules 1 to 12)**.
- Every detected code finding is dynamically matched to its exact legal provision (e.g. **Section 9(3)** for children's tracking, **Section 8(5)** for security safeguards, **Section 8(6)** for breach notification, **Section 6(4)** for consent withdrawal, **Section 16** for cross-border egress, **Rule 6** for cryptographic encryption).
- Built-in interactive command `code-dpdp rag "<query>"` lets you query the entire Gazette law directly from the command line.

---

## 🚀 One-Click Installation & Setup Guide

Whether you **cloned the repo from GitHub** or **downloaded and extracted the ZIP file**, you can set up everything with **a single command**.

### 🐧 For Linux & macOS

1. Open terminal and navigate to the project directory:
   ```bash
   cd code-dpdp
   ```

2. Run the automated installer:
   ```bash
   ./setup.sh
   ```
   *(Or `bash setup.sh`)*

3. **What the script does automatically:**
   - Detects Python 3 (requires Python 3.10+)
   - Creates an isolated virtual environment (`.venv`)
   - Installs all dependencies from `requirements.txt`
   - Installs optional Node/npm packages if available
   - Symlinks `code-dpdp` to `~/.local/bin/code-dpdp` (accessible from any terminal)
   - Runs a self-test to verify installation

4. Verify installation:
   ```bash
   code-dpdp --version
   ```

---

### 🪟 For Windows (Command Prompt or PowerShell)

#### Option A: Command Prompt (CMD)
1. Open Command Prompt (`cmd.exe`) in the extracted `code-dpdp` folder:
   ```cmd
   cd code-dpdp
   ```

2. Run the automated setup script:
   ```cmd
   setup.bat
   ```

#### Option B: PowerShell
1. Open PowerShell in the extracted folder:
   ```powershell
   cd code-dpdp
   .\setup.ps1
   ```

3. **What the script does automatically:**
   - Detects Python 3.10+ (alerts if missing from PATH)
   - Creates Python virtual environment (`.venv`)
   - Installs all dependencies via `pip`
   - Sets up Windows CLI wrappers (`code-dpdp.cmd` / `code-dpdp.bat`)
   - Copies launcher to `%USERPROFILE%\.local\bin`
   - Runs verification self-test

4. Verify installation:
   ```cmd
   code-dpdp --version
   ```

---

## 🛠️ Command-Line Interface (CLI) Reference

| Command | Description |
| :--- | :--- |
| `code-dpdp scan [path]` | Full AST, config, schema, and vulnerability audit with dynamic statutory mapping |
| `code-dpdp scan . --pdf report.pdf` | Generates official executive PDF audit report with all findings and citations |
| `code-dpdp rag "<query>"` | Queries official DPDP Act 2023 Gazette & DPDP Rules 2025 rulebook via RAG |
| `code-dpdp pii [path]` | Indian PII Radar: detects Aadhaar (Verhoeff), PAN, Indian phone (+91), cards (Luhn) |
| `code-dpdp consent [path]` | 5-Pillar Consent Architecture assessment (DPDP Sec 5 & 6, Rules 3 & 4) |
| `code-dpdp egress [path]` | Audits third-party SDK trackers (Meta Pixel, Google Analytics, foreign egress) |
| `code-dpdp penalty [path]` | Computes financial penalty exposure under the DPDP Act Schedule (up to ₹250 Cr) |
| `code-dpdp live <baseUrl>` | Non-destructive live API compliance & security probe (HTTPS, headers, routes) |
| `code-dpdp patch [path]` | Generates unified git diff patches (`.patch`) for detected vulnerabilities |
| `code-dpdp coderabbit [path]` | Auto-generates compliant `.coderabbit.yaml` rule contract for CI/CD PR reviews |
| `code-dpdp rules` | Lists all statutory DPDP Act & Rules checks with legal citations & penalty limits |
| `code-dpdp info` | Displays system status, active rules count, and local Ollama daemon status |

---

## 📖 Detailed Examples & Usage

### 1. Full Compliance Scan & PDF Report
```bash
# Scan current repository and generate official PDF report
code-dpdp scan . --pdf result.pdf

# Export structured JSON findings for CI/CD pipelines
code-dpdp scan . --json out.json

# Filter output by severity
code-dpdp scan . --severity critical

# Enforce CI failure threshold (exits with non-zero status on critical violations)
code-dpdp scan . --fail-on critical
```

### 2. Interactive Statutory RAG Search (`code-dpdp rag`)
Query any topic, section number, or rule. The RAG engine retrieves the official Gazette text, technical mandate, and maximum fine:
```bash
# Search by topic:
code-dpdp rag "parental consent for children"

# Search by section:
code-dpdp rag "Section 9"
code-dpdp rag "Section 16 cross-border transfer"
code-dpdp rag "breach notification timeline 6 hours"
code-dpdp rag "storage limitation and data erasure"
```

### 3. Indian PII & Credentials Radar (`code-dpdp pii`)
Identifies sensitive Indian personal data and unencrypted credentials:
- **Aadhaar Numbers**: Validated via **Verhoeff checksum algorithm**
- **PAN Cards**: Validated via Income Tax PAN regex `[A-Z]{5}[0-9]{4}[A-Z]`
- **Indian Mobile Numbers**: `+91` and 10-digit formats starting with 6, 7, 8, or 9
- **Credit / Debit Cards**: Validated via **Luhn checksum algorithm**
- **Plaintext Passwords, API Keys, Tokens, and Private Keys**
```bash
# Scan and show masked PII
code-dpdp pii .

# Export PII findings to JSON
code-dpdp pii . --json pii.json

# Display unredacted values (audit mode)
code-dpdp pii . --no-redact
```

### 4. 5-Pillar Consent Architecture (`code-dpdp consent`)
Evaluates consent mechanisms under Sections 5 & 6 and Rules 3 & 4:
1. **Notice Specification**: Itemised collection notices in English and Eighth Schedule languages
2. **Affirmative Action**: No pre-ticked checkboxes or deceptive dark patterns
3. **Granular Purpose Separation**: Unbundled service agreements and marketing opt-ins
4. **Comparable Ease of Withdrawal**: 1-click user settings revocation
5. **Consent Recordkeeping**: Audit trail and Consent Manager API integration

```bash
code-dpdp consent .
```

### 5. Third-Party Trackers & Data Egress (`code-dpdp egress`)
Audits unconsented third-party telemetry and cross-border data flows:
```bash
code-dpdp egress .
```

### 6. Statutory Financial Penalty Exposure (`code-dpdp penalty`)
Evaluates monetary liability under the official **DPDP Act 2023 Schedule**:
- **Schedule Item 1 (Sec 8(5) / Rule 6)**: Failure to take reasonable security safeguards (Up to **₹250 Crore**)
- **Schedule Item 2 (Sec 8(6) / Rule 7)**: Failure to notify personal data breach (Up to **₹200 Crore**)
- **Schedule Item 3 (Sec 9 / Rule 8)**: Breach of obligations regarding children (Up to **₹200 Crore**)
- **Schedule Item 4 (Sec 10 / Rule 10)**: Significant Data Fiduciary breach (Up to **₹150 Crore**)
- **Schedule Item 7 (Sec 5, 6, 8(7), 16)**: Breach of consent, notice, retention, or cross-border rules (Up to **₹50 Crore**)

```bash
code-dpdp penalty .
```

### 7. Automated Remediation Patches (`code-dpdp patch`)
Generates unified git `.patch` files for detected security flaws:
```bash
# Generate patches in a folder
code-dpdp patch . --patches patches/

# Generate and apply patches directly to the codebase
code-dpdp patch . --patches patches/ --apply
```

### 8. Live API Endpoint Security Probe (`code-dpdp live`)
Non-destructive active probe of running HTTP services:
```bash
code-dpdp live https://api.example.com
```

---

## 🤖 Local AI & Ollama Integration (Optional)

`code-dpdp` is 100% functional offline without requiring any LLM. However, if you have [Ollama](https://ollama.ai) running locally, `code-dpdp` automatically leverages it for deep legal-technical defense synthesis:

1. Start your local Ollama daemon:
   ```bash
   ollama run llama3   # or mistral, codellama, qwen2.5-coder
   ```

2. Run scan with AI copilot:
   ```bash
   code-dpdp scan . --ai
   ```

3. Explain any vulnerability or compliance mandate:
   ```bash
   code-dpdp explain "SQL injection under DPDP Section 8(5)"
   ```

---

## 📂 Project Structure

```
code-dpdp/
├── bin/
│   ├── code-dpdp           # Linux/macOS executable launcher
│   ├── code-dpdp.cmd       # Windows CMD launcher
│   └── dpdp-audit.js       # Node wrapper (optional)
├── data/
│   └── knowledge_base/
│       ├── dpdp_rulebook.json           # Comprehensive 40+ statutory sections (RAG knowledge base)
│       ├── dpdp_act_2023_full_text.txt  # Complete official Gazette text (Act No. 22 of 2023)
│       └── dpdp_act_2023_official.pdf   # Official Gazette PDF publication
├── python/
│   └── dpdp_audit/
│       ├── analyzers/      # Real vulnerability, AST, schema, consent, egress, live testers
│       ├── core/           # RAG pipeline, rules engine, PII detector, risk scorer, models
│       ├── report/         # Vector PDF report generator, HTML generator
│       └── cli.py          # Central CLI command controller
├── src/
│   └── rules/              # YAML rules definitions mapped to DPDP provisions
├── setup.sh                # Linux/macOS one-click installation script
├── setup.bat               # Windows Command Prompt one-click installation script
├── setup.ps1               # Windows PowerShell installation script
├── requirements.txt        # Python dependency manifest
├── package.json            # Node project configuration
└── README.md               # Complete documentation & setup guide
```

---

## 🧪 Running Tests

To run the automated test suite:
```bash
# Linux/macOS
.venv/bin/pytest python/tests

# Windows
.venv\Scripts\pytest.exe python\tests
```

---

## ⚖️ Legal Disclaimer

`code-dpdp` is an automated technical and architectural compliance scanner designed to assist engineering teams and privacy officers in identifying software vulnerabilities and adherence to statutory privacy frameworks. It does not constitute formal legal counsel. Formal compliance audits should be reviewed by qualified legal practitioners.

---

## 📄 License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.
# code-dpdp
