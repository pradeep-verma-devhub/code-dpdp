import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.models import Finding, Severity, DataFlow, PiiType
from ..core.pii_detector import PiiDetector, validate_verhoeff, validate_luhn
from ..core.dpdp_mapper import DpdpMapper
from ..core.risk_scorer import RiskScorer
from ..core.file_walker import FileWalker
from ..core.rag_pipeline import RagPipeline

VULNERABILITY_DEFINITIONS = [
    {
        "id": "SEC-SQLI-001",
        "title": "SQL Injection via Dynamic String Concatenation",
        "category": "injection",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:query|execute|rawQuery|\$queryRawUnsafe)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT|WHERE)[^'"]*['"]\s*\+)""",
        "data_flow": "exposed",
        "pii_types": ["financial", "password", "email", "aadhaar"],
        "description": "SQL query dynamically constructed with unvalidated concatenation, enabling arbitrary database exfiltration and breach under DPDP Section 8(6).",
        "fix": "Use parameterized queries or prepared statements (e.g., db.query('SELECT * FROM users WHERE id = $1', [userId])).",
        "remediation_diff": "- db.query('SELECT * FROM users WHERE id = ' + userId)\n+ db.query('SELECT * FROM users WHERE id = $1', [userId])",
    },
    {
        "id": "SEC-SQLI-002",
        "title": "Python SQL Injection via String Formatting/f-strings",
        "category": "injection",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:cursor|db|session)\.execute\s*\(\s*(?:f['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'"]*\{|['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'"]*['"]\s*%)""",
        "data_flow": "exposed",
        "pii_types": ["financial", "password", "email", "aadhaar"],
        "description": "Python database query constructed using f-strings or % formatting without parameterized placeholders.",
        "fix": "Pass SQL parameters as a tuple argument (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))).",
        "remediation_diff": "- cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n+ cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    },

    {
        "id": "SEC-XSS-001",
        "title": "Cross-Site Scripting (DOM XSS) via innerHTML/outerHTML",
        "category": "xss",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""\.(?:innerHTML|outerHTML)\s*=\s*(?!['"][^'"]*['"]$)(?!sanitize)[a-zA-Z0-9_\.\[\]]+""",
        "data_flow": "exposed",
        "pii_types": ["password", "email", "phone"],
        "description": "Direct assignment of unsanitized input to innerHTML/outerHTML, enabling session hijacking and credential harvesting.",
        "fix": "Use textContent / innerText, or sanitize HTML strings using DOMPurify before DOM insertion.",
        "remediation_diff": "- element.innerHTML = userContent\n+ element.textContent = userContent // or DOMPurify.sanitize(userContent)",
    },
    {
        "id": "SEC-XSS-002",
        "title": "React DangerouslySetInnerHTML Unsanitized XSS Hazard",
        "category": "xss",
        "severity": "high",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify)[a-zA-Z0-9_\.\[\]]+""",
        "data_flow": "exposed",
        "pii_types": ["password", "email"],
        "description": "React component rendering raw HTML via dangerouslySetInnerHTML without verified DOMPurify sanitization.",
        "fix": "Sanitize HTML using DOMPurify.sanitize() before passing to __html.",
        "remediation_diff": "- dangerouslySetInnerHTML={{ __html: userInput }}\n+ dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }}",
    },
    {
        "id": "SEC-XSS-003",
        "title": "Server-Side XSS via Raw HTTP Output Reflection",
        "category": "xss",
        "severity": "high",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""res\.(?:send|write)\s*\(\s*(?:['"][^'"]*<[^>]+>[^'"]*['"]\s*\+\s*req\.(?:query|body|params)|req\.(?:query|params)\.[a-zA-Z0-9_]+)""",
        "data_flow": "exposed",
        "pii_types": ["email", "phone"],
        "description": "Reflecting request parameters directly in HTML HTTP responses without HTML entity encoding.",
        "fix": "Use res.json() for API data or encode inputs using an HTML escape utility.",
        "remediation_diff": "- res.send('<h1>Hello ' + req.query.name + '</h1>')\n+ res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>')",
    },

    {
        "id": "SEC-RCE-001",
        "title": "OS Command Injection Hazard via child_process.exec",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_\.\[\]]+)""",
        "data_flow": "exposed",
        "pii_types": ["password", "financial", "aadhaar"],
        "description": "Executing operating system shell commands with concatenated variables allows arbitrary code execution and full host takeover.",
        "fix": "Use child_process.execFile() or spawn() with arguments passed as an explicit array without a shell.",
        "remediation_diff": "- exec('ping ' + host)\n+ execFile('ping', [host])",
    },
    {
        "id": "SEC-RCE-002",
        "title": "Python OS Command Injection via os.system or shell=True",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(\s*(?:f['"][^'"]*\{|['"][^'"]*['"]\s*\+|\s*[^,]+,\s*shell\s*=\s*True)""",
        "data_flow": "exposed",
        "pii_types": ["password", "financial", "aadhaar"],
        "description": "Invoking system commands through shell=True with dynamic input allows remote command execution.",
        "fix": "Pass commands as an argument list with shell=False: subprocess.run(['cmd', arg1], shell=False).",
        "remediation_diff": "- subprocess.run(f'convert {filename}', shell=True)\n+ subprocess.run(['convert', filename], shell=False)",
    },
    {
        "id": "SEC-RCE-003",
        "title": "Dangerous Dynamic Code Execution (eval/Function)",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""\b(?:eval|new\s+Function|vm\.runInThisContext)\s*\(""",
        "data_flow": "exposed",
        "pii_types": ["password", "financial"],
        "description": "Dynamic execution of arbitrary JavaScript/Python strings via eval() allows code injection and memory corruption.",
        "fix": "Replace eval() with safe JSON parsing (JSON.parse), mathematical parsers, or strict map lookups.",
        "remediation_diff": "- const res = eval(inputExpression)\n+ const res = JSON.parse(inputExpression)",
    },

    {
        "id": "SEC-LFI-001",
        "title": "Path Traversal & Arbitrary File Read Hazard",
        "category": "traversal",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:fs\.readFile|fs\.readFileSync|res\.sendFile|res\.download)\s*\([^)]*req\.(?:query|params|body)""",
        "data_flow": "exposed",
        "pii_types": ["password", "financial", "aadhaar"],
        "description": "Accessing filesystem files directly via request parameters without directory whitelisting or path traversal sanitization (../).",
        "fix": "Resolve and whitelist paths using path.resolve() and verify the target path stays within the base directory.",
        "remediation_diff": "- res.sendFile(path.join(__dirname, req.query.file))\n+ const safe = path.resolve(__dirname, 'public', path.basename(req.query.file)); res.sendFile(safe)",
    },

    {
        "id": "SEC-SSRF-001",
        "title": "Server-Side Request Forgery (SSRF) via Dynamic URL Fetch",
        "category": "ssrf",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:axios\.(?:get|post|put)|fetch|http\.get|https\.get|requests\.(?:get|post)|urllib\.request\.urlopen)\s*\(\s*req\.(?:query|body|params)""",
        "data_flow": "transferred",
        "pii_types": ["password", "device_id"],
        "description": "Dispatching outbound HTTP requests directly to client-supplied URLs without domain whitelisting, enabling internal cloud metadata exfiltration.",
        "fix": "Enforce strict allowlist validation of target domains and reject private IP ranges (127.0.0.1, 169.254.169.254, 10.0.0.0/8).",
        "remediation_diff": "- axios.get(req.query.url)\n+ if (!ALLOWED_DOMAINS.includes(new URL(req.query.url).hostname)) throw new Error('Untrusted domain'); axios.get(req.query.url)",
    },

    {
        "id": "SEC-CRED-001",
        "title": "Hardcoded AWS Access Key ID Detected",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""\b(AKIA[0-9A-Z]{16})\b""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Amazon Web Services (AWS) IAM Access Key hardcoded in repository files, granting full infrastructure cloud access upon commit.",
        "fix": "Revoke the exposed AWS key immediately in IAM and load credentials via AWS IAM Roles or AWS_ACCESS_KEY_ID environment variable.",
        "remediation_diff": "- const accessKey = 'AKIAIOSFODNN7EXAMPLE'\n+ const accessKey = process.env.AWS_ACCESS_KEY_ID",
    },
    {
        "id": "SEC-CRED-002",
        "title": "Hardcoded GitHub Personal Access Token",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""\bghp_[a-zA-Z0-9]{36}\b""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "GitHub Personal Access Token hardcoded in source code, permitting unauthorized repository manipulation and data leakage.",
        "fix": "Revoke the exposed token in GitHub Developer Settings and use environment secrets (GITHUB_TOKEN).",
        "remediation_diff": "- const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx'\n+ const token = process.env.GITHUB_TOKEN",
    },
    {
        "id": "SEC-CRED-003",
        "title": "Hardcoded Private Cryptographic Key (RSA/EC/SSH)",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Unencrypted private cryptographic key committed to application repository, breaking end-to-end transport confidentiality.",
        "fix": "Remove private key from source control. Store keys in a secure secrets manager (AWS KMS, HashiCorp Vault) or load at runtime.",
        "remediation_diff": "- const privateKey = '-----BEGIN RSA PRIVATE KEY...'\n+ const privateKey = process.env.APP_PRIVATE_KEY",
    },
    {
        "id": "SEC-CRED-004",
        "title": "Hardcoded Database Connection String with Password",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-\.]+:[^@\s"']+@[a-zA-Z0-9_\-\.]+""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Database connection URI containing plaintext database credentials committed directly to repository files.",
        "fix": "Extract connection string into protected environment variables (DATABASE_URL) and do not commit to version control.",
        "remediation_diff": "- const uri = 'mongodb+srv://admin:pass123@cluster.mongodb.net/prod'\n+ const uri = process.env.DATABASE_URL",
    },
    {
        "id": "SEC-CRED-005",
        "title": "Hardcoded JWT Signing Secret Key",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:jwtSecret|jwt_secret|secretOrKey)\s*[:=]\s*['\"][a-zA-Z0-9_\-!@#$%^&*+=]{6,}['\"]""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Cryptographic JWT signing secret hardcoded in source files, allowing attackers to forge arbitrary user authentication tokens.",
        "fix": "Load JWT secret securely from environment variable (process.env.JWT_SECRET) with minimum 256-bit entropy.",
        "remediation_diff": "- const secret = 'mySuperSecretKey123'\n+ const secret = process.env.JWT_SECRET",
    },

    {
        "id": "SEC-CRYP-001",
        "title": "Broken Hash Algorithm (MD5/SHA-1) Used for Cryptography",
        "category": "crypto",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:crypto\.createHash|hashlib\.md5|hashlib\.sha1)\s*\(\s*(?:['\"](md5|sha1)['\"])?""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "MD5 and SHA-1 are cryptographically broken with known collision attacks. Using them for passwords or integrity violates DPDP Rule 6.",
        "fix": "Upgrade to SHA-256 / SHA-3 for integrity verification, and Argon2id / bcrypt for password storage.",
        "remediation_diff": "- crypto.createHash('md5')\n+ crypto.createHash('sha256')",
    },
    {
        "id": "SEC-CRYP-002",
        "title": "Insecure Pseudo-Random Number Generation (PRNG) for Security Tokens",
        "category": "crypto",
        "severity": "high",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:token|sessionId|salt|secret|otp|password)\s*[:=]\s*[^;\n]*(?:Math\.random|random\.random|random\.randint)""",
        "data_flow": "exposed",
        "pii_types": ["password"],
        "description": "Math.random() and Python's random module are predictable pseudo-random number generators unsuitable for cryptographic tokens.",
        "fix": "Use cryptographically secure pseudorandom number generators: crypto.randomBytes() or Python secrets module (secrets.token_hex).",
        "remediation_diff": "- const token = Math.random().toString(36)\n+ const token = crypto.randomBytes(32).toString('hex')",
    },

    {
        "id": "SEC-TLS-001",
        "title": "TLS Certificate Verification Explicitly Disabled",
        "category": "transport",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]""",
        "data_flow": "transit",
        "pii_types": ["password", "email", "phone", "financial"],
        "description": "Disabling TLS certificate verification allows Man-in-the-Middle (MitM) attackers to intercept and decrypt all in-transit personal data.",
        "fix": "Remove rejectUnauthorized: false and install proper root certificate authorities.",
        "remediation_diff": "- { rejectUnauthorized: false }\n+ { rejectUnauthorized: true }",
    },
    {
        "id": "SEC-TLS-002",
        "title": "Insecure Plaintext HTTP URL for Sensitive Data Transfer",
        "category": "transport",
        "severity": "high",
        "dpdp_ref": "RULE_6",
        "pattern": r"""['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}[^'"]*['"]""",
        "data_flow": "transit",
        "pii_types": ["email", "phone", "aadhaar", "financial"],
        "description": "Transmitting personal data over plaintext HTTP transmits information in cleartext across public networks without encryption.",
        "fix": "Enforce HTTPS with TLS 1.3 across all production external communications.",
        "remediation_diff": "- 'http://api.domain.com/v1'\n+ 'https://api.domain.com/v1'",
    },

    {
        "id": "SEC-COOK-001",
        "title": "Sensitive Session Cookie Missing HttpOnly Flag",
        "category": "cookies",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:res\.cookie|setCookie)\s*\([^)]*httpOnly\s*:\s*false""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Session cookies without the HttpOnly flag can be read by malicious client-side JavaScript during an XSS attack.",
        "fix": "Set httpOnly: true on all authentication, session, and identity cookies.",
        "remediation_diff": "- res.cookie('token', token, { httpOnly: false })\n+ res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })",
    },
    {
        "id": "SEC-COOK-002",
        "title": "Sensitive Session Cookie Missing Secure Flag",
        "category": "cookies",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:res\.cookie|setCookie)\s*\([^)]*secure\s*:\s*false""",
        "data_flow": "transit",
        "pii_types": ["password"],
        "description": "Session cookies without the Secure flag will be transmitted across unencrypted HTTP connections.",
        "fix": "Set secure: true on all session cookies to ensure cookies are only sent over encrypted HTTPS.",
        "remediation_diff": "- res.cookie('session', sid, { secure: false })\n+ res.cookie('session', sid, { secure: true, httpOnly: true })",
    },

    {
        "id": "SEC-CORS-001",
        "title": "Insecure CORS Policy Allowing Any Origin with Credentials",
        "category": "cors",
        "severity": "high",
        "dpdp_ref": "RULE_6",
        "pattern": r"""origin\s*:\s*['"]\*['"]\s*,\s*credentials\s*:\s*true|Access-Control-Allow-Origin['"]?\s*:\s*['"]\*['"]""",
        "data_flow": "exposed",
        "pii_types": ["email", "financial"],
        "description": "Wildcard Access-Control-Allow-Origin: * allows untrusted third-party web domains to read cross-origin responses.",
        "fix": "Specify explicit trusted origins in CORS configuration instead of wildcards.",
        "remediation_diff": "- cors({ origin: '*' })\n+ cors({ origin: process.env.ALLOWED_ORIGIN || 'https://app.mydomain.com', credentials: true })",
    },

    {
        "id": "SEC-CRED-006",
        "title": "Hardcoded AWS Secret Access Key",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"][a-zA-Z0-9/+=]{40}['"]""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "AWS Secret Access Key hardcoded in source code or configuration files, granting full privileged infrastructure access.",
        "fix": "Revoke the exposed AWS secret key immediately and load credentials using AWS IAM instance profiles or environment variables.",
        "remediation_diff": "- aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n+ aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')",
    },
    {
        "id": "SEC-CRED-007",
        "title": "Hardcoded Google Cloud Platform API Key",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""AIza[0-9A-Za-z\\-_]{35}""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Google Cloud Platform (GCP) API Key detected in repository files without secret manager protection.",
        "fix": "Restrict or rotate the API key in GCP Console and inject it via environment variables.",
        "remediation_diff": "- const gcpKey = 'AIzaSyA...'\n+ const gcpKey = process.env.GCP_API_KEY",
    },
    {
        "id": "SEC-CRED-008",
        "title": "Hardcoded Stripe Live Secret Key",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:sk|rk)_live_[0-9a-zA-Z]{24,}""",
        "data_flow": "stored",
        "pii_types": ["financial", "password"],
        "description": "Stripe Live API secret key exposed in source code, permitting unauthorized access to financial transaction records.",
        "fix": "Roll the secret key immediately in the Stripe Dashboard and load it via STRIPE_SECRET_KEY environment variable.",
        "remediation_diff": "- const stripe = require('stripe')('sk_live_...')\n+ const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)",
    },
    {
        "id": "SEC-CRED-009",
        "title": "Hardcoded Slack Webhook / Integration Token",
        "category": "credentials",
        "severity": "high",
        "dpdp_ref": "RULE_6",
        "pattern": r"""https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]+\/B[0-9A-Za-z_]+\/[0-9A-Za-z_]+""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "Slack incoming webhook URL hardcoded in source code, allowing attackers to post unauthorized messages or spoof notifications.",
        "fix": "Store Slack webhook URLs in environment secrets (SLACK_WEBHOOK_URL).",
        "remediation_diff": "- const url = 'https://hooks.slack.com/services/T.../B.../...'\n+ const url = process.env.SLACK_WEBHOOK_URL",
    },
    {
        "id": "SEC-CRED-010",
        "title": "Hardcoded Secret API Key or Authentication Token",
        "category": "credentials",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?i)(?:api_key|apikey|secret_key|client_secret|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-!@#$%^&*+=]{14,}['\"]""",
        "data_flow": "stored",
        "pii_types": ["password"],
        "description": "High-entropy API secret or authentication token hardcoded in repository files.",
        "fix": "Load sensitive credentials through environment variables or secure key vaults.",
        "remediation_diff": "- const apiKey = 'secret_token_12345678'\n+ const apiKey = process.env.API_KEY",
    },

    {
        "id": "SEC-DESER-001",
        "title": "Unsafe Object Deserialization (Pickle / Unsafe YAML)",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""pickle\.(?:loads|load)\(|yaml\.load\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)""",
        "data_flow": "exposed",
        "pii_types": ["password"],
        "description": "Deserializing untrusted data with pickle or unvalidated YAML loaders allows arbitrary remote code execution.",
        "fix": "Use safe JSON serialization or yaml.safe_load() instead of pickle.",
        "remediation_diff": "- data = pickle.loads(user_input)\n+ data = json.loads(user_input)",
    },
    {
        "id": "SEC-REDIR-001",
        "title": "Open URL Redirection Hazard",
        "category": "exposure",
        "severity": "high",
        "dpdp_ref": "ACT_SEC_16",
        "pattern": r"""(?:res\.redirect|redirect)\s*\(\s*(?:req\.(?:query|params|body)|request\.(?:args|form)\.get)""",
        "data_flow": "exposed",
        "pii_types": ["email"],
        "description": "Redirecting users to unvalidated external URLs supplied via request query or body parameters enables phishing and credential theft.",
        "fix": "Validate destination URLs against an allowlist of trusted domains or use relative path redirects.",
        "remediation_diff": "- res.redirect(req.query.url)\n+ if (isAllowed(req.query.url)) res.redirect(req.query.url)",
    },

    {
        "id": "SEC-GO-001",
        "title": "Go SQL Injection via Dynamic Query Construction",
        "category": "injection",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:db\.Query|db\.Exec|db\.QueryRow)\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+)""",
        "data_flow": "exposed",
        "pii_types": ["financial", "password", "aadhaar"],
        "description": "Go database query dynamically constructed using string concatenation or Sprintf formatting.",
        "fix": "Use parameterized queries ($1, ? placeholders) in db.Query and db.Exec.",
        "remediation_diff": '- db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n+ db.Query("SELECT * FROM users WHERE id = $1", id)',
    },
    {
        "id": "SEC-GO-002",
        "title": "Go TLS InsecureSkipVerify Enabled",
        "category": "transport",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""InsecureSkipVerify\s*:\s*true""",
        "data_flow": "transit",
        "pii_types": ["password", "financial"],
        "description": "Setting InsecureSkipVerify: true disables TLS server certificate verification in Go, allowing Man-in-the-Middle attacks.",
        "fix": "Set InsecureSkipVerify: false and supply a valid trusted CA root pool.",
        "remediation_diff": "- InsecureSkipVerify: true\n+ InsecureSkipVerify: false",
    },
    {
        "id": "SEC-GO-003",
        "title": "Go OS Command Injection via Shell Execution",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']\s*,\s*["']-c["']""",
        "data_flow": "exposed",
        "pii_types": ["password"],
        "description": "Invoking a shell ('sh -c', 'bash -c') in Go with dynamic arguments allows arbitrary command injection.",
        "fix": "Invoke binaries directly without a shell wrapper and pass arguments as separate slice elements.",
        "remediation_diff": '- exec.Command("sh", "-c", cmdStr)\n+ exec.Command(binaryPath, arg1, arg2)',
    },

    {
        "id": "SEC-CRYP-003",
        "title": "Deprecated Cipher or Insecure Electronic Codebook (ECB) Mode",
        "category": "crypto",
        "severity": "critical",
        "dpdp_ref": "RULE_6",
        "pattern": r"""(?:crypto\.createCipher(?:iv)?\s*\(\s*['"](?:des|des-ede|blowfish|rc4)|AES\.MODE_ECB|AES\.new\([^)]*MODE_ECB)""",
        "data_flow": "stored",
        "pii_types": ["password", "financial"],
        "description": "Using legacy ciphers (DES, RC4, Blowfish) or ECB mode fails to provide semantic security and exposes data patterns.",
        "fix": "Use AES-256-GCM or ChaCha20-Poly1305 authenticated encryption.",
        "remediation_diff": "- crypto.createCipher('des', key)\n+ crypto.createCipheriv('aes-256-gcm', key, iv)",
    },
    {
        "id": "SEC-SHELL-001",
        "title": "Insecure Remote Script Piping Hazard (curl | bash)",
        "category": "rce",
        "severity": "critical",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh)""",
        "data_flow": "exposed",
        "pii_types": ["password"],
        "description": "Piping unverified remote web scripts directly into a shell allows untrusted remote code execution.",
        "fix": "Download scripts, verify cryptographic SHA-256 checksums, and execute from disk after review.",
        "remediation_diff": "- curl -sSL https://example.com/install.sh | bash\n+ # Download, verify SHA-256 hash, then execute locally",
    },

    {
        "id": "MALF-001",
        "title": "Silent Exception Swallowing / Empty Catch Block",
        "category": "malfunction",
        "severity": "medium",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""catch\s*\([^)]*\)\s*\{\s*\}""",
        "data_flow": "exposed",
        "pii_types": [],
        "description": "Empty catch block silently suppresses runtime errors, hiding failures and corrupting application state.",
        "fix": "Log the caught exception using a structured logger or handle the error gracefully.",
        "remediation_diff": "- catch (err) {}\n+ catch (err) { logger.error('Operation failed', err); throw err; }",
    },
    {
        "id": "MALF-004",
        "title": "Prototype Pollution Hazard via Unvalidated Object Merge",
        "category": "malfunction",
        "severity": "high",
        "dpdp_ref": "ACT_SEC_8_5",
        "pattern": r"""(?:Object\.assign|_\.merge|_\.extend)\s*\([^)]*req\.body""",
        "data_flow": "exposed",
        "pii_types": [],
        "description": "Merging unvalidated request body directly into application objects can overwrite Object.prototype properties.",
        "fix": "Validate and whitelist object keys before merging, or create objects using Object.create(null).",
        "remediation_diff": "- Object.assign(target, req.body)\n+ Object.assign(target, sanitizePayload(req.body))",
    },
]

class RealVulnScanner:

    compiled_rules: Optional[List[Dict[str, Any]]] = None

    @classmethod
    def get_compiled_rules(cls) -> List[Dict[str, Any]]:
        if cls.compiled_rules is not None:
            return cls.compiled_rules

        compiled = []
        dpdp_map = DpdpMapper.load_map()

        for r in VULNERABILITY_DEFINITIONS:
            try:
                rx = re.compile(r["pattern"], re.IGNORECASE)
                prov = dpdp_map.get(r["dpdp_ref"])
                compiled.append({
                    "id": r["id"],
                    "title": r["title"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "dpdp_ref": r["dpdp_ref"],
                    "rx": rx,
                    "data_flow": r["data_flow"],
                    "pii_types": r["pii_types"],
                    "description": r["description"],
                    "fix": r["fix"],
                    "remediation_diff": r.get("remediation_diff"),
                    "prov_obj": prov,
                })
            except Exception:
                continue

        cls.compiled_rules = compiled
        return compiled

    @classmethod
    def scan_file(cls, file_path: Path, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(root))

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return findings

        rules = cls.get_compiled_rules()

        for line_no, line in enumerate(lines, 1):
            clean = line.strip()
            if not clean or clean.startswith("//") or clean.startswith("#") or clean.startswith("/*"):
                continue

            for r in rules:
                if FileWalker.has_ignore_comment(line, r["id"]):
                    continue

                m = r["rx"].search(line)
                if m:
                    masked_snippet = PiiDetector.mask_snippet(clean[:150])
                    piis = r["pii_types"]
                    sev, just = RiskScorer.calculate_risk(piis, r["data_flow"], r["category"], r["severity"])

                    statutory_res = RagPipeline.resolve_statutory_reference(
                        title=r["title"],
                        category=r["category"],
                        snippet=clean,
                        pii_types=piis,
                        data_flow=r["data_flow"],
                        fallback_ref=r.get("dpdp_ref", "")
                    )

                    patch_diff = None
                    if r.get("remediation_diff"):
                        patch_diff = f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{line_no},1 +{line_no},1 @@\n{r['remediation_diff']}"

                    findings.append(Finding(
                        id=f"{r['id']}-{abs(hash(rel_path + str(line_no) + r['id'])) % 10000:04d}",
                        rule_id=r["id"],
                        title=r["title"],
                        file=rel_path,
                        line=line_no,
                        snippet=masked_snippet,
                        pii_types=piis,
                        data_flow=r["data_flow"],
                        dpdp_ref={
                            "sectionOrRule": statutory_res["sectionOrRule"],
                            "explanation": statutory_res["explanation"],
                            "penaltyClause": statutory_res["penaltyClause"],
                            "statutory_citation": statutory_res["statutory_citation"],
                        },
                        severity=sev,
                        justification=f"Real Vulnerability [{r['category'].upper()}]: {r['description']} {just}",
                        fix=r["fix"],
                        patch_available=bool(patch_diff),
                        patch_unified_diff=patch_diff,
                        cwe=statutory_res.get("cwe"),
                        owasp=statutory_res.get("owasp"),
                        engine="code-dpdp AST Engine"
                    ))

            pii_matches = PiiDetector.scan_text(clean, line_no=line_no)
            for pm in pii_matches:
                if pm.type in ("aadhaar", "pan", "financial", "password"):
                    rule_id = f"DPDP-PII-{pm.type.upper()}"
                    statutory_res = RagPipeline.resolve_statutory_reference(
                        title=f"Unencrypted Sensitive Personal Data Leak ({pm.type.upper()})",
                        category="storage",
                        snippet=clean,
                        pii_types=[pm.type],
                        data_flow="exposed",
                        fallback_ref=rule_id
                    )
                    findings.append(Finding(
                        id=f"{rule_id}-{abs(hash(rel_path + str(line_no) + pm.type)) % 10000:04d}",
                        rule_id=rule_id,
                        title=f"Unencrypted Sensitive Personal Data Leak ({pm.type.upper()})",
                        file=rel_path,
                        line=line_no,
                        snippet=PiiDetector.mask_snippet(clean[:150]),
                        pii_types=[pm.type],
                        data_flow="exposed",
                        dpdp_ref={
                            "sectionOrRule": statutory_res["sectionOrRule"],
                            "explanation": statutory_res["explanation"],
                            "penaltyClause": statutory_res["penaltyClause"],
                            "statutory_citation": statutory_res["statutory_citation"],
                        },
                        severity="critical",
                        justification=f"Direct exposure of validated Indian personal data ({pm.type.upper()}: {pm.value_snippet}) in code or configuration without cryptographic protection.",
                        fix=f"Remove or mask cleartext {pm.type} data. Load credentials securely from environment variables.",
                        patch_available=True,
                        patch_unified_diff=f"--- a/{rel_path}\n+++ b/{rel_path}\n@@ -{line_no},1 +{line_no},1 @@\n-{clean}\n+// [REDACTED_{pm.type.upper()}_DATA]",
                        cwe=statutory_res.get("cwe"),
                        owasp=statutory_res.get("owasp"),
                        engine="code-dpdp AST Engine"
                    ))

        return findings
