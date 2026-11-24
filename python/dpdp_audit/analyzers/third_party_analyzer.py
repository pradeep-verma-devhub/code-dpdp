import re
from pathlib import Path
from typing import List, Dict, Any
from ..core.models import Finding
from ..core.risk_scorer import RiskScorer
from ..core.dpdp_mapper import DpdpMapper
from ..core.file_walker import FileWalker

THIRD_PARTY_SERVICES = [
    {
        "name": "Meta / Facebook Pixel",
        "category": "Advertising & Tracking",
        "patterns": [
            r"fbq\s*\(\s*['\"]init['\"]",
            r"fbq\s*\(\s*['\"]track['\"]",
            r"connect\.facebook\.net",
        ],
        "default_pii": ["device_id", "email", "phone"],
        "description": "Meta Pixel tracking user pageviews, actions, and identities without prior itemised consent.",
    },
    {
        "name": "Google Analytics / Tag Manager",
        "category": "Analytics & Telemetry",
        "patterns": [
            r"gtag\s*\(\s*['\"](config|event)['\"]",
            r"ga\s*\(\s*['\"]send['\"]",
            r"google-analytics\.com",
            r"googletagmanager\.com",
        ],
        "default_pii": ["ip", "device_id", "geolocation"],
        "description": "Google Analytics transmitting user interaction telemetry, IP, and identifiers to foreign cloud servers.",
    },
    {
        "name": "Mixpanel Tracking",
        "category": "Product Analytics",
        "patterns": [
            r"mixpanel\.(?:identify|track|people\.set)\s*\(",
            r"api\.mixpanel\.com",
        ],
        "default_pii": ["email", "name", "device_id"],
        "description": "Mixpanel SDK identifying user profiles with raw email or username without granular consent gating.",
    },
    {
        "name": "Segment / Twilio Telemetry",
        "category": "Customer Data Platform",
        "patterns": [
            r"analytics\.(?:identify|track|page)\s*\(",
            r"cdn\.segment\.com",
        ],
        "default_pii": ["email", "phone", "name"],
        "description": "Segment CDP receiving user profile data and fanning out to downstream advertising services.",
    },
    {
        "name": "TikTok Pixel Tracker",
        "category": "Advertising Tracker",
        "patterns": [
            r"ttq\.(?:load|track)\s*\(",
            r"analytics\.tiktok\.com",
        ],
        "default_pii": ["device_id", "ip"],
        "description": "TikTok tracking pixel gathering device telemetry and behavioral events without explicit consent.",
    },
    {
        "name": "Insecure Third-Party Webhook / HTTP Endpoint",
        "category": "Data Egress",
        "patterns": [
            r"""axios\.(?:post|put)\s*\(\s*['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+""",
            r"""fetch\s*\(\s*['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+""",
        ],
        "default_pii": ["financial", "email", "phone"],
        "description": "Outbound HTTP egress transmitting customer data to external hosts over unencrypted plaintext HTTP.",
    },
]

class ThirdPartyAnalyzer:

    @classmethod
    def analyze_file(cls, file_path: Path, root: Path) -> List[Dict[str, Any]]:
        egress_events: List[Dict[str, Any]] = []
        rel_path = str(file_path.relative_to(root))

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return egress_events

        consent_guard_patterns = re.compile(r"""(?:requireConsent|hasConsent|checkConsent|cookieConsent|userConsent|isConsentGiven)""", re.IGNORECASE)

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or not clean:
                continue

            for service in THIRD_PARTY_SERVICES:
                for pat in service["patterns"]:
                    if re.search(pat, line, re.IGNORECASE):
                        start_win = max(0, idx - 4)
                        end_win = min(len(lines), idx + 2)
                        window_text = "".join(lines[start_win:end_win])

                        has_guard = bool(consent_guard_patterns.search(window_text))

                        egress_events.append({
                            "service": service["name"],
                            "category": service["category"],
                            "file": rel_path,
                            "line": idx,
                            "snippet": clean[:140],
                            "pii": service["default_pii"],
                            "hasConsentGuard": has_guard,
                            "status": "AUTHORIZED" if has_guard else "UNAUTHORIZED_LEAK",
                            "severity": "low" if has_guard else "critical",
                            "description": service["description"],
                            "remediation": f"Gate '{service['name']}' call behind verified user consent: `if (hasConsent('{service['category']}')) {{ ... }}`",
                            "dpdpSection": "Section 6(1) (Specific Informed Consent) & Section 16 (Cross-Border Transfer)",
                        })
                        break

        return egress_events
