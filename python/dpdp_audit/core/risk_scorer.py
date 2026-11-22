from typing import List, Tuple
from .models import Severity, PiiType, DataFlow

class RiskScorer:
    """
    DPDP-Audit Risk Classification Engine.
    Formula: Data Sensitivity (1-5) x Exposure Vector (1-5) x Ease of Exploit (1-5)
    Total Score: 1 to 125
    Thresholds:
      - Critical: >= 60
      - High:     30 - 59
      - Medium:   12 - 29
      - Low:      1 - 11
    """

    SENSITIVITY_WEIGHTS = {
        "password": 5,
        "aadhaar": 5,
        "pan": 5,
        "financial": 5,
        "biometrics": 5,
        "health": 5,
        "children_data": 5,
        "phone": 4,
        "email": 4,
        "dob": 4,
        "geolocation": 4,
        "name": 3,
        "address": 3,
        "ip": 2,
        "device_id": 2,
    }

    EXPOSURE_WEIGHTS = {
        "exposed": 5,
        "transferred": 4,
        "logged": 4,
        "stored": 3,
        "collected": 2,
    }

    @classmethod
    def calculate_risk(
        cls,
        pii_types: List[PiiType],
        data_flow: DataFlow,
        category: str,
        base_severity: Severity
    ) -> Tuple[Severity, str]:
        """Compute severity score and generate documented risk justification."""
        # 1. Data Sensitivity (1-5)
        if not pii_types:
            # Config or infrastructure rules without specific PII
            if category in ("config", "exposure") and base_severity in ("critical", "high"):
                sensitivity = 4
            elif base_severity == "critical":
                sensitivity = 5
            elif base_severity == "high":
                sensitivity = 3
            elif base_severity == "medium":
                sensitivity = 2
            else:
                sensitivity = 1
            pii_desc = "Infrastructure/Config Security"
        else:
            sensitivity = max(cls.SENSITIVITY_WEIGHTS.get(p, 2) for p in pii_types)
            pii_desc = ", ".join(pii_types)

        # 2. Exposure Vector (1-5)
        exposure = cls.EXPOSURE_WEIGHTS.get(data_flow, 3)

        # 3. Ease of Exploit (1-5)
        if category in ("exposure", "transfer"):
            exploit = 5 if data_flow == "exposed" else 4
        elif category in ("storage", "logging"):
            exploit = 4 if data_flow == "logged" else 3
        elif category in ("children", "breach"):
            exploit = 4
        else:
            exploit = 3

        # Critical overrides for direct password / credential breaches or child tracking
        if "children_data" in pii_types and category == "children":
            exploit = 5
            sensitivity = 5
        if "password" in pii_types and data_flow in ("exposed", "logged"):
            exploit = 5
            sensitivity = 5

        score = sensitivity * exposure * exploit

        # Assign severity based on mathematical score
        if score >= 60 or base_severity == "critical":
            sev: Severity = "critical"
        elif score >= 30 or base_severity == "high":
            sev = "high"
        elif score >= 12 or base_severity == "medium":
            sev = "medium"
        else:
            sev = "low"

        justification = (
            f"Risk Score {score}/125: Sensitivity ({sensitivity}/5 - {pii_desc}) x "
            f"Exposure ({exposure}/5 - {data_flow}) x Exploit ({exploit}/5). "
            f"Evaluated against DPDP Act 2023 impact thresholds."
        )

        return sev, justification
