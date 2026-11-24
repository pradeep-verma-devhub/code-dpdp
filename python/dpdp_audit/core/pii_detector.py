import re
from typing import List, Optional, Tuple, Dict, Any
from .models import PiiType, DataFlow, PiiDetection

VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

def validate_verhoeff(num_str: str) -> bool:
    clean = re.sub(r"\s+", "", num_str)
    if not re.match(r"^\d{12}$", clean):
        return False
    if clean[0] in ("0", "1"):
        return False
    c = 0
    inverted = [int(d) for d in reversed(clean)]
    for i, digit in enumerate(inverted):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0

def validate_luhn(card_str: str) -> bool:
    clean = re.sub(r"[\s-]+", "", card_str)
    if not re.match(r"^\d{13,19}$", clean):
        return False
    digits = [int(d) for d in clean]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d = (d % 10) + 1
        checksum += d
    return checksum % 10 == 0

PII_FIELD_DICTIONARY: Dict[PiiType, Dict[str, Any]] = {
    "aadhaar": {
        "keywords": ["aadhaar", "aadhar", "uidai", "aadhaarno", "aadharnumber"],
        "exact": ["aadhaar", "aadhar", "uidai", "aadhaar_no", "aadhar_no", "aadhaarnumber"],
        "sensitivity": "critical",
    },
    "pan": {
        "keywords": ["pan", "pancard", "pannumber", "incometaxpan"],
        "exact": ["pan", "pan_card", "pan_number", "pancard"],
        "sensitivity": "critical",
    },
    "financial": {
        "keywords": [
            "creditcard", "debitcard", "cvv", "cardnumber", "bankaccount",
            "accountnumber", "ifsc", "upi", "upiid", "vpa", "salary"
        ],
        "exact": [
            "cvv", "card_number", "account_number", "ifsc", "upi_id",
            "credit_card", "debit_card", "salary", "bank_account"
        ],
        "sensitivity": "critical",
    },
    "password": {
        "keywords": [
            "password", "passwd", "pwd", "secretkey", "privatekey",
            "authtoken", "accesstoken", "refreshtoken", "jwtsecret", "apikey"
        ],
        "exact": [
            "password", "passwd", "pwd", "secret_key", "private_key",
            "auth_token", "access_token", "jwt_secret", "api_key"
        ],
        "sensitivity": "critical",
    },
    "biometrics": {
        "keywords": ["biometric", "fingerprint", "retina", "iris", "facescan", "voiceprint"],
        "exact": ["fingerprint", "iris_scan", "retina_scan", "biometric_data"],
        "sensitivity": "critical",
    },
    "health": {
        "keywords": ["health", "medical", "diagnosis", "prescription", "bloodgroup", "patient", "clinical"],
        "exact": ["blood_group", "bloodgroup", "medical_history", "diagnosis", "patient_id"],
        "sensitivity": "critical",
    },
    "children_data": {
        "keywords": ["child", "minor", "guardian", "parentalconsent", "kid", "schoolid"],
        "exact": ["is_minor", "parental_consent", "guardian_name", "child_name", "child_dob"],
        "sensitivity": "critical",
    },
    "phone": {
        "keywords": ["phone", "mobile", "cellphone", "telephoneno", "contactnumber", "msisdn", "whatsapp"],
        "exact": ["phone", "phone_number", "mobile", "mobile_number", "contact_no", "tel", "msisdn"],
        "sensitivity": "high",
    },
    "email": {
        "keywords": ["email", "useremail", "emailaddress"],
        "exact": ["email", "email_address", "user_email", "mail"],
        "sensitivity": "high",
    },
    "dob": {
        "keywords": ["dob", "dateofbirth", "birthdate", "birthyear"],
        "exact": ["dob", "date_of_birth", "birth_date", "birthdate"],
        "sensitivity": "high",
    },
    "name": {
        "keywords": ["fullname", "firstname", "lastname", "middlename", "maidenname", "username"],
        "exact": ["name", "first_name", "last_name", "full_name", "username"],
        "sensitivity": "high",
    },
    "geolocation": {
        "keywords": ["latitude", "longitude", "lat", "lng", "geolocation", "coordinates", "gps"],
        "exact": ["latitude", "longitude", "lat", "lng", "geo_location", "coordinates"],
        "sensitivity": "high",
    },
    "address": {
        "keywords": ["address", "street", "city", "state", "postalcode", "zipcode", "pincode", "pin_code"],
        "exact": ["address", "street", "city", "state", "postal_code", "pincode", "pin_code"],
        "sensitivity": "medium",
    },
    "ip": {
        "keywords": ["ipaddress", "clientip", "remoteaddr", "userip"],
        "exact": ["ip", "ip_address", "client_ip", "remote_addr"],
        "sensitivity": "medium",
    },
    "device_id": {
        "keywords": ["deviceid", "imei", "imsi", "macaddress", "advertisingid", "idfa", "gaid"],
        "exact": ["device_id", "imei", "imsi", "mac_address", "idfa", "gaid"],
        "sensitivity": "medium",
    },
}

class PiiDetector:

    AADHAAR_REGEX = re.compile(r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b")
    PAN_REGEX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    PHONE_REGEX = re.compile(r"(?:\+91[-\s]?|91[-\s]?|0)?[6-9]\d{4}[-\s]?\d{5}\b")
    EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    PIN_CODE_REGEX = re.compile(r"\b[1-9][0-9]{2}\s?[0-9]{3}\b")
    UPI_REGEX = re.compile(r"\b[a-zA-Z0-9._-]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|upi|axl|apl)\b", re.IGNORECASE)
    CARD_REGEX = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b")
    IFSC_REGEX = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    DOB_REGEX = re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b")
    PASSPORT_REGEX = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b")

    @classmethod
    def match_identifier(cls, identifier: str) -> Optional[PiiType]:
        if not identifier or len(identifier) < 2:
            return None

        clean = re.sub(r"[^a-z0-9]", "", identifier.lower())

        tokens = [t.lower() for t in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)", identifier) if t]
        clean_tokens = set(tokens)

        for pii_type, defs in PII_FIELD_DICTIONARY.items():
            for exact in defs.get("exact", []):
                clean_exact = re.sub(r"[^a-z0-9]", "", exact.lower())
                if clean == clean_exact:
                    return pii_type

        for pii_type, defs in PII_FIELD_DICTIONARY.items():
            for exact in defs.get("exact", []):
                clean_exact = re.sub(r"[^a-z0-9]", "", exact.lower())
                if clean_exact in clean_tokens:
                    return pii_type
            for kw in defs.get("keywords", []):
                if len(kw) < 5:
                    if kw in clean_tokens:
                        return pii_type
                else:
                    if kw in clean or any(kw in t for t in clean_tokens):
                        return pii_type

        return None

    @classmethod
    def scan_text(cls, text: str, line_no: int = 1, default_flow: DataFlow = "exposed") -> List[PiiDetection]:
        detections: List[PiiDetection] = []

        for m in cls.AADHAAR_REGEX.finditer(text):
            val = m.group(0)
            if validate_verhoeff(val):
                detections.append(PiiDetection(
                    type="aadhaar",
                    confidence=0.99,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("aadhaar", val)
                ))

        for m in cls.PAN_REGEX.finditer(text):
            val = m.group(0)
            valid_4th = ("P", "C", "H", "F", "A", "T", "B", "L", "J", "G")
            if len(val) == 10 and val[3] in valid_4th:
                detections.append(PiiDetection(
                    type="pan",
                    confidence=0.95,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("pan", val)
                ))

        for m in cls.CARD_REGEX.finditer(text):
            val = m.group(0)
            if validate_luhn(val):
                detections.append(PiiDetection(
                    type="financial",
                    confidence=0.95,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("financial", val)
                ))

        for m in cls.UPI_REGEX.finditer(text):
            val = m.group(0)
            detections.append(PiiDetection(
                type="financial",
                confidence=0.95,
                matched_term=val,
                data_flow=default_flow,
                line=line_no,
                value_snippet=cls.mask_value("financial", val)
            ))

        for m in cls.EMAIL_REGEX.finditer(text):
            val = m.group(0)
            if not val.endswith(".example.com") and not val.endswith(".local"):
                detections.append(PiiDetection(
                    type="email",
                    confidence=0.95,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("email", val)
                ))

        for m in cls.PHONE_REGEX.finditer(text):
            val = m.group(0)
            digits = re.sub(r"\D", "", val)
            if len(digits) >= 10 and digits[-10] in ("6", "7", "8", "9"):
                detections.append(PiiDetection(
                    type="phone",
                    confidence=0.90,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("phone", val)
                ))

        for m in cls.IPV4_REGEX.finditer(text):
            val = m.group(0)
            if val not in ("127.0.0.1", "0.0.0.0") and not val.startswith("192.168.") and not val.startswith("10."):
                detections.append(PiiDetection(
                    type="ip",
                    confidence=0.85,
                    matched_term=val,
                    data_flow=default_flow,
                    line=line_no,
                    value_snippet=cls.mask_value("ip", val)
                ))

        for m in cls.DOB_REGEX.finditer(text):
            val = m.group(0)
            detections.append(PiiDetection(
                type="dob",
                confidence=0.85,
                matched_term=val,
                data_flow=default_flow,
                line=line_no,
                value_snippet=cls.mask_value("dob", val)
            ))

        return detections

    @classmethod
    def mask_value(cls, pii_type: PiiType, val: str) -> str:
        clean = val.strip()
        if pii_type == "aadhaar":
            digits = re.sub(r"\D", "", clean)
            return f"XXXX-XXXX-{digits[-4:]}" if len(digits) >= 12 else "XXXX-XXXX-XXXX"
        elif pii_type == "pan":
            return f"XXXXX{clean[5:9]}X" if len(clean) == 10 else "XXXXXXXXXX"
        elif pii_type == "email":
            parts = clean.split("@")
            if len(parts) == 2:
                u, d = parts
                mu = f"{u[0]}***{u[-1]}" if len(u) > 2 else "***"
                return f"{mu}@{d}"
            return "***@***.***"
        elif pii_type == "phone":
            digits = re.sub(r"\D", "", clean)
            return f"+91 XXXXX {digits[-4:]}" if len(digits) >= 10 else "XXXXX XXXXX"
        elif pii_type in ("password", "financial"):
            return "[REDACTED_CREDENTIAL]"
        elif pii_type in ("health", "biometrics"):
            return f"[REDACTED_{pii_type.upper()}_DATA]"
        return f"{clean[:2]}****{clean[-2:]}" if len(clean) > 4 else "****"

    @classmethod
    def mask_snippet(cls, snippet: str) -> str:
        res = snippet
        res = re.sub(
            r"""(?i)(password|passwd|secret|apikey|token|private_key)\s*[:=]\s*["']([^"']+)["']""",
            r'\1: "[REDACTED_SECRET]"',
            res
        )
        res = cls.EMAIL_REGEX.sub(lambda m: cls.mask_value("email", m.group(0)), res)
        res = cls.PHONE_REGEX.sub(lambda m: cls.mask_value("phone", m.group(0)), res)
        return res
