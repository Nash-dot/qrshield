"""
UPI VPA & Deep Link Analysis Module
-----------------------------------
Validates UPI VPA format (user@handle) and parses upi://pay deep-link parameters.
"""

import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_VPA_KEYWORDS = [
    "refund", "support", "kyc", "customer", "care", "reward", "cashback", "claim", "winner", "bonus"
]


def is_valid_upi_vpa(vpa: str) -> bool:
    """Validates UPI VPA syntax: username@handle."""
    pattern = r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$'
    return bool(re.match(pattern, vpa))


def analyse_upi_vpa(vpa: str) -> Dict[str, Any]:
    """Analyzes a standard UPI VPA string."""
    score = 0
    flags = []

    if not is_valid_upi_vpa(vpa):
        score += 50
        flags.append("Invalid or malformed UPI VPA format")
    else:
        username = vpa.lower().split("@", 1)[0]
        matched = [kw for kw in SUSPICIOUS_VPA_KEYWORDS if kw in username]
        if matched:
            score += 35
            flags.append(f"VPA username contains fraud-associated keyword(s): {', '.join(matched)}")

    verdict = "SAFE" if score <= 30 else ("SUSPICIOUS" if score <= 60 else "DANGEROUS")

    return {
        "vpa": vpa,
        "score": score,
        "verdict": verdict,
        "is_valid_format": is_valid_upi_vpa(vpa),
        "flags": flags
    }


def analyse_upi_deeplink(url: str) -> Dict[str, Any]:
    """
    Parses upi:// scheme payment payloads:
    upi://pay?pa=payee@vpa&pn=PayeeName&am=Amount&tn=Note
    """
    score = 0
    flags = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    pa = params.get("pa", [None])[0]   # payee VPA
    am = params.get("am", [None])[0]   # pre-filled amount
    tn = params.get("tn", [None])[0]   # transaction note

    if not pa:
        score += 40
        flags.append("UPI deep link missing payee address (pa parameter)")
    else:
        vpa_result = analyse_upi_vpa(pa)
        score += vpa_result["score"]
        flags.extend(vpa_result["flags"])

    if am:
        score += 30
        flags.append(f"Pre-filled payment amount detected: ₹{am} — verify before paying")

    if tn:
        tn_lower = tn.lower()
        matched_tn = [kw for kw in SUSPICIOUS_VPA_KEYWORDS if kw in tn_lower]
        if matched_tn:
            score += 35
            flags.append(f"Transaction note contains suspicious keyword(s): {', '.join(matched_tn)}")

    verdict = "SAFE" if score <= 30 else ("SUSPICIOUS" if score <= 60 else "DANGEROUS")

    return {
        "url": url,
        "domain": "upi://",
        "score": score,
        "verdict": verdict,
        "payee_vpa": pa,
        "pre_filled_amount": am,
        "note": tn,
        "flags": flags
    }
