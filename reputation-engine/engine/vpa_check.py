"""
vpa_check.py
------------
Handles UPI-specific inputs:
  - VPA (Virtual Payment Address) format validation e.g. merchant@okaxis
  - UPI deep link analysis e.g. upi://pay?pa=vpa&pn=name&am=amount

These are specific to QRIshield's Indian UPI payment context.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any


# ---------------------------------------------------------------------------
# VPA Format Validation
# ---------------------------------------------------------------------------

_VPA_PATTERN = re.compile(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$')

_SUSPICIOUS_VPA_KEYWORDS = [
    "refund", "support", "kyc", "customer", "care",
    "reward", "cashback", "claim", "help", "helpdesk"
]


def is_valid_upi_vpa(vpa: str) -> bool:
    """
    Returns True if the string matches the standard UPI VPA format.
    Format: localpart@handle  (e.g. shop@okaxis, user@ybl, merchant@paytm)
    """
    return bool(_VPA_PATTERN.match(vpa))


def analyse_upi_vpa(vpa: str) -> Dict[str, Any]:
    """
    Scores a UPI VPA string for fraud indicators.

    Checks:
      - Whether the VPA format is valid
      - Whether the username contains fraud-associated keywords
        (e.g. refund, kyc, support — common in social engineering attacks)
    """
    score = 0
    flags = []

    if not is_valid_upi_vpa(vpa):
        score += 50
        flags.append("Invalid or malformed UPI VPA format")
    else:
        username = vpa.lower().split("@", 1)[0]
        matched_kw = [kw for kw in _SUSPICIOUS_VPA_KEYWORDS if kw in username]
        if matched_kw:
            score += 35
            flags.append(
                f"VPA username contains fraud-associated keyword(s): {', '.join(matched_kw)}"
            )

    verdict = "SAFE" if score <= 30 else ("SUSPICIOUS" if score <= 60 else "DANGEROUS")

    return {
        "vpa": vpa,
        "score": score,
        "verdict": verdict,
        "is_valid_format": is_valid_upi_vpa(vpa),
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# UPI Deep Link Analysis
# ---------------------------------------------------------------------------

def analyse_upi_deeplink(url: str) -> Dict[str, Any]:
    """
    Analyses a upi:// scheme deep link payload from a QR code.

    UPI deep link format:
        upi://pay?pa=<vpa>&pn=<name>&am=<amount>&cu=INR&tn=<note>

    Checks:
      - Whether the payee VPA (pa) is present and valid
      - Whether an amount is pre-filled (am parameter)
        Pre-filled amounts in QR codes are a common scam technique —
        legitimate merchant QR codes typically do not pre-fill amounts.
    """
    score = 0
    flags = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Extract key parameters
    pa = params.get("pa", [None])[0]   # payee VPA
    am = params.get("am", [None])[0]   # pre-filled amount
    pn = params.get("pn", [None])[0]   # payee name (informational)

    # Check payee VPA
    if not pa:
        score += 40
        flags.append("UPI deep link is missing the payee address (pa parameter)")
    else:
        vpa_result = analyse_upi_vpa(pa)
        score += vpa_result["score"]
        flags += vpa_result["flags"]

    # Check pre-filled amount
    if am:
        score += 30
        flags.append(
            f"Pre-filled payment amount detected: ₹{am} — "
            f"legitimate merchant QR codes typically do not pre-fill amounts"
        )

    verdict = "SAFE" if score <= 30 else ("SUSPICIOUS" if score <= 60 else "DANGEROUS")

    return {
        "url": url,
        "domain": "upi://",
        "score": score,
        "verdict": verdict,
        "payee_vpa": pa,
        "payee_name": pn,
        "pre_filled_amount": am,
        "flags": flags,
    }