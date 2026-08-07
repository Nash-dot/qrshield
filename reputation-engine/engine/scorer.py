"""
scorer.py
---------
The main orchestrator. Takes a URL or UPI VPA, runs all checks,
and returns a unified reputation report with a final verdict.

Verdict thresholds:
    Score 0  - 30 : SAFE
    Score 31 - 60 : SUSPICIOUS
    Score 61+     : DANGEROUS

Import and use:
    from engine.scorer import analyse
    result = analyse("https://some-url.com")
    result = analyse("merchant@okaxis")
    result = analyse("upi://pay?pa=abc@ybl&am=500")
"""

import tldextract
from urllib.parse import urlparse
from typing import Dict, Any

from engine.whois_check import get_domain_age_days
from engine.ssl_check import check_ssl_valid
from engine.url_features import (
    has_https,
    has_ip_in_url,
    is_shortened_url,
    is_free_hosting,
    check_abnormal_structure,
    fuzzy_blacklist_match,
    url_entropy_features,
)
from engine.vpa_check import is_valid_upi_vpa, analyse_upi_vpa, analyse_upi_deeplink


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

def _is_valid_input(url: str) -> bool:
    """
    Rejects strings that are clearly not URLs or VPAs.
    A valid input must have at least one of: a scheme, a dot, or an @ symbol.
    """
    if not url or len(url.strip()) < 4:
        return False
    return "://" in url or "." in url or "@" in url


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyse(url: str) -> Dict[str, Any]:
    """
    Analyses a URL, UPI VPA, or UPI deep link and returns a reputation report.

    Args:
        url: Any of:
             - A standard URL   e.g. "https://example.com/pay"
             - A UPI VPA        e.g. "merchant@okaxis"
             - A UPI deep link  e.g. "upi://pay?pa=abc@ybl&pn=Shop&am=100"

    Returns:
        A dict with keys: url/vpa, domain, score, verdict, flags, and
        individual check results.
    """
    url = url.strip()

    # --- Step 1: Validate input ---
    if not _is_valid_input(url):
        return {
            "url": url,
            "domain": None,
            "score": 0,
            "verdict": "INVALID",
            "flags": ["Input is not a recognisable URL or UPI VPA — analysis skipped"],
        }

    # --- Step 2: Route by input type ---

    # UPI deep link (e.g. from QR code scan)
    if url.startswith("upi://"):
        return analyse_upi_deeplink(url)

    # UPI VPA string (e.g. merchant@okaxis)
    if "@" in url and "://" not in url:
        if is_valid_upi_vpa(url):
            return analyse_upi_vpa(url)

    # --- Step 3: Standard URL analysis ---

    # Normalize — add http:// if no scheme present so urlparse works correctly
    normalized = url if "://" in url else f"http://{url}"

    score = 0
    flags = []

    # Extract clean domain using tldextract (handles subdomains correctly)
    extracted = tldextract.extract(normalized)
    domain = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.suffix
        else extracted.domain
    )

    # --- Check 1: WHOIS domain age ---
    age_days = get_domain_age_days(domain)
    if age_days is None:
        score += 20
        flags.append("WHOIS lookup failed — domain may be privacy-protected or unreachable")
    elif age_days < 30:
        score += 25
        flags.append(f"Very new domain: registered only {age_days} day(s) ago")
    elif age_days < 180:
        score += 10
        flags.append(f"Relatively new domain: {age_days} days old")

    # --- Check 2: SSL certificate ---
    ssl_valid = check_ssl_valid(domain)
    if not ssl_valid:
        score += 20
        flags.append("SSL certificate is missing or invalid")

    # --- Check 3: HTTPS ---
    uses_https = has_https(normalized)
    if not uses_https:
        score += 15
        flags.append("URL does not use HTTPS")

    # --- Check 4: Raw IP address in URL ---
    ip_in_url = has_ip_in_url(normalized)
    if ip_in_url:
        score += 25
        flags.append("Raw IP address used instead of a domain name")

    # --- Check 5: URL shortener ---
    shortened = is_shortened_url(domain)
    if shortened:
        score += 15
        flags.append("URL uses a known shortening service — real destination is hidden")

    # --- Check 6: Free hosting ---
    free_host = is_free_hosting(normalized)
    if free_host:
        score += 10
        flags.append("Hosted on a known free hosting platform")

    # --- Check 7: Abnormal structure ---
    is_abnormal, is_at_attack = check_abnormal_structure(normalized)
    if is_at_attack:
        score += 40  # @ obfuscation is critical — push directly to DANGEROUS range
        flags.append(
            "CRITICAL: @ symbol obfuscation detected — "
            "a fake trusted domain is embedded before the real malicious domain"
        )
    elif is_abnormal:
        score += 15
        flags.append(
            "Abnormal URL structure detected (nested redirect or excessive subdomains)"
        )

    # --- Check 8: UPI phishing keyword blacklist ---
    blacklist_hit = fuzzy_blacklist_match(normalized)
    if blacklist_hit:
        score += 30
        flags.append("URL contains a known UPI phishing keyword pattern")

    # --- Check 9: URL length ---
    features = url_entropy_features(normalized)
    if features["url_length"] > 100:
        score += 10
        flags.append(f"Unusually long URL ({features['url_length']} characters)")

    # --- Final Verdict ---
    if score <= 30:
        verdict = "SAFE"
    elif score <= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "domain_age_days": age_days,
        "ssl_valid": ssl_valid,
        "has_https": uses_https,
        "has_ip_in_url": ip_in_url,
        "is_shortened": shortened,
        "is_free_hosting": free_host,
        "fuzzy_blacklist_hit": blacklist_hit,
        "url_length": features["url_length"],
        "flags": flags,
    }