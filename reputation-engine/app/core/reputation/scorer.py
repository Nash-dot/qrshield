"""
Main Reputation Engine Scorer
-----------------------------
Combines domain age, SSL, URL features, and UPI VPA checks to return final verdict.
"""

from typing import Dict, Any
import tldextract

from app.core.reputation.whois_check import get_domain_age_days
from app.core.reputation.ssl_check import check_ssl_valid
from app.core.reputation.url_features import (
    has_https, has_ip_in_url, is_shortened_url, is_free_hosting,
    check_abnormal_structure, fuzzy_blacklist_match, url_entropy_features
)
from app.core.reputation.vpa_check import is_valid_upi_vpa, analyse_upi_vpa, analyse_upi_deeplink


def is_valid_input(url: str) -> bool:
    """Rejects garbage strings that are not URLs or VPAs."""
    if not url or len(url) < 4:
        return False
    has_scheme = "://" in url
    has_dot = "." in url
    has_at = "@" in url
    return has_scheme or has_dot or has_at


def analyse_target(url: str) -> Dict[str, Any]:
    """
    Main entry point for analyzing a URL, UPI VPA, or upi:// deep link payload.
    """
    url = url.strip()

    # 0. Input validation
    if not is_valid_input(url):
        return {
            "url": url,
            "domain": None,
            "score": 0,
            "verdict": "INVALID",
            "flags": ["Input is not a valid URL or UPI VPA — skipped analysis"]
        }

    # 1. Handle upi:// payment deep link
    if url.startswith("upi://"):
        return analyse_upi_deeplink(url)

    # 2. Handle UPI VPA (e.g. merchant@okaxis)
    if "@" in url and "://" not in url:
        return analyse_upi_vpa(url)

    # 3. Handle Web URLs
    normalized = url if "://" in url else f"http://{url}"
    score = 0
    flags = []

    extracted = tldextract.extract(normalized)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

    # Check 1: WHOIS domain age
    age_days = get_domain_age_days(domain)
    if age_days is None:
        score += 20
        flags.append("WHOIS lookup failed — domain may be privacy-protected or unreachable")
    elif age_days < 30:
        score += 25
        flags.append(f"Very new domain: {age_days} days old")
    elif age_days < 180:
        score += 10
        flags.append(f"Relatively new domain: {age_days} days old")

    # Check 2: SSL certificate
    ssl_valid = check_ssl_valid(domain)
    if not ssl_valid:
        score += 20
        flags.append("SSL certificate missing or invalid")

    # Check 3: HTTPS
    uses_https = has_https(normalized)
    if not uses_https:
        score += 15
        flags.append("URL does not use HTTPS")

    # Check 4: IP address in URL
    ip_in_url = has_ip_in_url(normalized)
    if ip_in_url:
        score += 25
        flags.append("Raw IP address found in URL instead of domain name")

    # Check 5: URL shortener
    shortened = is_shortened_url(domain)
    if shortened:
        score += 15
        flags.append("URL uses a known shortening service")

    # Check 6: Free hosting
    free_host = is_free_hosting(normalized)
    if free_host:
        score += 10
        flags.append("Hosted on a known free hosting platform")

    # Check 7: Abnormal structure
    is_abnormal, is_at_attack = check_abnormal_structure(normalized, extracted)
    if is_at_attack:
        score += 40
        flags.append("CRITICAL: @ symbol obfuscation detected — fake domain embedded in URL")
    elif is_abnormal:
        score += 15
        flags.append("Abnormal URL structure detected (nested redirect or excessive subdomains)")

    # Check 8: Fuzzy domain blacklist
    blacklist_hit = fuzzy_blacklist_match(normalized)
    if blacklist_hit:
        score += 30
        flags.append("URL matches a known UPI phishing domain pattern")

    # Check 9: Entropy / Length
    entropy = url_entropy_features(normalized)
    if entropy["url_length"] > 100:
        score += 10
        flags.append(f"Unusually long URL: {entropy['url_length']} characters")

    # Verdict Tiering
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
        "url_length": entropy["url_length"],
        "flags": flags,
    }
