"""
URL Feature Extraction & Anomaly Detection
------------------------------------------
Inspects URL scheme, IP presence, shortener patterns, free hosting, and obfuscation.
"""

import re
import ipaddress
from typing import Any, Tuple
from urllib.parse import urlparse
import tldextract


SHORTENER_RE = re.compile(
    r'(^|\.)(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|'
    r'tr\.im|is\.gd|cli\.gs|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|'
    r'snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|bkite\.com|'
    r'snipr\.com|fic\.kr|doiop\.com|short\.ie|kl\.am|wp\.me|om\.ly|to\.ly|'
    r'bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|'
    r'q\.gs|po\.st|bc\.vc|u\.to|j\.mp|buzurl\.com|cutt\.us|yourls\.org|'
    r'v\.gd|link\.zip\.net)$', re.IGNORECASE)

FREE_HOST_RE = re.compile(
    r'wordpress|blogspot|weebly|wix|tumblr|github\.io|gitlab\.io|'
    r'herokuapp\.com|000webhost|000webhostapp|firebaseapp|firebaseio|'
    r'appspot|azurewebsites|netlify|webcindario|tripod|yola|ucoz|'
    r'freehosting|freehostia|byethost|infinityfree|awardspace|profreehost|'
    r'biz\.nf|phpnet|zohosites|epizy|webnode|webflow|jimdo|siterubix|strikingly',
    re.IGNORECASE)

BLACKLIST_FRAGMENTS = [
    "secure-upi", "upi-verify", "paytm-offer", "phonepay", "gpay-reward",
    "bhim-upi", "upi-kyc", "upi-update", "upi-login", "upi-refund",
    "npci-upi", "upi-cashback", "upi-bonus", "free-upi", "upi-activate"
]


def has_https(url: str) -> bool:
    """Returns True if scheme is HTTPS."""
    return urlparse(url).scheme.lower() == "https"


def has_ip_in_url(url: str) -> bool:
    """Returns True if hostname is a raw IP address (IPv4/IPv6)."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_shortened_url(domain: str) -> bool:
    """Returns True if domain is a known URL shortening service."""
    return bool(SHORTENER_RE.search(domain))


def is_free_hosting(url: str) -> bool:
    """Returns True if URL matches known free hosting platforms."""
    return bool(FREE_HOST_RE.search(url))


def check_abnormal_structure(url: str, extracted: Any) -> Tuple[bool, bool]:
    """
    Checks for abnormal structure.
    Returns (is_abnormal, is_at_attack).
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")

    # 1. Embedded credentials / fake domain prefix before @
    if "@" in parsed.netloc:
        return True, True

    # 2. Redirect/Protocol obfuscation in path
    rest = url[len(parsed.scheme) + 3:]
    if re.search(r'https?://', rest):
        return True, False

    # 3. Excessive subdomain depth (tldextract safe)
    if extracted.subdomain and len(extracted.subdomain.split(".")) > 3:
        return True, False

    return False, False


def fuzzy_blacklist_match(url: str) -> bool:
    """Returns True if URL contains any known phishing domain fragment."""
    url_lower = url.lower()
    return any(fragment in url_lower for fragment in BLACKLIST_FRAGMENTS)


def url_entropy_features(url: str) -> dict:
    """Returns key character counts and total length."""
    special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    return {
        "url_length": len(url),
        "digit_count": sum(c.isdigit() for c in url),
        "letter_count": sum(c.isalpha() for c in url),
        "special_char_count": sum(url.count(c) for c in special_chars),
    }
