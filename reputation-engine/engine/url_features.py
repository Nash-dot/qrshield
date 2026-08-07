"""
url_features.py
---------------
Extracts URL-based features used for reputation scoring.
All checks are self-contained — no external API calls.

Checks:
  - HTTPS presence
  - Raw IP address in URL
  - URL shortening service detection
  - Free hosting platform detection
  - Abnormal URL structure (@ obfuscation, nested redirects, excessive subdomains)
  - UPI phishing keyword blacklist
  - URL length and character features
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple


# ---------------------------------------------------------------------------
# HTTPS
# ---------------------------------------------------------------------------

def has_https(url: str) -> bool:
    """Returns True if the URL scheme is HTTPS."""
    return urlparse(url).scheme.lower() == "https"


# ---------------------------------------------------------------------------
# IP Address in URL
# ---------------------------------------------------------------------------

def has_ip_in_url(url: str) -> bool:
    """
    Returns True if the hostname is a raw IPv4 or IPv6 address.
    Phishing sites often use IPs to avoid leaving domain registration trails.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# URL Shortener Detection
# ---------------------------------------------------------------------------

_SHORTENER_RE = re.compile(
    r'(^|\.)(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|'
    r'tr\.im|is\.gd|cli\.gs|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|'
    r'snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|bkite\.com|'
    r'snipr\.com|fic\.kr|doiop\.com|short\.ie|kl\.am|wp\.me|om\.ly|to\.ly|'
    r'bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|'
    r'q\.gs|po\.st|bc\.vc|u\.to|j\.mp|buzurl\.com|cutt\.us|yourls\.org|'
    r'v\.gd|link\.zip\.net)$',
    re.IGNORECASE
)

def is_shortened_url(domain: str) -> bool:
    """Returns True if the domain belongs to a known URL shortening service."""
    return bool(_SHORTENER_RE.search(domain))


# ---------------------------------------------------------------------------
# Free Hosting Detection
# ---------------------------------------------------------------------------

_FREE_HOST_RE = re.compile(
    r'wordpress|blogspot|weebly|wix|tumblr|github\.io|gitlab\.io|'
    r'herokuapp\.com|000webhost|000webhostapp|firebaseapp|firebaseio|'
    r'appspot|azurewebsites|netlify|webcindario|tripod|yola|ucoz|'
    r'freehosting|freehostia|byethost|infinityfree|awardspace|profreehost|'
    r'biz\.nf|phpnet|zohosites|epizy|webnode|webflow|jimdo|siterubix|strikingly',
    re.IGNORECASE
)

def is_free_hosting(url: str) -> bool:
    """Returns True if the URL is hosted on a known free hosting platform."""
    return bool(_FREE_HOST_RE.search(url))


# ---------------------------------------------------------------------------
# Abnormal URL Structure
# ---------------------------------------------------------------------------

def check_abnormal_structure(url: str) -> Tuple[bool, bool]:
    """
    Detects common URL obfuscation techniques used in phishing.

    Returns:
        (is_abnormal, is_at_attack)

        is_at_attack = True means @ symbol obfuscation was found.
        This is a CRITICAL-level indicator and should be scored much higher
        than a generic structural anomaly.

    Techniques detected:
        1. @ in netloc:  http://paypal.com@attacker.com  <- real domain is attacker.com
        2. Nested protocol in query: legit.com/go?url=http://evil.com
        3. Excessive subdomain depth (> 4 levels)
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")

    # Technique 1: @ obfuscation — most dangerous
    if "@" in parsed.netloc:
        return True, True

    # Technique 2: Nested protocol in path/query
    rest = url[len(parsed.scheme) + 3:]
    if re.search(r'https?://', rest):
        return True, False

    # Technique 3: Excessive subdomains
    if parsed.hostname and len(parsed.hostname.split(".")) > 4:
        return True, False

    return False, False


# ---------------------------------------------------------------------------
# UPI Phishing Keyword Blacklist
# ---------------------------------------------------------------------------

_BLACKLIST_FRAGMENTS = [
    "secure-upi", "upi-verify", "paytm-offer", "phonepay", "gpay-reward",
    "bhim-upi", "upi-kyc", "upi-update", "upi-login", "upi-refund",
    "npci-upi", "upi-cashback", "upi-bonus", "free-upi", "upi-activate"
]

def fuzzy_blacklist_match(url: str) -> bool:
    """Returns True if the URL contains a known UPI phishing keyword fragment."""
    url_lower = url.lower()
    return any(fragment in url_lower for fragment in _BLACKLIST_FRAGMENTS)


# ---------------------------------------------------------------------------
# URL Entropy / Character Features (informational)
# ---------------------------------------------------------------------------

def url_entropy_features(url: str) -> dict:
    """Returns basic character-level URL statistics used in scoring."""
    special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    return {
        "url_length": len(url),
        "digit_count": sum(c.isdigit() for c in url),
        "letter_count": sum(c.isalpha() for c in url),
        "special_char_count": sum(url.count(c) for c in special_chars),
    }