"""
whois_check.py
--------------
Checks domain age via WHOIS lookup.
No external API — queries the domain registry directly.
"""

from datetime import datetime, timezone
from typing import Optional
import whois


def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Returns the age of the domain in days.
    Returns None if WHOIS lookup fails (privacy-protected, unreachable, etc).
    """
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        # creation_date is sometimes a list (multiple registration events)
        if isinstance(creation_date, list):
            dates = [d for d in creation_date if isinstance(d, datetime)]
            creation_date = min(dates) if dates else None

        if not isinstance(creation_date, datetime):
            return None

        # Normalize timezone to avoid comparison errors
        if creation_date.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()

        return (now - creation_date).days

    except Exception:
        return None