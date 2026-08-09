"""
WHOIS Domain Age Validation Check
---------------------------------
Retrieves creation date for a domain using python-whois with timezone-safe math.
"""

from datetime import datetime, timezone
from typing import Optional
import whois


def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Returns domain age in days using WHOIS lookup.
    Returns None if the lookup fails or date is unavailable.
    """
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            dates = [d for d in creation_date if isinstance(d, datetime)]
            creation_date = min(dates) if dates else None

        if not isinstance(creation_date, datetime):
            return None

        # Normalize to UTC for timezone-safe comparison
        if creation_date.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()

        age = (now - creation_date).days
        return age if age >= 0 else None

    except Exception:
        return None
