"""
QR-iShield blocklist on Firebase (Cloud Firestore).

Same functions as blocklist_db.py (SQLite), so main.py can use either:
    lookup(), add_dangerous(), list_entries(), stats(), init_db()

Collection : blocked_qr
Document ID: SHA-256 of the normalised payload  -> exact match is a single read
Stores ONLY payloads judged DANGEROUS.
"""
import hashlib
import os
from urllib.parse import urlparse, parse_qs

import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import AlreadyExists
from google.cloud.firestore_v1.base_query import FieldFilter

COLLECTION = "blocked_qr"

# Shorteners host many unrelated links -> never block by host alone
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "shorturl.at", "tiny.cc"}

_client = None


# ---------- connection ----------
def init_db(key_path: str = None):
    """Connect to Firebase. Call once at startup."""
    global _client
    if not firebase_admin._apps:
        path = key_path or os.environ.get("FIREBASE_KEY_PATH", "serviceAccountKey.json")
        firebase_admin.initialize_app(credentials.Certificate(path))
    _client = firestore.client()


def _col():
    if _client is None:
        init_db()
    return _client.collection(COLLECTION)


# ---------- normalisation (same rules as blocklist_db.py) ----------
def parse_payload(raw: str) -> dict:
    raw = raw.strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() == "upi":
        vpa = (parse_qs(parsed.query).get("pa", [""])[0]).strip().lower()
        return {"type": "upi", "normalised": f"upi://pay?pa={vpa}",
                "host": None, "vpa": vpa or None}
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")
    norm = f"{(parsed.scheme or 'http').lower()}://{host}{path}"
    if parsed.query:
        norm += "?" + parsed.query
    return {"type": "url", "normalised": norm, "host": host or None, "vpa": None}


def _hash(normalised: str) -> str:
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _clean(d: dict) -> dict:
    """Make a Firestore document JSON-friendly (timestamps -> text)."""
    out = dict(d)
    for k in ("first_seen", "last_seen"):
        if out.get(k) is not None:
            out[k] = out[k].strftime("%Y-%m-%d %H:%M:%S")
    return out


# ---------- lookup ----------
def lookup(raw_payload: str):
    """Return the matching blocklist entry (dict) or None. Call BEFORE the ML/rules."""
    p = parse_payload(raw_payload)
    col = _col()

    snap, match = col.document(_hash(p["normalised"])).get(), "exact"

    if not snap.exists and p["vpa"]:
        found = list(col.where(filter=FieldFilter("upi_vpa", "==", p["vpa"])).limit(1).stream())
        snap, match = (found[0] if found else None), "upi_id"

    if (snap is None or not snap.exists) and p["host"] and p["host"] not in SHORTENERS:
        found = list(col.where(filter=FieldFilter("host", "==", p["host"])).limit(1).stream())
        snap, match = (found[0] if found else None), "domain"

    if snap is not None and snap.exists:
        snap.reference.update({"last_seen": firestore.SERVER_TIMESTAMP})
        d = _clean(snap.to_dict())
        d["match_type"] = match
        return d
    return None


# ---------- insert (DANGEROUS only) ----------
def add_dangerous(raw_payload: str, risk_score: float, reasons=None,
                  source: str = "auto", detected_by: str = None, details: dict = None):
    """Insert a dangerous QR, or bump report_count if it already exists."""
    p = parse_payload(raw_payload)
    ref = _col().document(_hash(p["normalised"]))
    data = {
        "raw_payload": raw_payload,
        "payload_type": p["type"],
        "host": p["host"],
        "upi_vpa": p["vpa"],
        "risk_score": risk_score,
        "reasons": ",".join(reasons or []),
        "source": source,
        "detected_by": detected_by,
        "details": details,
        "report_count": 1,
        "first_seen": firestore.SERVER_TIMESTAMP,
        "last_seen": firestore.SERVER_TIMESTAMP,
    }
    try:
        ref.create(data)                       # fails if it already exists
        return "inserted"
    except AlreadyExists:
        ref.update({"report_count": firestore.Increment(1),
                    "last_seen": firestore.SERVER_TIMESTAMP})
        return "updated"


# ---------- view ----------
def list_entries(limit: int = 50, offset: int = 0):
    """Stored dangerous QRs, newest first."""
    q = (_col().order_by("last_seen", direction=firestore.Query.DESCENDING)
         .limit(limit).offset(offset))
    return [dict(_clean(s.to_dict()), id=s.id) for s in q.stream()]


def stats():
    docs = list(_col().select(["report_count"]).stream())
    return {"unique_blocked": len(docs),
            "total_reports": sum((s.to_dict().get("report_count") or 0) for s in docs)}
