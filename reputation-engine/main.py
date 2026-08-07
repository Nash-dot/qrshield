"""
main.py
-------
FastAPI app for the QRIshield Reputation Engine.

Exposes a single POST endpoint:
    POST /analyse
    Body: { "url": "https://example.com" }

Returns a full reputation report with score, verdict, and flags.

Run locally:
    uvicorn main:app --reload --port 8001
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from engine.scorer import analyse

app = FastAPI(
    title="QRIshield Reputation Engine",
    description="Independent URL and UPI VPA reputation analysis — no external API dependencies.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class AnalyseRequest(BaseModel):
    url: str  # Can be a URL, UPI VPA, or UPI deep link


class AnalyseResponse(BaseModel):
    verdict: str          # SAFE | SUSPICIOUS | DANGEROUS | INVALID
    score: int            # 0-100+ numeric risk score
    flags: list[str]      # Human-readable list of reasons
    domain: str | None    # Extracted domain (None for INVALID inputs)
    url: str | None = None
    vpa: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "service": "QRIshield Reputation Engine",
        "status": "running",
        "endpoint": "POST /analyse  —  body: { url: string }",
    }


@app.post("/analyse", response_model=AnalyseResponse)
def analyse_url(request: AnalyseRequest):
    """
    Analyse a URL, UPI VPA, or UPI deep link (upi://) for phishing indicators.
    Returns a verdict of SAFE, SUSPICIOUS, DANGEROUS, or INVALID.
    """
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="url field cannot be empty")

    result = analyse(request.url)
    return result


# ---------------------------------------------------------------------------
# Health check (useful for mobile app connectivity tests)
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}