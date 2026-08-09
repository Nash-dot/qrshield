"""
API Router Endpoints
"""

from fastapi import APIRouter, HTTPException, status
from app.api.schemas import ScanRequest, ReputationResponse, HealthResponse
from app.core.reputation.scorer import analyse_target

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="ok", version="1.0.0")


@router.post("/reputation", response_model=ReputationResponse, tags=["Reputation Engine"])
async def analyze_reputation(request: ScanRequest):
    """
    Analyzes a target URL, UPI VPA, or upi:// payment deep link string.
    Returns reputation score (0-100+), verdict (SAFE | SUSPICIOUS | DANGEROUS | INVALID), and flagged risks.
    """
    if not request.target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target input string cannot be empty"
        )
    
    result = analyse_target(request.target)
    return result
