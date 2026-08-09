"""
Pydantic API Request/Response Schemas
"""

from typing import List, Optional, Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., description="URL string, UPI VPA, or upi:// deep link payload to analyze", example="https://secure-upi-login.xyz")


class ReputationResponse(BaseModel):
    url: str
    domain: Optional[str] = None
    score: int
    verdict: str  # SAFE, SUSPICIOUS, DANGEROUS, INVALID
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    has_https: Optional[bool] = None
    has_ip_in_url: Optional[bool] = None
    is_shortened: Optional[bool] = None
    is_free_hosting: Optional[bool] = None
    fuzzy_blacklist_hit: Optional[bool] = None
    url_length: Optional[int] = None
    payee_vpa: Optional[str] = None
    pre_filled_amount: Optional[str] = None
    note: Optional[str] = None
    flags: List[str]


class HealthResponse(BaseModel):
    status: str
    version: str
