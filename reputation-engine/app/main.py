"""
QRIshield FastAPI Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

app = FastAPI(
    title="QRIshield Threat Detection Engine",
    description="Independent URL Reputation & UPI Payment Fraud Analysis Platform",
    version="1.0.0",
)

# Enable CORS for mobile & web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "message": "QRIshield Threat Detection API is running",
        "docs": "/docs",
        "health": "/api/v1/health"
    }
