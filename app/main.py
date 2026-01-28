"""
FastAPI application entrypoint.
"""

from __future__ import annotations

# Load .env file before other imports
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI

from app.api.routes import router
from app.core.config import settings


app = FastAPI(
    title="Honeypot Scam Detection API",
    description="API for classifying messages as scam or benign",
    version="0.1.0",
    debug=settings.debug,
)

# Include API routes
app.include_router(router, prefix="/api/v1", tags=["messages"])


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/config")
async def get_config() -> dict:
    """Get non-sensitive configuration."""
    return settings.to_dict()
