"""
FastAPI application entrypoint.
"""

from __future__ import annotations

# Load .env file before other imports
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Header, HTTPException

from app.api.routes import router, process_message, verify_api_key
from app.api.schemas import MessageRequest, MessageResponse
from app.core.config import settings


app = FastAPI(
    title="Honeypot Scam Detection API",
    description="API for classifying messages as scam or benign",
    version="0.1.0",
    debug=settings.debug,
)

# Include API routes at /api/v1
app.include_router(router, prefix="/api/v1", tags=["messages"])


# Also expose message endpoint at root for judge compatibility
@app.post("/", response_model=MessageResponse)
async def root_message(
    request: MessageRequest,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> MessageResponse:
    """Root endpoint - forwards to /api/v1/message for judge compatibility."""
    return await process_message(request, x_api_key)


@app.post("/message", response_model=MessageResponse)
async def alt_message(
    request: MessageRequest,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> MessageResponse:
    """Alternative endpoint at /message for judge compatibility."""
    return await process_message(request, x_api_key)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/config")
async def get_config() -> dict:
    """Get non-sensitive configuration."""
    return settings.to_dict()
