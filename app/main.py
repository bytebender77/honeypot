"""
FastAPI application entrypoint.
"""

from __future__ import annotations

# Load .env file before other imports
from dotenv import load_dotenv
load_dotenv()

import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from app.api.routes import router, process_message, verify_api_key
from app.api.schemas import MessageRequest, MessageResponse, ScamClassification
from app.core.config import settings
from app.orchestration.graph import EngagementOrchestrator


app = FastAPI(
    title="Honeypot Scam Detection API",
    description="API for classifying messages as scam or benign",
    version="0.1.0",
    debug=settings.debug,
)

# Include API routes at /api/v1
app.include_router(router, prefix="/api/v1", tags=["messages"])

# Shared orchestrator for root endpoints
_root_orchestrator: EngagementOrchestrator | None = None

def get_root_orchestrator() -> EngagementOrchestrator:
    global _root_orchestrator
    if _root_orchestrator is None:
        _root_orchestrator = EngagementOrchestrator()
    return _root_orchestrator


# Flexible root endpoint that accepts multiple request formats
@app.post("/")
async def root_message(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> dict[str, Any]:
    """
    Root endpoint - accepts multiple request formats for judge compatibility.
    
    Accepts:
    - {"message": "..."}
    - {"text": "..."}
    - {"content": "..."}
    - {"session_id": "...", "message": "..."}
    """
    verify_api_key(x_api_key)
    
    if not settings.has_api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")
    
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Extract message from various possible field names
    message = None
    for field in ["message", "text", "content", "msg", "input"]:
        if field in body and body[field]:
            message = str(body[field])
            break
    
    if not message:
        raise HTTPException(status_code=400, detail="No message field found")
    
    # Get or generate session_id
    session_id = body.get("session_id") or str(uuid.uuid4())
    
    try:
        orchestrator = get_root_orchestrator()
        state = orchestrator.process_message(session_id=session_id, message=message)
        
        return {
            "classification": {
                "is_scam": state.classification.is_scam if state.classification else True,
                "confidence": state.classification.confidence if state.classification else 0.7,
                "reason": state.classification.reason if state.classification else "Classification error",
            },
            "agent_reply": state.agent_reply,
            "extracted_intel": state.extracted_intel,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Processing failed")


@app.post("/message")
async def alt_message(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> dict[str, Any]:
    """Alternative endpoint at /message."""
    return await root_message(request, x_api_key)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/config")
async def get_config() -> dict:
    """Get non-sensitive configuration."""
    return settings.to_dict()
