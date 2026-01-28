"""
API Routes - HTTP endpoints for the scam detection pipeline.

Current endpoints:
- POST /message - Process a message through the honeypot pipeline
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.schemas import (
    MessageRequest,
    MessageResponse,
    ScamClassification,
    ErrorResponse,
)
from app.core.config import settings
from app.orchestration.graph import EngagementOrchestrator


router = APIRouter()

# Shared orchestrator instance for session management
_orchestrator: EngagementOrchestrator | None = None


def get_orchestrator() -> EngagementOrchestrator:
    """Get or create the shared orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = EngagementOrchestrator()
    return _orchestrator


@router.post(
    "/message",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        500: {"model": ErrorResponse, "description": "Processing failed"},
    },
    summary="Process a message",
    description="Process a message through the honeypot pipeline. Returns classification, optional agent reply, and extracted intel.",
)
async def process_message(request: MessageRequest) -> MessageResponse:
    """
    Process a message through the honeypot pipeline.
    
    Args:
        request: The message request containing session_id and message.
        
    Returns:
        MessageResponse with:
        - classification: Scam classification result (always present)
        - agent_reply: Honeypot response (if engaged)
        - extracted_intel: Scam indicators (if conversation complete and was scam)
    """
    # Validate API key is configured
    if not settings.has_api_key:
        raise HTTPException(
            status_code=500,
            detail="API key not configured. Set GROQ_API_KEY environment variable.",
        )
    
    try:
        orchestrator = get_orchestrator()
        
        # Process message through orchestration
        state = orchestrator.process_message(
            session_id=request.session_id,
            message=request.message,
        )
        
        # Build classification from state
        classification = ScamClassification(
            is_scam=state.classification.is_scam if state.classification else True,
            confidence=state.classification.confidence if state.classification else 0.7,
            reason=state.classification.reason if state.classification else "Classification error",
        )
        
        # Build response
        return MessageResponse(
            classification=classification,
            agent_reply=state.agent_reply,
            extracted_intel=state.extracted_intel,
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Processing failed. Please try again.",
        )


@router.post(
    "/session/{session_id}/end",
    response_model=MessageResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Session not found"},
    },
    summary="End a session",
    description="Forcefully end a session and trigger extraction.",
)
async def end_session(session_id: str) -> MessageResponse:
    """
    End a session and get final results with extraction.
    
    Args:
        session_id: The session to end.
        
    Returns:
        Final MessageResponse with extracted_intel if scam.
    """
    orchestrator = get_orchestrator()
    
    state = orchestrator.get_session(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # End the session
    orchestrator.end_session(session_id, "Manually ended by user")
    
    # Run extraction if was a scam and not already extracted
    if state.classification and state.classification.is_scam:
        if state.extracted_intel is None:
            state = orchestrator._run_extraction(state)
    
    # Build response
    classification = ScamClassification(
        is_scam=state.classification.is_scam if state.classification else True,
        confidence=state.classification.confidence if state.classification else 0.7,
        reason=state.classification.reason if state.classification else "Session ended",
    )
    
    return MessageResponse(
        classification=classification,
        agent_reply=state.agent_reply,
        extracted_intel=state.extracted_intel,
    )
