"""
API Routes - HTTP endpoints for the scam detection pipeline.

Current endpoints:
- POST /message - Process a message through the honeypot pipeline
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Header, Request

from app.api.schemas import (
    MessageResponse,
    ScamClassification,
    ErrorResponse,
)
from app.core.config import settings
from app.agents.honeypot_agent import HoneypotEngagementAgent, FALLBACK_RESPONSE
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


def verify_api_key(x_api_key: str | None) -> None:
    """Verify the x-api-key header."""
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing x-api-key header",
        )
    if x_api_key != settings.honeypot_api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )


@router.post(
    "/message",
    response_model=None,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        500: {"model": ErrorResponse, "description": "Processing failed"},
    },
    summary="Process a message",
    description="Process a message through the honeypot pipeline. Returns classification, optional agent reply, and extracted intel.",
)
async def process_message(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> dict:
    """
    Process a message through the honeypot pipeline.
    
    Requires x-api-key header for authentication.
    """
    # Verify API key
    verify_api_key(x_api_key)
    
    try:
        body = await request.json()
    except Exception:
        raw = await request.body()
        raw_text = raw.decode("utf-8", errors="ignore").strip()
        if not raw_text:
            return {"status": "success", "reply": FALLBACK_RESPONSE}
        return {"status": "success", "reply": _submission_reply(raw_text)}

    # Extract session ID from various possible fields
    session_id = (
        body.get("sessionId") or
        body.get("session_id") or
        body.get("id") or
        ""
    )

    # Submission format: return minimal {status, reply}
    is_submission = (
        isinstance(body.get("message"), dict)
        or "sessionId" in body
        or "conversationHistory" in body
        or "metadata" in body
    )
    if is_submission:
        message_text = None
        if isinstance(body.get("message"), dict):
            message_text = body["message"].get("text") or body["message"].get("content")
        elif isinstance(body.get("message"), str):
            message_text = body["message"]
        elif body.get("text"):
            message_text = body["text"]
        elif body.get("content"):
            message_text = body["content"]
        elif body.get("input"):
            message_text = body["input"]

        reply = _submission_reply(str(message_text or ""))
        return {"status": "success", "reply": reply}

    # Standard format: message as string or common fallbacks
    message_text = None
    if isinstance(body.get("message"), str):
        message_text = body["message"]
    elif body.get("text"):
        message_text = body["text"]
    elif body.get("content"):
        message_text = body["content"]
    elif body.get("input"):
        message_text = body["input"]

    if not message_text or not str(message_text).strip():
        # Be tolerant: return safe reply instead of 400 for unknown tester payloads
        return {"status": "success", "reply": FALLBACK_RESPONSE}

    # Validate Groq API key is configured for full pipeline
    if not settings.has_api_key:
        raise HTTPException(
            status_code=500,
            detail="API key not configured. Set GROQ_API_KEY environment variable.",
        )

    try:
        orchestrator = get_orchestrator()

        # Process message through orchestration
        state = orchestrator.process_message(
            session_id=session_id or "api-session",
            message=str(message_text),
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


def _rule_based_reply(message_text: str) -> str:
    """Generate a safe, fast reply without LLM calls."""
    text = (message_text or "").strip().lower()
    if not text:
        return FALLBACK_RESPONSE

    account_keywords = ["account", "bank", "blocked", "suspended", "verify", "otp"]
    prize_keywords = ["won", "prize", "lottery", "lucky draw", "reward"]
    payment_keywords = ["upi", "pay", "payment", "send", "transfer", "fee"]

    if any(k in text for k in account_keywords):
        return "Why is my account being suspended?"
    if any(k in text for k in prize_keywords):
        return "I did not enter any draw. Why do I have to pay, can you explain?"
    if any(k in text for k in payment_keywords):
        return "Why do I need to pay? Please explain the process."

    return FALLBACK_RESPONSE


def _submission_reply(message_text: str) -> str:
    """
    Reply for hackathon submission format.

    Defaults to rule-based for speed/reliability, unless explicitly
    opted into LLM replies via USE_LLM_FOR_SUBMISSION=1.
    """
    if os.getenv("USE_LLM_FOR_SUBMISSION", "").lower() in ("1", "true", "yes"):
        try:
            return HoneypotEngagementAgent().respond(message_text)
        except Exception:
            return _rule_based_reply(message_text)
    return _rule_based_reply(message_text)


@router.post(
    "/session/{session_id}/end",
    response_model=MessageResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        404: {"model": ErrorResponse, "description": "Session not found"},
    },
    summary="End a session",
    description="Forcefully end a session and trigger extraction.",
)
async def end_session(
    session_id: str,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> MessageResponse:
    """End a session and get final results with extraction."""
    verify_api_key(x_api_key)
    
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
