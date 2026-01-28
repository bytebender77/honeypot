"""
FastAPI application entrypoint - GUVI Honeypot Hackathon Format.
"""

from __future__ import annotations

# Load .env file before other imports
from dotenv import load_dotenv
load_dotenv()

import uuid
import time
import httpx
from typing import Any
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, Request

from app.core.config import settings
from app.orchestration.graph import EngagementOrchestrator
from app.agents.intel_extractor import ScamIntelExtractor


app = FastAPI(
    title="Honeypot Scam Detection API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0",
    debug=settings.debug,
)


# ============================================================================
# Session Tracking
# ============================================================================

class SessionData:
    def __init__(self):
        self.start_time: float = time.time()
        self.messages_exchanged: int = 0
        self.scam_detected: bool = False
        self.upi_ids: list[str] = []
        self.phishing_links: list[str] = []
        self.bank_accounts: list[str] = []
        self.phone_numbers: list[str] = []
        self.suspicious_keywords: list[str] = []
        self.agent_notes: list[str] = []


_sessions: dict[str, SessionData] = {}
_orchestrator: EngagementOrchestrator | None = None
_extractor: ScamIntelExtractor | None = None


def get_orchestrator() -> EngagementOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = EngagementOrchestrator()
    return _orchestrator


def get_extractor() -> ScamIntelExtractor:
    global _extractor
    if _extractor is None:
        _extractor = ScamIntelExtractor()
    return _extractor


def get_session(session_id: str) -> SessionData:
    if session_id not in _sessions:
        _sessions[session_id] = SessionData()
    return _sessions[session_id]


# ============================================================================
# GUVI Callback
# ============================================================================

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


async def send_guvi_callback(session_id: str, session: SessionData):
    """Send final results to GUVI endpoint."""
    payload = {
        "sessionId": session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.messages_exchanged,
        "extractedIntelligence": {
            "bankAccounts": session.bank_accounts,
            "upiIds": session.upi_ids,
            "phishingLinks": session.phishing_links,
            "phoneNumbers": session.phone_numbers,
            "suspiciousKeywords": session.suspicious_keywords,
        },
        "agentNotes": "; ".join(session.agent_notes) if session.agent_notes else "Engagement completed",
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass


# ============================================================================
# API Key Verification
# ============================================================================

def verify_api_key(x_api_key: str | None) -> None:
    """Verify the x-api-key header."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing x-api-key header")
    if x_api_key != settings.honeypot_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ============================================================================
# Flexible Main Endpoint - Accepts ANY format
# ============================================================================

@app.post("/")
async def honeypot_endpoint(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> dict[str, Any]:
    """
    Main honeypot endpoint - accepts any JSON format.
    """
    verify_api_key(x_api_key)
    
    if not settings.has_api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")
    
    # Parse raw JSON body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Extract session ID from various possible fields
    session_id = (
        body.get("sessionId") or 
        body.get("session_id") or 
        body.get("id") or 
        str(uuid.uuid4())
    )
    
    # Extract message from various possible formats
    message_text = None
    
    # Format 1: message.text (GUVI format)
    if isinstance(body.get("message"), dict):
        message_text = body["message"].get("text") or body["message"].get("content")
    
    # Format 2: message as string
    elif isinstance(body.get("message"), str):
        message_text = body["message"]
    
    # Format 3: text field directly
    elif body.get("text"):
        message_text = body["text"]
    
    # Format 4: content field
    elif body.get("content"):
        message_text = body["content"]
    
    # Format 5: input field
    elif body.get("input"):
        message_text = body["input"]
    
    if not message_text:
        # Return a simple success for basic connectivity test
        return {
            "status": "success",
            "scamDetected": False,
            "engagementMetrics": {
                "engagementDurationSeconds": 0,
                "totalMessagesExchanged": 0,
            },
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
            },
            "agentResponse": None,
            "agentNotes": "No message content provided",
        }
    
    session = get_session(session_id)
    
    try:
        orchestrator = get_orchestrator()
        extractor = get_extractor()
        
        # Process message through orchestration
        state = orchestrator.process_message(session_id=session_id, message=message_text)
        
        # Update session tracking
        session.messages_exchanged += 2
        
        # Check if scam detected
        if state.classification and state.classification.is_scam:
            session.scam_detected = True
            session.agent_notes.append(state.classification.reason)
        
        # Build conversation for extraction
        conversation_history = body.get("conversationHistory", [])
        conversation_for_extraction = []
        
        for msg in conversation_history:
            if isinstance(msg, dict):
                role = msg.get("sender", msg.get("role", "user"))
                text = msg.get("text", msg.get("content", ""))
                conversation_for_extraction.append({"role": role, "content": text})
        
        conversation_for_extraction.append({"role": "scammer", "content": message_text})
        if state.agent_reply:
            conversation_for_extraction.append({"role": "user", "content": state.agent_reply})
        
        # Extract intelligence
        intel = extractor.extract(conversation_for_extraction)
        
        # Update session intelligence
        session.upi_ids = list(set(session.upi_ids + intel.upi_ids))
        session.phishing_links = list(set(session.phishing_links + intel.phishing_links))
        session.bank_accounts = list(set(session.bank_accounts + intel.bank_accounts))
        for indicator in intel.other_indicators:
            if indicator not in session.suspicious_keywords:
                session.suspicious_keywords.append(indicator)
        
        duration = int(time.time() - session.start_time)
        
        response = {
            "status": "success",
            "scamDetected": session.scam_detected,
            "engagementMetrics": {
                "engagementDurationSeconds": duration,
                "totalMessagesExchanged": session.messages_exchanged,
            },
            "extractedIntelligence": {
                "bankAccounts": session.bank_accounts,
                "upiIds": session.upi_ids,
                "phishingLinks": session.phishing_links,
                "phoneNumbers": session.phone_numbers,
                "suspiciousKeywords": session.suspicious_keywords,
            },
            "agentResponse": state.agent_reply,
            "agentNotes": "; ".join(session.agent_notes) if session.agent_notes else "",
        }
        
        # Send callback if complete
        if state.is_complete or (session.scam_detected and session.messages_exchanged >= 4):
            await send_guvi_callback(session_id, session)
        
        return response
        
    except Exception as e:
        return {
            "status": "error",
            "scamDetected": False,
            "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
            "extractedIntelligence": {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []},
            "agentResponse": None,
            "agentNotes": f"Error: {str(e)}",
        }


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/")
async def root_get() -> dict[str, str]:
    """Root GET endpoint for health checks."""
    return {"status": "healthy", "service": "honeypot"}
