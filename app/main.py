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
from pydantic import BaseModel, Field

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
# Request/Response Schemas (GUVI Format)
# ============================================================================

class MessagePayload(BaseModel):
    sender: str = Field(default="scammer")
    text: str
    timestamp: str | None = None


class MetadataPayload(BaseModel):
    channel: str = Field(default="SMS")
    language: str = Field(default="English")
    locale: str = Field(default="IN")


class ConversationMessage(BaseModel):
    sender: str
    text: str
    timestamp: str | None = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessagePayload
    conversationHistory: list[ConversationMessage] = Field(default_factory=list)
    metadata: MetadataPayload = Field(default_factory=MetadataPayload)


class ExtractedIntelligence(BaseModel):
    bankAccounts: list[str] = Field(default_factory=list)
    upiIds: list[str] = Field(default_factory=list)
    phishingLinks: list[str] = Field(default_factory=list)
    phoneNumbers: list[str] = Field(default_factory=list)
    suspiciousKeywords: list[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = 0
    totalMessagesExchanged: int = 0


class HoneypotResponse(BaseModel):
    status: str = "success"
    scamDetected: bool = False
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    agentResponse: str | None = None
    agentNotes: str = ""


# ============================================================================
# Session Tracking
# ============================================================================

class SessionData:
    def __init__(self):
        self.start_time: float = time.time()
        self.messages_exchanged: int = 0
        self.scam_detected: bool = False
        self.intelligence: ExtractedIntelligence = ExtractedIntelligence()
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
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords,
        },
        "agentNotes": "; ".join(session.agent_notes) if session.agent_notes else "Engagement completed",
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass  # Best effort, don't fail the main response


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
# Main Endpoint
# ============================================================================

@app.post("/", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> HoneypotResponse:
    """
    Main honeypot endpoint - GUVI format.
    
    Accepts scam messages, engages scammers, extracts intelligence.
    """
    verify_api_key(x_api_key)
    
    if not settings.has_api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")
    
    session_id = request.sessionId
    message_text = request.message.text
    session = get_session(session_id)
    
    try:
        orchestrator = get_orchestrator()
        extractor = get_extractor()
        
        # Process message through orchestration
        state = orchestrator.process_message(session_id=session_id, message=message_text)
        
        # Update session tracking
        session.messages_exchanged += 2  # scammer message + agent response
        
        # Check if scam detected
        if state.classification and state.classification.is_scam:
            session.scam_detected = True
            session.agent_notes.append(state.classification.reason)
        
        # Extract intelligence from conversation
        conversation_for_extraction = [
            {"role": msg.sender, "content": msg.text}
            for msg in request.conversationHistory
        ]
        conversation_for_extraction.append({"role": "scammer", "content": message_text})
        if state.agent_reply:
            conversation_for_extraction.append({"role": "user", "content": state.agent_reply})
        
        intel = extractor.extract(conversation_for_extraction)
        
        # Update session intelligence (merge)
        session.intelligence.upiIds = list(set(session.intelligence.upiIds + intel.upi_ids))
        session.intelligence.phishingLinks = list(set(session.intelligence.phishingLinks + intel.phishing_links))
        session.intelligence.bankAccounts = list(set(session.intelligence.bankAccounts + intel.bank_accounts))
        
        # Add any IFSC/other indicators
        for indicator in intel.other_indicators:
            if indicator not in session.intelligence.suspiciousKeywords:
                session.intelligence.suspiciousKeywords.append(indicator)
        
        # Calculate engagement duration
        duration = int(time.time() - session.start_time)
        
        # Build response
        response = HoneypotResponse(
            status="success",
            scamDetected=session.scam_detected,
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=duration,
                totalMessagesExchanged=session.messages_exchanged,
            ),
            extractedIntelligence=session.intelligence,
            agentResponse=state.agent_reply,
            agentNotes="; ".join(session.agent_notes) if session.agent_notes else "",
        )
        
        # Send callback to GUVI if conversation is complete or has extracted intel
        if state.is_complete or (session.scam_detected and session.messages_exchanged >= 4):
            await send_guvi_callback(session_id, session)
        
        return response
        
    except Exception as e:
        return HoneypotResponse(
            status="error",
            scamDetected=False,
            agentNotes=f"Processing error: {str(e)}",
        )


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/config")
async def get_config() -> dict:
    """Get non-sensitive configuration."""
    return settings.to_dict()
