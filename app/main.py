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
from typing import Any, Optional
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException
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
# Request Schemas (for Swagger UI)
# ============================================================================

class MessagePayload(BaseModel):
    """Message content from scammer."""
    sender: str = Field(default="scammer", description="Message sender (scammer or user)")
    text: str = Field(..., description="Message text content")
    timestamp: Optional[str] = Field(default=None, description="ISO-8601 timestamp")


class MetadataPayload(BaseModel):
    """Optional metadata about the message."""
    channel: str = Field(default="SMS", description="Communication channel")
    language: str = Field(default="English", description="Message language")
    locale: str = Field(default="IN", description="Region/locale")


class ConversationMessage(BaseModel):
    """Previous message in conversation history."""
    sender: str = Field(..., description="Message sender")
    text: str = Field(..., description="Message text")
    timestamp: Optional[str] = Field(default=None, description="Timestamp")


class HoneypotRequest(BaseModel):
    """
    Request body for honeypot endpoint.
    
    Example:
    {
        "sessionId": "test-session",
        "message": {"sender": "scammer", "text": "Send Rs 5000 to UPI: fraud@okaxis"},
        "conversationHistory": []
    }
    """
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessagePayload = Field(..., description="Current message to process")
    conversationHistory: list[ConversationMessage] = Field(default_factory=list, description="Previous messages")
    metadata: Optional[MetadataPayload] = Field(default=None, description="Optional metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "demo-session-123",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Send Rs 5000 to UPI: fraud@okaxis to verify your account"
                },
                "conversationHistory": []
            }
        }


# ============================================================================
# Response Schemas
# ============================================================================

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = 0
    totalMessagesExchanged: int = 0


class ExtractedIntelligence(BaseModel):
    bankAccounts: list[str] = Field(default_factory=list)
    upiIds: list[str] = Field(default_factory=list)
    phishingLinks: list[str] = Field(default_factory=list)
    phoneNumbers: list[str] = Field(default_factory=list)
    suspiciousKeywords: list[str] = Field(default_factory=list)


class HoneypotResponse(BaseModel):
    status: str = "success"
    scamDetected: bool = False
    scamType: Optional[str] = None
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    agentResponse: Optional[str] = None
    agentNotes: str = ""


# ============================================================================
# Session Tracking
# ============================================================================

class SessionData:
    def __init__(self):
        self.start_time: float = time.time()
        self.messages_exchanged: int = 0
        self.scam_detected: bool = False
        self.scam_type: str | None = None
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
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing x-api-key header")
    if x_api_key != settings.honeypot_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ============================================================================
# Main Endpoint with Proper Schema
# ============================================================================

@app.post("/", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    x_api_key: str | None = Header(None, alias="x-api-key"),
) -> HoneypotResponse:
    """
    Main honeypot endpoint - processes scam messages and engages scammers.
    
    - Detects scam intent in messages
    - Generates believable victim persona responses
    - Extracts intelligence (UPI IDs, bank accounts, phishing links)
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
        
        state = orchestrator.process_message(session_id=session_id, message=message_text)
        
        session.messages_exchanged += 2
        
        if state.classification and state.classification.is_scam:
            session.scam_detected = True
            session.scam_type = state.classification.scam_type
            session.agent_notes.append(state.classification.reason)
        
        # Build conversation for extraction
        conversation_for_extraction = [
            {"role": msg.sender, "content": msg.text}
            for msg in request.conversationHistory
        ]
        conversation_for_extraction.append({"role": "scammer", "content": message_text})
        if state.agent_reply:
            conversation_for_extraction.append({"role": "user", "content": state.agent_reply})
        
        intel = extractor.extract(conversation_for_extraction)
        
        session.upi_ids = list(set(session.upi_ids + intel.upi_ids))
        session.phishing_links = list(set(session.phishing_links + intel.phishing_links))
        session.bank_accounts = list(set(session.bank_accounts + intel.bank_accounts))
        for indicator in intel.other_indicators:
            if indicator not in session.suspicious_keywords:
                session.suspicious_keywords.append(indicator)
        
        duration = int(time.time() - session.start_time)
        
        response = HoneypotResponse(
            status="success",
            scamDetected=session.scam_detected,
            scamType=session.scam_type,
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=duration,
                totalMessagesExchanged=session.messages_exchanged,
            ),
            extractedIntelligence=ExtractedIntelligence(
                bankAccounts=session.bank_accounts,
                upiIds=session.upi_ids,
                phishingLinks=session.phishing_links,
                phoneNumbers=session.phone_numbers,
                suspiciousKeywords=session.suspicious_keywords,
            ),
            agentResponse=state.agent_reply,
            agentNotes="; ".join(session.agent_notes) if session.agent_notes else "",
        )
        
        if state.is_complete or (session.scam_detected and session.messages_exchanged >= 4):
            await send_guvi_callback(session_id, session)
        
        return response
        
    except Exception as e:
        return HoneypotResponse(
            status="error",
            scamDetected=False,
            agentNotes=f"Error: {str(e)}",
        )


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/")
async def root_get() -> dict[str, str]:
    return {"status": "healthy", "service": "honeypot"}
