"""
API Schemas - Locked request/response contracts for the scam detection pipeline.

These schemas define the contract between the API and all agents.
Do NOT modify without version bump.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Request Schemas
# ============================================================================

class MessageRequest(BaseModel):
    """
    Incoming message request from client.
    
    Attributes:
        session_id: Unique session identifier (optional, auto-generated if missing).
        message: The message content to classify (required, max 4000 chars).
    """
    session_id: str = Field(
        default="",
        max_length=128,
        description="Unique session identifier (optional)"
    )
    message: str | dict[str, Any] = Field(
        ...,
        description="Message content to classify"
    )
    
    def __init__(self, **data):
        import uuid
        if not data.get("session_id"):
            data["session_id"] = str(uuid.uuid4())
        super().__init__(**data)
    
    @field_validator("message")
    @classmethod
    def validate_message(cls, v: Any) -> Any:
        """Ensure message is present and not empty."""
        if isinstance(v, str) and not v.strip():
            raise ValueError("message cannot be empty or whitespace")
        return v


# ============================================================================
# Classification Schema (LOCKED - matches ScamClassifierAgent output)
# ============================================================================

class ScamClassification(BaseModel):
    """
    Scam classification result.
    
    This schema is LOCKED and must match ScamClassifierAgent output exactly.
    Do NOT add optional fields or extensions.
    
    Attributes:
        is_scam: Whether the message is classified as a scam.
        confidence: Confidence score between 0.0 and 1.0.
        reason: Brief explanation (max 25 words).
    """
    is_scam: bool = Field(..., description="True if message is a scam")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0"
    )
    reason: str = Field(
        ...,
        max_length=200,
        description="Brief explanation (max 25 words)"
    )


# ============================================================================
# Response Schemas
# ============================================================================

class MessageResponse(BaseModel):
    """
    API response for message classification.
    
    Future-proof structure that will accommodate:
    - Scam classification (always present)
    - Honeypot agent reply (null until engaged)
    - Extracted intelligence (null until extraction runs)
    
    Attributes:
        classification: The scam classification result (always present).
        agent_reply: Honeypot agent's response (null if not engaged).
        extracted_intel: Extracted scammer intelligence (null if not extracted).
    """
    classification: ScamClassification = Field(
        ...,
        description="Scam classification result"
    )
    agent_reply: str | None = Field(
        default=None,
        description="Honeypot agent response (null if not engaged)"
    )
    extracted_intel: dict[str, Any] | None = Field(
        default=None,
        description="Extracted intelligence (null if not extracted)"
    )


# ============================================================================
# Error Schemas
# ============================================================================

class ErrorResponse(BaseModel):
    """
    Standard error response.
    
    Attributes:
        error: Error type or code.
        detail: Human-readable error message.
    """
    error: str = Field(..., description="Error type or code")
    detail: str = Field(..., description="Human-readable error message")
