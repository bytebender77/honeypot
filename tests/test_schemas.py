"""
Tests for API schemas and routes.

Tests verify:
- Request validation (valid/invalid inputs)
- Response schema compliance
- Classification propagation
"""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from app.api.schemas import (
    MessageRequest,
    MessageResponse,
    ScamClassification,
    ErrorResponse,
)


class TestMessageRequestSchema:
    """Tests for MessageRequest validation."""
    
    def test_valid_request(self) -> None:
        """Test that valid request is accepted."""
        request = MessageRequest(
            session_id="test-session-123",
            message="Hello, this is a test message"
        )
        assert request.session_id == "test-session-123"
        assert request.message == "Hello, this is a test message"
    
    def test_session_id_required(self) -> None:
        """Test that session_id is required."""
        with pytest.raises(ValidationError) as exc_info:
            MessageRequest(message="test")
        assert "session_id" in str(exc_info.value)
    
    def test_message_required(self) -> None:
        """Test that message is required."""
        with pytest.raises(ValidationError) as exc_info:
            MessageRequest(session_id="test-123")
        assert "message" in str(exc_info.value)
    
    def test_empty_session_id_rejected(self) -> None:
        """Test that empty session_id is rejected."""
        with pytest.raises(ValidationError):
            MessageRequest(session_id="", message="test")
    
    def test_whitespace_session_id_rejected(self) -> None:
        """Test that whitespace-only session_id is rejected."""
        with pytest.raises(ValidationError):
            MessageRequest(session_id="   ", message="test")
    
    def test_empty_message_rejected(self) -> None:
        """Test that empty message is rejected."""
        with pytest.raises(ValidationError):
            MessageRequest(session_id="test", message="")
    
    def test_whitespace_message_rejected(self) -> None:
        """Test that whitespace-only message is rejected."""
        with pytest.raises(ValidationError):
            MessageRequest(session_id="test", message="   ")
    
    def test_oversized_message_rejected(self) -> None:
        """Test that message over 4000 chars is rejected."""
        long_message = "x" * 4001
        with pytest.raises(ValidationError) as exc_info:
            MessageRequest(session_id="test", message=long_message)
        assert "message" in str(exc_info.value).lower()
    
    def test_max_length_message_accepted(self) -> None:
        """Test that message at exactly 4000 chars is accepted."""
        max_message = "x" * 4000
        request = MessageRequest(session_id="test", message=max_message)
        assert len(request.message) == 4000


class TestScamClassificationSchema:
    """Tests for ScamClassification schema (LOCKED)."""
    
    def test_valid_scam_classification(self) -> None:
        """Test valid scam classification."""
        classification = ScamClassification(
            is_scam=True,
            confidence=0.95,
            reason="Detected urgency and UPI request"
        )
        assert classification.is_scam is True
        assert classification.confidence == 0.95
        assert classification.reason == "Detected urgency and UPI request"
    
    def test_valid_benign_classification(self) -> None:
        """Test valid benign classification."""
        classification = ScamClassification(
            is_scam=False,
            confidence=0.88,
            reason="Normal conversation message"
        )
        assert classification.is_scam is False
    
    def test_confidence_bounds_enforced(self) -> None:
        """Test that confidence must be between 0.0 and 1.0."""
        with pytest.raises(ValidationError):
            ScamClassification(is_scam=True, confidence=1.5, reason="test")
        
        with pytest.raises(ValidationError):
            ScamClassification(is_scam=True, confidence=-0.1, reason="test")
    
    def test_all_fields_required(self) -> None:
        """Test that all fields are required (no optional fields)."""
        with pytest.raises(ValidationError):
            ScamClassification(is_scam=True, confidence=0.5)
        
        with pytest.raises(ValidationError):
            ScamClassification(is_scam=True, reason="test")
        
        with pytest.raises(ValidationError):
            ScamClassification(confidence=0.5, reason="test")


class TestMessageResponseSchema:
    """Tests for MessageResponse schema."""
    
    def test_minimal_response(self) -> None:
        """Test response with only classification (agent_reply and intel null)."""
        response = MessageResponse(
            classification=ScamClassification(
                is_scam=True,
                confidence=0.9,
                reason="Scam detected"
            )
        )
        assert response.classification.is_scam is True
        assert response.agent_reply is None
        assert response.extracted_intel is None
    
    def test_full_response(self) -> None:
        """Test response with all fields populated."""
        response = MessageResponse(
            classification=ScamClassification(
                is_scam=True,
                confidence=0.9,
                reason="Scam detected"
            ),
            agent_reply="Hello, please tell me more about this offer.",
            extracted_intel={"phone": "1234567890", "upi_id": "scammer@upi"}
        )
        assert response.agent_reply is not None
        assert response.extracted_intel is not None
        assert response.extracted_intel["phone"] == "1234567890"
    
    def test_classification_required(self) -> None:
        """Test that classification is always required."""
        with pytest.raises(ValidationError):
            MessageResponse(agent_reply="test")
    
    def test_response_serialization(self) -> None:
        """Test that response can be serialized to dict/JSON."""
        response = MessageResponse(
            classification=ScamClassification(
                is_scam=True,
                confidence=0.9,
                reason="Test"
            )
        )
        data = response.model_dump()
        assert data["classification"]["is_scam"] is True
        assert data["agent_reply"] is None
        assert data["extracted_intel"] is None


class TestErrorResponseSchema:
    """Tests for ErrorResponse schema."""
    
    def test_error_response(self) -> None:
        """Test error response structure."""
        error = ErrorResponse(
            error="validation_error",
            detail="Message exceeds maximum length"
        )
        assert error.error == "validation_error"
        assert error.detail == "Message exceeds maximum length"
