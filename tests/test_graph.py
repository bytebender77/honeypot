"""
Tests for LangGraph orchestration.

Tests verify:
- Non-scam messages end immediately
- Scam messages trigger engagement
- Turn limit enforced
- Conversation state updates correctly
- No infinite loops possible
"""

from __future__ import annotations

import os

import pytest

from app.orchestration.state import (
    ConversationState,
    ClassificationResult,
    Message,
    MAX_TURNS,
)
from app.orchestration.graph import (
    classify_node,
    engage_node,
    check_exit_node,
    route_after_classify,
    EngagementOrchestrator,
)


# Skip integration tests if no API key is available
needs_api_key = pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY"),
    reason="GROQ_API_KEY environment variable not set"
)


class TestConversationState:
    """Tests for ConversationState dataclass."""
    
    def test_initial_state(self) -> None:
        """Test default state values."""
        state = ConversationState(
            session_id="test-123",
            user_message="Hello"
        )
        assert state.session_id == "test-123"
        assert state.user_message == "Hello"
        assert state.turns == 0
        assert state.conversation == []
        assert state.is_complete is False
        assert state.classification is None
        assert state.agent_reply is None
    
    def test_add_user_message(self) -> None:
        """Test adding user message to conversation."""
        state = ConversationState(session_id="test", user_message="")
        state.add_user_message("Hello scammer")
        
        assert len(state.conversation) == 1
        assert state.conversation[0].role == "user"
        assert state.conversation[0].content == "Hello scammer"
    
    def test_add_agent_message(self) -> None:
        """Test adding agent message to conversation."""
        state = ConversationState(session_id="test", user_message="")
        state.add_agent_message("I don't understand")
        
        assert len(state.conversation) == 1
        assert state.conversation[0].role == "agent"
        assert state.conversation[0].content == "I don't understand"
    
    def test_should_stop_when_complete(self) -> None:
        """Test should_stop returns True when is_complete is True."""
        state = ConversationState(session_id="test", user_message="")
        state.is_complete = True
        assert state.should_stop() is True
    
    def test_should_stop_at_max_turns(self) -> None:
        """Test should_stop returns True at max turns."""
        state = ConversationState(session_id="test", user_message="")
        state.turns = MAX_TURNS
        assert state.should_stop() is True
    
    def test_should_not_stop_normally(self) -> None:
        """Test should_stop returns False during normal operation."""
        state = ConversationState(session_id="test", user_message="Test")
        state.turns = 2
        assert state.should_stop() is False
    
    def test_mark_complete(self) -> None:
        """Test marking conversation as complete."""
        state = ConversationState(session_id="test", user_message="")
        state.mark_complete("Test reason")
        
        assert state.is_complete is True
        assert state.stop_reason == "Test reason"
    
    def test_to_dict(self) -> None:
        """Test state serialization."""
        state = ConversationState(session_id="test", user_message="Hello")
        state.classification = ClassificationResult(
            is_scam=True, confidence=0.9, reason="Scam detected"
        )
        state.add_user_message("Hello")
        state.add_agent_message("Hi there")
        
        data = state.to_dict()
        
        assert data["session_id"] == "test"
        assert data["classification"]["is_scam"] is True
        assert len(data["conversation"]) == 2


class TestRouting:
    """Tests for routing logic."""
    
    def test_route_to_engage_for_scam(self) -> None:
        """Test routing to engage node for scam messages."""
        state = ConversationState(session_id="test", user_message="Scam")
        state.classification = ClassificationResult(
            is_scam=True, confidence=0.9, reason="Scam"
        )
        
        assert route_after_classify(state) == "engage"
    
    def test_route_to_end_for_benign(self) -> None:
        """Test routing to end for benign messages."""
        state = ConversationState(session_id="test", user_message="Hello")
        state.classification = ClassificationResult(
            is_scam=False, confidence=0.8, reason="Benign"
        )
        
        assert route_after_classify(state) == "end"
    
    def test_route_to_end_when_complete(self) -> None:
        """Test routing to end when already complete."""
        state = ConversationState(session_id="test", user_message="Test")
        state.is_complete = True
        
        assert route_after_classify(state) == "end"


class TestCheckExitNode:
    """Tests for exit checking logic."""
    
    def test_marks_complete_at_max_turns(self) -> None:
        """Test that max turns triggers completion."""
        state = ConversationState(session_id="test", user_message="Test")
        state.turns = MAX_TURNS
        
        result = check_exit_node(state)
        
        assert result.is_complete is True
        assert "Maximum turns" in result.stop_reason
    
    def test_marks_complete_on_empty_input(self) -> None:
        """Test that empty input triggers completion."""
        state = ConversationState(session_id="test", user_message="")
        
        result = check_exit_node(state)
        
        assert result.is_complete is True
        assert "Empty" in result.stop_reason
    
    def test_continues_normally(self) -> None:
        """Test that normal state continues."""
        state = ConversationState(session_id="test", user_message="Hello")
        state.turns = 2
        
        result = check_exit_node(state)
        
        assert result.is_complete is False


class TestTurnLimits:
    """Tests for turn limit enforcement."""
    
    def test_max_turns_constant(self) -> None:
        """Test that MAX_TURNS is reasonable."""
        assert MAX_TURNS == 6
        assert MAX_TURNS > 0
        assert MAX_TURNS <= 20  # Sanity check
    
    def test_turns_increment(self) -> None:
        """Test that turns are tracked properly."""
        state = ConversationState(session_id="test", user_message="Test")
        
        assert state.turns == 0
        state.turns += 1
        assert state.turns == 1
    
    def test_no_engage_after_complete(self) -> None:
        """Test that engage_node does nothing when complete."""
        state = ConversationState(session_id="test", user_message="Test")
        state.is_complete = True
        initial_turns = state.turns
        
        result = engage_node(state)
        
        assert result.turns == initial_turns
        assert result.agent_reply is None


@needs_api_key
class TestClassifyNodeIntegration:
    """Integration tests for classify node (requires API key)."""
    
    def test_classify_scam_message(self) -> None:
        """Test classification of obvious scam."""
        state = ConversationState(
            session_id="test",
            user_message="You won Rs 50 lakh! Send Rs 5000 to claim prize!"
        )
        
        result = classify_node(state)
        
        assert result.classification is not None
        assert result.classification.is_scam is True
        assert result.classification.confidence >= 0.7
    
    def test_classify_benign_message(self) -> None:
        """Test classification of benign message."""
        state = ConversationState(
            session_id="test",
            user_message="Hey, are we meeting for coffee tomorrow at 4pm?"
        )
        
        result = classify_node(state)
        
        assert result.classification is not None
        assert result.classification.is_scam is False
        assert result.is_complete is True
        assert "benign" in result.stop_reason.lower()


@needs_api_key
class TestEngageNodeIntegration:
    """Integration tests for engage node (requires API key)."""
    
    def test_engage_produces_reply(self) -> None:
        """Test that engage node produces a reply."""
        state = ConversationState(
            session_id="test",
            user_message="Send Rs 5000 to win Rs 50 lakh!"
        )
        
        result = engage_node(state)
        
        assert result.agent_reply is not None
        assert len(result.agent_reply) > 0
        assert result.turns == 1
    
    def test_engage_adds_to_conversation(self) -> None:
        """Test that engage adds message to conversation."""
        state = ConversationState(
            session_id="test",
            user_message="Click here to verify your account!"
        )
        
        result = engage_node(state)
        
        assert len(result.conversation) == 1
        assert result.conversation[0].role == "agent"


@needs_api_key
class TestOrchestratorIntegration:
    """Integration tests for full orchestrator (requires API key)."""
    
    def test_benign_message_ends_immediately(self) -> None:
        """Test that benign messages end without engagement."""
        orchestrator = EngagementOrchestrator()
        
        result = orchestrator.process_message(
            "test-session",
            "Hey, want to grab lunch tomorrow?"
        )
        
        assert result.classification is not None
        assert result.classification.is_scam is False
        assert result.is_complete is True
        assert result.agent_reply is None
    
    def test_scam_message_triggers_engagement(self) -> None:
        """Test that scam messages get engagement response."""
        orchestrator = EngagementOrchestrator()
        
        result = orchestrator.process_message(
            "test-session",
            "URGENT: Your bank account will be blocked! Send OTP now!"
        )
        
        assert result.classification is not None
        assert result.classification.is_scam is True
        assert result.agent_reply is not None
        assert result.turns == 1
    
    def test_session_state_persists(self) -> None:
        """Test that session state persists across calls."""
        orchestrator = EngagementOrchestrator()
        
        # First message
        result1 = orchestrator.process_message(
            "persist-test",
            "You won a lottery! Send Rs 1000 to claim."
        )
        
        # Second message in same session
        result2 = orchestrator.process_message(
            "persist-test",
            "Why do I need to pay to win?"
        )
        
        assert result2.turns == 2
        assert len(result2.conversation) >= 2
    
    def test_max_turns_enforced(self) -> None:
        """Test that max turns limit is enforced."""
        orchestrator = EngagementOrchestrator()
        session_id = "turn-limit-test"
        
        # Simulate max turns
        for i in range(MAX_TURNS + 2):
            result = orchestrator.process_message(
                session_id,
                f"Scam message {i}: Send money now!"
            )
            if result.is_complete:
                break
        
        assert result.is_complete is True
        assert result.turns <= MAX_TURNS
    
    def test_end_session_works(self) -> None:
        """Test manual session ending."""
        orchestrator = EngagementOrchestrator()
        
        orchestrator.process_message("end-test", "Scam message here!")
        orchestrator.end_session("end-test", "Testing manual end")
        
        session = orchestrator.get_session("end-test")
        assert session is not None
        assert session.is_complete is True
        assert session.stop_reason == "Testing manual end"
