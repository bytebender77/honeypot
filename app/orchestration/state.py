"""
Conversation State - Typed state object for multi-turn engagement.

This module defines the state that flows through the LangGraph orchestration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# Maximum number of engagement turns before forced stop
MAX_TURNS = 6


@dataclass
class Message:
    """A single message in the conversation."""
    role: Literal["user", "agent"]
    content: str


@dataclass
class ClassificationResult:
    """Result from the scam classifier."""
    is_scam: bool
    confidence: float
    reason: str


@dataclass
class ConversationState:
    """
    State object for multi-turn scammer engagement.
    
    This state flows through the LangGraph nodes and tracks:
    - Session identification
    - Current message being processed
    - Turn count for loop limiting
    - Full conversation history
    - Completion status
    
    Attributes:
        session_id: Unique session identifier.
        user_message: The current user message being processed.
        turns: Number of engagement turns completed (starts at 0).
        conversation: List of all messages in the conversation.
        is_complete: Whether the conversation has ended.
        classification: Result from scam classification (set after classify node).
        agent_reply: Current agent reply (set after engage node).
        stop_reason: Reason for conversation ending (if complete).
        extracted_intel: Extracted scam intelligence (set after extraction).
    """
    session_id: str
    user_message: str
    turns: int = 0
    conversation: list[Message] = field(default_factory=list)
    is_complete: bool = False
    classification: ClassificationResult | None = None
    agent_reply: str | None = None
    stop_reason: str | None = None
    extracted_intel: dict | None = None
    
    def add_user_message(self, content: str) -> None:
        """Add a user message to the conversation."""
        self.conversation.append(Message(role="user", content=content))
    
    def add_agent_message(self, content: str) -> None:
        """Add an agent message to the conversation."""
        self.conversation.append(Message(role="agent", content=content))
    
    def should_stop(self) -> bool:
        """Check if the conversation should stop."""
        if self.is_complete:
            return True
        if self.turns >= MAX_TURNS:
            return True
        return False
    
    def mark_complete(self, reason: str) -> None:
        """Mark the conversation as complete with a reason."""
        self.is_complete = True
        self.stop_reason = reason
    
    def to_dict(self) -> dict:
        """Convert state to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "turns": self.turns,
            "is_complete": self.is_complete,
            "stop_reason": self.stop_reason,
            "classification": {
                "is_scam": self.classification.is_scam,
                "confidence": self.classification.confidence,
                "reason": self.classification.reason,
            } if self.classification else None,
            "agent_reply": self.agent_reply,
            "conversation": [
                {"role": m.role, "content": m.content}
                for m in self.conversation
            ],
            "extracted_intel": self.extracted_intel,
        }
