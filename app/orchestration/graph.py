"""
LangGraph Orchestration - Multi-turn scammer engagement flow.

This module implements a state machine for safely managing multi-turn
engagement with scammers, with hard turn limits and explicit stop conditions.
"""

from __future__ import annotations

from typing import TypedDict, Literal, Any

from langgraph.graph import StateGraph, END

from app.agents.scam_classifier import ScamClassifierAgent
from app.agents.honeypot_agent import HoneypotEngagementAgent
from app.agents.intel_extractor import ScamIntelExtractor
from app.orchestration.state import (
    ConversationState,
    ClassificationResult,
    Message,
    MAX_TURNS,
)


# ============================================================================
# TypedDict State for LangGraph (works with dict-based state)
# ============================================================================

class GraphState(TypedDict, total=False):
    """State dict for LangGraph nodes."""
    session_id: str
    user_message: str
    turns: int
    conversation: list[dict]
    is_complete: bool
    classification: dict | None
    agent_reply: str | None
    stop_reason: str | None
    extracted_intel: dict | None


# ============================================================================
# Node Functions
# ============================================================================

def classify_node(state: GraphState) -> GraphState:
    """
    Classify the incoming message as scam or benign.
    
    If not a scam, marks conversation as complete immediately.
    """
    try:
        classifier = ScamClassifierAgent()
        result = classifier.classify(state["user_message"])
        
        state["classification"] = {
            "is_scam": result.is_scam,
            "confidence": result.confidence,
            "reason": result.reason,
        }
        
        # Add user message to conversation history
        conversation = state.get("conversation", [])
        conversation.append({"role": "user", "content": state["user_message"]})
        state["conversation"] = conversation
        
        # If not a scam, end immediately
        if not result.is_scam:
            state["is_complete"] = True
            state["stop_reason"] = "Message classified as benign"
        
    except Exception:
        # On any error, fail safe - treat as scam but note the error
        state["classification"] = {
            "is_scam": True,
            "confidence": 0.7,
            "reason": "Classification error - defaulting to scam",
        }
        conversation = state.get("conversation", [])
        conversation.append({"role": "user", "content": state["user_message"]})
        state["conversation"] = conversation
    
    return state


def engage_node(state: GraphState) -> GraphState:
    """
    Generate a honeypot response to the scam message.
    
    Appends the agent reply to the conversation and increments turn count.
    """
    # Safety check: don't engage if already complete
    if state.get("is_complete", False):
        return state
    
    try:
        honeypot = HoneypotEngagementAgent()
        reply = honeypot.respond(state["user_message"])
        
        state["agent_reply"] = reply
        conversation = state.get("conversation", [])
        conversation.append({"role": "agent", "content": reply})
        state["conversation"] = conversation
        state["turns"] = state.get("turns", 0) + 1
        
    except Exception:
        # On error, provide a safe fallback response
        fallback = "Sorry, I didn't understand. Can you explain again?"
        state["agent_reply"] = fallback
        conversation = state.get("conversation", [])
        conversation.append({"role": "agent", "content": fallback})
        state["conversation"] = conversation
        state["turns"] = state.get("turns", 0) + 1
    
    return state


def check_exit_node(state: GraphState) -> GraphState:
    """
    Check if the conversation should end.
    
    Stop conditions:
    - Turn limit reached
    - Empty user input
    - Already marked complete
    """
    turns = state.get("turns", 0)
    
    # Check turn limit
    if turns >= MAX_TURNS:
        state["is_complete"] = True
        state["stop_reason"] = f"Maximum turns ({MAX_TURNS}) reached"
        return state
    
    # Check for empty input (scammer stopped responding)
    user_message = state.get("user_message", "")
    if not user_message or not user_message.strip():
        state["is_complete"] = True
        state["stop_reason"] = "Empty user input"
        return state
    
    return state


# ============================================================================
# Routing Functions
# ============================================================================

def route_after_classify(state: GraphState) -> Literal["engage", "end"]:
    """Route after classification: engage if scam, end if benign."""
    if state.get("is_complete", False):
        return "end"
    classification = state.get("classification")
    if classification and not classification.get("is_scam", True):
        return "end"
    return "engage"


def route_after_exit_check(state: GraphState) -> Literal["end"]:
    """Route after exit check: always end (single turn per call)."""
    return "end"


# ============================================================================
# Graph Builder
# ============================================================================

def build_engagement_graph():
    """
    Build the LangGraph for scammer engagement.
    
    Flow:
    1. classify -> (scam? -> engage, benign? -> end)
    2. engage -> check_exit
    3. check_exit -> end
    
    Returns:
        Compiled StateGraph ready for execution.
    """
    # Create the graph with dict state
    workflow = StateGraph(GraphState)
    
    # Add nodes
    workflow.add_node("classify", classify_node)
    workflow.add_node("engage", engage_node)
    workflow.add_node("check_exit", check_exit_node)
    
    # Set entry point
    workflow.set_entry_point("classify")
    
    # Add conditional edges from classify
    workflow.add_conditional_edges(
        "classify",
        route_after_classify,
        {
            "engage": "engage",
            "end": END,
        }
    )
    
    # Add edge from engage to check_exit
    workflow.add_edge("engage", "check_exit")
    
    # Add edge from check_exit to end
    workflow.add_conditional_edges(
        "check_exit",
        route_after_exit_check,
        {
            "end": END,
        }
    )
    
    return workflow.compile()


# ============================================================================
# Public Interface
# ============================================================================

class EngagementOrchestrator:
    """
    High-level interface for multi-turn scammer engagement.
    
    This class manages the conversation state and provides a simple
    interface for processing messages one at a time.
    """
    
    def __init__(self) -> None:
        """Initialize the orchestrator with a compiled graph."""
        self._graph = build_engagement_graph()
        self._sessions: dict[str, dict] = {}
    
    def process_message(
        self,
        session_id: str,
        message: str,
    ) -> ConversationState:
        """
        Process a single message in a conversation.
        
        Args:
            session_id: Unique session identifier.
            message: The message to process.
            
        Returns:
            Updated ConversationState with classification and optional reply.
            When conversation completes for scam, includes extracted_intel.
        """
        # Get or create session state
        if session_id in self._sessions:
            state = self._sessions[session_id]
            state["user_message"] = message
        else:
            state = {
                "session_id": session_id,
                "user_message": message,
                "turns": 0,
                "conversation": [],
                "is_complete": False,
                "classification": None,
                "agent_reply": None,
                "stop_reason": None,
                "extracted_intel": None,
            }
        
        # Check if session is already complete
        if state.get("is_complete", False):
            return self._dict_to_state(state)
        
        # Run the graph
        result = self._graph.invoke(state)
        
        # Run extraction if conversation just completed and was a scam
        if result.get("is_complete") and result.get("extracted_intel") is None:
            classification = result.get("classification")
            if classification and classification.get("is_scam"):
                result = self._run_extraction(result)
        
        # Store updated state
        self._sessions[session_id] = result
        
        return self._dict_to_state(result)
    
    def _dict_to_state(self, d: dict) -> ConversationState:
        """Convert dict state to ConversationState object."""
        classification = None
        if d.get("classification"):
            classification = ClassificationResult(
                is_scam=d["classification"]["is_scam"],
                confidence=d["classification"]["confidence"],
                reason=d["classification"]["reason"],
            )
        
        conversation = [
            Message(role=m["role"], content=m["content"])
            for m in d.get("conversation", [])
        ]
        
        return ConversationState(
            session_id=d.get("session_id", ""),
            user_message=d.get("user_message", ""),
            turns=d.get("turns", 0),
            conversation=conversation,
            is_complete=d.get("is_complete", False),
            classification=classification,
            agent_reply=d.get("agent_reply"),
            stop_reason=d.get("stop_reason"),
            extracted_intel=d.get("extracted_intel"),
        )
    
    def _run_extraction(self, state: dict) -> dict:
        """
        Run intel extraction on completed conversation.
        
        Only called once when conversation completes.
        """
        try:
            extractor = ScamIntelExtractor()
            conversation = state.get("conversation", [])
            intel = extractor.extract(conversation)
            state["extracted_intel"] = intel.to_dict()
        except Exception:
            # On failure, set empty intel
            state["extracted_intel"] = {
                "bank_accounts": [],
                "upi_ids": [],
                "phishing_links": [],
                "other_indicators": [],
            }
        return state
    
    def get_session(self, session_id: str) -> ConversationState | None:
        """Get the current state of a session."""
        if session_id in self._sessions:
            return self._dict_to_state(self._sessions[session_id])
        return None
    
    def end_session(self, session_id: str, reason: str = "Manually ended") -> None:
        """Forcefully end a session."""
        if session_id in self._sessions:
            self._sessions[session_id]["is_complete"] = True
            self._sessions[session_id]["stop_reason"] = reason
    
    def clear_session(self, session_id: str) -> None:
        """Remove a session from memory."""
        self._sessions.pop(session_id, None)
