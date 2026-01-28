"""
ScamClassifierAgent - Security-first scam classification agent.

This agent classifies messages as scam or benign with deterministic,
safety-first behavior. It is the gatekeeper for the honeypot pipeline.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from groq import Groq


# Maximum characters allowed in input message to prevent abuse
MAX_MESSAGE_LENGTH = 4000

# Default fallback values when classification fails
FALLBACK_IS_SCAM = True
FALLBACK_CONFIDENCE = 0.7
FALLBACK_REASON = "Unreliable classification output"


@dataclass
class ScamClassificationResult:
    """
    Result of scam classification.
    
    Attributes:
        is_scam: Whether the message is classified as a scam.
        confidence: Confidence score between 0.0 and 1.0.
        reason: Brief explanation (max 25 words).
    """
    is_scam: bool
    confidence: float
    reason: str
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_scam": self.is_scam,
            "confidence": self.confidence,
            "reason": self.reason
        }


class ScamClassifierAgent:
    """
    Agent that classifies messages as scam or benign.
    
    This agent uses a strict, deterministic approach with temperature=0
    and fail-safe defaults that bias toward classifying as scam.
    """
    
    def __init__(self, api_key: str | None = None) -> None:
        """
        Initialize the ScamClassifierAgent.
        
        Args:
            api_key: Groq API key. If None, reads from GROQ_API_KEY env var.
        """
        self._api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self._api_key:
            raise ValueError("GROQ_API_KEY environment variable is required")
        
        self._client = Groq(api_key=self._api_key)
        self._system_prompt = self._load_prompt()
        self._model = "llama-3.3-70b-versatile"  # Fast and capable model
    
    def _load_prompt(self) -> str:
        """Load the system prompt from the prompts directory."""
        prompt_path = Path(__file__).parent.parent / "prompts" / "scam_classifier.md"
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
        return prompt_path.read_text(encoding="utf-8")
    
    def _truncate_message(self, message: str) -> str:
        """
        Safely truncate message to prevent token abuse.
        
        Args:
            message: The input message to truncate.
            
        Returns:
            Truncated message if too long, otherwise original.
        """
        if len(message) > MAX_MESSAGE_LENGTH:
            return message[:MAX_MESSAGE_LENGTH] + "... [TRUNCATED]"
        return message
    
    def _parse_response(self, response_text: str) -> ScamClassificationResult:
        """
        Parse and validate the LLM response.
        
        Args:
            response_text: Raw response text from the LLM.
            
        Returns:
            Validated ScamClassificationResult.
            
        Note:
            Returns fail-safe result if parsing/validation fails.
        """
        try:
            # Clean response text - remove any markdown fences if present
            cleaned = response_text.strip()
            if cleaned.startswith("```"):
                # Remove markdown code fences
                lines = cleaned.split("\n")
                # Remove first line (```json or ```)
                lines = lines[1:]
                # Remove last line if it's ```)
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned = "\n".join(lines).strip()
            
            # Parse JSON
            data = json.loads(cleaned)
            
            # Validate required fields
            if not isinstance(data, dict):
                raise ValueError("Response is not a JSON object")
            
            if "is_scam" not in data:
                raise ValueError("Missing 'is_scam' field")
            if "confidence" not in data:
                raise ValueError("Missing 'confidence' field")
            if "reason" not in data:
                raise ValueError("Missing 'reason' field")
            
            # Validate types
            is_scam = bool(data["is_scam"])
            
            confidence = float(data["confidence"])
            # Clamp confidence to valid range
            confidence = max(0.0, min(1.0, confidence))
            
            reason = str(data["reason"])
            # Truncate reason to ~25 words
            words = reason.split()
            if len(words) > 25:
                reason = " ".join(words[:25]) + "..."
            
            return ScamClassificationResult(
                is_scam=is_scam,
                confidence=confidence,
                reason=reason
            )
            
        except (json.JSONDecodeError, ValueError, KeyError, TypeError):
            # Return fail-safe result
            return ScamClassificationResult(
                is_scam=FALLBACK_IS_SCAM,
                confidence=FALLBACK_CONFIDENCE,
                reason=FALLBACK_REASON
            )
    
    def classify(self, message: str) -> ScamClassificationResult:
        """
        Classify a message as scam or benign.
        
        Args:
            message: The message to classify.
            
        Returns:
            ScamClassificationResult with classification details.
            
        Note:
            Always returns a valid result. On any failure,
            returns fail-safe values biased toward scam classification.
        """
        if not message or not message.strip():
            return ScamClassificationResult(
                is_scam=FALLBACK_IS_SCAM,
                confidence=FALLBACK_CONFIDENCE,
                reason="Empty or invalid message"
            )
        
        # Truncate long messages
        safe_message = self._truncate_message(message.strip())
        
        try:
            # Call the LLM with strict settings
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": safe_message}
                ],
                temperature=0.0,  # Deterministic output
                max_tokens=256,  # Limit response size
            )
            
            # Extract response text
            response_text = response.choices[0].message.content
            if not response_text:
                return ScamClassificationResult(
                    is_scam=FALLBACK_IS_SCAM,
                    confidence=FALLBACK_CONFIDENCE,
                    reason="No response from classifier"
                )
            
            return self._parse_response(response_text)
            
        except Exception:
            # Any exception results in fail-safe classification
            return ScamClassificationResult(
                is_scam=FALLBACK_IS_SCAM,
                confidence=FALLBACK_CONFIDENCE,
                reason=FALLBACK_REASON
            )
