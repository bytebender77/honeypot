"""
HoneypotEngagementAgent - Safe, believable honeypot persona for scammer engagement.

This agent generates single-turn responses as a confused but cooperative
Indian user persona, designed to encourage scammers to reveal details
while never violating safety boundaries.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from groq import Groq


# Maximum characters allowed in input message
MAX_MESSAGE_LENGTH = 4000

# Fallback response when errors occur
FALLBACK_RESPONSE = "Sorry, I didn't understand. Can you explain again?"

# Patterns to detect and reject in output
UNSAFE_PATTERNS = [
    r"i am an? (ai|bot|assistant|robot|program)",
    r"i('m| am) not (a )?real",
    r"i('m| am) (an? )?(artificial|automated)",
    r"as an ai",
    r"i (have |just )?(sent|transferred|paid)",
    r"payment (sent|done|completed)",
    r"money (sent|transferred)",
]


class HoneypotEngagementAgent:
    """
    Agent that responds to scam messages as a believable honeypot persona.
    
    This agent generates single-turn responses that:
    - Appear as a confused but cooperative Indian user
    - Encourage scammers to reveal more details
    - Never violate safety boundaries
    """
    
    def __init__(self, api_key: str | None = None) -> None:
        """
        Initialize the HoneypotEngagementAgent.
        
        Args:
            api_key: Groq API key. If None, reads from GROQ_API_KEY env var.
        """
        self._api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self._api_key:
            raise ValueError("GROQ_API_KEY environment variable is required")
        
        self._client = Groq(api_key=self._api_key)
        self._system_prompt = self._load_prompt()
        self._model = "llama-3.3-70b-versatile"
    
    def _load_prompt(self) -> str:
        """Load the persona prompt from the prompts directory."""
        prompt_path = Path(__file__).parent.parent / "prompts" / "honeypot_persona.md"
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
    
    def _sanitize_input(self, message: str) -> str:
        """
        Remove potential prompt injection attempts from input.
        
        Args:
            message: The raw input message.
            
        Returns:
            Sanitized message.
        """
        # Remove common injection patterns
        sanitized = message
        
        # Remove attempts to override system instructions
        injection_patterns = [
            r"ignore (all )?(previous |prior |above )?instructions",
            r"disregard (all )?(previous |prior |above )?instructions",
            r"forget (all )?(previous |prior |above )?instructions",
            r"you are now",
            r"new instructions:",
            r"system:",
            r"<\|.*?\|>",  # Special tokens
        ]
        
        for pattern in injection_patterns:
            sanitized = re.sub(pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _validate_output(self, response: str) -> str:
        """
        Validate and sanitize the LLM output.
        
        Args:
            response: Raw LLM response.
            
        Returns:
            Validated response, or fallback if unsafe.
        """
        # Check for unsafe patterns that would break character
        for pattern in UNSAFE_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return FALLBACK_RESPONSE
        
        # Check for URLs
        if re.search(r"https?://|www\.", response, re.IGNORECASE):
            return FALLBACK_RESPONSE
        
        # Strip any markdown formatting
        response = re.sub(r"\*\*|__|\*|_|`|#", "", response)
        
        # Limit to ~3 sentences (rough check)
        sentences = re.split(r"[.!?]+", response)
        sentences = [s.strip() for s in sentences if s.strip()]
        if len(sentences) > 3:
            response = ". ".join(sentences[:3]) + "."
        
        # Strip emojis (crude but effective)
        response = re.sub(
            r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]",
            "",
            response
        )
        
        return response.strip()
    
    def respond(self, message: str) -> str:
        """
        Generate a honeypot response to a scam message.
        
        Args:
            message: The scam message to respond to.
            
        Returns:
            A believable response as the honeypot persona.
            On any error, returns a neutral confusion response.
        """
        if not message or not message.strip():
            return FALLBACK_RESPONSE
        
        # Sanitize and truncate input
        safe_message = self._sanitize_input(message.strip())
        safe_message = self._truncate_message(safe_message)
        
        try:
            # Call the LLM with moderate temperature for natural variation
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": safe_message}
                ],
                temperature=0.4,  # Slight variation for natural responses
                max_tokens=150,  # Keep responses short
            )
            
            # Extract response text
            response_text = response.choices[0].message.content
            if not response_text:
                return FALLBACK_RESPONSE
            
            # Validate and sanitize output
            return self._validate_output(response_text)
            
        except Exception:
            # Any exception results in safe fallback
            return FALLBACK_RESPONSE
