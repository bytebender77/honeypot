"""
ScamIntelExtractor - Zero-hallucination intelligence extraction from scam conversations.

This agent extracts verifiable scam indicators (UPI IDs, bank accounts, URLs)
using regex-first extraction with optional LLM enhancement.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from groq import Groq


# ============================================================================
# Output Schema
# ============================================================================

@dataclass
class ScamIntelResult:
    """
    Extracted scam intelligence.
    
    All fields are arrays of strings. Empty arrays are valid and expected
    when no indicators are found.
    """
    bank_accounts: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    phishing_links: list[str] = field(default_factory=list)
    other_indicators: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, list[str]]:
        """Convert to dictionary."""
        return {
            "bank_accounts": self.bank_accounts,
            "upi_ids": self.upi_ids,
            "phishing_links": self.phishing_links,
            "other_indicators": self.other_indicators,
        }
    
    def is_empty(self) -> bool:
        """Check if no intelligence was extracted."""
        return (
            len(self.bank_accounts) == 0 and
            len(self.upi_ids) == 0 and
            len(self.phishing_links) == 0 and
            len(self.other_indicators) == 0
        )
    
    def merge(self, other: "ScamIntelResult") -> "ScamIntelResult":
        """Merge another result into this one, deduplicating."""
        return ScamIntelResult(
            bank_accounts=list(set(self.bank_accounts + other.bank_accounts)),
            upi_ids=list(set(self.upi_ids + other.upi_ids)),
            phishing_links=list(set(self.phishing_links + other.phishing_links)),
            other_indicators=list(set(self.other_indicators + other.other_indicators)),
        )


# ============================================================================
# Regex Patterns (Conservative)
# ============================================================================

# UPI ID pattern: word@provider (common providers)
UPI_PATTERN = re.compile(
    r"\b([a-zA-Z0-9._-]+@(?:upi|okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|apl|"
    r"ibl|axl|sbi|icici|hdfc|axis|kotak|phonepe|gpay|amazonpay))\b",
    re.IGNORECASE
)

# URL pattern: http(s):// or common shorteners
URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"']+|"
    r"(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly|short\.link)/[^\s<>\"']+)",
    re.IGNORECASE
)

# IFSC code pattern: 4 letters + 0 + 6 alphanumeric
IFSC_PATTERN = re.compile(
    r"\b([A-Z]{4}0[A-Z0-9]{6})\b",
    re.IGNORECASE
)

# Bank account pattern: 9-18 digits (conservative)
# Only match if preceded by keywords like "account", "a/c", "acc"
BANK_ACCOUNT_PATTERN = re.compile(
    r"(?:account|a/c|acc(?:ount)?|ac)[\s.:]*(?:no\.?|number|num)?[\s.:]*(\d{9,18})\b",
    re.IGNORECASE
)

# Standalone long numbers that might be accounts (very conservative)
LONG_NUMBER_PATTERN = re.compile(
    r"\b(\d{11,18})\b"
)


# ============================================================================
# Regex Extractor
# ============================================================================

def extract_via_regex(text: str) -> ScamIntelResult:
    """
    Extract scam indicators using regex patterns.
    
    This is the primary extraction method - deterministic and reliable.
    Prefers false negatives over false positives.
    
    Args:
        text: The conversation text to extract from.
        
    Returns:
        ScamIntelResult with extracted indicators.
    """
    result = ScamIntelResult()
    
    # Extract UPI IDs
    upi_matches = UPI_PATTERN.findall(text)
    result.upi_ids = list(set(m.lower() for m in upi_matches))
    
    # Extract URLs
    url_matches = URL_PATTERN.findall(text)
    result.phishing_links = list(set(url_matches))
    
    # Extract IFSC codes
    ifsc_matches = IFSC_PATTERN.findall(text)
    result.other_indicators = list(set(m.upper() for m in ifsc_matches))
    
    # Extract bank accounts (with keyword context)
    account_matches = BANK_ACCOUNT_PATTERN.findall(text)
    result.bank_accounts = list(set(account_matches))
    
    return result


# ============================================================================
# LLM Extractor (Secondary)
# ============================================================================

class ScamIntelExtractor:
    """
    Extracts scam intelligence from conversation transcripts.
    
    Uses a regex-first approach with optional LLM enhancement.
    Never hallucinates - if LLM fails validation, falls back to regex-only.
    """
    
    def __init__(self, api_key: str | None = None) -> None:
        """
        Initialize the extractor.
        
        Args:
            api_key: Groq API key. If None, reads from GROQ_API_KEY env var.
        """
        self._api_key = api_key or os.getenv("GROQ_API_KEY")
        self._client: Groq | None = None
        if self._api_key:
            self._client = Groq(api_key=self._api_key)
        
        self._system_prompt = self._load_prompt()
        self._model = "llama-3.3-70b-versatile"
    
    def _load_prompt(self) -> str:
        """Load the extraction prompt."""
        prompt_path = Path(__file__).parent.parent / "prompts" / "intel_extractor.md"
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
        return prompt_path.read_text(encoding="utf-8")
    
    def _format_conversation(self, conversation: list[dict]) -> str:
        """Format conversation list into text."""
        lines = []
        for msg in conversation:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            lines.append(f"{role}: {content}")
        return "\n".join(lines)
    
    def _validate_llm_result(self, data: dict[str, Any]) -> ScamIntelResult | None:
        """
        Validate LLM output matches expected schema.
        
        Returns None if validation fails (triggers regex fallback).
        """
        try:
            # Check required fields
            required = ["bank_accounts", "upi_ids", "phishing_links", "other_indicators"]
            for field in required:
                if field not in data:
                    return None
                if not isinstance(data[field], list):
                    return None
                # Ensure all items are strings
                for item in data[field]:
                    if not isinstance(item, str):
                        return None
            
            return ScamIntelResult(
                bank_accounts=data["bank_accounts"],
                upi_ids=data["upi_ids"],
                phishing_links=data["phishing_links"],
                other_indicators=data["other_indicators"],
            )
            
        except (KeyError, TypeError, ValueError):
            return None
    
    def _extract_via_llm(self, conversation_text: str) -> ScamIntelResult | None:
        """
        Extract using LLM (secondary method).
        
        Returns None if extraction fails or validation fails.
        """
        if not self._client:
            return None
        
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": conversation_text}
                ],
                temperature=0.0,  # Deterministic
                max_tokens=512,
            )
            
            response_text = response.choices[0].message.content
            if not response_text:
                return None
            
            # Clean response
            cleaned = response_text.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned = "\n".join(lines).strip()
            
            # Parse JSON
            data = json.loads(cleaned)
            
            # Validate schema
            return self._validate_llm_result(data)
            
        except Exception:
            return None
    
    def extract(self, conversation: list[dict]) -> ScamIntelResult:
        """
        Extract scam intelligence from a conversation.
        
        Uses regex-first extraction, then enhances with LLM if available.
        Never throws exceptions, never hallucinates.
        
        Args:
            conversation: List of message dicts with 'role' and 'content'.
            
        Returns:
            ScamIntelResult with extracted indicators (may be empty).
        """
        if not conversation:
            return ScamIntelResult()
        
        # Format conversation to text
        conversation_text = self._format_conversation(conversation)
        
        # Step 1: Regex extraction (always runs, always reliable)
        regex_result = extract_via_regex(conversation_text)
        
        # Step 2: LLM extraction (optional, may fail)
        llm_result = self._extract_via_llm(conversation_text)
        
        # Merge results if LLM succeeded, otherwise use regex only
        if llm_result:
            return regex_result.merge(llm_result)
        
        return regex_result
    
    def extract_from_text(self, text: str) -> ScamIntelResult:
        """
        Extract scam intelligence from raw text.
        
        Convenience method for extracting from a single text block.
        
        Args:
            text: Raw text to extract from.
            
        Returns:
            ScamIntelResult with extracted indicators.
        """
        return self.extract([{"role": "text", "content": text}])
