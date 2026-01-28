"""
Application configuration - Centralized settings and environment variables.

This module provides type-safe configuration with sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModelConfig:
    """LLM model configuration."""
    name: str = "llama-3.3-70b-versatile"
    temperature: float = 0.0
    max_output_tokens: int = 256


@dataclass
class InputConfig:
    """Input validation configuration."""
    max_message_length: int = 4000
    max_session_id_length: int = 128


@dataclass
class Settings:
    """
    Application settings.
    
    Loads from environment variables with sensible defaults.
    Does NOT fail if API keys are missing (allows import without env).
    """
    
    # API Keys (optional at import time)
    groq_api_key: str | None = field(default=None)
    
    # Model settings
    model: ModelConfig = field(default_factory=ModelConfig)
    
    # Input settings
    input: InputConfig = field(default_factory=InputConfig)
    
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False
    
    def __post_init__(self) -> None:
        """Load values from environment after initialization."""
        # Load API key from environment if not provided
        if self.groq_api_key is None:
            self.groq_api_key = os.getenv("GROQ_API_KEY")
        
        # Load optional overrides
        if port := os.getenv("API_PORT"):
            self.api_port = int(port)
        
        if host := os.getenv("API_HOST"):
            self.api_host = host
        
        if os.getenv("DEBUG", "").lower() in ("1", "true", "yes"):
            self.debug = True
    
    @property
    def has_api_key(self) -> bool:
        """Check if API key is configured."""
        return bool(self.groq_api_key)
    
    def require_api_key(self) -> str:
        """Get API key or raise error if not configured."""
        if not self.groq_api_key:
            raise ValueError("GROQ_API_KEY environment variable is required")
        return self.groq_api_key
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes sensitive data)."""
        return {
            "model": {
                "name": self.model.name,
                "temperature": self.model.temperature,
                "max_output_tokens": self.model.max_output_tokens,
            },
            "input": {
                "max_message_length": self.input.max_message_length,
                "max_session_id_length": self.input.max_session_id_length,
            },
            "api": {
                "host": self.api_host,
                "port": self.api_port,
                "debug": self.debug,
            },
            "has_api_key": self.has_api_key,
        }


# Global settings instance
settings = Settings()
