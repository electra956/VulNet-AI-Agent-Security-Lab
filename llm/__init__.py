"""
VulNet FinTech AI Agent Security Lab - LLM Abstraction Module
"""

from llm.models import (
    ChatMessage,
    ChatRole,
    ChatRequest,
    ChatResponse,
    ToolCallRequest,
    ToolDefinition,
    ToolParameterProperty,
    LLMHealthStatus,
)
from llm.ollama_client import OllamaClient, get_ollama_client
from llm.prompts import SYSTEM_FINTECH_PROMPT, SYSTEM_DATA_BOUNDARY_PROMPT

__all__ = [
    "ChatMessage",
    "ChatRole",
    "ChatRequest",
    "ChatResponse",
    "ToolCallRequest",
    "ToolDefinition",
    "ToolParameterProperty",
    "LLMHealthStatus",
    "OllamaClient",
    "get_ollama_client",
    "SYSTEM_FINTECH_PROMPT",
    "SYSTEM_DATA_BOUNDARY_PROMPT",
]
