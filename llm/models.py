"""
VulNet FinTech AI Agent Security Lab - LLM Models
Pydantic contracts for chat messages, tool definitions, tool invocations, and health status.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolParameterProperty(BaseModel):
    type: str
    description: str
    enum: Optional[List[str]] = None


class ToolParameters(BaseModel):
    type: str = "object"
    properties: Dict[str, Any] = Field(default_factory=dict)
    required: List[str] = Field(default_factory=list)


class ToolFunction(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    type: str = "function"
    function: ToolFunction


class ToolCallRequest(BaseModel):
    id: Optional[str] = None
    type: str = "function"
    function_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    raw_arguments: Optional[str] = None


class ChatMessage(BaseModel):
    role: str
    content: str = ""
    name: Optional[str] = None
    tool_calls: Optional[List[ToolCallRequest]] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            data["name"] = self.name
        if self.tool_calls:
            data["tool_calls"] = [
                {
                    "function": {
                        "name": tc.function_name,
                        "arguments": tc.arguments,
                    }
                }
                for tc in self.tool_calls
            ]
        return data


class ChatRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    stream: bool = False
    tools: Optional[List[ToolDefinition]] = None
    options: Optional[Dict[str, Any]] = None
    temperature: float = 0.1


class ChatResponse(BaseModel):
    model: str
    content: str
    role: str = "assistant"
    tool_calls: List[ToolCallRequest] = Field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None
    finish_reason: Optional[str] = None
    prompt_eval_count: Optional[int] = None
    eval_count: Optional[int] = None
    is_fallback: bool = False


class LLMHealthStatus(BaseModel):
    connected: bool
    base_url: str
    model: str
    embed_model: str
    available_models: List[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    mode: str = "live"  # "live" or "fallback"
