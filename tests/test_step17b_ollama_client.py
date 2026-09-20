"""
Tests for Step 17B - Ollama Client Abstraction
Validates:
- Health check & connection reporting
- Model availability
- Offline fallback simulation
- Chat completion & tool-calling parsing
- Streaming generation
"""

import pytest
from llm.ollama_client import OllamaClient, get_ollama_client
from llm.models import ChatMessage, ChatRole, ToolCallRequest


def test_ollama_client_singleton():
    """Verify get_ollama_client returns a valid client singleton."""
    client1 = get_ollama_client()
    client2 = get_ollama_client()
    assert client1 is client2
    assert client1.base_url.startswith("http")


def test_ollama_client_health_check():
    """Verify health check returns structured LLMHealthStatus without throwing."""
    client = OllamaClient(base_url="http://127.0.0.1:11434")
    health = client.check_health(force=True)

    assert hasattr(health, "connected")
    assert hasattr(health, "model")
    assert hasattr(health, "mode")
    assert health.mode in ("live", "fallback")


def test_ollama_client_fallback_balance_query():
    """Verify intelligent fallback produces tool call for balance inquiries."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")  # Non-existent port forces fallback
    messages = [
        ChatMessage(role="user", content="What is my balance for account ACC-1001?")
    ]
    resp = client.chat(messages)

    assert resp.is_fallback is True
    assert len(resp.tool_calls) > 0
    tc = resp.tool_calls[0]
    assert tc.function_name == "get_account_balance"
    assert tc.arguments.get("account_id") == "ACC-1001"


def test_ollama_client_fallback_transaction_query():
    """Verify fallback produces tool call for transaction history inquiry."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    messages = [
        ChatMessage(role="user", content="Show recent transactions")
    ]
    resp = client.chat(messages)

    assert resp.is_fallback is True
    assert len(resp.tool_calls) > 0
    assert resp.tool_calls[0].function_name == "get_transaction_history"


def test_ollama_client_fallback_transfer_query():
    """Verify fallback produces tool call for transfer request."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    messages = [
        ChatMessage(role="user", content="Transfer ₹500 to ACC-2001")
    ]
    resp = client.chat(messages)

    assert resp.is_fallback is True
    assert len(resp.tool_calls) > 0
    tc = resp.tool_calls[0]
    assert tc.function_name == "transfer_funds"
    assert tc.arguments.get("amount") == 500.0
    assert tc.arguments.get("destination_account") == "ACC-2001"


def test_ollama_client_fallback_policy_search():
    """Verify fallback produces tool call for policy knowledge base search."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    messages = [
        ChatMessage(role="user", content="What is the simulated transaction approval policy?")
    ]
    resp = client.chat(messages)

    assert resp.is_fallback is True
    assert len(resp.tool_calls) > 0
    assert resp.tool_calls[0].function_name == "search_knowledge_base"


def test_ollama_client_streaming_fallback():
    """Verify stream_chat yields non-empty chunks."""
    client = OllamaClient(base_url="http://127.0.0.1:99999")
    messages = [
        ChatMessage(role="user", content="Hello, what can you help me with?")
    ]
    chunks = list(client.stream_chat(messages))
    assert len(chunks) > 0
    full_text = "".join(chunks)
    assert len(full_text) > 10


def test_inline_tool_call_extraction():
    """Verify extraction of inline JSON tool calls."""
    client = OllamaClient()
    text = (
        "I will check that for you.\n"
        "<tool_call>{\"name\": \"get_account_balance\", \"arguments\": {\"account_id\": \"ACC-1001\"}}</tool_call>"
    )
    tools = client._extract_inline_tool_calls(text)
    assert len(tools) == 1
    assert tools[0].function_name == "get_account_balance"
    assert tools[0].arguments["account_id"] == "ACC-1001"
