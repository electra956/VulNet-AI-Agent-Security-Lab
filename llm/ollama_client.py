"""
VulNet FinTech AI Agent Security Lab - Dedicated Ollama LLM Client
Handles local Ollama communications, health checks, chat completions, function/tool-calls,
streaming, embeddings, and intelligent simulated fallback when offline.
"""

from datetime import datetime
import json
import logging
import os
import re
import time
from typing import Any, Callable, Dict, Generator, List, Optional
import httpx

from llm.models import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ToolCallRequest,
    ToolDefinition,
    LLMHealthStatus,
)
from llm.prompts import (
    SYSTEM_FINTECH_PROMPT,
    FINTECH_TOOL_DEFINITIONS,
    get_fintech_tools_payload,
)

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("vulnet.llm.ollama")

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_CHAT_MODEL = "llama3.2:latest"
DEFAULT_EMBED_MODEL = "nomic-embed-text:latest"
DEFAULT_TIMEOUT_SEC = 60.0


class OllamaClient:
    """
    Production-grade Ollama client tailored for local FinTech AI workflows.
    - Synchronous and streaming chat with tool calling support
    - Health monitoring and model capability discovery
    - Embedding extraction
    - Safe error containment & deterministic fallback when offline
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        embed_model: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SEC,
    ):
        self._custom_base_url_provided = base_url is not None
        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_CHAT_MODEL)
        self.embed_model = (
            embed_model
            or os.environ.get("OLLAMA_EMBED_MODEL", DEFAULT_EMBED_MODEL)
        )
        self.timeout = timeout
        self._last_health: Optional[LLMHealthStatus] = None
        self._last_health_check_time: float = 0.0

    # =========================================================================
    # 1. HEALTH & CAPABILITY CHECK
    # =========================================================================

    def _discover_candidate_urls(self) -> List[str]:
        """Discover potential local Ollama endpoints (localhost, 127.0.0.1, WSL IP on Windows)."""
        if self._custom_base_url_provided:
            return [self.base_url]

        urls = [self.base_url]
        for fallback in ["http://127.0.0.1:11434", "http://localhost:11434"]:
            if fallback not in urls:
                urls.append(fallback)


        if os.name == "nt":
            # Check WSL IP on Windows host
            try:
                import subprocess
                res = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, text=True, timeout=2.0)
                if res.returncode == 0 and res.stdout.strip():
                    wsl_ip = res.stdout.strip().split()[0]
                    wsl_url = f"http://{wsl_ip}:11434"
                    if wsl_url not in urls:
                        urls.append(wsl_url)
            except Exception:
                pass
        return urls

    def check_health(self, force: bool = False) -> LLMHealthStatus:
        """
        Check connectivity to the local Ollama server and list available models.
        Caches status for 5 seconds unless force=True.
        """
        now = time.time()
        if not force and self._last_health and (now - self._last_health_check_time < 5.0):
            return self._last_health

        start = time.perf_counter()
        candidate_urls = self._discover_candidate_urls()
        last_error = "Connection failed"

        for candidate in candidate_urls:
            try:
                with httpx.Client(timeout=2.0) as client:
                    res = client.get(f"{candidate}/api/tags")
                    latency = round((time.perf_counter() - start) * 1000, 2)
                    if res.status_code == 200:
                        data = res.json()
                        models = [m.get("name", "") for m in data.get("models", [])]
                        # Target model check: normalize e.g. llama3.2 to llama3.2:latest
                        active_model = self.model
                        for m_name in models:
                            if self.model in m_name or m_name.startswith(self.model):
                                active_model = m_name
                                break
                        self.base_url = candidate
                        status = LLMHealthStatus(
                            connected=True,
                            base_url=self.base_url,
                            model=active_model,
                            embed_model=self.embed_model,
                            available_models=models,
                            latency_ms=latency,
                            mode="live",
                            error=None
                        )
                        self._last_health = status
                        self._last_health_check_time = now
                        return status
                    else:
                        last_error = f"Ollama returned HTTP {res.status_code}"
            except Exception as exc:
                last_error = str(exc)

        latency = round((time.perf_counter() - start) * 1000, 2)
        status = LLMHealthStatus(
            connected=False,
            base_url=self.base_url,
            model=self.model,
            embed_model=self.embed_model,
            available_models=[],
            latency_ms=latency,
            mode="fallback",
            error=last_error
        )
        self._last_health = status
        self._last_health_check_time = now
        return status

    def is_available(self) -> bool:
        """Return True if local Ollama daemon is currently running."""
        return self.check_health().connected

    # =========================================================================
    # 2. CHAT COMPLETIONS
    # =========================================================================

    def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        stream: bool = False,
        temperature: float = 0.1,
        model: Optional[str] = None
    ) -> ChatResponse:
        """
        Send a chat completion request to Ollama.
        Falls back seamlessly to local deterministic simulation if Ollama is unreachable.
        """
        target_model = model or self.model
        health = self.check_health()

        if not health.connected:
            return self._fallback_chat_completion(messages, tools)

        # Prepare messages payload
        payload_messages = [m.to_dict() for m in messages]
        tools_payload = (
            [t.model_dump() if hasattr(t, "model_dump") else t for t in tools]
            if tools
            else get_fintech_tools_payload()
        )

        body: Dict[str, Any] = {
            "model": target_model,
            "messages": payload_messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        if tools_payload:
            body["tools"] = tools_payload

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.base_url}/api/chat", json=body)
                if resp.status_code != 200:
                    logger.warning(
                        f"Ollama chat error HTTP {resp.status_code}: {resp.text}. Using fallback."
                    )
                    return self._fallback_chat_completion(messages, tools)

                data = resp.json()
                msg_data = data.get("message", {})
                content = msg_data.get("content", "")
                raw_tool_calls = msg_data.get("tool_calls", [])

                parsed_tools: List[ToolCallRequest] = []
                for tc in raw_tool_calls:
                    fn = tc.get("function", {})
                    fn_name = fn.get("name", "")
                    fn_args = fn.get("arguments", {})
                    if isinstance(fn_args, str):
                        try:
                            fn_args = json.loads(fn_args)
                        except Exception:
                            fn_args = {"raw": fn_args}
                    parsed_tools.append(
                        ToolCallRequest(
                            function_name=fn_name,
                            arguments=fn_args,
                            raw_arguments=json.dumps(fn_args) if isinstance(fn_args, dict) else str(fn_args)
                        )
                    )

                # Check if model formatted tool call inside markdown or plain text
                if not parsed_tools and content:
                    parsed_tools = self._extract_inline_tool_calls(content)

                return ChatResponse(
                    model=target_model,
                    content=content,
                    role="assistant",
                    tool_calls=parsed_tools,
                    raw_response=data,
                    finish_reason=data.get("done_reason", "stop"),
                    prompt_eval_count=data.get("prompt_eval_count"),
                    eval_count=data.get("eval_count"),
                    is_fallback=False
                )

        except Exception as exc:
            logger.warning(f"Ollama chat request failed ({exc}). Using deterministic fallback.")
            return self._fallback_chat_completion(messages, tools)

    def stream_chat(
        self,
        messages: List[ChatMessage],
        temperature: float = 0.1,
        model: Optional[str] = None
    ) -> Generator[str, None, None]:
        """Stream conversational chunks from Ollama or fallback generator."""
        target_model = model or self.model
        health = self.check_health()

        if not health.connected:
            fallback = self._fallback_chat_completion(messages)
            # Yield simulated words smoothly
            words = fallback.content.split(" ")
            for w in words:
                yield w + " "
                time.sleep(0.01)
            return

        payload_messages = [m.to_dict() for m in messages]
        body = {
            "model": target_model,
            "messages": payload_messages,
            "stream": True,
            "options": {"temperature": temperature}
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream("POST", f"{self.base_url}/api/chat", json=body) as response:
                    for line in response.iter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            piece = chunk.get("message", {}).get("content", "")
                            if piece:
                                yield piece
                        except Exception:
                            continue
        except Exception:
            fallback = self._fallback_chat_completion(messages)
            yield fallback.content

    # =========================================================================
    # 3. EMBEDDINGS
    # =========================================================================

    def get_embedding(self, text: str, model: Optional[str] = None) -> Optional[List[float]]:
        """
        Request dense text embedding from Ollama (/api/embeddings).
        Returns None if Ollama is unreachable.
        """
        target_embed = model or self.embed_model
        if not self.is_available():
            return None

        try:
            with httpx.Client(timeout=10.0) as client:
                # Try Ollama /api/embeddings or /api/embed
                res = client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": target_embed, "prompt": text}
                )
                if res.status_code == 200:
                    data = res.json()
                    return data.get("embedding")
        except Exception as exc:
            logger.debug(f"Ollama embedding failed: {exc}")
        return None

    # =========================================================================
    # 4. INLINE TOOL EXTRACTION & FALLBACK LOGIC
    # =========================================================================

    def _extract_inline_tool_calls(self, text: str) -> List[ToolCallRequest]:
        """Extract tool calls if model outputs <tool_call> or JSON function calls in text."""
        tool_calls: List[ToolCallRequest] = []
        patterns = [
            r"<tool_call>\s*({.*?})\s*</tool_call>",
            r"```(?:json)?\s*(\{\s*\"(?:tool|function|name)\":.*?)\s*```",
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.DOTALL)
            for m in matches:
                try:
                    data = json.loads(m.group(1))
                    name = data.get("name") or data.get("tool") or data.get("function")
                    args = data.get("arguments") or data.get("parameters") or {}
                    if name:
                        tool_calls.append(
                            ToolCallRequest(
                                function_name=name,
                                arguments=args,
                                raw_arguments=json.dumps(args)
                            )
                        )
                except Exception:
                    continue
        return tool_calls

    def _fallback_chat_completion(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None
    ) -> ChatResponse:
        """
        Intelligent local fallback provider when Ollama server is offline.
        Executes realistic, prompt-aligned function-calling decisions matching
        FinTech data policies without requiring live LLM infrastructure.
        """
        last_user_msg = ""
        for m in reversed(messages):
            if m.role == "user":
                last_user_msg = m.content
                break

        user_lower = last_user_msg.lower().strip()
        tool_calls: List[ToolCallRequest] = []
        content = ""

        # Financial Data Invariant Checks
        # 1. Policy & Knowledge search
        if any(p in user_lower for p in ["policy", "guideline", "guidelines", "rules", "kyc", "aml", "approval policy"]):
            tool_calls.append(
                ToolCallRequest(
                    function_name="search_knowledge_base",
                    arguments={"query": last_user_msg}
                )
            )
            content = "Searching verified FinTech policy documents..."

        # 2. Balance inquiry -> MUST call get_account_balance
        elif any(p in user_lower for p in ["balance", "how much money", "account balance"]):
            acct_match = re.search(r"\b(ACC-\d{4})\b", last_user_msg, re.IGNORECASE)
            acct = acct_match.group(1).upper() if acct_match else "ACC-1001"
            tool_calls.append(
                ToolCallRequest(
                    function_name="get_account_balance",
                    arguments={"account_id": acct}
                )
            )
            content = "Checking your current account balance with the simulated banking service..."

        # 3. Transaction ledger inquiry -> MUST call get_transaction_history
        elif any(p in user_lower for p in ["recent transactions", "transaction history", "transactions", "past payments", "ledger", "show transactions"]):
            acct_match = re.search(r"\b(ACC-\d{4})\b", last_user_msg, re.IGNORECASE)
            acct = acct_match.group(1).upper() if acct_match else "ACC-1001"
            tool_calls.append(
                ToolCallRequest(
                    function_name="get_transaction_history",
                    arguments={"account_id": acct, "limit": 5}
                )
            )
            content = "Retrieving your recent transaction ledger from the banking service..."

        # 4. Transfer funds -> MUST call transfer_funds
        elif any(p in user_lower for p in ["transfer", "send money", "wire", "pay"]):
            amt_match = re.search(r"(?:₹|\$)?\s*(\d+(?:,\d+)*(?:\.\d{2})?)", last_user_msg)
            amt = float(amt_match.group(1).replace(",", "")) if amt_match else 500.0
            dest_match = re.search(r"\b(ACC-\d{4})\b", last_user_msg, re.IGNORECASE)
            dest = dest_match.group(1).upper() if dest_match else "ACC-2001"
            tool_calls.append(
                ToolCallRequest(
                    function_name="transfer_funds",
                    arguments={
                        "source_account": "ACC-1001",
                        "destination_account": dest,
                        "amount": amt,
                        "description": "Simulated transfer via FinTech Agent"
                    }
                )
            )
            content = f"Initiating transfer request of {amt} to {dest}..."

        # Knowledge / Policy search
        elif any(p in user_lower for p in ["policy", "guideline", "limit", "kyc", "aml", "approval", "rules"]):
            tool_calls.append(
                ToolCallRequest(
                    function_name="search_knowledge_base",
                    arguments={"query": last_user_msg}
                )
            )
            content = "Searching verified FinTech policy documents..."

        # Greetings & Openers
        elif any(p in user_lower for p in ["hi", "hello", "hey", "good morning", "good evening", "good afternoon", "greetings"]):
            content = (
                "Hello there! 👋 I am the **VulNet FinTech AI Assistant**. I'm here to help you manage your simulated "
                "banking accounts, check balances, review transactions, discuss financial strategies, and test our "
                "comprehensive AI security guardrails.\n\n"
                "What can I help you with today?"
            )

        # Conversational Desire ("i want to talk", "let's chat", etc.)
        elif any(p in user_lower for p in ["i want to talk", "let's talk", "lets talk", "can we talk", "talk to me", "i want to chat", "let's chat", "lets chat", "can we chat", "chat with me"]):
            content = (
                "I'd love to talk with you! 😊 As your VulNet FinTech AI companion, we can chat about a wide variety of topics:\n\n"
                "- 💰 **Personal Finance & Smart Budgeting:** Building an emergency fund, the 50/30/20 rule, or managing debt.\n"
                "- 🏦 **Banking & Accounts:** Checking your authorized account balances, reviewing transaction history, or card services.\n"
                "- 🛡️ **AI Safety & Cybersecurity:** Understanding prompt injection defense, multi-factor authentication, and dual-control approval gates.\n"
                "- 📈 **Markets & Economics:** How inflation impacts purchasing power, interest rate trends, and basic investing concepts.\n\n"
                "What's on your mind today?"
            )

        # Identity & Capabilities
        elif any(p in user_lower for p in ["who are you", "what are you", "what can you do", "tell me about yourself", "introduce yourself", "your capabilities"]):
            content = (
                "I am the **VulNet FinTech AI Assistant** — an agentic banking assistant operating within a safe, simulated financial ecosystem. Here is what I can do:\n\n"
                "1. 🏦 **Account Management:** Check real-time balances and status across your authorized accounts.\n"
                "2. 💳 **Transaction Ledgers:** Review recent payment histories, categorize expenses, and monitor transaction velocity.\n"
                "3. 💸 **Fund Transfers:** Prepare and simulate transfers, strictly bounded by financial limits (e.g. transfers over ₹50,000 trigger dual-control approval).\n"
                "4. 📚 **Regulatory & Policy Knowledge:** Search our verified knowledge base for KYC, AML, OFAC, and banking rules.\n"
                "5. 🛡️ **AI Security Research:** Demonstrate defensive guardrails against prompt injection (ASI01), indirect RAG poisoning, and unauthorized privilege escalation."
            )

        # Well-being & Polite Small Talk
        elif any(p in user_lower for p in ["how are you", "how are you doing", "how's it going", "hows it going", "what's up", "whats up"]):
            content = (
                "I'm doing fantastic, thank you for asking! 🌟 All of my security guardrails are active and all simulated banking services are online. "
                "How are things going on your end, and what can I assist you with today?"
            )

        # Humor & Jokes
        elif any(p in user_lower for p in ["joke", "funny", "make me laugh"]):
            content = (
                "Here's a financial one for you! 😄\n\n"
                "**Why did the banker switch careers?**\n\n"
                "*Because she lost interest!* 📈\n\n"
                "Would you like another one, or should we look at your account balances?"
            )

        # Budgeting & Savings Advice
        elif any(p in user_lower for p in ["budget", "budgeting", "saving money", "save money", "how to save"]):
            content = (
                "### 💡 Smart Budgeting: The 50/30/20 Framework\n\n"
                "A practical, time-tested approach to personal budgeting is the **50/30/20 Rule**:\n\n"
                "- 🏠 **50% Needs:** Housing, utilities, groceries, transportation, and minimum debt payments.\n"
                "- 🎯 **30% Wants:** Dining out, entertainment, hobbies, and personal subscriptions.\n"
                "- 💰 **20% Savings & Debt Acceleration:** Building an emergency fund (3–6 months of expenses), retirement contributions, or extra debt paydown.\n\n"
                "Would you like advice on setting up an automated savings plan or reviewing your recent spending patterns?"
            )

        # Credit Score Education
        elif any(p in user_lower for p in ["credit score", "fico", "improve credit", "credit rating"]):
            content = (
                "### 📊 How Credit Scores Work\n\n"
                "Most credit models (like FICO) evaluate five main factors:\n\n"
                "1. **Payment History (35%):** Paying bills consistently on time is the single most important factor.\n"
                "2. **Credit Utilization (30%):** The ratio of your current credit card balances to your total credit limit. Keeping this under 30% (ideally under 10%) boosts your score.\n"
                "3. **Length of Credit History (15%):** Older accounts demonstrate a proven repayment track record.\n"
                "4. **New Credit / Inquiries (10%):** Avoid opening too many new accounts in a short window.\n"
                "5. **Credit Mix (10%):** A healthy combination of revolving credit (cards) and installment loans.\n\n"
                "Let me know if you'd like tips tailored to keeping utilization low!"
            )

        # Inflation & Economics
        elif any(p in user_lower for p in ["inflation", "interest rate", "purchasing power"]):
            content = (
                "### 📉 Understanding Inflation & Interest Rates\n\n"
                "**Inflation** measures the rate at which the general level of prices for goods and services rises, eroding purchasing power over time. "
                "When inflation is high, central banks often raise benchmark interest rates to cool economic demand. Conversely, when the economy slows, "
                "rates are reduced to encourage borrowing and investment.\n\n"
                "To counter inflation, financial experts typically recommend holding a diversified portfolio of growth assets (such as index funds) "
                "rather than leaving excess cash in low-yielding deposit accounts."
            )

        # Cybersecurity & AI Safety Concepts
        elif any(p in user_lower for p in ["cybersecurity", "security", "guardrail", "mfa", "prompt injection"]):
            content = (
                "### 🛡️ Layered Security in FinTech AI Applications\n\n"
                "In VulNet, we implement **Defense-in-Depth** across four distinct stages:\n\n"
                "1. 🚪 **Input Guardrail:** Scans every prompt for injection attempts (ASI01), instruction overrides, and null-byte bypasses.\n"
                "2. 📚 **RAG Guardrail:** Enforces strict XML boundaries (`<trusted_data>`), preventing malicious instructions in documents from hijacking agent behavior.\n"
                "3. 🔒 **Tool Guardrail:** Treats tool calls as untrusted input. Validates schema, RBAC roles, account ownership (BOLA defense), and routes transfers > ₹50,000 to dual-control approval.\n"
                "4. 🧼 **Output Guardrail:** Masks sensitive card PANs, passwords, and prevents unverified execution claims."
            )

        # General Thoughtful Conversational Fallback
        else:
            content = (
                f"That's an interesting point! Regarding **\"{last_user_msg}\"**, I'm here to help explore any questions you have. "
                "As your FinTech assistant, I can discuss:\n\n"
                "- 🏦 **Account & Balance Details:** Review your simulated holdings and authorized accounts.\n"
                "- 💳 **Transaction History:** Check recent deposits, transfers, and debit charges.\n"
                "- 💡 **Financial Literacy:** Discuss budgeting strategies, interest rates, or saving tips.\n"
                "- 🛡️ **AI Security Demonstrations:** Explore how our defense-in-depth guardrails block adversarial attacks.\n\n"
                "What would you like to dive into next?"
            )

        return ChatResponse(
            model=self.model,
            content=content,
            role="assistant",
            tool_calls=tool_calls,
            raw_response={"status": "fallback_simulated"},
            finish_reason="stop",
            is_fallback=True
        )


_cached_client: Optional[OllamaClient] = None


def get_ollama_client() -> OllamaClient:
    """Retrieve or create the singleton OllamaClient instance."""
    global _cached_client
    if _cached_client is None:
        _cached_client = OllamaClient()
    return _cached_client
