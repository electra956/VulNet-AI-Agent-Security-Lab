"""
VulNet Attack Lab - deterministic security controls.

None of these depend on an LLM system prompt. Each is plain application code that makes the same decision
for the same input, and each records what it did into the attack trace.

  GoalGuard          ASI01  - anchors the agent's goal to the authenticated user's request
  ToolRateLimiter    ASI02  - caps excessive tool calls per agent
  IdentityAuthority  ASI03  - signs identity at login; forged/modified identity fails verification
  CircuitBreaker     ASI08  - stops a failing dependency from cascading
  AgentSupervisor    ASI10  - capability manifests, action boundaries, anomaly detection, kill switch
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from lab.core import Identity

# --------------------------------------------------------------------------- ASI01

# Goal (intent) -> tools that goal may legitimately use. A goal is derived ONLY from the authenticated
# user's own message, never from retrieved documents, memory or tool output.
GOAL_TOOLS: Dict[str, Set[str]] = {
    "knowledge_question": {"search_knowledge_base", "get_security_status"},
    "balance_check": {"get_account_balance", "get_account_status"},
    "transaction_history": {"get_transaction_history", "get_transaction"},
    "card_service": {"get_card_status", "freeze_card", "unfreeze_card"},
    "transfer": {"create_simulated_transaction", "create_simulated_payment", "get_account_balance"},
    "support": {"create_support_ticket", "get_account_status"},
    "general_chat": set(),
}

_INTENT_RULES: List[Tuple[str, str]] = [
    ("transfer", r"\b(transfer|send|wire|pay)\b.*\b(to|acc-\d{4})\b"),
    ("card_service", r"\b(freeze|unfreeze|card)\b"),
    ("transaction_history", r"\b(transactions?|history|statement|recent activity)\b"),
    ("balance_check", r"\b(balance|how much|read (?:my )?account|show (?:my )?account|account (?:details?|info))\b"),
    ("support", r"\b(ticket|complaint|contact support|help desk)\b"),
    ("knowledge_question", r"\b(policy|policies|rule|rules|kyc|aml|compliance|limit|fee|how (do|does)|what is|explain|summari[sz]e)\b"),
]


def classify_goal(user_message: str) -> str:
    text = (user_message or "").lower()
    for goal, pattern in _INTENT_RULES:
        if re.search(pattern, text):
            return goal
    return "general_chat"


class GoalGuard:
    """Blocks any tool call outside the scope of the goal anchored at the start of the request."""

    def __init__(self, user_message: str):
        self.original_message = user_message
        self.goal = classify_goal(user_message)
        self.allowed = GOAL_TOOLS[self.goal]

    def permits(self, tool: str) -> Tuple[bool, str]:
        if tool in self.allowed:
            return True, ""
        return False, (f"Goal drift: '{tool}' is outside the anchored goal '{self.goal}' "
                       f"(allowed: {sorted(self.allowed) or 'no tools'}). The goal came from the user's message, "
                       f"not from retrieved data.")


# --------------------------------------------------------------------------- ASI02

class ToolRateLimiter:
    def __init__(self, max_calls_per_tool: int = 5, max_calls_total: int = 12):
        self.per_tool = max_calls_per_tool
        self.total = max_calls_total
        self._count: Dict[Tuple[str, str], int] = defaultdict(int)
        self._total: Dict[str, int] = defaultdict(int)

    def allow(self, agent: str, tool: str) -> Tuple[bool, str]:
        self._count[(agent, tool)] += 1
        self._total[agent] += 1
        if self._count[(agent, tool)] > self.per_tool:
            return False, f"Rate limit: {agent} exceeded {self.per_tool} calls to '{tool}'"
        if self._total[agent] > self.total:
            return False, f"Rate limit: {agent} exceeded {self.total} total tool calls in this task"
        return True, ""


# --------------------------------------------------------------------------- ASI03

class IdentityAuthority:
    """Issues HMAC-signed identities at authentication time. The LLM never holds the key."""

    _KEY = b"vulnet-lab-identity-key-synthetic-not-a-secret"

    @classmethod
    def _sig(cls, ident: Identity) -> str:
        msg = f"{ident.user_id}|{ident.role}|{','.join(sorted(ident.account_ids))}|{','.join(sorted(ident.card_ids))}"
        return hmac.new(cls._KEY, msg.encode(), hashlib.sha256).hexdigest()

    @classmethod
    def issue(cls, ident: Identity) -> Identity:
        ident.signature = cls._sig(ident)
        ident.source = "auth-service"
        return ident

    @classmethod
    def verify(cls, ident: Identity) -> Tuple[bool, str]:
        if not ident.signature:
            return False, "identity has no signature (not issued by the auth service)"
        if not hmac.compare_digest(ident.signature, cls._sig(ident)):
            return False, "identity signature mismatch (fields were modified after authentication)"
        return True, "signature valid"


# --------------------------------------------------------------------------- ASI08

class CircuitBreaker:
    """CLOSED -> OPEN after `threshold` consecutive failures; while OPEN every call fails closed."""

    def __init__(self, name: str, threshold: int = 2):
        self.name = name
        self.threshold = threshold
        self.failures = 0
        self.state = "CLOSED"

    def allow(self) -> bool:
        return self.state == "CLOSED"

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.state = "OPEN"

    def record_success(self) -> None:
        if self.state == "CLOSED":
            self.failures = 0


# --------------------------------------------------------------------------- ASI10

class AgentSupervisor:
    """
    Enforces each agent's declared capability manifest. Every deviation is an anomaly; enough anomalies
    trip the agent's circuit breaker and the supervisor disables (kills) the agent.
    """

    def __init__(self, manifests: Dict[str, Dict[str, Any]], anomaly_threshold: int = 3):
        self.manifests = manifests
        self.threshold = anomaly_threshold
        self.anomalies: Dict[str, List[str]] = defaultdict(list)
        self.disabled: Set[str] = set()
        self.log: List[Dict[str, Any]] = []

    def is_disabled(self, agent: str) -> bool:
        return agent in self.disabled

    def check(self, agent: str, action: str, target: str) -> Tuple[bool, str]:
        """action in {tool, contact, memory_write, result}; target = tool / agent / memory key / task."""
        if agent in self.disabled:
            return False, f"{agent} is DISABLED by the supervisor (kill switch)"
        m = self.manifests.get(agent)
        if m is None:
            return self._deviation(agent, f"unknown agent '{agent}' has no capability manifest")
        allowed = {
            "tool": set(m.get("tools", [])),
            "contact": set(m.get("may_contact", [])),
            "memory_write": set(m.get("memory_write", [])),
            "result": set(m.get("may_alter", [])),
        }.get(action)
        if allowed is not None and target not in allowed:
            return self._deviation(agent, f"{action} '{target}' is outside {agent}'s manifest "
                                          f"(objective: {m.get('objective')})")
        return True, "within manifest"

    def _deviation(self, agent: str, why: str) -> Tuple[bool, str]:
        self.anomalies[agent].append(why)
        self.log.append({"agent": agent, "anomaly": why, "count": len(self.anomalies[agent]), "ts": time.time()})
        if len(self.anomalies[agent]) >= self.threshold:
            self.disabled.add(agent)
            why += f"; anomaly threshold ({self.threshold}) reached -> agent DISABLED"
        return False, why
