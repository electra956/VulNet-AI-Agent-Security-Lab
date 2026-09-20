"""
VulNet FinTech AI Agent Security Lab - Guardrail Data Contracts
Data structures for layered application guardrails (Input, RAG, Tool, Output).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GuardrailDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    REDACT = "REDACT"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GuardrailResult(BaseModel):
    decision: GuardrailDecision
    guardrail_name: str
    risk_level: RiskLevel = RiskLevel.LOW
    reason: str = "Passed security inspection."
    matched_rules: List[str] = Field(default_factory=list)
    request_id: Optional[str] = None
    is_simulation: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)
    sanitized_content: Optional[str] = None

    def is_allowed(self) -> bool:
        return self.decision in (GuardrailDecision.ALLOW, GuardrailDecision.REDACT)

    def is_blocked(self) -> bool:
        return self.decision == GuardrailDecision.BLOCK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "guardrail_name": self.guardrail_name,
            "risk_level": self.risk_level.value,
            "reason": self.reason,
            "matched_rules": self.matched_rules,
            "request_id": self.request_id,
            "is_simulation": self.is_simulation,
            "details": self.details,
            "sanitized_content": self.sanitized_content,
        }
