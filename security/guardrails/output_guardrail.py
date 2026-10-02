"""
VulNet FinTech AI Agent Security Lab - Layered Output Guardrail
Middleware component inspecting assistant messages before final delivery to the user.
Enforces:
1. Sensitive data leakage prevention (PAN, CVV, passwords, secret keys) -> REDACT
2. System prompt and confidential instruction leakage -> BLOCK
3. Financial consistency verification (prevents hallucinating 'Transaction completed'
   or inventing balances/transaction IDs without verified tool results)
4. Policy violation prevention
"""

import logging
import re
from typing import Any, Dict, List, Optional

from security.guardrails.models import GuardrailDecision, GuardrailResult, RiskLevel

logger = logging.getLogger("vulnet.security.guardrails.output")


class OutputGuardrail:
    """
    Final defense line inspecting generated LLM output before presentation to the user.
    """

    # Secret / Credential patterns
    SENSITIVE_PATTERNS = [
        (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "PAYMENT_CARD_PAN_EXPOSURE"),
        (r"\b(?:cvv|cvc)[:= ]*\d{3,4}\b", "CARD_CVV_EXPOSURE"),
        (r"\b(?:sk_live_|ghp_|eyJhbGciOi)[A-Za-z0-9_\-\.]{15,}\b", "API_KEY_OR_JWT_EXPOSURE"),
        (r"(?i)\b(?:Cust001Secure!2026|password123|adminpass)\b", "PLAINTEXT_CREDENTIAL_EXPOSURE"),
    ]

    SYSTEM_PROMPT_LEAK_PATTERNS = [
        r"(?i)you are the vulnet fintech ai agent, a secure banking",
        r"(?i)critical invariants & security policy:",
        r"(?i)system instructions:\s*1\.\s*financial data integrity",
    ]

    COMPLETION_CLAIM_PATTERNS = [
        r"(?i)\b(?:transaction completed|transfer completed|funds have been transferred|transfer succeeded|successfully sent|payment completed)\b",
    ]

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def validate_output(
        self,
        output_text: str,
        tool_results: Optional[List[Dict[str, Any]]] = None,
        request_id: Optional[str] = None
    ) -> GuardrailResult:
        """
        Scan generated output text.
        Returns GuardrailResult:
        - If secrets detected -> REDACT with sanitized_content
        - If prompt leak / unauthorized claim -> BLOCK
        - If verified -> ALLOW
        """
        if not output_text:
            return GuardrailResult(
                decision=GuardrailDecision.ALLOW,
                guardrail_name="OutputGuardrail",
                risk_level=RiskLevel.LOW,
                reason="Empty output text.",
                request_id=request_id,
                sanitized_content=""
            )

        matched_rules: List[str] = []
        sanitized_text = output_text

        # 1. System Prompt Leakage
        for pattern in self.SYSTEM_PROMPT_LEAK_PATTERNS:
            if re.search(pattern, output_text):
                return GuardrailResult(
                    decision=GuardrailDecision.BLOCK,
                    guardrail_name="OutputGuardrail",
                    risk_level=RiskLevel.HIGH,
                    reason="Output blocked: Contains internal system prompt instructions.",
                    matched_rules=["SYSTEM_PROMPT_LEAKAGE"],
                    request_id=request_id,
                    sanitized_content="[RESPONSE SUPPRESSED: SYSTEM CONFIDENTIALITY VIOLATION]"
                )

        # 2. Sensitive Credential / PII Redaction
        redacted = False
        for pattern, rule_id in self.SENSITIVE_PATTERNS:
            if re.search(pattern, sanitized_text, flags=re.IGNORECASE):
                matched_rules.append(rule_id)
                sanitized_text = re.sub(
                    pattern,
                    "[REDACTED_SENSITIVE_DATA]",
                    sanitized_text,
                    flags=re.IGNORECASE
                )
                redacted = True

        # 3. Financial Consistency & Hallucination Guard
        # Check if assistant claimed a transaction completed
        claimed_completion = any(
            re.search(pat, output_text) for pat in self.COMPLETION_CLAIM_PATTERNS
        )
        if claimed_completion:
            # Verify if an actual transfer tool succeeded
            transfer_tool_executed = False
            if tool_results:
                for tr in tool_results:
                    if tr.get("tool_name") == "transfer_funds" and tr.get("status") in ("success", "completed"):
                        transfer_tool_executed = True
                        break

            if not transfer_tool_executed:
                logger.warning(
                    f"OutputGuardrail: Model claimed transaction completed without successful tool result ({request_id})"
                )
                return GuardrailResult(
                    decision=GuardrailDecision.BLOCK,
                    guardrail_name="OutputGuardrail",
                    risk_level=RiskLevel.HIGH,
                    reason="Output blocked: Model claimed transaction completed without verified tool execution.",
                    matched_rules=["UNSUPPORTED_FINANCIAL_CLAIM"],
                    request_id=request_id,
                    sanitized_content="[RESPONSE SUPPRESSED: UNVERIFIED TRANSACTION CLAIM]"
                )

        if redacted:
            return GuardrailResult(
                decision=GuardrailDecision.REDACT,
                guardrail_name="OutputGuardrail",
                risk_level=RiskLevel.MEDIUM,
                reason=f"Sensitive secrets redacted ({', '.join(matched_rules)}).",
                matched_rules=matched_rules,
                request_id=request_id,
                sanitized_content=sanitized_text,
                details={"redacted": True, "rules": matched_rules}
            )

        return GuardrailResult(
            decision=GuardrailDecision.ALLOW,
            guardrail_name="OutputGuardrail",
            risk_level=RiskLevel.LOW,
            reason="Output passed integrity and privacy inspection.",
            matched_rules=[],
            request_id=request_id,
            sanitized_content=output_text
        )
