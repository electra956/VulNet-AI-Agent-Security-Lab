"""
VulNet FinTech AI Agent Security Lab - Layered Input Guardrail
Middleware component inspecting incoming user prompts before LLM or agent dispatch.
Enforces deterministic detection of prompt injections, goal hijacks, role overrides,
data exfiltration requests, and obfuscation.
"""

import base64
import logging
import re
from typing import Any, Dict, List, Optional

from security.guardrails.models import GuardrailDecision, GuardrailResult, RiskLevel

logger = logging.getLogger("vulnet.security.guardrails.input")


class InputGuardrail:
    """
    Evaluates incoming user input against deterministic security signatures,
    adversarial injection patterns, and protocol constraints.
    """

    MAX_INPUT_LENGTH = 4000

    INJECTION_PATTERNS = [
        (r"(?i)\bignore (?:all )?(?:previous |prior )?instructions\b", "ASI01_GOAL_HIJACK_IGNORE_INSTRUCTIONS"),
        (r"(?i)\bforget (?:all )?(?:your |the )?(?:previous )?(?:instructions|rules|policy)\b", "ASI01_GOAL_HIJACK_FORGET_POLICY"),
        (r"(?i)\boverride (?:all )?(?:your |security |system )?(?:rules|goals?|policies|policy|guardrails?|controls?)\b", "ASI01_GOAL_HIJACK_OVERRIDE_RULES"),
        (r"(?i)\b(?:system prompt override|new objective:|new instructions:)\b", "ASI01_GOAL_HIJACK_NEW_OBJECTIVE"),
        (r"(?i)\b(?:dan mode|developer mode|jailbreak)\b", "ROLE_MANIPULATION_DAN_JAILBREAK"),
        (r"(?i)\byou are now (?:an? )?(?:administrator|admin|root|superuser|developer mode|dan)\b", "ROLE_MANIPULATION_ADMIN"),
        (r"(?i)\bact as (?:an? )?(?:unrestricted|root|admin|system|evaluator)\b", "ROLE_MANIPULATION_ACT_AS"),
        (r"(?i)\b(?:reveal|print|show|dump|leak|repeat) (?:the |your )?(?:system prompt|system message|initial instructions)\b", "SYSTEM_PROMPT_EXTRACTION"),
        (r"(?i)\b(?:bypass|disable|ignore) (?:security|controls|mfa|guardrails|filters|firewall)\b", "SECURITY_POLICY_MANIPULATION"),
        (r"(?i)\b(?:export|dump|steal|exfiltrate) (?:all |the )?(?:database|users|passwords|accounts|credentials|tokens)\b", "DATA_EXFILTRATION_REQUEST"),
        (r"(?i)\b(?:drop table|union select|delete from|exec\s*\(|eval\s*\(|os\.system|subprocess)\b", "MALICIOUS_TOOL_CODE_INJECTION"),
        (r"(?i)\b(?:import os|import sys|__import__|subprocess\.Popen)\b", "DYNAMIC_CODE_EXECUTION_ASI05"),
        (r"(?i)\b(?:canary\w*|test_\w+|system_canary|auth[_\s]*token|internal[_\s]*config\w*)\b", "CANARY_SECRET_EXTRACTION"),
        (r"(?i)\b(?:print|reveal|output|display|show|export|dump)\s+(?:all\s+)?(?:internal\s+)?(?:secrets?|api\s*keys?|tokens?|credentials?|passwords?|configuration|config)\b", "SECRET_CREDENTIAL_EXTRACTION"),
        (r"(?i)\b(?:delegated message|unsigned message|spoofed message|\(unsigned\)|unsigned delegation)\b", "INTER_AGENT_SPOOFING_ASI07"),
        (r"(?i)\b(?:in a hypothetical|hypothetical scenario|pretend to|imagine you)\b.*(?:print|reveal|give|output|secret)", "HYPOTHETICAL_POLICY_BYPASS"),
    ]

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def _check_base64_payload(self, text: str) -> Optional[str]:
        """Scans for embedded Base64 chunks and attempts decoding to check for hidden instructions."""
        b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
        for chunk in b64_matches:
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                for pattern, rule_id in self.INJECTION_PATTERNS:
                    if re.search(pattern, decoded):
                        return f"BASE64_OBFUSCATED_{rule_id}"
            except Exception:
                continue
        return None

    def inspect(
        self,
        user_input: Optional[str],
        request_id: Optional[str] = None,
        session_context: Optional[Dict[str, Any]] = None
    ) -> GuardrailResult:
        """
        Inspect incoming user prompt.
        Returns GuardrailResult:
        - In Secure Mode: threats trigger GuardrailDecision.BLOCK
        - In Vulnerable Mode: threats trigger GuardrailDecision.ALLOW (flagged as simulation)
        """
        if user_input is None:
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="InputGuardrail",
                risk_level=RiskLevel.MEDIUM,
                reason="Input cannot be None.",
                matched_rules=["EMPTY_INPUT"],
                request_id=request_id
            )

        stripped = user_input.strip()
        if not stripped:
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="InputGuardrail",
                risk_level=RiskLevel.LOW,
                reason="Empty or whitespace-only input received.",
                matched_rules=["WHITESPACE_INPUT"],
                request_id=request_id
            )

        # 1. Structural / Length Constraints
        if len(stripped) > self.MAX_INPUT_LENGTH:
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="InputGuardrail",
                risk_level=RiskLevel.MEDIUM,
                reason=f"Input exceeds maximum allowed length ({len(stripped)} > {self.MAX_INPUT_LENGTH}).",
                matched_rules=["EXCESSIVE_LENGTH"],
                request_id=request_id
            )

        # 2. Obfuscation & Malformed Encodings
        if "\x00" in stripped or any(ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF] for c in stripped):
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="InputGuardrail",
                risk_level=RiskLevel.HIGH,
                reason="Malformed input contains null bytes or hidden zero-width unicode characters.",
                matched_rules=["OBFUSCATED_MALFORMED_INPUT"],
                request_id=request_id
            )

        b64_rule = self._check_base64_payload(stripped)
        if b64_rule:
            matched_rules = [b64_rule]
            if self.mode == "vulnerable":
                return GuardrailResult(
                    decision=GuardrailDecision.ALLOW,
                    guardrail_name="InputGuardrail",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Vulnerable mode: Base64 obfuscated payload allowed for simulation ({b64_rule}).",
                    matched_rules=matched_rules,
                    request_id=request_id,
                    is_simulation=True
                )
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="InputGuardrail",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Security alert: Malicious Base64 obfuscated payload detected ({b64_rule}).",
                matched_rules=matched_rules,
                request_id=request_id
            )

        # 3. Adversarial Prompt Injection and Intent Scans
        matched_rules: List[str] = []
        for pattern, rule_id in self.INJECTION_PATTERNS:
            if re.search(pattern, stripped):
                matched_rules.append(rule_id)

        if matched_rules:
            is_vuln = (self.mode == "vulnerable")
            if is_vuln:
                return GuardrailResult(
                    decision=GuardrailDecision.ALLOW,
                    guardrail_name="InputGuardrail",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Vulnerable mode enabled: Threat pattern allowed for simulation ({', '.join(matched_rules)}).",
                    matched_rules=matched_rules,
                    request_id=request_id,
                    is_simulation=True,
                    details={"mode": "vulnerable", "simulated_threat": True}
                )
            else:
                return GuardrailResult(
                    decision=GuardrailDecision.BLOCK,
                    guardrail_name="InputGuardrail",
                    risk_level=RiskLevel.CRITICAL if any("ASI01" in r or "CODE" in r for r in matched_rules) else RiskLevel.HIGH,
                    reason=f"Security alert: Malicious prompt intent detected ({matched_rules[0]}). Execution halted.",
                    matched_rules=matched_rules,
                    request_id=request_id,
                    is_simulation=False,
                    details={"mode": "secure", "blocked_rules": matched_rules}
                )

        return GuardrailResult(
            decision=GuardrailDecision.ALLOW,
            guardrail_name="InputGuardrail",
            risk_level=RiskLevel.LOW,
            reason="Input passed security inspection.",
            matched_rules=[],
            request_id=request_id
        )
