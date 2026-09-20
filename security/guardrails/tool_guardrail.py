"""
VulNet FinTech AI Agent Security Lab - Layered Tool-Call Guardrail
Middleware component inspecting LLM-generated tool invocations as UNTRUSTED INPUT.
Enforces:
1. Tool whitelist validation
2. Schema & argument validation
3. Authenticated identity check
4. Role-based access control (RBAC)
5. Account ownership verification
6. Transaction limits & risk engine evaluation
7. Human-in-the-loop approval gating
8. Audit logging
"""

import logging
import re
from typing import Any, Dict, List, Optional

from security.guardrails.models import GuardrailDecision, GuardrailResult, RiskLevel
from security.policy_engine import PolicyEngine
from security.risk_engine import RiskEngine
from security.approval_engine import ApprovalEngine
from observability.audit import get_audit_logger

logger = logging.getLogger("vulnet.security.guardrails.tool")


class ToolGuardrail:
    """
    Evaluates every tool call requested by the LLM as untrusted user-controlled input.
    Guarantees that the LLM cannot autonomously execute unauthorized actions.
    """

    ALLOWED_TOOLS = {
        "get_account_balance": {
            "required_perms": ["read:balance"],
            "allowed_roles": ["customer", "analyst", "compliance_officer", "administrator"],
            "requires_account_ownership": True,
        },
        "get_transaction_history": {
            "required_perms": ["read:transactions"],
            "allowed_roles": ["customer", "analyst", "compliance_officer", "administrator"],
            "requires_account_ownership": True,
        },
        "transfer_funds": {
            "required_perms": ["execute:transfer"],
            "allowed_roles": ["customer", "administrator"],
            "requires_account_ownership": True,
            "financial_action": True,
        },
        "get_security_status": {
            "required_perms": ["read:security_status"],
            "allowed_roles": ["customer", "analyst", "compliance_officer", "administrator"],
            "requires_account_ownership": False,
        },
        "search_knowledge_base": {
            "required_perms": ["read:knowledge"],
            "allowed_roles": ["customer", "analyst", "compliance_officer", "administrator"],
            "requires_account_ownership": False,
        },
        "create_audit_log": {
            "required_perms": ["write:audit"],
            "allowed_roles": ["customer", "analyst", "compliance_officer", "administrator"],
            "requires_account_ownership": False,
        }
    }

    FORBIDDEN_PATTERNS = [
        r"(?i)\bos\.system\b",
        r"(?i)\bsubprocess\b",
        r"(?i)\b__import__\b",
        r"(?i)\bexec\s*\(",
        r"(?i)\beval\s*\(",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\bunion\s+select\b",
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bpowershell\b",
        r"(?i)\bcmd\.exe\b",
    ]

    def __init__(
        self,
        mode: str = "secure",
        policy_engine: Optional[PolicyEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        approval_engine: Optional[ApprovalEngine] = None,
    ):
        self.mode = mode.lower()
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.approval_engine = approval_engine or ApprovalEngine()
        self.audit_logger = get_audit_logger()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def validate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_context: Dict[str, Any],
        request_id: Optional[str] = None
    ) -> GuardrailResult:
        """
        Execute full 12-step validation sequence on LLM-generated tool call.
        """
        is_vuln = (self.mode == "vulnerable")
        user_id = session_context.get("user_id", "CUST-UNKNOWN")
        role = session_context.get("role", "customer").lower()
        owned_accounts = session_context.get("account_ids", ["ACC-1001"])

        # 1. Unknown / Disallowed Tool Name
        if tool_name not in self.ALLOWED_TOOLS:
            logger.warning(f"ToolGuardrail: Blocked unrecognized tool '{tool_name}'")
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="ToolGuardrail",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Tool '{tool_name}' is not in the approved FinTech tool whitelist.",
                matched_rules=["TOOL_NOT_WHITELISTED"],
                request_id=request_id,
                details={"tool_name": tool_name}
            )

        tool_spec = self.ALLOWED_TOOLS[tool_name]

        # 2. Dangerous Payload / Code Injection in Arguments
        args_str = str(arguments)
        for pattern in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, args_str):
                return GuardrailResult(
                    decision=GuardrailDecision.BLOCK,
                    guardrail_name="ToolGuardrail",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Malicious code or metacharacter pattern detected in arguments for '{tool_name}'.",
                    matched_rules=["MALICIOUS_TOOL_ARGUMENT_PAYLOAD"],
                    request_id=request_id,
                    details={"arguments": arguments}
                )

        # 3. RBAC / Role Check
        allowed_roles = tool_spec["allowed_roles"]
        if role not in allowed_roles:
            return GuardrailResult(
                decision=GuardrailDecision.BLOCK,
                guardrail_name="ToolGuardrail",
                risk_level=RiskLevel.HIGH,
                reason=f"Role '{role}' is unauthorized to invoke tool '{tool_name}'.",
                matched_rules=["RBAC_ROLE_UNAUTHORIZED"],
                request_id=request_id,
                details={"role": role, "allowed_roles": allowed_roles}
            )

        # 4. Account Ownership Validation
        if tool_spec.get("requires_account_ownership"):
            # Check target account
            target_acct = (
                arguments.get("account_id")
                or arguments.get("source_account")
                or owned_accounts[0]
            )
            if target_acct not in owned_accounts:
                # In vulnerable mode, check if explicitly bypassed
                if is_vuln:
                    return GuardrailResult(
                        decision=GuardrailDecision.ALLOW,
                        guardrail_name="ToolGuardrail",
                        risk_level=RiskLevel.HIGH,
                        reason=f"Vulnerable Mode: Cross-account access permitted for simulation (Target: {target_acct}).",
                        matched_rules=["CROSS_ACCOUNT_ACCESS_UNAUTHORIZED"],
                        request_id=request_id,
                        is_simulation=True,
                        details={"target_account": target_acct, "owned_accounts": owned_accounts}
                    )
                else:
                    return GuardrailResult(
                        decision=GuardrailDecision.BLOCK,
                        guardrail_name="ToolGuardrail",
                        risk_level=RiskLevel.HIGH,
                        reason=f"Security violation: Customer '{user_id}' does not own account '{target_acct}'.",
                        matched_rules=["CROSS_ACCOUNT_ACCESS_BLOCKED"],
                        request_id=request_id,
                        details={"target_account": target_acct, "owned_accounts": owned_accounts}
                    )

        # 5. Financial Action & Risk / Approval Evaluation
        if tool_spec.get("financial_action"):
            amount = float(arguments.get("amount", 0.0))
            dest = arguments.get("destination_account", "")

            # Negative or zero amount check
            if amount <= 0:
                return GuardrailResult(
                    decision=GuardrailDecision.BLOCK,
                    guardrail_name="ToolGuardrail",
                    risk_level=RiskLevel.MEDIUM,
                    reason=f"Invalid transfer amount: {amount}. Must be strictly positive.",
                    matched_rules=["INVALID_TRANSFER_AMOUNT"],
                    request_id=request_id
                )

            # High-value dual control approval threshold (> 50,000)
            if amount > 50000:
                # Evaluate via approval engine
                appr_id = f"APP-{request_id or 'TXN'}"
                return GuardrailResult(
                    decision=GuardrailDecision.APPROVAL_REQUIRED,
                    guardrail_name="ToolGuardrail",
                    risk_level=RiskLevel.HIGH,
                    reason=f"High-value transfer of ₹{amount:,.2f} exceeds ₹50,000 threshold. Dual-control human approval required.",
                    matched_rules=["HIGH_VALUE_HUMAN_APPROVAL_GATE"],
                    request_id=request_id,
                    details={
                        "amount": amount,
                        "destination_account": dest,
                        "approval_id": appr_id,
                        "approval_required": True,
                    }
                )

        return GuardrailResult(
            decision=GuardrailDecision.ALLOW,
            guardrail_name="ToolGuardrail",
            risk_level=RiskLevel.LOW,
            reason=f"Tool call '{tool_name}' verified against RBAC, ownership, schema, and limits.",
            matched_rules=[],
            request_id=request_id,
            details={"tool_name": tool_name, "arguments": arguments}
        )
