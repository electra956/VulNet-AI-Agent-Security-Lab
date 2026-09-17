"""
VulNet FinTech AI Agent Security Lab - Financial Policy Engine.
Level 2 Step 7: AI Security Gateway.

Enforces financial safety policies, cross-customer isolation invariants,
role-based constraints, and high-value transaction approval gates.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional

from auth.roles import Role, normalize_role
from auth.permissions import Permission, normalize_permission
from auth.authorization import has_permission


@dataclass
class PolicyViolation:
    """Record of a policy restriction or constraint violation."""
    policy: str             # e.g., "CROSS_CUSTOMER_ISOLATION", "HIGH_VALUE_TRANSFER_GATE"
    category: str           # e.g., "ASI03", "FINANCIAL_POLICY", "RBAC"
    severity: str           # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str             # Clear rationale explaining the policy
    requires_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    """
    Evaluates requests against organizational and financial domain policies.
    """

    def __init__(self, high_value_threshold: float = 10_000.0):
        self.high_value_threshold = high_value_threshold

    def evaluate_policies(
        self,
        text: str,
        session_context: Optional[Any] = None
    ) -> List[PolicyViolation]:
        """
        Evaluate text and session context against financial and identity policies.
        """
        violations: List[PolicyViolation] = []
        if not text:
            return violations

        # Extract session metadata safely
        user_id = None
        user_role = "CUSTOMER"
        user_accounts: List[str] = []

        if session_context is not None:
            if hasattr(session_context, "user_id"):
                user_id = getattr(session_context, "user_id")
                user_role = getattr(session_context, "role", "CUSTOMER")
                user_accounts = getattr(session_context, "account_ids", [])
            elif isinstance(session_context, dict):
                user_id = session_context.get("user_id")
                user_role = session_context.get("role", "CUSTOMER")
                user_accounts = session_context.get("account_ids", [])

        user_role_norm = Role.CUSTOMER
        try:
            if user_role:
                user_role_norm = normalize_role(user_role)
        except ValueError:
            user_role_norm = Role.CUSTOMER

        # -------------------------------------------------------------------
        # Policy 1: Cross-Customer Isolation (BOLA / ASI03)
        # -------------------------------------------------------------------
        if user_role_norm == Role.CUSTOMER and user_id:
            # Check for explicitly referenced customer IDs other than the caller
            cust_matches = re.findall(r"\b(CUST-\d{3})\b", text, re.IGNORECASE)
            for target_cust in cust_matches:
                if target_cust.upper() != user_id.upper():
                    violations.append(PolicyViolation(
                        policy="CROSS_CUSTOMER_ISOLATION",
                        category="ASI03",
                        severity="HIGH",
                        reason=(
                            f"Policy Violation: Customer '{user_id}' requested information or "
                            f"access for customer '{target_cust.upper()}'."
                        ),
                        requires_approval=False
                    ))
                    break

            # Check for explicitly referenced account IDs not owned by the caller
            acct_matches = re.findall(r"\b(ACC-\d{4})\b", text, re.IGNORECASE)
            for target_acct in acct_matches:
                if user_accounts and target_acct.upper() not in [a.upper() for a in user_accounts]:
                    # Allow unowned account if it is explicitly the destination/payee of a transfer
                    is_payee = bool(re.search(rf"\b(?:to|into|towards)\s+{re.escape(target_acct)}\b", text, re.IGNORECASE))
                    if not is_payee:
                        violations.append(PolicyViolation(
                            policy="CROSS_ACCOUNT_ISOLATION",
                            category="ASI03",
                            severity="HIGH",
                            reason=(
                                f"Policy Violation: Customer '{user_id}' requested access to unowned "
                                f"account '{target_acct.upper()}'."
                            ),
                            requires_approval=False
                        ))
                        break


        # -------------------------------------------------------------------
        # Policy 2: High-Value Financial Transfer Gate (Requires Approval)
        # -------------------------------------------------------------------
        amount_match = re.search(r"(?:\$|₹|rs\.?\s*|inr\s*)(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)", text, re.IGNORECASE)
        if not amount_match:
            amount_match = re.search(r"\b(?:transfer|send|wire|pay)\s+(?:\$|₹|rs\.?\s*|inr\s*)?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)\b", text, re.IGNORECASE)

        if amount_match:
            amount_str = amount_match.group(1).replace(",", "")
            try:
                amount = float(amount_str)
                if amount >= self.high_value_threshold:
                    violations.append(PolicyViolation(
                        policy="HIGH_VALUE_TRANSFER_GATE",
                        category="FINANCIAL_POLICY",
                        severity="MEDIUM",
                        reason=(
                            f"Financial Threshold Gate: Transfer amount ${amount:,.2f} exceeds standard "
                            f"approval threshold of ${self.high_value_threshold:,.2f} and requires manual approval."
                        ),
                        requires_approval=True
                    ))
            except ValueError:
                pass

        # -------------------------------------------------------------------
        # Policy 3: Sensitive Operational Keywords Restriction
        # -------------------------------------------------------------------
        lower_text = text.lower()
        if user_role_norm == Role.CUSTOMER:
            if any(term in lower_text for term in ["cancel transaction", "reverse wire", "override limit", "unfreeze all"]):
                violations.append(PolicyViolation(
                    policy="RESTRICTED_OPERATION_POLICY",
                    category="RBAC",
                    severity="HIGH",
                    reason="Policy Violation: Retail customers cannot execute administrative transaction overrides or cancellations.",
                    requires_approval=False
                ))

        return violations
