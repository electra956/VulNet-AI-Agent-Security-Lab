"""
VulNet AI Agent Security Lab - MCP Risk Evaluator
Level 2 Step 11: Secure MCP Tool Gateway

Evaluates tool risk classifications (LOW, MEDIUM, HIGH, CRITICAL)
and enforces human-in-the-loop approval gates.
High-risk tools cannot execute autonomously unless explicit user authorization is provided.
"""

from typing import Any, Dict


class MCPRiskEvaluator:
    """
    Evaluates tool risk posture and requires_approval policies.
    """

    RISK_SEVERITY_ORDER = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def evaluate_risk(
        self,
        tool_name: str,
        risk_level: str,
        requires_approval: bool,
        user_authorized: bool = False
    ) -> Dict[str, Any]:
        """
        Evaluate if tool execution is permitted given its risk level and approval status.

        Returns:
            Dict containing:
            - permitted (bool)
            - risk_level (str)
            - requires_approval (bool)
            - user_authorized (bool)
            - reason (str)
            - simulated (bool)
        """
        risk_norm = risk_level.upper()
        needs_human_approval = requires_approval or (risk_norm in ("HIGH", "CRITICAL"))

        if not needs_human_approval:
            return {
                "permitted": True,
                "risk_level": risk_norm,
                "requires_approval": False,
                "user_authorized": user_authorized,
                "reason": f"Tool '{tool_name}' is classified as {risk_norm} risk and does not require manual approval.",
                "simulated": False
            }

        # Needs approval: check if user_authorized is True
        if user_authorized:
            return {
                "permitted": True,
                "risk_level": risk_norm,
                "requires_approval": True,
                "user_authorized": True,
                "reason": f"Tool '{tool_name}' ({risk_norm} risk) explicitly approved by user.",
                "simulated": False
            }

        # Needs approval, but not authorized
        if self.mode == "secure":
            return {
                "permitted": False,
                "risk_level": risk_norm,
                "requires_approval": True,
                "user_authorized": False,
                "reason": f"Tool '{tool_name}' is high risk and requires explicit human authorization.",
                "simulated": False
            }
        else:
            # Vulnerable mode: allow simulation for demonstration
            return {
                "permitted": True,
                "risk_level": risk_norm,
                "requires_approval": True,
                "user_authorized": False,
                "reason": f"High-risk tool '{tool_name}' executed without authorization in Vulnerable Mode.",
                "simulated": True
            }
