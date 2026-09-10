"""
VulNet AI Agent Security Lab - Action Agent
Formulates and validates safe simulated actions based on research findings,
enforcing risk tiers and authorization gates (ASI02).
"""

from typing import Any, Dict, Optional


class ActionAgent:
    """
    Action Agent for the VulNet AI Agent Security Lab.

    Responsibilities:
    - Formulates simulated action proposals
    - Assesses operational risk tier (LOW, MEDIUM, HIGH)
    - Enforces authorization constraints in Secure Mode
    - Never triggers real infrastructure or external systems
    """

    def execute(
        self,
        user_request: str,
        research_result: Dict[str, Any],
        mode: str = "secure",
        user_authorized: bool = False
    ) -> Dict[str, Any]:
        """Formulate and validate a safe simulated action proposal."""
        if not research_result:
            return {
                "status": "blocked",
                "decision": "No research result was provided.",
                "action": "No action performed.",
                "risk_tier": "NONE"
            }

        documents_analyzed = research_result.get("documents_analyzed", 0)
        if documents_analyzed == 0:
            return {
                "status": "completed",
                "decision": "No relevant context was available.",
                "action": "No simulated action was performed because no relevant documents were found.",
                "risk_tier": "LOW",
                "documents_analyzed": 0
            }

        # Determine risk tier based on requested intent
        req_lower = user_request.lower()
        if any(term in req_lower for term in ["delete", "modify", "policy", "grant", "admin", "export all"]):
            risk_tier = "HIGH"
        elif any(term in req_lower for term in ["export", "download", "query"]):
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        # In Secure Mode, High-Risk actions require explicit authorization
        if mode == "secure" and risk_tier == "HIGH" and not user_authorized:
            action_message = f"""
## Action Agent Result

**User Request:** `{user_request}`

### Security Gate: Authorization Required
The requested action tier is **HIGH RISK**. In Secure Mode, administrative actions
require explicit human authorization before proposal execution.

- **Status:** ⚠️ PENDING_AUTHORIZATION
- **Risk Tier:** `HIGH`
- **Simulation:** Safe simulation halted pending approval.
"""
            return {
                "status": "pending_authorization",
                "decision": "High-risk action requires human authorization.",
                "action": action_message.strip(),
                "risk_tier": risk_tier,
                "documents_analyzed": documents_analyzed
            }

        action_message = f"""
## Action Agent Result

**User Request:** `{user_request}`

### Research Validation
The Action Agent validated findings across **{documents_analyzed} document(s)**.

### Simulated Action
The Action Agent approved a **safe simulated action** (Risk Tier: `{risk_tier}`).
No real systems, credentials, files, networks, or databases were modified.

### Security Posture
🟢 Safe simulation completed under {mode.upper()} mode.
"""
        return {
            "status": "completed",
            "decision": f"Safe simulated action approved (Risk: {risk_tier}).",
            "action": action_message.strip(),
            "risk_tier": risk_tier,
            "documents_analyzed": documents_analyzed
        }
