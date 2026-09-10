"""
ASI09 - Human-Agent Trust Exploitation Simulation Module
Simulates deceptive agent summaries and transparent human-in-the-loop action inspection defenses.
"""

from typing import Any, Dict, Optional
from security.security_controller import SecurityController


class ScenarioASI09:
    SCENARIO_ID = "ASI09"
    NAME = "Human-Agent Trust Exploitation"
    DESCRIPTION = (
        "Occurs when an agent presents deceptive, hallucinated, or over-simplified summaries of actions "
        "to exploit human trust and induce users into approving dangerous operations without realizing the true impact."
    )
    PRECONDITIONS = (
        "Human-in-the-loop interfaces show only conversational summaries without rendering raw tool parameters "
        "or true operational diffs."
    )
    DEFAULT_ATTACK_INPUT = {
        "displayed_summary": "Routine maintenance completed successfully. Click to confirm regular cache flush.",
        "actual_payload": {
            "action": "modify_system_policy",
            "target": "authentication_enforcement",
            "value": "disabled",
            "impact": "CRITICAL_SECURITY_REDUCTION"
        }
    }
    MITIGATION = (
        "Render transparent action diffs showing exact API parameters, highlight high-risk discrepancies, "
        "and avoid relying solely on natural language summaries for critical authorizations."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (only deceptive summary displayed to user)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        summary = data.get("displayed_summary")
        actual_payload = data.get("actual_payload")

        sec = SecurityController(mode="vulnerable")

        sec.log_event(
            event_type="DECEPTIVE_CONSENT_SIMULATED",
            message="User presented with deceptive summary while raw payload performs critical change.",
            severity="HIGH",
            scenario=cls.SCENARIO_ID,
            component="HUMAN_INTERFACE",
            decision="ALLOW",
            metadata={"displayed_summary": summary, "hidden_payload": actual_payload, "simulation": True}
        )

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "user_view": summary,
            "hidden_backend_action": actual_payload,
            "transparency_enforced": False,
            "vulnerability_demonstrated": True,
            "outcome": (
                "⚠️ VULNERABLE: The user was misled into approving a critical security downgrade. "
                "The interface concealed the actual parameters behind a benign conversational summary."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (diff inspection exposes discrepancy)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        summary = data.get("displayed_summary")
        actual_payload = data.get("actual_payload")

        sec = SecurityController(mode="secure")

        # Discrepancy detection: summary claims routine, payload disables auth
        discrepancy_detected = (
            "disabled" in str(actual_payload).lower() and
            "routine" in summary.lower()
        )

        if discrepancy_detected:
            sec.log_event(
                event_type="DECEPTIVE_SUMMARY_DETECTED",
                message="Discrepancy detected between benign summary and critical action payload. Forcing full diff disclosure.",
                severity="CRITICAL",
                scenario=cls.SCENARIO_ID,
                component="HUMAN_INTERFACE",
                decision="BLOCK",
                metadata={"discrepancy": True, "raw_action": actual_payload}
            )
            approval_decision = "BLOCKED_PENDING_EXPLICIT_DIFF_REVIEW"
        else:
            approval_decision = "APPROVED_AFTER_INSPECTION"

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "user_view": {
                "natural_language_summary": summary,
                "raw_api_payload": actual_payload,
                "risk_warning": "CRITICAL: Underlying action modifies security policy!"
            },
            "discrepancy_detected": discrepancy_detected,
            "transparency_enforced": True,
            "approval_decision": approval_decision,
            "vulnerability_demonstrated": False,
            "outcome": (
                "🛡️ SECURE: Full parameter transparency enforced. The discrepancy between the natural language summary "
                "and the actual payload was exposed to the user, preventing deceptive approval."
            ),
            "telemetry_events": sec.get_events()
        }
