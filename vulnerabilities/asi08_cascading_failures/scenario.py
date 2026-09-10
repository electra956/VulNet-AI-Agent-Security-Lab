"""
ASI08 - Cascading Failures Simulation Module
Simulates unhandled error propagation across multi-agent pipelines and circuit-breaker isolation.
"""

from typing import Any, Dict, Optional
from security.security_controller import SecurityController


class ScenarioASI08:
    SCENARIO_ID = "ASI08"
    NAME = "Cascading Failures"
    DESCRIPTION = (
        "Occurs when an exception, malformed output, or timeout in one agent propagates unhandled "
        "through the agent graph, causing cascading system breakdowns, retry storms, or complete denial of service."
    )
    PRECONDITIONS = (
        "Agent pipelines lack circuit breakers, fault isolation boundaries, or fallback degradation strategies."
    )
    DEFAULT_ATTACK_INPUT = {
        "trigger_fault": "SIMULATED_MALFORMED_JSON_CORRUPTION",
        "affected_component": "RESEARCH_AGENT"
    }
    MITIGATION = (
        "Implement circuit breakers, fallback responses, timeout bounds, "
        "and isolated try/except fault containment boundaries for every agent and tool."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (unhandled error crashes pipeline)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        fault = data.get("trigger_fault")
        component = data.get("affected_component")

        sec = SecurityController(mode="vulnerable")

        # Simulate unhandled exception crashing downstream pipeline
        try:
            raise RuntimeError(f"Unchecked fatal exception in {component}: {fault}")
        except RuntimeError as exc:
            sec.log_event(
                event_type="CASCADING_FAILURE_UNCAUGHT",
                message=f"Pipeline crashed due to unhandled failure: {str(exc)}",
                severity="CRITICAL",
                scenario=cls.SCENARIO_ID,
                component=component,
                decision="CRASH",
                metadata={"error": str(exc), "simulation": True}
            )
            crash_report = {
                "crashed": True,
                "uncaught_exception": str(exc),
                "subsequent_agents_executed": False
            }

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "triggered_fault": fault,
            "pipeline_status": "CRASHED",
            "crash_details": crash_report,
            "vulnerability_demonstrated": True,
            "outcome": (
                "⚠️ VULNERABLE: A single component failure bubbled up uncaught, terminating the entire multi-agent workflow. "
                "The pipeline lacked fault isolation or circuit breaking."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (circuit breaker isolates error and degrades safely)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        fault = data.get("trigger_fault")
        component = data.get("affected_component")

        sec = SecurityController(mode="secure")

        # Circuit breaker containment
        try:
            raise RuntimeError(f"Exception in {component}: {fault}")
        except RuntimeError as exc:
            sec.log_event(
                event_type="CASCADING_FAILURE_CONTAINED",
                message=f"Fault in {component} contained by circuit breaker. Degrading to safe fallback response.",
                severity="HIGH",
                scenario=cls.SCENARIO_ID,
                component=component,
                decision="MITIGATE",
                metadata={"error": str(exc), "fallback_engaged": True}
            )
            fallback_response = {
                "crashed": False,
                "circuit_breaker_status": "OPEN_ISOLATED",
                "contained_error": str(exc),
                "safe_fallback_active": True,
                "message": "The pipeline experienced an isolated error, but gracefully degraded without crashing."
            }

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "triggered_fault": fault,
            "pipeline_status": "GRACEFULLY_DEGRADED",
            "fallback_details": fallback_response,
            "vulnerability_demonstrated": False,
            "outcome": (
                f"🛡️ SECURE: The circuit breaker intercepted the failure in {component}. "
                "The fault was isolated and the system returned a safe fallback response without crashing."
            ),
            "telemetry_events": sec.get_events()
        }
