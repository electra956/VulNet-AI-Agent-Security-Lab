"""
ASI10 - Rogue Agents Simulation Module
Simulates unauthorized autonomous sub-agent spawning, recursive drift, and governor quota limits.
"""

from typing import Any, Dict, Optional
from security.security_controller import SecurityController


class ScenarioASI10:
    SCENARIO_ID = "ASI10"
    NAME = "Rogue Agents"
    DESCRIPTION = (
        "Occurs when an agent operates beyond its intended design bounds, spawns unmonitored sub-agents, "
        "enters uncontrolled recursive loops, or consumes excessive operational quotas without human oversight."
    )
    PRECONDITIONS = (
        "The agent platform allows autonomous sub-agent orchestration without hard budget caps, "
        "recursion depth limits, or lifecycle supervisors."
    )
    DEFAULT_ATTACK_INPUT = {
        "requested_sub_agents": 12,
        "recursion_depth": 5,
        "max_allowed_workers": 3
    }
    MITIGATION = (
        "Enforce strict agent lifecycle management, limit maximum recursion depth, cap sub-agent spawn quotas, "
        "and maintain a supervisor circuit-breaker with kill-switch capabilities."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (rogue spawning unchecked)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        requested = data.get("requested_sub_agents", 12)
        depth = data.get("recursion_depth", 5)

        sec = SecurityController(mode="vulnerable")

        sec.log_event(
            event_type="ROGUE_AGENT_SPAWN_UNCHECKED",
            message=f"Agent autonomously spawned {requested} sub-workers at depth {depth} without governor bounds.",
            severity="CRITICAL",
            scenario=cls.SCENARIO_ID,
            component="AGENT_GOVERNOR",
            decision="ALLOW",
            metadata={"requested_workers": requested, "depth": depth, "simulation": True}
        )

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "requested_sub_agents": requested,
            "actual_spawned": requested,
            "governor_enforced": False,
            "vulnerability_demonstrated": True,
            "outcome": (
                f"⚠️ VULNERABLE: The agent autonomously spawned {requested} workers unchecked. "
                "In real deployment, this causes operational runaway, resource exhaustion, and loss of governance."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (governor limits enforced)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        requested = data.get("requested_sub_agents", 12)
        depth = data.get("recursion_depth", 5)
        max_allowed = data.get("max_allowed_workers", 3)

        sec = SecurityController(mode="secure")

        if requested > max_allowed or depth > 3:
            sec.log_event(
                event_type="ROGUE_AGENT_BEHAVIOR_THROTTLED",
                message=f"Agent exceeded quota limit ({requested} > {max_allowed}). Governor throttled rogue execution.",
                severity="CRITICAL",
                scenario=cls.SCENARIO_ID,
                component="AGENT_GOVERNOR",
                decision="BLOCK",
                metadata={"requested": requested, "limit": max_allowed, "throttled": True}
            )
            governor_status = "THROTTLED_AND_CAPPED"
            actual_spawned = max_allowed
        else:
            governor_status = "APPROVED_WITHIN_QUOTA"
            actual_spawned = requested

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "requested_sub_agents": requested,
            "max_allowed_limit": max_allowed,
            "actual_spawned": actual_spawned,
            "governor_status": governor_status,
            "governor_enforced": True,
            "vulnerability_demonstrated": False,
            "outcome": (
                f"🛡️ SECURE: Agent Governor enforced hard spawn caps. "
                f"Requested {requested} workers were throttled and clamped to maximum {max_allowed}."
            ),
            "telemetry_events": sec.get_events()
        }
