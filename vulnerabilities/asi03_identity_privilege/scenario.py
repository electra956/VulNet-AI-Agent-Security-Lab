"""
ASI03 - Identity and Privilege Abuse Simulation Module
Simulates privilege escalation and unauthorized role assumption attempts.
"""

from typing import Any, Dict, Optional
from mcp_server.server import MCPServer
from security.security_controller import SecurityController


class ScenarioASI03:
    SCENARIO_ID = "ASI03"
    NAME = "Identity and Privilege Abuse"
    DESCRIPTION = (
        "Occurs when an agent assumes improper identity contexts, bypasses role-based access control, "
        "or inherits excessive privileges without identity verification."
    )
    PRECONDITIONS = (
        "Role verification is missing, or the system assumes all agent requests possess administrative authority."
    )
    DEFAULT_ATTACK_INPUT = {
        "caller_role": "GUEST",
        "tool_name": "modify_system_policy",
        "parameters": {
            "policy_key": "require_mfa",
            "new_value": "false"
        }
    }
    MITIGATION = (
        "Enforce strict Role-Based Access Control (RBAC), verify cryptographic session tokens, "
        "and enforce least-privilege scoping on every tool invocation."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (privilege check bypassed)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        role = data.get("caller_role", "GUEST")
        tool_name = data.get("tool_name", "modify_system_policy")
        params = data.get("parameters", {})

        sec = SecurityController(mode="vulnerable")
        mcp = MCPServer(mode="vulnerable", security_controller=sec)

        result = mcp.execute_tool(tool_name, caller_role=role, **params)

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "caller_role": role,
            "tool_requested": tool_name,
            "mcp_result": result,
            "vulnerability_demonstrated": True,
            "outcome": (
                f"⚠️ VULNERABLE: Role '{role}' successfully invoked admin tool '{tool_name}' in simulation. "
                "The system lacked privilege boundaries."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (privilege violation blocked)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        role = data.get("caller_role", "GUEST")
        tool_name = data.get("tool_name", "modify_system_policy")
        params = data.get("parameters", {})

        sec = SecurityController(mode="secure")
        mcp = MCPServer(mode="secure", security_controller=sec)

        result = mcp.execute_tool(tool_name, caller_role=role, **params)

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "caller_role": role,
            "tool_requested": tool_name,
            "mcp_result": result,
            "vulnerability_demonstrated": False,
            "outcome": (
                f"🛡️ SECURE: Role '{role}' was denied execution of '{tool_name}'. "
                "Strict RBAC rejected the privilege escalation attempt."
            ),
            "telemetry_events": sec.get_events()
        }
