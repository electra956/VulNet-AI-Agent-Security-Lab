"""
ASI02 - Tool Misuse and Exploitation Simulation Module
Simulates tool parameter injection and unauthorized tool execution attempts.
"""

from typing import Any, Dict, Optional
from mcp_server.server import MCPServer
from security.security_controller import SecurityController


class ScenarioASI02:
    SCENARIO_ID = "ASI02"
    NAME = "Tool Misuse and Exploitation"
    DESCRIPTION = (
        "Occurs when an agent is manipulated into invoking unapproved tools, "
        "or passes malicious/injected parameters to authorized tools causing unintended effects."
    )
    PRECONDITIONS = (
        "Agent has access to tool execution interfaces without strict parameter validation "
        "or tool capability bounding."
    )
    DEFAULT_ATTACK_INPUT = {
        "tool_name": "execute_data_export",
        "parameters": {
            "export_format": "json",
            "target_dataset": "telemetry; DROP TABLE users; --"
        }
    }
    MITIGATION = (
        "Enforce strict schema validation on all tool parameters, sanitize inputs against injection, "
        "and enforce least-privilege tool whitelisting."
    )

    @classmethod
    def run_vulnerable_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Vulnerable Mode (injected parameters execute in simulation)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        tool_name = data.get("tool_name", "execute_data_export")
        params = data.get("parameters", {})

        sec = SecurityController(mode="vulnerable")
        mcp = MCPServer(mode="vulnerable", security_controller=sec)

        result = mcp.execute_tool(tool_name, caller_role="USER", **params)

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "vulnerable",
            "tool_requested": tool_name,
            "parameters": params,
            "mcp_result": result,
            "vulnerability_demonstrated": True,
            "outcome": (
                "⚠️ VULNERABLE: The MCP server accepted tampered parameter syntax for simulation. "
                "In a real insecure system, this could lead to SQL/command injection or unauthorized data operations."
            ),
            "telemetry_events": sec.get_events()
        }

    @classmethod
    def run_secure_simulation(cls, attack_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute simulation in Secure Mode (parameter injection blocked)."""
        data = attack_input or cls.DEFAULT_ATTACK_INPUT
        tool_name = data.get("tool_name", "execute_data_export")
        params = data.get("parameters", {})

        sec = SecurityController(mode="secure")
        mcp = MCPServer(mode="secure", security_controller=sec)

        result = mcp.execute_tool(tool_name, caller_role="USER", **params)

        return {
            "scenario": cls.SCENARIO_ID,
            "name": cls.NAME,
            "mode": "secure",
            "tool_requested": tool_name,
            "parameters": params,
            "mcp_result": result,
            "vulnerability_demonstrated": False,
            "outcome": (
                "🛡️ SECURE: The MCP Server parameter validator detected dangerous characters/injection patterns. "
                "Tool execution was blocked before reaching the demo tool backend."
            ),
            "telemetry_events": sec.get_events()
        }
