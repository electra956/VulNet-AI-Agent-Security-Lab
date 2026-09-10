"""
VulNet AI Agent Security Lab - Safe Demonstration Tools
Provides simulated, safe educational tools with risk classifications and permission levels.

Security Boundary:
All tools are strictly simulated. No production databases, credentials,
external networks, or operating system shells are touched.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import re


class SafeDemoTools:
    """
    Safe demonstration tools for the VulNet AI Agent Security Lab.

    Every tool provides:
    - name
    - description
    - risk_level (LOW, MEDIUM, HIGH)
    - permission_required (READ_ONLY, AUDIT, USER, ADMIN)
    - input validation
    """

    TOOLS_REGISTRY: Dict[str, Dict[str, Any]] = {
        "get_security_status": {
            "name": "get_security_status",
            "description": "Return current security posture and simulation status.",
            "risk_level": "LOW",
            "permission_required": "READ_ONLY",
            "parameters": []
        },
        "check_tool_permission": {
            "name": "check_tool_permission",
            "description": "Verify whether a specific tool is approved for agent usage.",
            "risk_level": "LOW",
            "permission_required": "READ_ONLY",
            "parameters": ["requested_tool"]
        },
        "create_audit_log": {
            "name": "create_audit_log",
            "description": "Record an agent action in the local educational audit log.",
            "risk_level": "LOW",
            "permission_required": "AUDIT",
            "parameters": ["message"]
        },
        "execute_data_export": {
            "name": "execute_data_export",
            "description": "Simulate exporting non-sensitive laboratory telemetry data.",
            "risk_level": "MEDIUM",
            "permission_required": "USER",
            "parameters": ["export_format", "target_dataset"]
        },
        "modify_system_policy": {
            "name": "modify_system_policy",
            "description": "Simulate modifying security policies (High-Risk Admin Action).",
            "risk_level": "HIGH",
            "permission_required": "ADMIN",
            "parameters": ["policy_key", "new_value"]
        }
    }

    # Shell and injection metacharacters to detect in input parameters (ASI02)
    DANGEROUS_PARAM_PATTERNS = [
        r";", r"\|", r"&&", r"`", r"\$\(", r"__import__", r"eval\(", r"exec\("
    ]

    def validate_parameter(self, param_value: Any) -> Dict[str, Any]:
        """Validate input parameter to detect simulated injection/tampering attempts."""
        if not isinstance(param_value, str):
            return {"valid": True, "tampered": False}

        for pattern in self.DANGEROUS_PARAM_PATTERNS:
            if re.search(pattern, param_value):
                return {
                    "valid": False,
                    "tampered": True,
                    "pattern": pattern,
                    "reason": f"Suspicious parameter pattern detected: '{pattern}'"
                }
        return {"valid": True, "tampered": False}

    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for a registered tool."""
        return self.TOOLS_REGISTRY.get(tool_name)

    def list_tools(self) -> List[str]:
        """Return names of all available registered tools."""
        return list(self.TOOLS_REGISTRY.keys())

    def get_security_status(self) -> Dict[str, Any]:
        """Return simulated security status."""
        return {
            "status": "success",
            "tool": "get_security_status",
            "risk_level": "LOW",
            "result": {
                "environment": "Local Educational Lab",
                "production_access": False,
                "network_access": False,
                "credentials_used": False,
                "simulation_mode": True,
                "registered_tools_count": len(self.TOOLS_REGISTRY)
            }
        }

    def check_tool_permission(self, requested_tool: str) -> Dict[str, Any]:
        """Check whether a tool is approved in the registry."""
        approved = requested_tool in self.TOOLS_REGISTRY
        tool_meta = self.TOOLS_REGISTRY.get(requested_tool)

        return {
            "status": "success",
            "tool": "check_tool_permission",
            "risk_level": "LOW",
            "result": {
                "requested_tool": requested_tool,
                "approved": approved,
                "risk_level": tool_meta["risk_level"] if tool_meta else "UNKNOWN",
                "permission_required": tool_meta["permission_required"] if tool_meta else "NONE",
                "reason": (
                    "Tool is registered and permitted in this lab."
                    if approved
                    else f"Tool '{requested_tool}' is not approved in this lab."
                )
            }
        }

    def create_audit_log(self, message: str) -> Dict[str, Any]:
        """Create a simulated audit log."""
        timestamp = datetime.now().isoformat()
        return {
            "status": "success",
            "tool": "create_audit_log",
            "risk_level": "LOW",
            "result": {
                "timestamp": timestamp,
                "message": message,
                "location": "Simulated Local Audit Log",
                "real_system_modified": False
            }
        }

    def execute_data_export(self, export_format: str = "json", target_dataset: str = "telemetry") -> Dict[str, Any]:
        """Simulate data export tool (Medium Risk)."""
        return {
            "status": "success",
            "tool": "execute_data_export",
            "risk_level": "MEDIUM",
            "result": {
                "timestamp": datetime.now().isoformat(),
                "format": export_format,
                "dataset": target_dataset,
                "simulated_records_exported": 42,
                "simulation_only": True
            }
        }

    def modify_system_policy(self, policy_key: str, new_value: str) -> Dict[str, Any]:
        """Simulate administrative security policy modification (High Risk)."""
        return {
            "status": "success",
            "tool": "modify_system_policy",
            "risk_level": "HIGH",
            "result": {
                "timestamp": datetime.now().isoformat(),
                "policy_key": policy_key,
                "new_value": new_value,
                "status": "SIMULATED_POLICY_UPDATED",
                "real_system_modified": False
            }
        }
