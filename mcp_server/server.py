"""
VulNet AI Agent Security Lab - MCP Server
Implements Model Context Protocol simulation with authorization,
risk classification checks, parameter validation, and audit logging.
"""

from typing import Any, Dict, List, Optional
from mcp_server.tools import SafeDemoTools


class MCPServer:
    """
    MCP server for the VulNet AI Agent Security Lab.

    Enforces:
    - Tool registration and whitelist verification
    - Role-Based Access Control (RBAC: GUEST, USER, ADMIN)
    - Risk classification checks (LOW, MEDIUM, HIGH)
    - Input parameter sanitization and injection detection (ASI02)
    - Mode-aware behavior (Secure enforcement vs Vulnerable simulation)
    """

    ROLE_HIERARCHY = {
        "GUEST": 1,
        "USER": 2,
        "ADMIN": 3
    }

    PERMISSION_REQ = {
        "READ_ONLY": 1,
        "AUDIT": 1,
        "USER": 2,
        "ADMIN": 3
    }

    def __init__(self, mode: str = "secure", security_controller: Optional[Any] = None):
        self.mode = mode.lower()
        self.security_controller = security_controller
        self.tools = SafeDemoTools()

    def set_mode(self, mode: str) -> None:
        """Update operational mode."""
        self.mode = mode.lower()

    def set_security_controller(self, controller: Any) -> None:
        """Attach security controller for audit and event telemetry."""
        self.security_controller = controller

    def list_tools(self) -> List[str]:
        """Return the list of available safe tools."""
        return self.tools.list_tools()

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get registered metadata for a tool."""
        return self.tools.get_tool_metadata(tool_name)

    def execute_tool(
        self,
        tool_name: str,
        caller_role: str = "USER",
        user_authorized: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute an approved tool through security enforcement.
        """
        tool_meta = self.tools.get_tool_metadata(tool_name)

        # ------------------------------------------
        # 1. TOOL EXISTENCE CHECK
        # ------------------------------------------
        if not tool_meta:
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="UNAPPROVED_TOOL_INVOCATION",
                    message=f"Attempted execution of unapproved tool: '{tool_name}'",
                    severity="BLOCKED",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name}
                )
            return {
                "status": "blocked",
                "tool": tool_name,
                "reason": f"Tool '{tool_name}' is not approved in this MCP server."
            }

        risk_level = tool_meta["risk_level"]
        perm_required = tool_meta["permission_required"]

        # ------------------------------------------
        # 2. INPUT PARAMETER TAMPERING CHECK (ASI02)
        # ------------------------------------------
        tampered_param = None
        for key, value in kwargs.items():
            val_res = self.tools.validate_parameter(value)
            if val_res.get("tampered"):
                tampered_param = val_res
                break

        if tampered_param:
            if self.mode == "secure":
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="TOOL_PARAMETER_TAMPERING_BLOCKED",
                        message=f"Tool '{tool_name}' parameter injection detected: {tampered_param.get('pattern')}",
                        severity="BLOCKED",
                        scenario="ASI02 - Tool Misuse and Exploitation",
                        component="MCP",
                        decision="BLOCK",
                        metadata={"tool": tool_name, "parameter_check": tampered_param}
                    )
                return {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason": f"Parameter validation failed: {tampered_param.get('reason')}",
                    "scenario": "ASI02 - Tool Misuse and Exploitation"
                }
            else:
                # Vulnerable Mode: allow simulation of parameter tampering
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="TOOL_PARAMETER_TAMPERING_ALLOWED",
                        message=f"Parameter injection detected in '{tool_name}', but allowed for simulation in Vulnerable Mode.",
                        severity="WARNING",
                        scenario="ASI02 - Tool Misuse and Exploitation",
                        component="MCP",
                        decision="ALLOW",
                        metadata={"tool": tool_name, "tampered_param": tampered_param, "simulation": True}
                    )

        # ------------------------------------------
        # 3. RBAC & PERMISSION CHECK (ASI03)
        # ------------------------------------------
        caller_level = self.ROLE_HIERARCHY.get(caller_role.upper(), 1)
        required_level = self.PERMISSION_REQ.get(perm_required, 2)

        if caller_level < required_level:
            if self.mode == "secure":
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="PRIVILEGE_VIOLATION_BLOCKED",
                        message=f"Role '{caller_role}' unauthorized for tool '{tool_name}' requiring '{perm_required}'.",
                        severity="BLOCKED",
                        scenario="ASI03 - Identity and Privilege Abuse",
                        component="MCP",
                        decision="BLOCK",
                        metadata={"caller_role": caller_role, "required_permission": perm_required}
                    )
                return {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason": f"Insufficient privilege: role '{caller_role}' cannot execute '{tool_name}'.",
                    "scenario": "ASI03 - Identity and Privilege Abuse"
                }
            else:
                # Vulnerable Mode: simulate unauthorized privilege escalation
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="PRIVILEGE_ABUSE_SIMULATED",
                        message=f"Role '{caller_role}' allowed to execute '{tool_name}' in Vulnerable Mode simulation.",
                        severity="WARNING",
                        scenario="ASI03 - Identity and Privilege Abuse",
                        component="MCP",
                        decision="ALLOW",
                        metadata={"caller_role": caller_role, "tool": tool_name, "simulation": True}
                    )

        # ------------------------------------------
        # 4. HIGH-RISK HUMAN AUTHORIZATION CHECK
        # ------------------------------------------
        if risk_level == "HIGH" and not user_authorized:
            if self.mode == "secure":
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="HIGH_RISK_AUTHORIZATION_REQUIRED",
                        message=f"High-risk tool '{tool_name}' blocked: requires explicit human authorization.",
                        severity="BLOCKED",
                        scenario="ASI02 - Tool Misuse and Exploitation",
                        component="MCP",
                        decision="BLOCK",
                        metadata={"tool": tool_name, "risk": risk_level}
                    )
                return {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason": f"Tool '{tool_name}' is high risk and requires explicit human authorization."
                }
            else:
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="HIGH_RISK_ACTION_SIMULATED",
                        message=f"High-risk tool '{tool_name}' executed without authorization in Vulnerable Mode.",
                        severity="WARNING",
                        scenario="ASI02 - Tool Misuse and Exploitation",
                        component="MCP",
                        decision="ALLOW",
                        metadata={"tool": tool_name, "risk": risk_level, "simulation": True}
                    )

        # ------------------------------------------
        # 5. ROUTE TO APPROVED SAFE TOOL
        # ------------------------------------------
        if tool_name == "get_security_status":
            result = self.tools.get_security_status()
        elif tool_name == "check_tool_permission":
            requested_tool = kwargs.get("requested_tool", "")
            result = self.tools.check_tool_permission(requested_tool)
        elif tool_name == "create_audit_log":
            message = kwargs.get("message", "Agent action executed.")
            result = self.tools.create_audit_log(message)
        elif tool_name == "execute_data_export":
            fmt = kwargs.get("export_format", "json")
            target = kwargs.get("target_dataset", "telemetry")
            result = self.tools.execute_data_export(fmt, target)
        elif tool_name == "modify_system_policy":
            key = kwargs.get("policy_key", "default")
            val = kwargs.get("new_value", "updated")
            result = self.tools.modify_system_policy(key, val)
        else:
            result = {
                "status": "blocked",
                "tool": tool_name,
                "reason": "Unhandled tool mapping."
            }

        # Telemetry log of successful tool execution
        if self.security_controller and result.get("status") == "success":
            self.security_controller.log_event(
                event_type="TOOL_EXECUTION_COMPLETED",
                message=f"Tool '{tool_name}' executed successfully (Risk: {risk_level}).",
                severity="INFO",
                component="MCP",
                decision="ALLOW",
                metadata={"tool": tool_name, "risk_level": risk_level}
            )

        return result
