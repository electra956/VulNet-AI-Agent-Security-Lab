"""
VulNet AI Agent Security Lab - MCP Server / Secure Tool Gateway
Level 2 Step 11: Secure MCP Tool Gateway

Implements a security-controlled tool gateway adhering to defense-in-depth:
Agent
 ↓
MCP Gateway
 ↓
Tool Registry
 ↓
Permission Check
 ↓
Risk Check
 ↓
Argument Validation
 ↓
Execution Sandbox
 ↓
Tool
 ↓
Output Validation
 ↓
Audit
"""

from typing import Any, Dict, List, Optional
from mcp_server.registry import ToolMetadata, ToolRegistry
from mcp_server.permissions import MCPPermissionChecker
from mcp_server.risk import MCPRiskEvaluator
from mcp_server.validator import MCPArgumentValidator, MCPOutputValidator
from mcp_server.executor import ExecutionSandbox
from mcp_server.tools import SafeDemoTools, create_default_registry


class MCPServer:
    """
    Secure MCP Tool Gateway for the VulNet AI Agent Security Lab.

    Enforces:
    1. Tool Registry lookup & whitelisting (Unknown tools rejected)
    2. RBAC & caller permission verification (FinTech & legacy roles)
    3. Risk assessment & human-in-the-loop authorization gates
    4. Input argument validation & injection neutralization (ASI02)
    5. Isolated execution sandbox (strictly whitelisted handlers, no arbitrary execution)
    6. Output schema validation
    7. Educational audit telemetry logging
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

    def __init__(
        self,
        mode: str = "secure",
        security_controller: Optional[Any] = None,
        registry: Optional[ToolRegistry] = None
    ):
        self.mode = mode.lower()
        self.security_controller = security_controller
        self.registry = registry or create_default_registry()
        self.tools = SafeDemoTools()  # Kept for backward compatibility

        # Pipeline components
        self.permission_checker = MCPPermissionChecker(mode=self.mode)
        self.risk_evaluator = MCPRiskEvaluator(mode=self.mode)
        self.argument_validator = MCPArgumentValidator(mode=self.mode)
        self.output_validator = MCPOutputValidator()
        self.executor = ExecutionSandbox()

    def set_mode(self, mode: str) -> None:
        """Update operational mode across all gateway components."""
        self.mode = mode.lower()
        self.permission_checker.set_mode(self.mode)
        self.risk_evaluator.set_mode(self.mode)
        self.argument_validator.set_mode(self.mode)

    def set_security_controller(self, controller: Any) -> None:
        """Attach security controller for audit telemetry."""
        self.security_controller = controller

    def list_tools(self) -> List[str]:
        """Return list of all registered approved tool names."""
        return self.registry.list_tools()

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve registered metadata dictionary for a tool."""
        meta = self.registry.get(tool_name)
        return meta.to_dict() if meta else None

    def execute_tool(
        self,
        tool_name: str,
        caller_role: Any = "USER",
        user_authorized: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute an approved tool through the 7-stage security gateway pipeline:
        Registry -> Permission -> Risk -> Argument -> Sandbox -> Output -> Audit
        """
        # ==========================================
        # STAGE 1: TOOL REGISTRY LOOKUP
        # ==========================================
        tool_meta = self.registry.get(tool_name)
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

        # Determine permission required if legacy tool
        legacy_meta = self.tools.get_tool_metadata(tool_name)
        permission_required = legacy_meta.get("permission_required") if legacy_meta else None

        # ==========================================
        # STAGE 2: PERMISSION CHECK (ASI03)
        # ==========================================
        perm_res = self.permission_checker.check_permission(
            tool_name=tool_name,
            caller_role=caller_role,
            allowed_roles=tool_meta.allowed_roles,
            permission_required=permission_required
        )

        if not perm_res["allowed"]:
            if self.mode == "secure":
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="PRIVILEGE_VIOLATION_BLOCKED",
                        message=f"Role '{perm_res['caller_role']}' unauthorized for tool '{tool_name}'.",
                        severity="BLOCKED",
                        scenario="ASI03 - Identity and Privilege Abuse",
                        component="MCP",
                        decision="BLOCK",
                        metadata={"caller_role": perm_res["caller_role"], "tool": tool_name}
                    )
                return {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason": f"Insufficient privilege: role '{perm_res['caller_role']}' cannot execute '{tool_name}'.",
                    "scenario": "ASI03 - Identity and Privilege Abuse"
                }
            else:
                # Vulnerable mode: simulate privilege abuse
                if self.security_controller:
                    self.security_controller.log_event(
                        event_type="PRIVILEGE_ABUSE_SIMULATED",
                        message=f"Role '{perm_res['caller_role']}' allowed to execute '{tool_name}' in Vulnerable Mode simulation.",
                        severity="WARNING",
                        scenario="ASI03 - Identity and Privilege Abuse",
                        component="MCP",
                        decision="ALLOW",
                        metadata={"caller_role": perm_res["caller_role"], "tool": tool_name, "simulation": True}
                    )

        # ==========================================
        # STAGE 3: RISK CHECK & HUMAN APPROVAL
        # ==========================================
        risk_res = self.risk_evaluator.evaluate_risk(
            tool_name=tool_name,
            risk_level=tool_meta.risk_level,
            requires_approval=tool_meta.requires_approval,
            user_authorized=user_authorized
        )

        if not risk_res["permitted"]:
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="HIGH_RISK_AUTHORIZATION_REQUIRED",
                    message=f"High-risk tool '{tool_name}' blocked: requires explicit human authorization.",
                    severity="BLOCKED",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "risk": tool_meta.risk_level}
                )
            return {
                "status": "blocked",
                "tool": tool_name,
                "reason": f"Tool '{tool_name}' is high risk and requires explicit human authorization."
            }
        elif risk_res["simulated"]:
            # High-risk action allowed in Vulnerable Mode simulation
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="HIGH_RISK_ACTION_SIMULATED",
                    message=f"High-risk tool '{tool_name}' executed without authorization in Vulnerable Mode.",
                    severity="WARNING",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="ALLOW",
                    metadata={"tool": tool_name, "risk": tool_meta.risk_level, "simulation": True}
                )

        # Extract customer_id from caller_role context if available
        if hasattr(caller_role, "user_id") and "customer_id" not in kwargs:
            kwargs["customer_id"] = getattr(caller_role, "user_id")

        if tool_name == "create_simulated_transaction":
            kwargs.setdefault("user_authorized", user_authorized)
            kwargs.setdefault("caller_role", caller_role)

        # ==========================================
        # STAGE 4: ARGUMENT VALIDATION (ASI02)
        # ==========================================
        arg_res = self.argument_validator.validate_arguments(
            tool_name=tool_name,
            input_schema=tool_meta.input_schema,
            provided_kwargs=kwargs
        )

        if not arg_res["valid"]:
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="TOOL_PARAMETER_TAMPERING_BLOCKED",
                    message=f"Tool '{tool_name}' parameter injection detected: {arg_res.get('pattern')}",
                    severity="BLOCKED",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "parameter_check": arg_res}
                )
            return {
                "status": "blocked",
                "tool": tool_name,
                "reason": f"Parameter validation failed: {arg_res.get('reason')}",
                "scenario": "ASI02 - Tool Misuse and Exploitation"
            }
        elif arg_res.get("tampered") and self.mode == "vulnerable":
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="TOOL_PARAMETER_TAMPERING_ALLOWED",
                    message=f"Parameter injection detected in '{tool_name}', but allowed for simulation in Vulnerable Mode.",
                    severity="WARNING",
                    scenario="ASI02 - Tool Misuse and Exploitation",
                    component="MCP",
                    decision="ALLOW",
                    metadata={"tool": tool_name, "tampered_param": arg_res, "simulation": True}
                )

        # ==========================================
        # STAGE 5: EXECUTION SANDBOX
        # ==========================================
        result = self.executor.execute(tool_meta, arg_res["validated_args"])

        if result.get("status") == "blocked":
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="TOOL_ACCESS_DENIED",
                    message=f"Tool '{tool_name}' access blocked: {result.get('reason')}",
                    severity="BLOCKED",
                    scenario="ASI03 - Identity and Privilege Abuse",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "reason": result.get("reason")}
                )
            return result

        if result.get("status") == "error":
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="TOOL_EXECUTION_ERROR",
                    message=f"Tool '{tool_name}' execution failed: {result.get('reason')}",
                    severity="WARNING",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "error": result.get("reason")}
                )
            return result

        # ==========================================
        # STAGE 6: OUTPUT VALIDATION
        # ==========================================
        out_res = self.output_validator.validate_output(
            tool_name=tool_name,
            output_schema=tool_meta.output_schema,
            result=result
        )

        if not out_res["valid"]:
            if self.security_controller:
                self.security_controller.log_event(
                    event_type="TOOL_OUTPUT_VALIDATION_FAILED",
                    message=f"Output validation failed for '{tool_name}': {out_res.get('reason')}",
                    severity="WARNING",
                    component="MCP",
                    decision="BLOCK",
                    metadata={"tool": tool_name, "output_check": out_res}
                )
            if self.mode == "secure":
                return {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason": f"Output validation failed: {out_res.get('reason')}"
                }

        # ==========================================
        # STAGE 7: AUDIT & TELEMETRY LOGGING
        # ==========================================
        if self.security_controller and result.get("status") == "success":
            self.security_controller.log_event(
                event_type="TOOL_EXECUTION_COMPLETED",
                message=f"Tool '{tool_name}' executed successfully (Risk: {tool_meta.risk_level}).",
                severity="INFO",
                component="MCP",
                decision="ALLOW",
                metadata={"tool": tool_name, "risk_level": tool_meta.risk_level}
            )

        return result


# Alias for explicit gateway naming
MCPGateway = MCPServer
