"""
VulNet AI Agent Security Lab - MCP Permission Checker
Level 2 Step 11: Secure MCP Tool Gateway

Enforces Role-Based Access Control (RBAC) on MCP tool invocation.
Evaluates caller identity/role against the tool's allowed_roles.
Prevents unauthorized tool execution outside the LLM.
"""

from typing import Any, Dict, List, Optional, Union
from auth.roles import Role, normalize_role


class MCPPermissionChecker:
    """
    Evaluates role permissions for tool execution.

    Supports:
    - FinTech personas: CUSTOMER, SUPPORT_AGENT, FRAUD_ANALYST, COMPLIANCE_ANALYST, ADMIN
    - Legacy lab personas: GUEST, USER, ADMIN
    - SessionContext objects containing .role
    """

    # Legacy hierarchy for backward compatibility
    LEGACY_HIERARCHY: Dict[str, int] = {
        "GUEST": 1,
        "CUSTOMER": 2,
        "USER": 2,
        "SUPPORT": 2,
        "SUPPORT_AGENT": 2,
        "FRAUD": 2,
        "FRAUD_ANALYST": 2,
        "COMPLIANCE": 2,
        "COMPLIANCE_ANALYST": 2,
        "ADMIN": 3,
        "ADMINISTRATOR": 3
    }

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def resolve_caller_role(self, caller: Any) -> str:
        """Extract a canonical uppercase string role from caller argument."""
        if caller is None:
            return "GUEST"

        # Check if caller is a SessionContext (duck-typing)
        if hasattr(caller, "role"):
            role_val = getattr(caller, "role")
            if isinstance(role_val, Role):
                return role_val.value
            return str(role_val).strip().upper()

        if isinstance(caller, Role):
            return caller.value

        if isinstance(caller, str):
            clean = caller.strip().upper()
            # If it's a known FinTech role or variant, normalize it
            try:
                norm = normalize_role(clean)
                return norm.value
            except ValueError:
                # Might be GUEST, USER, or custom
                return clean

        return str(caller).strip().upper()

    def check_permission(
        self,
        tool_name: str,
        caller_role: Any,
        allowed_roles: List[str],
        permission_required: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify whether caller_role has authorization to invoke the tool.

        Returns:
            Dict containing:
            - allowed (bool)
            - caller_role (str)
            - allowed_roles (List[str])
            - reason (str)
        """
        role_str = self.resolve_caller_role(caller_role)
        norm_allowed = [r.upper() for r in allowed_roles]

        # Universal access if "*" is in allowed roles
        if "*" in norm_allowed or "ALL" in norm_allowed:
            return {
                "allowed": True,
                "caller_role": role_str,
                "allowed_roles": norm_allowed,
                "reason": "Tool is publicly accessible to all roles."
            }

        # Direct match in allowed_roles list
        if role_str in norm_allowed:
            return {
                "allowed": True,
                "caller_role": role_str,
                "allowed_roles": norm_allowed,
                "reason": f"Role '{role_str}' is explicitly authorized."
            }

        # ADMIN override: ADMIN role is authorized if ADMIN is in allowed_roles
        if role_str in ("ADMIN", "ADMINISTRATOR") and any(r in ("ADMIN", "ADMINISTRATOR") for r in norm_allowed):
            return {
                "allowed": True,
                "caller_role": role_str,
                "allowed_roles": norm_allowed,
                "reason": "Administrative privilege granted."
            }

        # Legacy role check if permission_required is specified (e.g. READ_ONLY=1, USER=2, ADMIN=3)
        if permission_required:
            perm_req_levels = {"READ_ONLY": 1, "AUDIT": 1, "USER": 2, "ADMIN": 3}
            caller_lvl = self.LEGACY_HIERARCHY.get(role_str, 1)
            req_lvl = perm_req_levels.get(permission_required.upper(), 2)
            if caller_lvl >= req_lvl:
                return {
                    "allowed": True,
                    "caller_role": role_str,
                    "allowed_roles": norm_allowed,
                    "reason": f"Hierarchy privilege check passed for required '{permission_required}'."
                }

        # Unauthorized
        return {
            "allowed": False,
            "caller_role": role_str,
            "allowed_roles": norm_allowed,
            "reason": f"Insufficient privilege: role '{role_str}' cannot execute '{tool_name}'. Allowed roles: {norm_allowed}"
        }
