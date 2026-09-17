"""
VulNet AI Agent Security Lab - Safe Demonstration & FinTech Lab Tools
Level 2 Step 12: Simulated FinTech Tool Ecosystem

Provides:
- SafeDemoTools: Legacy safe tools for backward compatibility with Level 1 scenarios.
- FinTechToolSuite: Simulated FinTech educational tools across 6 categories:
  1. ACCOUNT: get_account_balance, get_account_status, get_customer_profile, get_transaction_history
  2. PAYMENT: create_payment, schedule_payment, cancel_payment
  3. CARD: get_card_status, freeze_card, unfreeze_card
  4. FRAUD: check_transaction_risk, flag_transaction, get_fraud_case
  5. KYC: get_kyc_status, verify_identity_simulated
  6. SUPPORT: create_support_ticket, send_simulated_notification
- create_default_registry(): Builds a ToolRegistry loaded with all approved tools,
  schemas, risk classifications, allowed roles, and handlers.

Security Boundary:
All tools are strictly simulated. No production databases, credentials,
external networks, or operating system shells are touched.
"""

from datetime import datetime
import re
from typing import Any, Dict, List, Optional

from mcp_server.registry import ToolMetadata, ToolRegistry
from mcp_server.fintech_tools import FinTechToolSuite


class SafeDemoTools:
    """
    Safe demonstration tools for the VulNet AI Agent Security Lab.
    Retained for complete backward compatibility.
    """

    TOOLS_REGISTRY: Dict[str, Dict[str, Any]] = {
        "get_security_status": {
            "name": "get_security_status",
            "description": "Return current security posture and simulation status.",
            "risk_level": "LOW",
            "permission_required": "READ_ONLY",
            "allowed_roles": ["*"],
            "requires_approval": False,
            "parameters": []
        },
        "check_tool_permission": {
            "name": "check_tool_permission",
            "description": "Verify whether a specific tool is approved for agent usage.",
            "risk_level": "LOW",
            "permission_required": "READ_ONLY",
            "allowed_roles": ["*"],
            "requires_approval": False,
            "parameters": ["requested_tool"]
        },
        "create_audit_log": {
            "name": "create_audit_log",
            "description": "Record an agent action in the local educational audit log.",
            "risk_level": "LOW",
            "permission_required": "AUDIT",
            "allowed_roles": ["AUDIT", "USER", "CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "COMPLIANCE_ANALYST", "ADMIN"],
            "requires_approval": False,
            "parameters": ["message"]
        },
        "execute_data_export": {
            "name": "execute_data_export",
            "description": "Simulate exporting non-sensitive laboratory telemetry data.",
            "risk_level": "MEDIUM",
            "permission_required": "USER",
            "allowed_roles": ["USER", "SUPPORT_AGENT", "FRAUD_ANALYST", "COMPLIANCE_ANALYST", "ADMIN"],
            "requires_approval": False,
            "parameters": ["export_format", "target_dataset"]
        },
        "modify_system_policy": {
            "name": "modify_system_policy",
            "description": "Simulate modifying security policies (High-Risk Admin Action).",
            "risk_level": "HIGH",
            "permission_required": "ADMIN",
            "allowed_roles": ["ADMIN", "ADMINISTRATOR"],
            "requires_approval": True,
            "parameters": ["policy_key", "new_value"]
        }
    }

    DANGEROUS_PARAM_PATTERNS = [
        r";", r"\|", r"&&", r"`", r"\$\(", r"__import__", r"eval\(", r"exec\(", r"rm\s+-rf", r"(?i)drop\s+table"
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

    def check_tool_permission(self, requested_tool: str = "") -> Dict[str, Any]:
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

    def create_audit_log(self, message: str = "Agent action executed.") -> Dict[str, Any]:
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

    def modify_system_policy(self, policy_key: str = "default", new_value: str = "updated") -> Dict[str, Any]:
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


class FinTechSafeTools:
    """Legacy safe tools for Step 11 backward compatibility."""
    @staticmethod
    def create_transfer_simulation(from_account: str, to_account: str, amount: float, **kwargs) -> Dict[str, Any]:
        return {
            "status": "success",
            "tool": "create_transfer_simulation",
            "risk_level": "HIGH",
            "result": {
                "transfer_id": f"XFR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "from_account": from_account,
                "to_account": to_account,
                "amount": amount,
                "status": "SIMULATED_TRANSFERRED",
                "real_funds_moved": False
            }
        }

    @staticmethod
    def freeze_card_simulation(card_id: str, reason: str = "Customer request", **kwargs) -> Dict[str, Any]:
        return {
            "status": "success",
            "tool": "freeze_card_simulation",
            "risk_level": "HIGH",
            "result": {
                "card_id": card_id,
                "status": "FROZEN",
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            }
        }


# Singleton suite instance for shared tool registry state
_DEFAULT_FINTECH_SUITE = FinTechToolSuite()


def create_default_registry(fintech_suite: Optional[FinTechToolSuite] = None) -> ToolRegistry:
    """
    Construct and return the default ToolRegistry populated with:
    - 5 Safe Demo Tools (Level 1)
    - 16 Simulated FinTech Tools across 6 categories (Level 2)
    """
    registry = ToolRegistry()
    safe_demo = SafeDemoTools()
    ft = fintech_suite or _DEFAULT_FINTECH_SUITE

    # =========================================================================
    # SAFE DEMO TOOLS (Level 1 Backward Compatibility)
    # =========================================================================
    registry.register(ToolMetadata(
        name="get_security_status",
        description="Return current security posture and simulation status.",
        risk_level="LOW",
        allowed_roles=["*"],
        requires_approval=False,
        input_schema={"properties": {}, "required": []},
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=safe_demo.get_security_status
    ))

    registry.register(ToolMetadata(
        name="check_tool_permission",
        description="Verify whether a specific tool is approved for agent usage.",
        risk_level="LOW",
        allowed_roles=["*"],
        requires_approval=False,
        input_schema={
            "properties": {
                "requested_tool": {"type": "string"}
            },
            "required": []
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=safe_demo.check_tool_permission
    ))

    registry.register(ToolMetadata(
        name="create_audit_log",
        description="Record an agent action in the local educational audit log.",
        risk_level="LOW",
        allowed_roles=["AUDIT", "USER", "CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "COMPLIANCE_ANALYST", "ADMIN"],
        requires_approval=False,
        input_schema={
            "properties": {
                "message": {"type": "string"}
            },
            "required": ["message"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=safe_demo.create_audit_log
    ))

    registry.register(ToolMetadata(
        name="execute_data_export",
        description="Simulate exporting non-sensitive laboratory telemetry data.",
        risk_level="MEDIUM",
        allowed_roles=["USER", "SUPPORT_AGENT", "FRAUD_ANALYST", "COMPLIANCE_ANALYST", "ADMIN"],
        requires_approval=False,
        input_schema={
            "properties": {
                "export_format": {"type": "string"},
                "target_dataset": {"type": "string"}
            },
            "required": []
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=safe_demo.execute_data_export
    ))

    registry.register(ToolMetadata(
        name="modify_system_policy",
        description="Simulate modifying security policies (High-Risk Admin Action).",
        risk_level="HIGH",
        allowed_roles=["ADMIN", "ADMINISTRATOR"],
        requires_approval=True,
        input_schema={
            "properties": {
                "policy_key": {"type": "string"},
                "new_value": {"type": "string"}
            },
            "required": []
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=safe_demo.modify_system_policy
    ))

    # =========================================================================
    # CATEGORY 1: ACCOUNT
    # =========================================================================
    registry.register(ToolMetadata(
        name="get_account_balance",
        description="Retrieve account balance details with customer ownership validation.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "account_id": {"type": "string"},
                "customer_id": {"type": "string"}
            },
            "required": ["account_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_account_balance
    ))

    registry.register(ToolMetadata(
        name="get_account_status",
        description="Retrieve account status, account type, and operational status.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "account_id": {"type": "string"},
                "customer_id": {"type": "string"}
            },
            "required": ["account_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_account_status
    ))

    registry.register(ToolMetadata(
        name="get_customer_profile",
        description="Retrieve customer profile and list of owned accounts.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "COMPLIANCE_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "customer_id": {"type": "string"}
            },
            "required": ["customer_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_customer_profile
    ))

    registry.register(ToolMetadata(
        name="get_transaction_history",
        description="Retrieve transaction history for an authorized account.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "account_id": {"type": "string"},
                "customer_id": {"type": "string"},
                "limit": {"type": "integer"}
            },
            "required": ["account_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_transaction_history
    ))

    # =========================================================================
    # CATEGORY 2: PAYMENT
    # =========================================================================
    registry.register(ToolMetadata(
        name="create_payment",
        description="Simulate transferring funds between customer accounts (High-Risk).",
        risk_level="HIGH",
        allowed_roles=["CUSTOMER", "ADMIN", "USER"],
        requires_approval=True,
        input_schema={
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
                "customer_id": {"type": "string"},
                "description": {"type": "string"}
            },
            "required": ["from_account", "to_account", "amount"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.create_payment
    ))

    # Alias for create_payment
    registry.register(ToolMetadata(
        name="create_transfer_simulation",
        description="Alias for create_payment.",
        risk_level="HIGH",
        allowed_roles=["CUSTOMER", "ADMIN", "USER"],
        requires_approval=True,
        input_schema={
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
                "customer_id": {"type": "string"}
            },
            "required": ["from_account", "to_account", "amount"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=FinTechSafeTools.create_transfer_simulation
    ))

    # Step 17 simulated financial transaction tool
    registry.register(ToolMetadata(
        name="create_simulated_transaction",
        description="Execute simulated financial transaction with full independent MCP authorization checks.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "ADMIN", "USER"],
        requires_approval=False,  # Evaluated dynamically by handler based on amount/risk
        input_schema={
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
                "customer_id": {"type": "string"},
                "currency": {"type": "string"},
                "description": {"type": "string"}
            },
            "required": ["from_account", "to_account", "amount"]
        },
        output_schema={"required": ["status", "tool", "result"]},
        handler=ft.create_simulated_transaction
    ))


    registry.register(ToolMetadata(
        name="schedule_payment",
        description="Schedule a future simulated payment.",
        risk_level="MEDIUM",
        allowed_roles=["CUSTOMER", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
                "execution_date": {"type": "string"},
                "customer_id": {"type": "string"}
            },
            "required": ["from_account", "to_account", "amount", "execution_date"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.schedule_payment
    ))

    registry.register(ToolMetadata(
        name="cancel_payment",
        description="Cancel a pending scheduled payment.",
        risk_level="MEDIUM",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "payment_id": {"type": "string"},
                "customer_id": {"type": "string"}
            },
            "required": ["payment_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.cancel_payment
    ))

    # =========================================================================
    # CATEGORY 3: CARD
    # =========================================================================
    registry.register(ToolMetadata(
        name="get_card_status",
        description="Retrieve status of a debit/credit card.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "card_id": {"type": "string"},
                "customer_id": {"type": "string"}
            },
            "required": ["card_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_card_status
    ))

    registry.register(ToolMetadata(
        name="freeze_card",
        description="Freeze a compromised or requested payment card (High-Risk).",
        risk_level="HIGH",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=True,
        input_schema={
            "properties": {
                "card_id": {"type": "string"},
                "customer_id": {"type": "string"},
                "reason": {"type": "string"}
            },
            "required": ["card_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.freeze_card
    ))

    # Alias for freeze_card
    registry.register(ToolMetadata(
        name="freeze_card_simulation",
        description="Alias for freeze_card.",
        risk_level="HIGH",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=True,
        input_schema={
            "properties": {
                "card_id": {"type": "string"},
                "reason": {"type": "string"}
            },
            "required": ["card_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=FinTechSafeTools.freeze_card_simulation
    ))

    registry.register(ToolMetadata(
        name="unfreeze_card",
        description="Unfreeze a previously frozen payment card (High-Risk).",
        risk_level="HIGH",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=True,
        input_schema={
            "properties": {
                "card_id": {"type": "string"},
                "customer_id": {"type": "string"},
                "reason": {"type": "string"}
            },
            "required": ["card_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.unfreeze_card
    ))

    # =========================================================================
    # CATEGORY 4: FRAUD
    # =========================================================================
    registry.register(ToolMetadata(
        name="check_transaction_risk",
        description="Evaluate transaction against heuristic risk rules.",
        risk_level="LOW",
        allowed_roles=["FRAUD_ANALYST", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "transaction_id": {"type": "string"},
                "amount": {"type": "number"}
            },
            "required": ["transaction_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.check_transaction_risk
    ))

    registry.register(ToolMetadata(
        name="flag_transaction",
        description="Flag a transaction as suspicious for fraud investigation.",
        risk_level="MEDIUM",
        allowed_roles=["FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "transaction_id": {"type": "string"},
                "suspicion_reason": {"type": "string"}
            },
            "required": ["transaction_id", "suspicion_reason"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.flag_transaction
    ))

    # Alias for flag_transaction
    registry.register(ToolMetadata(
        name="flag_fraud_simulation",
        description="Alias for flag_transaction.",
        risk_level="MEDIUM",
        allowed_roles=["FRAUD_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "transaction_id": {"type": "string"},
                "suspicion_reason": {"type": "string"}
            },
            "required": ["transaction_id", "suspicion_reason"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.flag_transaction
    ))

    registry.register(ToolMetadata(
        name="get_fraud_case",
        description="Retrieve details of an active fraud investigation case.",
        risk_level="LOW",
        allowed_roles=["FRAUD_ANALYST", "COMPLIANCE_ANALYST", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "case_id": {"type": "string"}
            },
            "required": ["case_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_fraud_case
    ))

    # =========================================================================
    # CATEGORY 5: KYC
    # =========================================================================
    registry.register(ToolMetadata(
        name="get_kyc_status",
        description="Retrieve customer identity verification (KYC) status.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "COMPLIANCE_ANALYST", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "customer_id": {"type": "string"}
            },
            "required": ["customer_id"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.get_kyc_status
    ))

    registry.register(ToolMetadata(
        name="verify_identity_simulated",
        description="Simulate synthetic identity verification for KYC compliance.",
        risk_level="MEDIUM",
        allowed_roles=["COMPLIANCE_ANALYST", "ADMIN"],
        requires_approval=False,
        input_schema={
            "properties": {
                "customer_id": {"type": "string"},
                "document_type": {"type": "string"},
                "document_number": {"type": "string"}
            },
            "required": ["customer_id", "document_type", "document_number"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.verify_identity_simulated
    ))

    # =========================================================================
    # CATEGORY 6: SUPPORT
    # =========================================================================
    registry.register(ToolMetadata(
        name="create_support_ticket",
        description="Create a customer assistance support ticket.",
        risk_level="LOW",
        allowed_roles=["CUSTOMER", "SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "customer_id": {"type": "string"},
                "subject": {"type": "string"},
                "description": {"type": "string"},
                "priority": {"type": "string"}
            },
            "required": ["customer_id", "subject", "description"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.create_support_ticket
    ))

    registry.register(ToolMetadata(
        name="send_simulated_notification",
        description="Simulate dispatching a multi-channel notification to a customer.",
        risk_level="LOW",
        allowed_roles=["SUPPORT_AGENT", "ADMIN", "USER"],
        requires_approval=False,
        input_schema={
            "properties": {
                "customer_id": {"type": "string"},
                "message": {"type": "string"},
                "channel": {"type": "string"}
            },
            "required": ["customer_id", "message"]
        },
        output_schema={"required": ["status", "tool", "risk_level", "result"]},
        handler=ft.send_simulated_notification
    ))

    return registry
