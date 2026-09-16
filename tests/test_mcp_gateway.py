"""
VulNet AI Agent Security Lab - MCP Tool Gateway Tests
Level 2 Step 11: Secure MCP Tool Gateway

Validates:
- registered tool
- unknown tool
- unauthorized tool
- invalid arguments
- high-risk tool
- output validation
- tool audit
- arbitrary execution prevention
- FinTech role compatibility
"""

import pytest
from mcp_server.server import MCPServer, MCPGateway
from mcp_server.registry import ToolMetadata, ToolRegistry
from mcp_server.validator import MCPOutputValidator
from security.security_controller import SecurityController
from auth.roles import Role
from chatbot.sessions.session_manager import SessionContext


def test_registered_tool_execution():
    """Verify approved registered tools execute cleanly and return valid schemas."""
    mcp = MCPGateway(mode="secure")

    # 1. get_security_status
    res1 = mcp.execute_tool("get_security_status")
    assert res1["status"] == "success"
    assert res1["tool"] == "get_security_status"
    assert res1["risk_level"] == "LOW"
    assert res1["result"]["simulation_mode"] is True

    # 2. get_account_balance (FinTech safe tool)
    res2 = mcp.execute_tool("get_account_balance", caller_role="CUSTOMER", account_id="ACC-1001")
    assert res2["status"] == "success"
    assert res2["result"]["account_id"] == "ACC-1001"
    assert res2["result"]["balance"] > 0

    # 3. get_tool_info metadata verification
    info = mcp.get_tool_info("get_account_balance")
    assert info is not None
    assert info["name"] == "get_account_balance"
    assert info["risk_level"] == "LOW"
    assert "CUSTOMER" in info["allowed_roles"]
    assert "account_id" in info["input_schema"]["properties"]
    assert "result" in info["output_schema"]["required"]


def test_unknown_tool_rejection():
    """Verify unknown or unwhitelisted tools are immediately rejected."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    res = mcp.execute_tool("unapproved_hack_script", caller_role="ADMIN")
    assert res["status"] == "blocked"
    assert "not approved" in res["reason"].lower()

    events = sec.get_events()
    assert any(e["event_type"] == "UNAPPROVED_TOOL_INVOCATION" for e in events)


def test_unauthorized_tool_invocation():
    """Verify RBAC blocks callers lacking permitted roles."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    # 1. CUSTOMER attempting ADMIN policy change
    res_customer = mcp.execute_tool(
        "modify_system_policy",
        caller_role="CUSTOMER",
        policy_key="mfa_policy",
        new_value="disabled"
    )
    assert res_customer["status"] == "blocked"
    assert "insufficient privilege" in res_customer["reason"].lower()

    # 2. GUEST attempting user tool
    res_guest = mcp.execute_tool(
        "execute_data_export",
        caller_role="GUEST",
        target_dataset="audit"
    )
    assert res_guest["status"] == "blocked"
    assert "insufficient privilege" in res_guest["reason"].lower()

    # Check security controller logged privilege violations
    events = sec.get_events()
    assert any(e["event_type"] == "PRIVILEGE_VIOLATION_BLOCKED" for e in events)


def test_unauthorized_tool_vulnerable_simulation():
    """Verify Vulnerable Mode permits simulation with warnings."""
    sec = SecurityController(mode="vulnerable")
    mcp = MCPServer(mode="vulnerable", security_controller=sec)

    res = mcp.execute_tool(
        "modify_system_policy",
        caller_role="GUEST",
        user_authorized=True,
        policy_key="k",
        new_value="v"
    )
    # In vulnerable mode, privilege check logs simulation warning and proceeds
    assert res["status"] == "success"

    events = sec.get_events()
    assert any(e["event_type"] == "PRIVILEGE_ABUSE_SIMULATED" for e in events)


def test_invalid_arguments_missing_required():
    """Verify missing required parameters are rejected before execution."""
    mcp = MCPServer(mode="secure")

    # get_account_balance requires account_id
    res = mcp.execute_tool("get_account_balance", caller_role="CUSTOMER")
    assert res["status"] == "blocked"
    assert "missing required parameter 'account_id'" in res["reason"].lower()


def test_invalid_arguments_type_mismatch():
    """Verify parameter type mismatches are caught."""
    mcp = MCPServer(mode="secure")

    # get_transaction_history requires integer limit
    res = mcp.execute_tool(
        "get_transaction_history",
        caller_role="CUSTOMER",
        account_id="ACC-1001",
        limit="not_an_int"
    )
    assert res["status"] == "blocked"
    assert "must be of type integer" in res["reason"].lower()


def test_invalid_arguments_injection_detection():
    """Verify ASI02 parameter injections are neutralized."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    injection_payloads = [
        "ACC-1001; rm -rf /",
        "ACC-1001 | cat /etc/passwd",
        "ACC-1001 && drop table users",
        "ACC-1001`whoami`",
        "ACC-1001$(id)",
        "eval('hack()')",
        "__import__('os').system('id')"
    ]

    for payload in injection_payloads:
        res = mcp.execute_tool("get_account_balance", caller_role="CUSTOMER", account_id=payload)
        assert res["status"] == "blocked"
        assert "parameter validation failed" in res["reason"].lower()

    events = sec.get_events()
    assert any(e["event_type"] == "TOOL_PARAMETER_TAMPERING_BLOCKED" for e in events)


def test_high_risk_tool_approval_gate():
    """Verify high-risk tools require explicit human authorization."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    # 1. High risk tool without approval -> blocked
    res_blocked = mcp.execute_tool(
        "freeze_card_simulation",
        caller_role="CUSTOMER",
        card_id="CARD-4001",
        user_authorized=False
    )
    assert res_blocked["status"] == "blocked"
    assert "requires explicit human authorization" in res_blocked["reason"].lower()

    # 2. High risk tool with approval -> allowed
    res_approved = mcp.execute_tool(
        "freeze_card_simulation",
        caller_role="CUSTOMER",
        card_id="CARD-4001",
        user_authorized=True
    )
    assert res_approved["status"] == "success"
    assert res_approved["result"]["card_id"] == "CARD-4001"
    assert res_approved["result"]["status"] == "FROZEN"

    events = sec.get_events()
    assert any(e["event_type"] == "HIGH_RISK_AUTHORIZATION_REQUIRED" for e in events)


def test_output_validation_conformance():
    """Verify output validation detects corrupted or non-conforming responses."""
    validator = MCPOutputValidator()

    # Valid output
    valid_res = {"status": "success", "tool": "test", "risk_level": "LOW", "result": {}}
    check_valid = validator.validate_output("test", {"required": ["status", "result"]}, valid_res)
    assert check_valid["valid"] is True

    # Missing status
    invalid_res = {"tool": "test", "result": {}}
    check_invalid = validator.validate_output("test", {"required": ["status"]}, invalid_res)
    assert check_invalid["valid"] is False
    assert "missing required 'status' field" in check_invalid["reason"].lower()

    # Non-dict output
    check_nondict = validator.validate_output("test", {}, "string_result")
    assert check_nondict["valid"] is False
    assert "must return a dictionary" in check_nondict["reason"].lower()


def test_tool_audit_telemetry():
    """Verify all successful executions emit TOOL_EXECUTION_COMPLETED telemetry."""
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)

    res = mcp.execute_tool("create_audit_log", caller_role="USER", message="Step 11 test audit")
    assert res["status"] == "success"

    events = sec.get_events()
    completed_events = [e for e in events if e["event_type"] == "TOOL_EXECUTION_COMPLETED"]
    assert len(completed_events) >= 1
    assert completed_events[-1]["metadata"]["tool"] == "create_audit_log"


def test_arbitrary_python_execution_prevention():
    """Verify agents cannot inject or register arbitrary callables or non-callables."""
    registry = ToolRegistry()

    # Rejection of empty name
    with pytest.raises(ValueError):
        registry.register(ToolMetadata(name="", description="", risk_level="LOW", handler=lambda: {}))

    # Rejection of non-callable handler
    with pytest.raises(ValueError):
        registry.register(ToolMetadata(
            name="evil_tool",
            description="Arbitrary code string",
            risk_level="HIGH",
            handler="import os; os.system('echo hacked')"  # type: ignore
        ))


def test_fintech_session_context_integration():
    """Verify MCP accepts SessionContext and typed Role enum members."""
    mcp = MCPServer(mode="secure")

    session = SessionContext(
        session_id="SESS-TEST-001",
        request_id="REQ-TEST-001",
        user_id="CUST-001",
        role=Role.CUSTOMER.value,
        account_ids=["ACC-1001"],
        created_at="2026-09-16T12:00:00Z",
        conversation_id="CONV-TEST-001"
    )

    # Calling tool using SessionContext as caller_role
    res = mcp.execute_tool("get_account_balance", caller_role=session, account_id="ACC-1001")
    assert res["status"] == "success"
    assert res["result"]["account_id"] == "ACC-1001"
