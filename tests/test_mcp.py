from mcp_server.server import MCPServer
from security.security_controller import SecurityController


def test_mcp_list_tools():
    mcp = MCPServer()
    tools = mcp.list_tools()
    assert "get_security_status" in tools
    assert "check_tool_permission" in tools
    assert "create_audit_log" in tools


def test_mcp_security_status_execution():
    mcp = MCPServer()
    result = mcp.execute_tool("get_security_status")
    assert result["status"] == "success"
    assert result["result"]["simulation_mode"] is True
    assert result["result"]["production_access"] is False


def test_mcp_check_tool_permission():
    mcp = MCPServer()
    res_approved = mcp.execute_tool("check_tool_permission", requested_tool="get_security_status")
    assert res_approved["status"] == "success"
    assert res_approved["result"]["approved"] is True

    res_unapproved = mcp.execute_tool("check_tool_permission", requested_tool="drop_database")
    assert res_unapproved["status"] == "success"
    assert res_unapproved["result"]["approved"] is False


def test_mcp_audit_log():
    mcp = MCPServer()
    result = mcp.execute_tool("create_audit_log", message="Test audit event")
    assert result["status"] == "success"
    assert "Test audit event" in result["result"]["message"]


def test_mcp_unapproved_tool_blocked():
    mcp = MCPServer()
    result = mcp.execute_tool("unapproved_hack_tool")
    assert result["status"] == "blocked"
    assert "not approved" in result["reason"].lower()


def test_mcp_parameter_injection_blocked_in_secure_mode():
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)
    result = mcp.execute_tool("execute_data_export", target_dataset="telemetry; rm -rf /")
    assert result["status"] == "blocked"
    assert "parameter validation failed" in result["reason"].lower()


def test_mcp_rbac_privilege_enforcement():
    sec = SecurityController(mode="secure")
    mcp = MCPServer(mode="secure", security_controller=sec)
    # GUEST attempting ADMIN tool modify_system_policy
    result = mcp.execute_tool("modify_system_policy", caller_role="GUEST", policy_key="k", new_value="v")
    assert result["status"] == "blocked"
    assert "insufficient privilege" in result["reason"].lower()


if __name__ == "__main__":
    test_mcp_list_tools()
    test_mcp_security_status_execution()
    test_mcp_check_tool_permission()
    test_mcp_audit_log()
    test_mcp_unapproved_tool_blocked()
    test_mcp_parameter_injection_blocked_in_secure_mode()
    test_mcp_rbac_privilege_enforcement()
    print("MCP Server tests passed successfully!")
