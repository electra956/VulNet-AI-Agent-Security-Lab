from mcp_server.server import MCPServer


# --------------------------------------------------
# CREATE MCP SERVER
# --------------------------------------------------

mcp = MCPServer()


print("\n========== MCP SERVER TEST ==========\n")


# --------------------------------------------------
# LIST AVAILABLE TOOLS
# --------------------------------------------------

print("AVAILABLE TOOLS:\n")

for tool in mcp.list_tools():

    print(f"- {tool}")


# --------------------------------------------------
# TEST SECURITY STATUS
# --------------------------------------------------

print("\n========== SECURITY STATUS ==========\n")

result = mcp.execute_tool(
    "get_security_status"
)

print(result)


# --------------------------------------------------
# TEST APPROVED TOOL
# --------------------------------------------------

print("\n========== TOOL PERMISSION ==========\n")

result = mcp.execute_tool(
    "check_tool_permission",

    requested_tool="get_security_status"
)

print(result)


# --------------------------------------------------
# TEST AUDIT LOG
# --------------------------------------------------

print("\n========== AUDIT LOG ==========\n")

result = mcp.execute_tool(
    "create_audit_log",

    message="Safe Action Agent simulation completed."
)

print(result)


# --------------------------------------------------
# TEST BLOCKED TOOL
# --------------------------------------------------

print("\n========== BLOCKED TOOL ==========\n")

result = mcp.execute_tool(
    "delete_production_database"
)

print(result)
