from mcp_server.tools import SafeDemoTools


class MCPServer:
    """
    Simple MCP-style server for the VulNet AI Agent Security Lab.

    It receives requests from agents and routes them
    to safe simulated tools.
    """

    def __init__(self):

        self.tools = SafeDemoTools()


    def list_tools(self):
        """
        Return the list of available safe tools.
        """

        return [
            "get_security_status",
            "check_tool_permission",
            "create_audit_log"
        ]


    def execute_tool(self, tool_name, **kwargs):
        """
        Execute an approved safe demo tool.
        """

        available_tools = self.list_tools()


        # ------------------------------------------
        # TOOL VALIDATION
        # ------------------------------------------

        if tool_name not in available_tools:

            return {
                "status": "blocked",

                "tool": tool_name,

                "reason": "Tool is not approved in this MCP server."
            }


        # ------------------------------------------
        # ROUTE TO TOOL
        # ------------------------------------------

        if tool_name == "get_security_status":

            return self.tools.get_security_status()


        elif tool_name == "check_tool_permission":

            requested_tool = kwargs.get(
                "requested_tool",
                ""
            )

            return self.tools.check_tool_permission(
                requested_tool
            )


        elif tool_name == "create_audit_log":

            message = kwargs.get(
                "message",
                "Agent action executed."
            )

            return self.tools.create_audit_log(
                message
            )


        # ------------------------------------------
        # SAFETY FALLBACK
        # ------------------------------------------

        return {
            "status": "blocked",

            "tool": tool_name,

            "reason": "Tool execution was not allowed."
        }
