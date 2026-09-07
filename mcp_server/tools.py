from datetime import datetime


class SafeDemoTools:
    """
    Safe demonstration tools for the VulNet AI Agent Security Lab.

    These tools are simulations only.

    They do NOT:
    - Access real systems
    - Modify real files
    - Use production credentials
    - Make network requests
    """

    def get_security_status(self):
        """Return simulated security status."""

        return {
            "status": "success",

            "tool": "get_security_status",

            "result": {
                "environment": "Local Educational Lab",
                "production_access": False,
                "network_access": False,
                "credentials_used": False,
                "simulation_mode": True
            }
        }


    def check_tool_permission(self, tool_name):
        """
        Check whether a tool is approved.

        This is a simulated permission check.
        """

        approved_tools = [
            "get_security_status",
            "check_tool_permission",
            "create_audit_log"
        ]

        approved = tool_name in approved_tools

        return {
            "status": "success",

            "tool": "check_tool_permission",

            "result": {
                "requested_tool": tool_name,
                "approved": approved,
                "reason": (
                    "Tool is approved for the educational lab."
                    if approved
                    else
                    "Tool is not approved in this lab."
                )
            }
        }


    def create_audit_log(self, message):
        """
        Create a simulated audit log.

        No real external logging system is used.
        """

        timestamp = datetime.now().isoformat()

        return {
            "status": "success",

            "tool": "create_audit_log",

            "result": {
                "timestamp": timestamp,
                "message": message,
                "location": "Simulated Local Audit Log",
                "real_system_modified": False
            }
        }
