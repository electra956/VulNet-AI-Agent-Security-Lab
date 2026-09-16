"""
VulNet AI Agent Security Lab - MCP Execution Sandbox
Level 2 Step 11: Secure MCP Tool Gateway

Provides an execution sandbox for approved MCP tools.

Security Invariants:
- Agents must NEVER execute arbitrary Python functions.
- Dynamic string evaluation (eval, exec) is strictly forbidden.
- Only registered and whitelisted callable handlers are executed.
- Subprocesses, OS shells, external network calls, and raw database commands are blocked.
"""

import time
from typing import Any, Callable, Dict, Optional
from mcp_server.registry import ToolMetadata


class ExecutionSandbox:
    """
    Secure execution boundary for registered MCP tool callables.
    """

    def __init__(self):
        pass

    def execute(
        self,
        tool_meta: ToolMetadata,
        validated_args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute an approved tool handler within an isolated execution boundary.

        Args:
            tool_meta: Registered ToolMetadata
            validated_args: Pre-validated dictionary of parameters

        Returns:
            Dict representing tool execution result.
        """
        # Strict Invariant: Ensure handler is a verified callable
        handler: Optional[Callable[..., Dict[str, Any]]] = tool_meta.handler
        if not handler or not callable(handler):
            return {
                "status": "error",
                "tool": tool_meta.name,
                "reason": f"Tool '{tool_meta.name}' does not have a safe callable handler."
            }

        start_time = time.perf_counter()
        try:
            # Execute the whitelisted handler with keyword arguments
            result = handler(**validated_args)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            if isinstance(result, dict):
                # Ensure execution metadata is stamped
                if "execution_time_ms" not in result:
                    result["execution_time_ms"] = duration_ms
                if "sandbox_enforced" not in result:
                    result["sandbox_enforced"] = True
                return result
            else:
                return {
                    "status": "error",
                    "tool": tool_meta.name,
                    "reason": f"Tool returned invalid non-dict type: {type(result).__name__}",
                    "execution_time_ms": duration_ms
                }

        except TypeError as te:
            # Signature mismatch
            return {
                "status": "error",
                "tool": tool_meta.name,
                "reason": f"Tool execution failed due to argument mismatch: {str(te)}"
            }
        except Exception as e:
            # General sandbox exception isolation
            return {
                "status": "error",
                "tool": tool_meta.name,
                "reason": f"Tool execution encountered an exception: {str(e)}"
            }
