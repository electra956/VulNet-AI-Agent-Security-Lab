"""
VulNet AI Agent Security Lab - MCP Tool Registry
Level 2 Step 11: Secure MCP Tool Gateway

Defines structured ToolMetadata and ToolRegistry.
Ensures every tool has:
- name
- description
- risk_level ("LOW", "MEDIUM", "HIGH", "CRITICAL")
- allowed_roles (List[str])
- requires_approval (bool)
- input_schema (Dict[str, Any])
- output_schema (Dict[str, Any])
- handler (Callable)

Strict Security Invariant:
Agents must never execute arbitrary Python functions or unwhitelisted callables.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ToolMetadata:
    """
    Metadata specification for an approved MCP tool.
    """
    name: str
    description: str
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    allowed_roles: List[str] = field(default_factory=list)
    requires_approval: bool = False
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    handler: Optional[Callable[..., Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary representation (omitting raw callable)."""
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.upper(),
            "allowed_roles": [r.upper() for r in self.allowed_roles],
            "requires_approval": self.requires_approval,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema
        }


class ToolRegistry:
    """
    Central registry for approved, safe MCP tools.

    Guarantees:
    - Only registered tools can be retrieved or executed.
    - Every tool provides complete metadata and a callable handler.
    - Arbitrary function execution is strictly blocked.
    """

    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}

    def register(self, tool: ToolMetadata) -> None:
        """
        Register a tool with verified metadata and safe handler.
        """
        if not tool.name or not isinstance(tool.name, str):
            raise ValueError("Tool must have a valid non-empty string name.")
        if not callable(tool.handler):
            raise ValueError(f"Tool '{tool.name}' must have a callable handler.")
        if not tool.risk_level:
            raise ValueError(f"Tool '{tool.name}' must have a defined risk_level.")

        # Normalize role names to uppercase
        tool.allowed_roles = [r.upper() for r in tool.allowed_roles]
        tool.risk_level = tool.risk_level.upper()

        self._tools[tool.name] = tool

    def unregister(self, name: str) -> bool:
        """Remove a tool from the registry."""
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def get(self, name: str) -> Optional[ToolMetadata]:
        """Retrieve tool metadata by name."""
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if a tool is approved and registered."""
        return name in self._tools

    def list_tools(self) -> List[str]:
        """List all approved tool names."""
        return sorted(list(self._tools.keys()))

    def get_all_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Return metadata dicts for all registered tools."""
        return {name: tool.to_dict() for name, tool in self._tools.items()}

    def clear(self) -> None:
        """Clear all registered tools."""
        self._tools.clear()
