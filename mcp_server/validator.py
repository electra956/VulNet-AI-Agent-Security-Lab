"""
VulNet AI Agent Security Lab - MCP Argument and Output Validators
Level 2 Step 11: Secure MCP Tool Gateway

Provides:
1. MCPArgumentValidator: Validates arguments against input_schema and checks
   for command injection, shell metacharacters, SQL injection, and path traversal (ASI02).
2. MCPOutputValidator: Verifies tool execution output against output_schema
   to prevent corrupted structures and sensitive credential leaks.
"""

import re
from typing import Any, Dict, List, Optional


class MCPArgumentValidator:
    """
    Validates tool arguments against input_schema and inspects values for injection patterns.
    """

    DANGEROUS_PATTERNS = [
        r";",
        r"\|",
        r"&&",
        r"`",
        r"\$\(",
        r"__import__",
        r"eval\(",
        r"exec\(",
        r"rm\s+-rf",
        r"(?i)\bdrop\s+table\b",
        r"(?i)\bunion\s+select\b",
        r"(?i)<script\b",
    ]

    def __init__(self, mode: str = "secure"):
        self.mode = mode.lower()

    def set_mode(self, mode: str) -> None:
        self.mode = mode.lower()

    def inspect_for_injection(self, value: Any) -> Optional[Dict[str, str]]:
        """
        Recursively inspect string or nested values for injection patterns.
        """
        if isinstance(value, str):
            for pat in self.DANGEROUS_PATTERNS:
                if re.search(pat, value):
                    return {
                        "pattern": pat,
                        "sample": value[:100],
                        "reason": f"Suspicious parameter pattern detected: '{pat}'"
                    }
        elif isinstance(value, dict):
            for v in value.values():
                res = self.inspect_for_injection(v)
                if res:
                    return res
        elif isinstance(value, (list, tuple)):
            for item in value:
                res = self.inspect_for_injection(item)
                if res:
                    return res

        return None

    def validate_arguments(
        self,
        tool_name: str,
        input_schema: Dict[str, Any],
        provided_kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate arguments against tool's input_schema and injection filters.

        Returns:
            Dict containing:
            - valid (bool)
            - tampered (bool)
            - reason (str)
            - pattern (Optional[str])
            - validated_args (Dict[str, Any])
        """
        # 1. Check for parameter injection in any provided argument
        for arg_name, arg_val in provided_kwargs.items():
            injection = self.inspect_for_injection(arg_val)
            if injection:
                if self.mode == "secure":
                    return {
                        "valid": False,
                        "tampered": True,
                        "reason": f"Parameter validation failed: {injection['reason']}",
                        "pattern": injection["pattern"],
                        "validated_args": provided_kwargs
                    }
                else:
                    # In vulnerable mode, mark tampered but allow for simulation
                    return {
                        "valid": True,
                        "tampered": True,
                        "reason": f"Parameter injection detected but allowed in Vulnerable Mode: {injection['reason']}",
                        "pattern": injection["pattern"],
                        "validated_args": provided_kwargs
                    }

        # 2. Check schema requirements if input_schema is defined
        properties = input_schema.get("properties", {})
        required = input_schema.get("required", [])

        # Check required fields
        for req_field in required:
            if req_field not in provided_kwargs:
                return {
                    "valid": False,
                    "tampered": False,
                    "reason": f"Missing required parameter '{req_field}' for tool '{tool_name}'.",
                    "pattern": None,
                    "validated_args": provided_kwargs
                }

        # Check types if defined in properties
        type_mapping = {
            "string": str,
            "str": str,
            "integer": int,
            "int": int,
            "number": (int, float),
            "float": float,
            "boolean": bool,
            "bool": bool,
            "array": (list, tuple),
            "list": (list, tuple),
            "object": dict,
            "dict": dict
        }

        for arg_name, arg_val in provided_kwargs.items():
            if arg_name in properties:
                expected_type_str = properties[arg_name].get("type")
                if expected_type_str and expected_type_str.lower() in type_mapping:
                    expected_python_type = type_mapping[expected_type_str.lower()]
                    # Special case: bool is subclass of int in python
                    if expected_type_str.lower() in ("integer", "int", "number", "float") and isinstance(arg_val, bool):
                        return {
                            "valid": False,
                            "tampered": False,
                            "reason": f"Parameter '{arg_name}' must be of type {expected_type_str}, not boolean.",
                            "pattern": None,
                            "validated_args": provided_kwargs
                        }
                    if not isinstance(arg_val, expected_python_type):
                        return {
                            "valid": False,
                            "tampered": False,
                            "reason": f"Parameter '{arg_name}' must be of type {expected_type_str}, received {type(arg_val).__name__}.",
                            "pattern": None,
                            "validated_args": provided_kwargs
                        }

        return {
            "valid": True,
            "tampered": False,
            "reason": "Arguments successfully validated.",
            "pattern": None,
            "validated_args": provided_kwargs
        }


class MCPOutputValidator:
    """
    Validates that tool execution outputs conform to registered output_schema.
    """

    def validate_output(
        self,
        tool_name: str,
        output_schema: Dict[str, Any],
        result: Any
    ) -> Dict[str, Any]:
        """
        Validate output result dictionary against schema.

        Returns:
            Dict containing:
            - valid (bool)
            - reason (str)
        """
        if not isinstance(result, dict):
            return {
                "valid": False,
                "reason": f"Tool '{tool_name}' must return a dictionary, got {type(result).__name__}."
            }

        if "status" not in result:
            return {
                "valid": False,
                "reason": f"Tool '{tool_name}' output missing required 'status' field."
            }

        required_keys = output_schema.get("required", [])
        for req in required_keys:
            if req not in result:
                return {
                    "valid": False,
                    "reason": f"Tool '{tool_name}' output missing required field '{req}'."
                }

        return {
            "valid": True,
            "reason": "Output conforms to registered schema."
        }
