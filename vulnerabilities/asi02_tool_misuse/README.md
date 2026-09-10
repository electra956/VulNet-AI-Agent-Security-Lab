# ASI02 — Tool Misuse and Exploitation

## Vulnerability Description
Tool Misuse occurs when an AI agent triggers tool calls with dangerous parameters, invokes inappropriate tools, or is tricked into chaining tools in a destructive manner.

## Attack Preconditions
- The agent has access to functional tools without parameter sanitization or schema validation.
- Tool interfaces trust arguments generated directly by LLM outputs.

## Simulated Attack Input
```json
{
  "tool_name": "execute_data_export",
  "parameters": {
    "export_format": "json",
    "target_dataset": "telemetry; DROP TABLE users; --"
  }
}
```

## Vulnerable Behavior
In Vulnerable Mode, parameter strings are forwarded directly into tool routines without validation, demonstrating how injection vectors reach backends.

## Security Controls
- **Schema Validation & Metacharacter Sanitization:** The MCP layer inspects parameters for command separators (`;`, `|`, `&&`) and SQL injection patterns.
- **Whitelist Enforcement:** Only approved tools in the tools registry may be invoked.

## Secure Behavior
In Secure Mode, the MCP server rejects the call with status `blocked`, logging a `TOOL_PARAMETER_TAMPERING_BLOCKED` event.

## Mitigation
1. Parameterize all tool arguments and validate against strict regex schemas.
2. Maintain strict tool allowlists with granular capabilities.
3. Require secondary human confirmation for state-changing or high-risk tools.
