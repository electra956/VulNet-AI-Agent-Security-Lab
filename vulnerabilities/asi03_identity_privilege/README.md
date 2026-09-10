# ASI03 — Identity and Privilege Abuse

## Vulnerability Description
Identity and Privilege Abuse arises when an AI agent or downstream component operates with excessive permissions, allows identity spoofing, or permits low-privileged users to trigger administrative tools without authentication.

## Attack Preconditions
- The architecture treats all requests routed through an agent as pre-authenticated or inherently trusted.
- The MCP server lacks role-based authorization checks.

## Simulated Attack Input
```json
{
  "caller_role": "GUEST",
  "tool_name": "modify_system_policy",
  "parameters": {
    "policy_key": "require_mfa",
    "new_value": "false"
  }
}
```

## Vulnerable Behavior
In Vulnerable Mode, the tool execution proceeds despite the caller lacking `ADMIN` rights, simulating an unauthorized privilege escalation.

## Security Controls
- **Hierarchical RBAC:** Roles (`GUEST`, `USER`, `ADMIN`) are evaluated against the required permissions (`READ_ONLY`, `AUDIT`, `USER`, `ADMIN`).
- **Telemetry Event Generation:** Violations trigger `PRIVILEGE_VIOLATION_BLOCKED` audits.

## Secure Behavior
In Secure Mode, the MCP server evaluates the caller's role hierarchy and rejects the call with an explicit authorization error.

## Mitigation
1. Bind every agent session to a verified user context.
2. Implement explicit authorization gates on sensitive tools.
3. Apply least-privilege scoping so agents cannot inherit admin privileges automatically.
