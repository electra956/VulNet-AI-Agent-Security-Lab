# ASI10 — Rogue Agents

## Vulnerability Description
Rogue Agents emerge when an autonomous AI agent exceeds operational scope, enters runaway recursive loops, triggers unmonitored sub-agents, or takes uncoordinated initiatives without human or supervisory consensus.

## Attack Preconditions
- The agent runtime permits dynamic task delegation or sub-agent generation without lifecycle quotas or operational limits.
- No central supervisor monitors recursive agent spawning.

## Simulated Attack Input
```json
{
  "requested_sub_agents": 12,
  "recursion_depth": 5,
  "max_allowed_workers": 3
}
```

## Vulnerable Behavior
In Vulnerable Mode, the agent spawns workers without limits, demonstrating how a runaway agent consumes quotas, creates resource exhaustion, and loses governance.

## Security Controls
- **Agent Governance Governor:** Imposes strict quotas on concurrent sub-agents, recursion depth, and execution timeouts.
- **Supervisor Telemetry:** Violations trigger `ROGUE_AGENT_BEHAVIOR_THROTTLED` events and clamp execution to safe limits.

## Secure Behavior
In Secure Mode, the governor caps sub-agent creation to the configured maximum (e.g. 3) and marks status `THROTTLED_AND_CAPPED`.

## Mitigation
1. Enforce strict budget, memory, and call-depth limits on all agentic workflows.
2. Implement an out-of-band supervisor capable of terminating runaway tasks.
3. Require cryptographic authorizations for spawning child agents.
