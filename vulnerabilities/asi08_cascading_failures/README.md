# ASI08 — Cascading Failures

## Vulnerability Description
Cascading Failures occur when a bug, timeout, rate limit, or unexpected exception in one agent propagates unhandled across the multi-agent dependency graph, bringing down the entire pipeline or generating infinite retry loops.

## Attack Preconditions
- Multi-agent components are tightly coupled without defensive boundary wrappers.
- The orchestrator lacks circuit breakers or fallback response handlers.

## Simulated Attack Input
```json
{
  "trigger_fault": "SIMULATED_MALFORMED_JSON_CORRUPTION",
  "affected_component": "RESEARCH_AGENT"
}
```

## Vulnerable Behavior
In Vulnerable Mode, a failure in the Research Agent bubbles up uncaught, abruptly halting the pipeline and crashing the application session.

## Security Controls
- **Circuit Breakers & Boundaries:** Every agent call is wrapped in a dedicated fault-containment block.
- **Graceful Degradation:** When a non-critical subsystem fails, the orchestrator supplies a safe fallback response rather than aborting.

## Secure Behavior
In Secure Mode, the error is contained. The circuit breaker enters state `OPEN_ISOLATED` and logs a `CASCADING_FAILURE_CONTAINED` event.

## Mitigation
1. Implement circuit breakers and dead-letter queues between agents.
2. Establish strict timeouts for all tool and LLM calls.
3. Design agents for graceful degradation when upstream data is unavailable.
