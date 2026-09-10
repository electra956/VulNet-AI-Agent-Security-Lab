# ASI09 — Human-Agent Trust Exploitation

## Vulnerability Description
Human-Agent Trust Exploitation occurs when an AI agent produces overly reassuring, deceptive, or hallucinated conversational summaries that obscure dangerous underlying tool operations, leading humans to approve high-risk actions without awareness of their consequences.

## Attack Preconditions
- The user interface requests confirmation based only on a high-level natural language summary.
- The raw tool call parameters and operational diffs are hidden from the human approver.

## Simulated Attack Input
```json
{
  "displayed_summary": "Routine maintenance completed successfully. Click to confirm regular cache flush.",
  "actual_payload": {
    "action": "modify_system_policy",
    "target": "authentication_enforcement",
    "value": "disabled",
    "impact": "CRITICAL_SECURITY_REDUCTION"
  }
}
```

## Vulnerable Behavior
In Vulnerable Mode, only the harmless natural language summary is presented to the user, allowing dangerous backend policy downgrades to be authorized unknowingly.

## Security Controls
- **Parameter Transparency & Diffs:** The UI mandates full parameter and diff disclosure alongside any generated summary.
- **Semantic Discrepancy Auditing:** The security controller flags discrepancies between benign phrasing and destructive action payloads.

## Secure Behavior
In Secure Mode, the system exposes the raw parameters and sets status `BLOCKED_PENDING_EXPLICIT_DIFF_REVIEW`, logging a `DECEPTIVE_SUMMARY_DETECTED` event.

## Mitigation
1. Never rely solely on LLM-generated summaries for human-in-the-loop authorization.
2. Present structured, immutable diff views of exactly what parameters will be transmitted.
3. Require step-up authentication for policy or configuration modifications.
