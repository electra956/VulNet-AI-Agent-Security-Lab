# Threat Model

Scope: the VulNet lab application (chat path + Attack Lab) running locally against synthetic data. This is the model the lab
*demonstrates*; it is not an assessment of any production system.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Customer balances and ownership boundaries | `FintechService` ledger, MCP suite | Core integrity/confidentiality property: CUST-001 must never act on CUST-002's data |
| Approval authority | `ApprovalEngine`, `TransactionLifecycleService` | The human-in-the-loop is the last gate for high-risk actions |
| Identity and role of the caller | auth sessions, `IdentityAuthority` | Every authorisation decision depends on it |
| Agent goal | `GoalGuard` anchor | An attacker who owns the goal owns the agent |
| Memory / RAG corpus | `memory/provenance.py`, `rag/` | Persistent influence over future behaviour |
| Secrets (synthetic canaries) | `security_tests/canaries.py`, `lab/sandbox.py` | Detect exfiltration |
| Audit trail | `logs/audit.jsonl` | Non-repudiation of decisions |

## Actors

* **Malicious customer** — controls the chat input, tries injection, cross-account access, role claims, self-approval.
* **Malicious content author** — controls a document that lands in RAG, a ledger text field, a tool description, an agent plugin.
* **Compromised agent/component** — a subverted agent, tool or upstream service inside the trust boundary.
* **Careless human approver** — approves what the agent tells them.

## Trust boundaries

`user → perimeter`, `retrieved/stored data → prompt`, `LLM → tool gateway`, `agent → agent (bus)`, `tool → backend (MCP)`,
`third-party component → runtime`, `code/expression → interpreter`. The LLM, RAG, memory, tool output, agent messages and third-party
components are all on the **untrusted** side of a boundary (see `security-model.md`).

## Threats by OWASP Agentic category

| ID | Threat in this system | Primary mitigations (deterministic) | Residual risk |
|---|---|---|---|
| ASI01 | Direct / indirect / multi-turn / role / tool-output goal hijack | Perimeter, RAG neutralisation, goal anchoring, no self-approval, tool-output sanitising | Pattern detectors are evadable; deeper layers carry the load |
| ASI02 | Privileged tool, malformed args, tool loops, unauthorised/cross-account transfers | Whitelist, schema/injection guard, limits, rate limit, RBAC, ownership, risk, approval, MCP | Per-tool budgets are static |
| ASI03 | Cross-customer access, forged identity, role confusion, tampered session | Signed identity, identity provenance, ownership, RBAC | Simulated MFA/session model; no device binding |
| ASI04 | Poisoned tool metadata, tampered/unpinned/unsigned components, poisoned plugin | Admission control (hash, pin, provenance, signature, metadata scan, permission check) | Trust anchors are lab keys; no real registry |
| ASI05 | Command injection via analysis tool, exfil, resource exhaustion, path traversal | Restricted AST sandbox, no subprocess/network/imports, budgets, private dir | Sandbox is in-process (not an OS-level jail) |
| ASI06 | Delayed instruction, poisoned preference, false history, RAG-to-memory persistence | Validation on write, quarantine, provenance, only validated data in prompts, memory never authorises | Validator is pattern-based |
| ASI07 | Spoofed/forged/modified/replayed messages, unauthorised agent requests, poisoned relayed content | Per-agent HMAC, payload hash, nonce, schema, authorisation matrix, data-only intents | Shared-secret scheme (lab); no PKI |
| ASI08 | Faulty upstream output cascades to money movement | Schema validation, retry limit, breaker, confidence gate, fail-closed, consistency check, rollback | Rollback covers the simulated ledger only |
| ASI09 | Persuasive/overconfident agent narrative misleads the approver | Evidence packet from deterministic sources, claim-vs-evidence check, dual control, scope-bound approval | A determined human can still approve; dual control needs two staff |
| ASI10 | Agent exceeds objective, contacts others, alters results, poisons memory | Capability manifests, anomaly counting, breaker, kill switch, audit | Manifests must be kept accurate |

## Out of scope

Real payment rails, real identity providers, network attackers, denial of service against the host, model-weight attacks, supply chain of
the Python dependencies themselves, multi-tenant isolation beyond the synthetic users.
