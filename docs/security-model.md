# Security Model

VulNet is a **security laboratory**: it contains deliberately vulnerable behaviour (Vulnerable mode) next to the controls that
stop it (Secure mode). This page states the rules the Secure side enforces and where the code lives.

## 1. Core principle: security is deterministic application code

The LLM is an **untrusted component**. It can be persuaded, confused or wrong. Therefore:

* No security decision is made by the LLM or depends on its system prompt. The prompt in `llm/prompts.py` asks the model to
  behave, but every rule below is enforced again in plain code.
* The same input always produces the same security decision (risk, RBAC, ownership, approval, guardrails).
* Security-sensitive failures **fail closed** (Ollama down → labelled offline simulator, never silent success; tool error →
  no action; unknown tool/agent/identity → blocked).

## 2. What is untrusted

| Source | Treatment |
|---|---|
| User text | Input guardrail / `SecurityController` perimeter; never an authority for identity or approval |
| LLM output (text and tool calls) | Tool calls must be offered for this request, grounded in what the user asked (no invented accounts/amounts), then pass the guardrail chain. Numeric claims must appear in the tool result. Raw tool-call JSON is stripped from replies |
| RAG documents | Data, trust-tagged (`TRUSTED_INTERNAL` / `UNTRUSTED_EXTERNAL`), injection-scanned; embedded instructions are neutralised in Secure mode; retrieved text can never grant anything |
| Memory | Data with provenance; validated on write; only validated records reach the prompt; can never grant a role, permission, ownership or approval (`memory/provenance.py`) |
| Tool output | Data (a ledger field can carry an injection); sanitised before it re-enters the context |
| Agent-to-agent messages | Signed envelopes verified on receipt; content of a valid message is still *data* (`DATA_ONLY_INTENT`) |
| Third-party tools / plugins | Admission control: hash, version pin, provenance, publisher signature, metadata-injection scan, permission escalation check |
| Code/expressions from the model | Never executed with a real interpreter; restricted AST sandbox only |

## 3. The tool boundary (Secure gateway)

Every tool request — from the chat LLM or from a lab agent — walks the same ordered chain. Each stage writes a step to the trace
and a record to the audit log (`logs/audit.jsonl`).

```
goal scope (GoalGuard) → tool whitelist → argument schema / injection scan / limits → rate limit
→ approval-forgery check → identity-provenance check → RBAC (role/permission) → ownership
→ deterministic risk → human approval → MCP server (independent second check) → tool → output
```

| Control | Code | Notes |
|---|---|---|
| Goal anchoring | `lab/controls.py::GoalGuard` | Goal is derived from the authenticated user's own message only; each goal permits a fixed tool set |
| Whitelist / schema | `lab/core.py::TOOL_POLICY`, `security/guardrails/tool_guardrail.py` | Unknown tool → BLOCK. Non-finite / negative / non-numeric amounts → BLOCK. Hard limit per transfer |
| Identity provenance | `lab/controls.py::IdentityAuthority` | Identity is HMAC-signed at login; `as_user`/`role`/`caller_role` in tool arguments are refused; tampered identities fail verification |
| RBAC | `auth/permissions.py` (`ROLE_PERMISSIONS`), `auth/authorization.py` | Roles: CUSTOMER, SUPPORT_AGENT, FRAUD_ANALYST, COMPLIANCE_ANALYST, ADMIN |
| Ownership | `TOOL_POLICY`, `fintech/service.py` | CUST-001 can never read or debit CUST-002's accounts/cards |
| Risk | `fintech/risk/transaction_risk.py`, `lab/core.py::classify_risk` | LOW/MEDIUM/HIGH/CRITICAL; the LLM cannot override; override flags are stripped |
| Human approval | `security/approval_engine.py`, `fintech/transaction_lifecycle.py` | PENDING → APPROVAL_REQUIRED → APPROVED/REJECTED/EXPIRED → COMPLETED. AI/agent identities and the requester cannot approve; approval cannot override a risk BLOCK; the executed transfer must match the approved parameters |
| MCP | `mcp_server/server.py` | Independent registry/permission/risk/argument/output checks even if upstream layers are bypassed |
| Output | `security/guardrails/output_guardrail.py` | Redacts card PANs/credentials, blocks prompt leakage, suppresses unverified success claims |

## 4. Secure vs Vulnerable mode

* **Secure** (default): every control above is active.
* **Vulnerable**: controls are relaxed *by design* so an attack can be seen working inside the lab (RAG passes raw text, memory is
  unvalidated, the tool gateway trusts asserted identity and skips ownership/risk/approval, the bus verifies nothing, etc.).
* Clients can only select Vulnerable when `VULNET_ALLOW_MODE_OVERRIDE=true` (default in `local_lab`); `VULNET_ENV=hardened` forces it
  off (`docs/hardening.md`).
* In Vulnerable mode the *chat* pipeline still runs a real LLM whose own alignment may refuse an injection. Attacks flagged by the
  perimeter are therefore routed to the deterministic lab pipeline in Vulnerable mode so the simulation is visible (see
  `api/routes/chat.py`, `chatbot/components/chat.py`).

### Trusted payees (secure mode)

In Secure Mode a transfer is only allowed to the customer's own accounts or to a **trusted payee**. Unknown accounts (including
malformed ids such as `ACC-10001`) and real-but-untrusted accounts are rejected in the transaction lifecycle with an audit record, before any
money moves. The check is deterministic code outside the LLM, and payees can only be added or removed on the dashboard's **Pay → Trusted payees**
panel, never from a chat message, so an injected prompt cannot add an attacker's account. Defaults: Alex (`CUST-001`) trusts `ACC-2001`, Jordan
(`CUST-002`) trusts `ACC-1001`. State is stored in `data/beneficiaries.json` (`VULNET_BENEFICIARY_FILE` overrides it). Vulnerable Mode skips the check.

## 5. Defence in depth ("assume breach")

The secure runs of the lab include **assume-breach probes**: after one control stops an attack, the raw attack is handed to the next
layer to prove that layer alone would also stop it. Examples: poisoned RAG chunk → neutralised, then GoalGuard blocks the out-of-scope
transfer; poisoned tool metadata → admission rejects, then the gateway refuses the un-admitted tool; injected expression → gateway
filter blocks, then the sandbox refuses it when the filter is skipped.

## 6. Lab safety boundary

* All data is synthetic (`SYNTHETIC LAB DATA`), all funds are simulated (`real_funds_moved: false`).
* No outbound network from lab code. "Exfiltration" lands in an in-memory *attacker sink*.
* No `eval`/`exec`/`subprocess`/`os.system` on attacker-controlled text. ASI05's vulnerable path is a shell **emulator** over an
  in-memory filesystem; the secure path is a restricted `ast` evaluator with a step budget, deadline, size caps and a private temp
  directory. `tests/lab/test_lab_sandbox.py` runs every ASI05 attack with the real exec primitives replaced by functions that fail
  the test if called.
* The demo credentials, canary secrets and signing keys in the repository are synthetic and labelled as such.

## 7. What is *not* claimed

* Passing the lab's tests does not show that a real deployment is secure.
* The pattern-based detectors (`ThreatDetector`, RAG scanners) are heuristics and can be evaded; the deterministic controls behind
  them (goal scope, ownership, risk, approval, sandbox) are what the design relies on.
* Telemetry is structured JSONL + an in-process trace store; there is no OpenTelemetry exporter.
