# Architecture

VulNet has **two execution paths** that share the same security building blocks:

1. **Chat path** — the application a user talks to: dashboard/API → perimeter → RAG → LLM (Ollama) → guarded tools → ledger.
2. **Lab path** — the OWASP Agentic Attack Lab: scripted attacks run through a multi-agent runtime (signed bus, six agents,
   tool gateway, memory, supply chain, sandbox) against a fresh synthetic world, in *vulnerable* and *secure* form.

They share: the RAG engine (`rag/`), provenance memory (`memory/provenance.py`), the approval engine, RBAC (`auth/`), the risk engine
(`fintech/risk/`), the MCP server (`mcp_server/`), the audit logger (`observability/`) and the perimeter (`security/`).
They do **not** share the conversation loop: the lab's agents/bus/gateway are a separate runtime (see *Known gaps* in
`project-status.md`).

```
USER ─▶ Streamlit dashboard :8501 ──(in-process)──┐
   └──▶ FastAPI gateway :8000 ────────────────────┤
                                                  ▼
                       AUTH (PBKDF2 + simulated MFA) → SESSION (SessionContext: user, role, accounts)
                                                  ▼
                       PERIMETER  (SecurityController / ThreatDetector; Secure blocks, Vulnerable flags)
                                                  ▼
   ┌──────────────────────── CHAT PATH ────────────────────────┐   ┌──────────────── LAB PATH ────────────────┐
   │ deterministic shortcuts: greeting, balance, history        │   │ scenario runner (lab/scenarios/asiNN.py) │
   │ memory service ("remember that …"; provenance memory)      │   │   ▼                                       │
   │ RAG (hybrid retrieval) → RAG guardrail → prompt            │   │ agent policy (deterministic | Ollama)    │
   │ Ollama /api/chat (+ real token streaming for tool-free     │   │   ▼                                       │
   │   turns) → tool call?                                      │   │ AgentBus (signed AgentMessage)           │
   │   → offered? → args grounded? → ToolGuardrail (whitelist,  │   │   ▼ six agents: Customer / Research /    │
   │     RBAC, ownership, ₹50k gate) → taint policy             │   │     Transaction / Fraud / Compliance /   │
   │   → TransactionLifecycle (24 steps: risk → approval →      │   │     Support (+ RogueAgent)               │
   │     MCP → ledger)                                          │   │   ▼                                       │
   │ → Ollama synthesises answer from the verified tool result  │   │ ToolGateway: goal scope → guardrail →    │
   │ → numeric grounding → OUTPUT guardrail                     │   │   rate limit → identity → RBAC →         │
   └────────────────────────────┬──────────────────────────────┘   │   ownership → risk → approval → MCP      │
                                 ▼                                  └───────────────────┬──────────────────────┘
        MCP SERVER (31 tools; independent permission/risk/argument checks) ◀──────────────┘
                                 ▼
        SYNTHETIC LEDGER (one FintechService per process)  +  MCP tool suite state (synced at execution)
                                 ▼
        AUDIT (logs/audit.jsonl)  ·  TRACE STORE  ·  AttackTrace (lab)  ·  reports/
```

## Components

| Concern | Implementation | Status |
|---|---|---|
| LLM | `llm/ollama_client.py` (health, model check, timeouts, tool calls, `stream_chat`), `llm/conversation.py` | Real; labelled offline fallback |
| Conversation | history (last turns), RAG in the same turn, grounded tool calls, numeric grounding, tool-JSON scrubbing | Real |
| Streaming | `ConversationEngine.stream` → `st.write_stream` for tool-free turns | Real (dashboard); the JSON API returns complete answers |
| RAG | `rag/` chunking + metadata (`document_id, source, title, version, chunk_id, trust_level, created_at, sensitivity, owner`), `nomic-embed-text` + TF-IDF, thresholds, injection scan | Real |
| Memory | `memory/provenance.py` (short-term/session/user layers, provenance, validation, quarantine); chat "remember" + prompt injection of validated notes | Real |
| Auth / RBAC | `auth/` (PBKDF2, MFA sim, sessions with TTL), 5 roles, 9 permissions, ownership | Real |
| Multi-agent | `agents/` (chat path, deterministic) and `lab/bus.py` (six agents with capability manifests, signed messages) | Real / lab-only |
| Inter-agent comms | `lab/bus.py::AgentBus` | Lab path |
| MCP | `mcp_server/` — 31 registered tools incl. all 20 spec tools; schema, risk, roles, owner, trust level | Real (in-process, not a network MCP server) |
| Risk / approval | `fintech/risk/`, `security/approval_engine.py`, `fintech/transaction_lifecycle.py` (`complete_approved`, `reject_pending`) | Real |
| Audit / telemetry | `observability/audit.py` (JSONL), `observability/trace.py`, `lab/core.py::AttackTrace` | Real; no OTLP exporter |
| Dashboard | `chatbot/` — Chat, Users, Account, Transactions, Approvals, Agents, RAG, Memory, MCP Tools, Security Gateway, Attack Lab, Agent Trace, Audit, Reports, System Health + 10 OWASP pages | Real |

## Data stores

* **Ledger**: `fintech.service.get_shared_fintech_service()` — one process-wide synthetic ledger read by chat, the API routes, the
  dashboard views and the transaction lifecycle. (An earlier version had five independent copies; a completed transfer never showed
  in the balance card. Fixed and covered by `tests/test_chat_streaming_history.py`.)
* **MCP tool suite** (`FinTechToolSuite`): its own copy of accounts/cards/tickets, synced from the ledger before each MCP execution.
  This remains a duplicate store (see gaps).
* **Vector stores**: `data/vector_store.json` (chat), `data/lab_vector_store.json` (lab).
* **Chat history**: `data/chat_history/<user>/<conversation>.json`, one file per chat (dashboard only); every login starts a new chat and earlier ones appear under Chat History in the sidebar.
* **Audit**: `logs/audit.jsonl`. **Reports**: `reports/`.

## Lab runtime

`lab/core.py` defines the trace, the synthetic world (`LabEnvironment`) and the `ToolGateway` in *vulnerable* and *secure* form.
`lab/controls.py` (goal guard, rate limiter, identity authority, circuit breaker, supervisor), `lab/bus.py`, `lab/sandbox.py`,
`lab/supplychain.py`, `lab/approval.py`, `memory/provenance.py` and `lab/policy.py` (the deliberately gullible agent policy, optionally
the real Ollama model) are composed by `lab/scenarios/asiNN.py`. `lab/runner.py` runs each variant in both modes and derives the test
records and reports. See `docs/owasp-agentic-top10.md` and `docs/security-model.md`.

## Request flow: a high-risk transfer from chat

1. Message → auth session → perimeter → `ConversationEngine` (tool `transfer_funds` offered because of the wording).
2. Ollama proposes `transfer_funds`; arguments are grounded in the user's text; `ToolGuardrail` checks whitelist/RBAC/ownership.
3. `TransactionLifecycleService` (24 steps) evaluates risk; ≥ 10,000 or HIGH/CRITICAL → **APPROVAL_REQUIRED**, an approval record is
   queued and *nothing moves*.
4. A human with a staff role (Support/Fraud/Admin) approves on the **Approvals** page or `POST /approvals/{id}/approve`. The request's
   own customer and AI identities are refused; a risk-policy BLOCK cannot be approved; the transfer must match the approved parameters.
5. `complete_approved` dispatches through the MCP gateway, updates the ledger once, and writes audit records.
