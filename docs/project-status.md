# 🛡️ VulNet FinTech AI Agent Security Lab — Project Status & Source of Truth

```text
PROJECT:                      VulNet FinTech AI Agent Security Lab
VERSION:                      Version 3.0 (Level 2 Enhanced)
BRANCH:                       version-3
STATUS:                       Audited, Verified & Operationally Complete
LAST COMPREHENSIVE AUDIT:     Step 17C Validation Suite
AUTOMATED TEST PASS RATE:     100% (329 Passed, 0 Failed across 32 suites)
```

---

## 🏗️ 1. Current Verified Architecture

```text
USER / CLIENT (Browser :8501 or REST API :8000)
       │
       ▼
[STAGE 1] INPUT GUARDRAIL
       │ Scans prompt injection (ASI01), overrides, prompt leakage, null bytes
       ▼
AUTHENTICATION & SESSION BINDING
       │ PBKDF2-HMAC-SHA256 password verification + simulated MFA challenge
       │ Injects immutable SessionContext (User ID, Role, Authorized Accounts)
       ▼
FINTECH AGENT ORCHESTRATOR
       │
       ├──► [STAGE 2] RAG GUARDRAIL & DENSE VECTOR STORE
       │      Quarantines untrusted sources, neutralizes embedded instructions
       │      Retrieves 128-dim normalized dense vector chunks via Cosine Similarity
       │      Envelopes passive reference context in XML <trusted_data> boundaries
       │
       ├──► CONVERSATIONAL LLM CLIENT (Ollama / Local Fallback)
       │      Live local Ollama connection (llama3.2 on GPU) + auto-discovering WSL bridge
       │      Zero-dependency fallback simulation when Ollama daemon is offline
       │
       ├──► [STAGE 3] TOOL GUARDRAIL (Zero-Trust Execution Gate)
       │      Validates tool whitelist, argument types & schema
       │      Enforces customer account ownership (BOLA prevention)
       │      Enforces RBAC matrix (actions permitted per role)
       │      Intercepts high-value transfers (> ₹50,000) -> APPROVAL_REQUIRED gate
       │
       ├──► FINTECH MCP SERVER & SIMULATED DOMAIN TOOLS
       │      Executes get_account_balance, get_transaction_history, transfer_funds
       │      Operates strictly on local in-memory synthetic state; 0 external bank APIs
       │
       └──► [STAGE 4] OUTPUT GUARDRAIL
              Redacts sensitive payment card PANs, CVVs, credentials
              Blocks internal system prompt leakage
              Suppresses unverified completion claims if tool was not called or failed
       │
       ▼
AUDIT LOGGER & OBSERVABILITY TRACE STORE
       │ Correlated request_id, session_id, execution latency, and step-by-step checklist
       ▼
USER RESPONSE & REAL-TIME DASHBOARD
```

---

## 🧩 2. Component Implementation Status

### ✅ Implemented & Verified Components
1. **Input Guardrail (`security/guardrails/input_guardrail.py`)**: Real regex & heuristic perimeter defense scanning prompts for ASI01, overrides, extraction, and null bytes.
2. **Ollama Integration & WSL Bridge (`llm/ollama_client.py`)**: Live `httpx` client with auto-discovery for local host and WSL IP (`172.x.x.x:11434`), supporting live `llama3.2` streaming, tool-calling extraction, and resilient offline fallback.
3. **Persistent Dense Vector RAG (`rag/vector_store.py`, `rag/rag_engine.py`)**: 128-dimensional dense vector embeddings (`LocalDenseEmbedder`), cosine similarity search, disk persistence in `data/vector_store.json`, and enriched chunk metadata.
4. **RAG Guardrail (`security/guardrails/rag_guardrail.py`)**: Validates trust levels, neutralizes indirect prompt injections (`[NEUTRALIZED_UNTRUSTED_INSTRUCTION]`), and wraps context in rigid XML data envelopes.
5. **Tool-Call Guardrail (`security/guardrails/tool_guardrail.py`)**: Zero-trust tool execution, argument validation, account ownership enforcement, and dual-control approval gate (> ₹50,000).
6. **Output Guardrail (`security/guardrails/output_guardrail.py`)**: PII redaction (PANs, CVVs, passwords), prompt leakage interception, and unverified claim suppression.
7. **Authentication & MFA (`auth/`)**: Salted PBKDF2 password hashing, one-time MFA challenges, and immutable `SessionContext` binding.
8. **FinTech RBAC (`auth/authorization.py`, `auth/permissions.py`)**: Granular permissions (`account.read`, `transaction.create`, `fraud.review`, etc.) enforced strictly outside the LLM.
9. **Account Ownership Boundaries (`fintech/service.py`)**: Direct BOLA prevention ensuring customers cannot access accounts they do not own.
10. **Transaction Risk Engine (`fintech/risk/transaction_risk.py`)**: Multi-factor velocity and tier evaluation flagging suspicious transactions.
11. **Human-in-the-Loop Approval Gate (`mcp_server/fintech_tools.py`, `security/guardrails/tool_guardrail.py`)**: Halts execution on transfers exceeding ₹50,000 until human dual-control confirmation.
12. **MCP Security Server (`mcp_server/`)**: Independent authorization boundary enforcing tool whitelists and role permissions.
13. **Agent Memory Subsystem (`memory/`)**: Partitioned conversation and user memory with strict anti-authorization validation (memory can never grant roles or permissions).
14. **Telemetry & Observability (`chatbot/observability/`)**: Request tracers recording end-to-end execution stages, timing profiling, and audit logging.
15. **Streamlit UI & FastAPI Gateway (`chatbot/`, `api/`)**: Interactive multi-turn chat, account cards, transaction ledgers, security mode toggle, and Swagger API docs.

### 🟡 Partially Implemented / Simplified Components
1. **Multi-Agent Chain-of-Thought Routing**: Specialized agents exist in `agents/specialized_agents.py`, but conversational tool calls currently route directly through the Orchestrator and Tool Guardrail for low latency.
2. **Dense Embeddings Granularity**: Built-in `LocalDenseEmbedder` uses 128-dimensional n-gram projection with cosine similarity; optionally bridges to Ollama `/api/embeddings` (`nomic-embed-text`) when running.

### 🔬 Simulated Components (By Design for Safety)
1. **FinTech Domain Data**: Accounts (`ACC-1001`, `ACC-2001`, etc.), balances, cards, and transactions exist strictly in local in-memory dictionaries.
2. **MFA Verification**: 6-digit challenge generation is simulated locally with 5-minute expirations; no SMS or external TOTP gateways.
3. **No External Network Access**: Zero outgoing calls to real payment networks (ACH, SWIFT, UPI) or cloud LLM APIs.

### ⏳ Not Yet Implemented (Planned)
1. **OWASP ASI02–ASI10 Multi-Stage Lab Scenarios**: While foundational guardrails prevent tool misuse and privilege escalation, dedicated educational demonstration views for ASI02 through ASI10 are scheduled for subsequent steps.

---

## 📊 3. Automated Test Status

Full regression run executed via `python -m pytest`:
- **Total Test Suites:** 32 test files
- **Total Tests Collected:** 329
- **Passed:** 329
- **Failed:** 0
- **Pass Rate:** **100%**
- **Execution Time:** ~42.1 seconds

---

## 🚨 4. OWASP Agentic AI Status Matrix

| ID | Threat Category | Status | Verified Implementation & Defensive Invariant |
|:---|:---|:---:|:---|
| **ASI01** | Agent Goal Hijack | ✅ IMPLEMENTED | InputGuardrail intercepts prompt injection; RAGGuardrail neutralizes indirect context injection; Goal anchoring in Orchestrator. |
| **ASI02** | Tool Misuse & Tampering | 🟡 PARTIAL | ToolGuardrail enforces zero-trust argument schemas and whitelist; dedicated exploitation scenario planned for Step 18. |
| **ASI03** | Identity & Privilege Abuse | 🟡 PARTIAL | Deterministic PBKDF2 authentication, RBAC, and BOLA account ownership checks outside LLM; interactive demo view planned. |
| **ASI04** | Supply Chain Risks | 🔬 SIMULATED | Tool imports and MCP server verified; standalone demonstration planned. |
| **ASI05** | Unexpected Code Execution | ✅ IMPLEMENTED | InputGuardrail blocks `eval`, `subprocess`, and SQL injection syntax in inputs; zero dynamic execution in agents. |
| **ASI06** | Memory & Context Poisoning | ✅ IMPLEMENTED | MemoryValidator rejects authorization claims, role upgrades, and exfiltration attempts before persistence. |
| **ASI07** | Inter-Agent Communication | 🔬 SIMULATED | Orchestrator validates data boundaries between pipeline stages. |
| **ASI08** | Cascading Failures | ✅ IMPLEMENTED | Graceful error containment; offline fallback simulator ensures zero cascading crashes when Ollama is unavailable. |
| **ASI09** | Over-reliance & Human Trust | ✅ IMPLEMENTED | OutputGuardrail suppresses unverified financial completion claims; dual-control human approval gate on > ₹50,000. |
| **ASI10** | Rogue Agents | 🟡 PARTIAL | Agent cannot directly execute tools without Orchestrator, Tool Guardrail, and MCP authorization. |

---

## ⚙️ 5. Current Run & Configuration Commands

### Environment Setup
```powershell
# Windows PowerShell
.\setup.ps1

# Linux / WSL
chmod +x setup.sh && ./setup.sh
```

### Running the Applications
```powershell
# Frontend Streamlit Dashboard & Chatbot (Port 8501)
.\venv_win\Scripts\python -m streamlit run chatbot/app.py

# Backend FastAPI Gateway (Port 8000)
.\venv_win\Scripts\python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

### Running the Test Suite
```powershell
.\venv_win\Scripts\python -m pytest -v
```

---

## 🔒 6. Important Security Design Principles
1. **LLM is Never an Authorization Authority**: Permissions, account ownership, and roles are determined strictly in deterministic code (`auth/`, `fintech/service.py`).
2. **Zero-Trust Tool Execution**: Tool calls emitted by the LLM are treated as untrusted user input and must pass schema, ownership, and whitelist checks.
3. **Passive RAG Data Boundary**: Retrieved documents are reference data, never executable instructions.
4. **Dual-Control Human Approval**: High-value transactions (> ₹50,000) cannot be executed autonomously by any model.
5. **Defense-in-Depth**: 4 independent guardrail layers operate before and after LLM generation.


## Hardening pass (real-world replication)
Server-side security mode, gated MFA code, random session IDs with TTL, login lockout (429), authenticated
`/security/evaluate`, CORS allow-list and security headers. See [hardening.md](hardening.md).
Tests: 396 total (`tests/test_hardening.py` adds 9; `tests/test_login_page.py` adds 3). `test_audit_phase3_ollama_live` needs a running Ollama server.


## Real LLM + RAG remediation (audit follow-up)
Fixed: tool results are fed back to the model (final answer is model-written); tools are exposed only when needed; model-invented
arguments are grounded or rejected; Ollama embeddings + hybrid retrieval with a persisted, model-tagged vector store;
stale `OLLAMA_BASE_URL` corrected; offline simulation clearly labelled; stronger RAG-poisoning patterns plus a taint policy;
FastAPI `/chat` shares the same engine (with `llm_model`, `retrieval_mode`, `retrieved_sources`, `tools_called` in the response).
See [llm-and-rag.md](llm-and-rag.md). Tests: 396 (`test_conversation_engine.py` 22 deterministic, `test_live_llm_rag.py` 7 live).
