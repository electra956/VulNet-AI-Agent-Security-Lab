# Project Status — single source of truth

Nothing below is marked **IMPLEMENTED** unless it was verified by a test or by a runtime check recorded in *TEST STATUS*.
`tests/lab/test_docs_sync.py` keeps the OWASP documentation aligned with the code.

## CURRENT VERSION

**3.1.0 — "Attack Lab"** (branch `version-3`, builds on 3.0). Adds the executable OWASP Top 10 for Agentic Applications (2026) lab,
signed inter-agent bus, provenance memory in chat, real streaming, one shared ledger, a working human-approval workflow and a
one-command launcher. Dated 2026-09-30.

## CURRENT ARCHITECTURE

Two paths sharing the security building blocks (details in [architecture.md](architecture.md)):

* **Chat path**: dashboard/API → auth → perimeter → RAG → Ollama → grounded tool calls → tool guardrail → 24-step transaction
  lifecycle (risk → human approval → MCP → shared ledger) → output guardrail → audit.
* **Lab path**: scenario → agent policy (deterministic or real Ollama) → signed `AgentBus` / six agents → `ToolGateway`
  (goal scope → guardrail → rate limit → identity → RBAC → ownership → risk → approval → MCP) → synthetic world → trace + audit → reports.

## IMPLEMENTED (verified)

* Real local LLM (Ollama): health/model check, timeouts, structured messages, multi-turn history, grounded tool calling, labelled
  offline fallback, **real token streaming** for tool-free turns, raw tool-call JSON scrubbing. *(runtime + `tests/test_chat_streaming_history.py`)*
* Real RAG: chunking with full metadata, `nomic-embed-text` + TF-IDF hybrid retrieval, thresholds, trust levels, injection scan and
  neutralisation, poisoned-document handling. *(runtime shows `hybrid:nomic-embed-text`; `tests/test_fintech_rag.py`, lab ASI01/06)*
* Memory with provenance (`memory/provenance.py`): validation, quarantine, per-user isolation; chat `Remember that …` + recall by the LLM;
  Memory page. *(runtime + tests)*
* Auth (PBKDF2, simulated MFA, TTL, lockout), six synthetic identities (`CUST-001/002`, `SUPPORT-001`, `FRAUD-001`, `COMPLIANCE-001`,
  `ADMIN-001`), five roles, nine permissions, ownership enforcement.
* MCP-style tool gateway with 31 registered tools (all 20 from the spec) carrying schema, risk, roles, owner, trust level, required permission.
* Deterministic risk engine, human-approval engine, 24-step transaction lifecycle, **human completion/rejection of queued transfers**
  (Approvals page + `/approvals` API): AI/requester cannot approve, risk BLOCK cannot be approved, scope-bound, single execution.
* One shared synthetic ledger per process (chat, API, dashboard, lifecycle).
* Attack Lab: 47 executable variants across ASI01–ASI10, each run vulnerable and secure with a 12-stage trace, controls named,
  ledger/sink impact measured, audit records, automated statuses, reports (`reports/*.md|json`), CLI, API and dashboard.
* Signed inter-agent bus + six agents with distinct capability manifests + `RogueAgent` and `AgentSupervisor` (kill switch).
* Restricted AST sandbox (real) and virtual-host emulator (vulnerable side).
* Supply-chain AIBOM with admission control; provenance/hash/version/signature/metadata checks.
* Dashboard: 15 pages + 10 OWASP pages, persistent chat history, live health page.
* `start.sh` launcher, setup scripts install Ollama and pull both models.

## PARTIAL

* **Multi-agent in the product path**: the chat pipeline's agents (`agents/`) are deterministic and separate from the lab's signed
  bus/agents. The lab agents are real but are not yet the runtime behind the chat.
* **MCP**: an MCP-*style* in-process gateway (registry, schemas, policy, sandboxed handlers). It does not speak the MCP wire protocol.
* **Telemetry**: structured JSONL audit + in-process trace store + per-run `AttackTrace`; no OpenTelemetry exporter.
* **Streaming**: dashboard only, and only for turns that need no tools; the JSON API returns complete answers.
* **Memory layers**: short-term = conversation history, user memory = provenance store; the legacy `memory/` stores
  (`ConversationMemory`, `MemoryStore`, `UserMemory`) remain unused by the app path (tests only).
* **Duplicate store**: `FinTechToolSuite` keeps its own account/card copy, synced from the ledger before MCP execution.

## SIMULATED (by design, for safety)

* All money, accounts, cards, KYC and fraud data (synthetic, `real_funds_moved: false`).
* MFA code (shown on screen), notifications, identity verification.
* ASI04 third-party components (in-process fixtures; no downloads) and the "attacker sink".
* ASI05 vulnerable side (virtual host emulator with canary secrets); the secure sandbox is real.
* ASI09 approver persona in automated runs (scripted; the real human workflow is the Approvals page).

## PLANNED

* Run the lab agents behind the chat (unify the two paths) and route chat tool calls through the lab `ToolGateway`.
* OpenTelemetry exporter; MCP wire-protocol server; SSE streaming on `/chat`.
* Retire the duplicate MCP-suite store; retire or wire the legacy `memory/` stores.
* Dockerfile / compose for one-command container start.

## KNOWN LIMITATIONS

* Lab PASS means "this control stops this attack class here", not that the system is secure; the vulnerable side is deliberately weak code.
* Default agent decisions are deterministic (repeatable); with the real LLM (`--llm`) results vary (example: ASI01 3 PASS / 2 PARTIAL).
* Pattern-based detectors are heuristics; the design relies on the deterministic layers behind them.
* Sandbox is an in-process AST evaluator, not an OS-level jail. Signing keys are lab keys.
* UI verified with Streamlit `AppTest` and HTTP checks, not with a real browser.
* Currencies are mixed in the chat path (₹ gate in the guardrail, USD ledger); a pre-existing inconsistency.

## OWASP STATUS

| ID | Category | Status | Evidence (tests / traces) |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | **REAL** | 5 variants PASS (`ASI01-*`); with real LLM 3 PASS / 2 PARTIAL |
| ASI02 | Tool Misuse & Exploitation | **REAL** | 5 variants PASS |
| ASI03 | Identity & Privilege Abuse | **REAL** | 5 variants PASS |
| ASI04 | Agentic Supply Chain | **SIMULATED** (local fixtures) | 6 variants PASS; AIBOM admission decisions tested |
| ASI05 | Unexpected Code Execution | **SIMULATED** vulnerable side / **REAL** secure sandbox | 4 SIMULATED + 1 control PASS; host-safety test |
| ASI06 | Memory & Context Poisoning | **REAL** | 4 variants PASS; chat memory runtime check |
| ASI07 | Insecure Inter-Agent Communication | **REAL** (lab path) | 6 variants PASS; bus unit tests |
| ASI08 | Cascading Failures | **REAL** (lab path) | 4 variants PASS incl. rollback |
| ASI09 | Human-Agent Trust Exploitation | **REAL** (scripted persona in automation) | 3 variants PASS; Approvals page tests |
| ASI10 | Rogue Agents | **REAL** (lab path) | 4 variants PASS; kill switch tested |

## SUBSYSTEM AUDIT

| Subsystem | Verdict | Evidence |
|---|---|---|
| LLM | **REAL** | live `llama3.2` replies, streamed, tool calls, offline fallback labelled |
| RAG | **REAL** | `hybrid:nomic-embed-text`, metadata table on RAG page, poisoned doc neutralised |
| MEMORY | **REAL** | chat remember/recall, poisoned memory rejected, isolation tests |
| MULTI-AGENT | **PARTIAL** | six distinct agents in the lab path; product path agents separate |
| INTER-AGENT | **REAL** (lab path) | signed envelopes, replay/spoof/tamper tests |
| MCP | **PARTIAL** | in-process MCP-style gateway, 31 tools, no wire protocol |
| RBAC | **REAL** | matrix + ownership tests, API 403s |
| RISK | **REAL** | deterministic engine, block/approval tests |
| APPROVAL | **REAL** | human completion, negative cases, API + UI tests |
| TELEMETRY | **PARTIAL** | JSONL audit + traces; no OTel |
| DASHBOARD | **REAL** | 25 AppTest page renders (15 pages + 10 OWASP) + approvals flows; not browser-verified |

## TEST STATUS

* Full suite (2026-09-30, `python -m pytest -q`): **667 passed, 1 skipped, 0 failed in 4 min (the skip is the ASI05 control experiment in the trace-order test)**.
* Lab: 47 tests → 43 PASS, 4 SIMULATED (ASI05 effect emulated), 0 PARTIAL, 0 FAIL (`python -m lab test`, `reports/`).
* Runtime checks on the live stack (`./start.sh`): login/MFA, chat with real LLM + RAG + memory, transfers, approval flow, lab API —
  see [testing.md](testing.md).

## RUN COMMANDS

```bash
./start.sh                      # Ollama + API :8000 + dashboard :8501
./start.sh stop | status | test | report
python -m lab list | run ASI01 direct --mode vulnerable | test | report
python -m security_tests owasp -c ASI07
python -m pytest -q
```

## CONFIGURATION

`.env` (see `.env.example`): `SECURITY_MODE`, `VULNET_ENV` (`local_lab`/`hardened`), `VULNET_ALLOW_MODE_OVERRIDE`, `VULNET_EXPOSE_MFA_CODE`,
`VULNET_SESSION_TTL_SECONDS`, `VULNET_CORS_ORIGINS`, `OLLAMA_BASE_URL` / `OLLAMA_MODEL=llama3.2` / `OLLAMA_EMBED_MODEL=nomic-embed-text`,
`VULNET_USE_LLM`, `VULNET_RAG_EMBEDDINGS`. Models are configurable; nothing is hard-coded to one model.

## CURRENT GAPS

1. Product path and lab path are two runtimes (see PLANNED #1).
2. No OpenTelemetry, no MCP wire protocol, no SSE streaming, no Docker files.
3. `FinTechToolSuite` duplicate store; legacy `memory/` stores unused by the app.
4. LLM-in-the-loop lab runs are not part of the automated suite (non-deterministic).

## NEXT STEP

Unify the runtimes: drive the chat's tool calls through the lab `ToolGateway`/`AgentBus` so every chat turn produces the same 12-stage
trace the lab shows, then retire the duplicate MCP-suite store and add an OpenTelemetry exporter.
