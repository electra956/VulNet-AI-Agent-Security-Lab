# Development Guide

## Repository layout

| Path | Purpose |
|---|---|
| `api/` | FastAPI gateway: `/auth`, `/chat`, `/account`, `/security`, `/lab`, `/approvals` |
| `chatbot/` | Streamlit dashboard (`app.py`, `components/*`), persistent chat history (`sessions/history_store.py`) |
| `llm/` | Ollama client, prompts, `ConversationEngine` (RAG → prompt → LLM → guarded tools → LLM), streaming |
| `rag/` | Hybrid retrieval (Ollama embeddings + TF-IDF), chunk metadata, vector store, `knowledge/*.txt` |
| `memory/` | Legacy stores + `provenance.py` (provenance memory used by chat and lab) |
| `agents/` | Chat-path orchestrator and specialised agents |
| `mcp_server/` | Tool registry (31 tools), permission/risk/argument validators, simulated FinTech tools |
| `auth/` | Users, PBKDF2 passwords, simulated MFA, sessions, roles, permissions |
| `fintech/` | Synthetic ledger (`FintechService`, shared singleton), risk engine, 24-step transaction lifecycle |
| `security/` | Security controller/gateway, threat detector, guardrails, approval engine, settings |
| `observability/` | Audit logger (JSONL), request tracer, trace store |
| `lab/` | **Attack Lab**: core gateway/trace, controls, agent bus, sandbox, supply chain, approval packet, scenarios, runner |
| `security_tests/` | Prompt-injection suite + `asi01/`…`asi10/` packages that run the lab tests + CLI |
| `tests/` | pytest suite (`tests/lab/` = lab, `tests/security/` = prompt-injection) |
| `docs/` | This documentation |
| `start.sh`, `setup.sh`, `setup.ps1`, `setup_windows.ps1` | Launch / install |

## Everyday commands

```bash
./start.sh                 # Ollama (if installed) + API :8000 + dashboard :8501
./start.sh stop | status | test | report
python -m pytest -q        # everything
python -m pytest -q tests/lab            # lab only (UI tests are slowest, ~2 min)
python -m lab list | run ASI01 direct --mode vulnerable | test | report
```

## Adding an attack scenario

1. Pick the category module in `lab/scenarios/asiNN.py`.
2. Write a runner `def _my_attack(ctx: RunCtx, payload, use_llm) -> dict`. Use the helpers on `RunCtx`:
   `ctx.attack_input(...)` (must be the first trace step), `ctx.perimeter(text)`, `ctx.use_goal_guard(msg)`,
   `ctx.plan(msg, blocks, use_llm)`, `ctx.run_calls(plan)`, `ctx.gw.request(tool, args, identity)`, `ctx.env` (ledger), `ctx.trace`.
   Return a dict of evidence; add `"impact": {...}` for extra measurable impact.
3. Register a `Variant(id, title, description, preconditions, default_input, expected_vulnerable, expected_secure, control, runner)`.
4. Make the **vulnerable** run produce an `ATTACK_EFFECT` step (ledger change, sink record, state change) and the **secure** run a
   `BLOCK` / `APPROVAL_REQUIRED` step whose `control=` names the control. Add an assume-breach probe when an upstream control stops
   the attack first.
5. Regenerate the docs table (`docs/owasp-agentic-top10.md`) — `tests/lab/test_docs_sync.py` fails if a test id is undocumented.
6. `python -m lab test ASINN` then `python -m pytest -q tests/lab`.

## Adding a control

Put deterministic logic in `lab/controls.py` (or the relevant production module), call it from `ToolGateway._secure` or the scenario,
record the decision with `trace.add(stage, component, verdict, detail, control="NAME")`, and add a unit test in
`tests/lab/test_lab_controls.py`. Controls must not call an LLM.

## Adding an MCP tool

Add the method to `mcp_server/fintech_tools.py::FinTechToolSuite`, register `ToolMetadata` (schema, risk, roles, owner, trust) in
`mcp_server/tools.py::create_default_registry`, and add the permission/ownership rule to `lab/core.py::TOOL_POLICY`.

## Conventions and gotchas

* `AttackTrace.add(stage, component, verdict, detail, /, agent=None, **data)` — the first four parameters are positional-only so a
  data key may be named `component`/`verdict`.
* Stages are the fixed list in `lab/core.py::STAGES`; verdicts are `INFO, ALLOW, BLOCK, REVIEW, APPROVAL_REQUIRED, ATTACK_EFFECT, ERROR`.
* Never take identity from tool arguments or message payloads in Secure code. Identity comes from the session (`Identity`).
* There is **one** synthetic ledger per process: use `fintech.service.get_shared_fintech_service()`; tests that need isolation build
  `FintechService()` or call `reset_shared_fintech_service()`.
* `lab/data/` holds synthetic fixtures (poisoned RAG document, rogue-agent config); `.gitignore` explicitly un-ignores it even though
  `data/` is ignored elsewhere.
* Lab runs write to `logs/audit.jsonl` and use `data/lab_vector_store.json`; neither touches the chat's `data/vector_store.json`.
* Do not add real credentials, hosts or endpoints anywhere. Everything must stay local and synthetic.

## Configuration

`.env` (copy from `.env.example`): `SECURITY_MODE`, `VULNET_ENV` (`local_lab` | `hardened`), `VULNET_ALLOW_MODE_OVERRIDE`,
`VULNET_EXPOSE_MFA_CODE`, `VULNET_SESSION_TTL_SECONDS`, `VULNET_CORS_ORIGINS`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_EMBED_MODEL`,
`VULNET_USE_LLM`, `VULNET_RAG_EMBEDDINGS`. Ports for `start.sh`: `API_PORT`, `UI_PORT`.
