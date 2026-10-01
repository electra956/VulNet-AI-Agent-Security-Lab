# Testing Guide

## Run everything

```bash
./start.sh test            # or: python -m pytest -q
python -m pytest -q tests/lab               # the executable OWASP lab (UI tests are the slow part, ~2 min)
python -m pytest -q tests/security          # prompt-injection suites
python -m security_tests owasp              # ten-category status table (vulnerable vs secure)
python -m security_tests prompt-injection   # prompt-injection engine (see docs/prompt-injection-testing.md)
python -m lab test                          # same 47 lab tests, printed as a table
```

Last full run: **685 passed, 1 skipped, 0 failed (~4 min; the single skip is the ASI05 legitimate-use control experiment inside the trace-order test)** (see `project-status.md` → TEST STATUS for the dated result). Nothing in the suite needs the network; tests
that talk to Ollama (`tests/test_live_llm_rag.py`) use it when reachable and fall back to the labelled offline path otherwise.

## What is tested, by layer

| Layer | Files | What is proved |
|---|---|---|
| **OWASP lab scenarios** | `tests/lab/test_lab_scenarios.py` | For all 47 variants: attack **succeeds** when vulnerable (ledger/sink/state change) and is **stopped by a named control** when secure; trace starts with `ATTACK_INPUT`, contains a blocking step and audit records; secure mode never moves funds to the attacker; runs are deterministic; unknown inputs rejected |
| **ASI05 safety** | `tests/lab/test_lab_sandbox.py` | Sandbox allows legitimate analysis, rejects calls/attributes/lambdas/comprehensions/strings/names, enforces size/step/resource limits and path rules; **all ASI05 attacks run with `os.system`, `subprocess`, `eval`, `exec` replaced by functions that fail the test if called**; virtual host is isolated |
| **Agent bus (ASI07)** | `tests/lab/test_lab_bus.py` | Valid delivery; spoofed sender, tampering, replay, authorisation matrix, unknown receiver/intent/schema rejected; vulnerable bus delivers forgeries; agents have distinct capability manifests |
| **Controls** | `tests/lab/test_lab_controls.py` | GoalGuard, rate limiter, identity signature, circuit breaker, supervisor kill switch, deterministic risk, gateway (unknown tool, forged authority args, invalid amounts, ownership, **AI cannot approve**, human approval executes through MCP, every decision audited) |
| **Supply chain / memory / approval / reports** | `tests/lab/test_lab_supply_memory_approval.py` | Admission decisions and findings per component; memory validation, quarantine, isolation; approval packet built from evidence, contradictions detected; reports generated from real runs and consistent with the counts; `security_tests/asiNN` packages and official OWASP names |
| **Lab API** | `tests/lab/test_lab_api.py` | Auth required, mode gate, validation errors (422), `/lab/test` record fields, tool catalogue contains all 20 spec tools, six synthetic identities exist |
| **Dashboard** | `tests/lab/test_lab_ui.py` | Streamlit `AppTest`: every page renders without exception; each of the ten OWASP pages launches a live test and renders the result; an admin approves through the Approvals page and the transfer executes; a customer has no decision buttons |
| **Docs sync** | `tests/lab/test_docs_sync.py` | Every lab test id is documented; required docs exist; `project-status.md` has the required sections; no wrong-taxonomy labels |
| **Chat engine** | `tests/test_conversation_engine.py`, `tests/test_chat_streaming_history.py` | Tool grounding, RAG in the prompt, numeric grounding; real chunked streaming for tool-free turns; chat memory (validated, poisoned rejected, per-user isolation, vulnerable mode); history store; tool-call JSON scrubbing; **one shared ledger** across chat/API/dashboard/lifecycle and a completed transfer visible everywhere |
| **Human approval** | `tests/test_human_approval_workflow.py`, `tests/test_approvals_api.py` | AI/orchestrator/requesting customer cannot approve; authorised staff completes exactly once; rejection keeps funds; tampered or expired requests refused; a risk BLOCK cannot be approved; API identity comes from the session; compliance is read-only |
| **Prompt-injection suites** | `tests/security/*`, `security_tests/` | 33 injection cases (direct, RAG, tool/MCP, exfiltration canaries) for ASI01–05/07 with zero canary leaks; ASI06/08/09/10 assert lab coverage |
| **Platform** | remaining `tests/test_*.py` | Auth/MFA, RBAC, ownership, risk engine, approval engine, MCP gateway, RAG + vector store, guardrails, orchestrator, observability, hardening, login page |

## How lab statuses are computed

`lab/runner.py` runs each variant in vulnerable then secure mode and classifies the pair: **PASS** (attack succeeded, then blocked by a named
control), **SIMULATED** (same but the effect is emulated — ASI05), **PARTIAL**, **FAIL**. No status is hard-coded; the reports
(`python -m lab report`) contain the counts derived from the same runs.

## Runtime (non-mocked) checks used during development

Performed against the live stack started by `./start.sh` (real Ollama `llama3.2`, `nomic-embed-text`):

* login + MFA → `/chat`: greeting (LLM), policy question (hybrid retrieval, ~15 s cold), balance (deterministic), `Remember that …`
  (memory service) and later recall by the LLM, perimeter block of an injection, cross-account block, ₹50k gate;
* `/chat` transfer of 25 → balance card 5,420.50 → 5,395.50; transfer of 11,000 → approval queued; customer approve → 403; support
  approve → completed; `ACC-1002` = 1,875.00;
* `/lab/run`, `/lab/test`, `/lab/report`; `python -m lab test ASI01 --llm` and `ASI06 --llm` with the real model deciding
  (ASI01: 3 PASS / 2 PARTIAL because the model ignored two injections in that run; ASI06: 4 PASS).

## Known test limitations

* LLM-in-the-loop runs (`--llm`) are non-deterministic by nature and are not part of the automated suite.
* The Streamlit tests use `AppTest` (no real browser); layout/CSS is not verified.
* There is no load/performance testing and no external penetration test.
