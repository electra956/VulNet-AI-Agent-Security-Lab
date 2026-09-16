# 🧪 VulNet FinTech AI Agent Security Lab — Testing Guide

The VulNet test suite provides comprehensive, deterministic unit and integration coverage across the entire Agentic AI pipeline, FastAPI API Gateway, Customer Authentication, Simulated FinTech Domain, and all 10 OWASP security scenarios.

---

## 1. Running the Automated Test Suite

### Run All Tests via Pytest
```bash
# In Linux / WSL
source venv/bin/activate
pytest

# In Windows PowerShell
.\venv\Scripts\Activate.ps1
pytest
```

The test runner will execute all **238 automated test cases** across **24 test suites**:
1. **Action Agent** (`tests/test_action_agent.py`) — Action execution, approval boundaries, and high-risk action authorization.
2. **FastAPI API Gateway** (`tests/test_api.py`) — Health, Auth enforcement, Chat endpoints, Account lookups, OWASP Security evaluations, and request correlation.
3. **Customer Authentication & MFA** (`tests/test_auth.py`) — PBKDF2 hashing, MFA challenge-response, session tokens, logout, unauthenticated chat rejections.
4. **FinTech RBAC & Authorization** (`tests/test_authorization.py`) — Role normalization, 9 granular permissions, allowed/denied actions, cross-customer account BOLA rejection, and ASI03 regression tests.
5. **FinTech Chatbot** (`tests/test_fintech_chatbot.py`) — Chat view routing, state persistence, greeting extraction, balance/transaction queries, ASI01 mode toggle.
6. **Simulated FinTech Domain** (`tests/test_fintech_domain.py`) — Customer & account repositories, ownership invariants, balance retrieval, transaction history.
7. **Simulated FinTech Tool Ecosystem** (`tests/test_fintech_tools.py`) — 16 tools across ACCOUNT, PAYMENT, CARD, FRAUD, KYC, and SUPPORT categories; object-level ownership (BOLA prevention), high-risk human approval enforcement, and audit telemetry.
8. **Transaction Risk Engine** (`tests/test_transaction_risk.py`) — Deterministic local risk rules across LOW, MEDIUM, HIGH, and CRITICAL tiers; policy decisions (ALLOW, VALIDATE, REVIEW, BLOCK), granular audit trace telemetry, and agent override rejection.
9. **Human-in-the-Loop Approval Engine** (`tests/test_approval_engine.py`) — High-risk simulated action approval workflows, expiration/TTL checks, human role enforcement, double-decision immutability, and strict anti-self-approval defenses blocking AI actors.
10. **Main Agent** (`tests/test_main_agent.py`) — Context handling, goal extraction, and goal-drift detection.
11. **MCP Server & Safe Tools** (`tests/test_mcp.py`) — Tool listing, role-based access control (RBAC), argument sanitization, audit logging.
12. **Secure MCP Tool Gateway** (`tests/test_mcp_gateway.py`) — Registered tools, unknown tool rejection, unauthorized tool blocks, argument validation (type check & ASI02 injection detection), high-risk human approval gates, output validation, tool audit telemetry, and arbitrary Python execution prevention.
13. **Agent Orchestrator** (`tests/test_orchestrator.py`) — Multi-agent pipeline flow from user prompt through research and action.
14. **FinTech Agent Orchestrator & Specialized Agents** (`tests/test_agent_orchestrator.py`) — Intent classification, task planning, agent routing, structured outputs, financial safety invariants, and invalid request handling.
15. **FinTech Agent Memory Subsystem** (`tests/test_memory.py`) — Short-term conversation memory, user preferences, session context memory, authorization claim prevention, sensitive data sanitization, and ASI06 memory poisoning defense.
16. **OWASP Top 10 Scenarios** (`tests/test_owasp_scenarios.py`) — Automated side-by-side verification of ASI01 through ASI10 in Secure vs. Vulnerable modes.
17. **Quick Prompts Suite** (`tests/test_quick_prompts.py`) — Pre-configured adversarial and benign prompts validation.
18. **RAG Engine Manual** (`tests/test_rag_manual.py`) — TF-IDF vector retrieval, cosine similarity thresholds, and indirect prompt injection filtering.
19. **FinTech Knowledge Base & Hardened RAG** (`tests/test_fintech_rag.py`) — Semantic chunking, document metadata (`source`, `document_type`, `trust_level`, `created_at`), trusted vs untrusted content boundaries, indirect prompt injection neutralization, and dynamic synthetic RAG poisoning simulation.
20. **Research Agent** (`tests/test_research_agent.py`) — Context synthesis and command neutralization under Secure Mode.
21. **Security Controller** (`tests/test_security_controller.py`) — Signature heuristics, security event telemetry, and mode evaluation.
22. **Security Gateway** (`tests/test_security_gateway.py`) — Input validation, threat detection, policy enforcement, risk scoring, and structured decision contracts (`ALLOW`/`BLOCK`/`APPROVAL`).
23. **Security Pipeline Integration** (`tests/test_security_pipeline.py`) — End-to-end integration between Security Controller and agent pipeline.
24. **Session Context** (`tests/test_session_context.py`) — Request ID tracking, session ID isolation, multi-tenant session segregation, context preservation.

---

## 2. Targeted Test Execution

### Run Only API and Authentication Tests
```bash
pytest tests/test_api.py tests/test_auth.py -v
```

### Run Only FinTech Domain Tests
```bash
pytest tests/test_fintech_domain.py tests/test_session_context.py -v
```

### Run Only OWASP Scenarios
```bash
pytest tests/test_owasp_scenarios.py -v
```

### Run a Specific Scenario Test
```bash
# Test ASI01 Agent Goal Hijack in both modes
pytest tests/test_owasp_scenarios.py -k "ASI01" -v

# Test ASI02 Tool Misuse in both modes
pytest tests/test_owasp_scenarios.py -k "ASI02" -v
```

### Run Subsystem Tests Directly
Every test file can also be run directly with Python:
```bash
python tests/test_api.py
python tests/test_auth.py
python tests/test_fintech_domain.py
python tests/test_security_pipeline.py
python tests/test_mcp.py
```

---

## 3. Python Syntax Verification
To verify syntax across the entire repository without execution:
```bash
python -m py_compile agents/*.py api/*.py api/routes/*.py auth/*.py chatbot/*.py chatbot/components/*.py chatbot/sessions/*.py fintech/*.py mcp_server/*.py rag/*.py security/*.py vulnerabilities/**/*.py tests/*.py
```

---

## 4. Test Categories
1. **Perimeter & Gateway Tests**: Validate that the Security Controller and FastAPI reject unauthenticated or malicious inputs in Secure Mode and correlate telemetry headers.
2. **Identity & Authentication Tests**: Validate PBKDF2 password verification, MFA challenge issuance and one-time verification, session token lifetime, and unauthorized endpoint rejection.
3. **FinTech Domain Invariants**: Validate customer-to-account isolation, ensuring customers cannot view unauthorized accounts or transactions.
4. **Context & RAG Tests**: Validate TF-IDF relevance scoring, minimum score filtering, and indirect injection sanitization.
5. **Agent Goal Invariance Tests**: Validate that the Main Agent anchors the initial goal and detects goal drift.
6. **Tool Authorization & RBAC Tests**: Validate tool permission checking, risk tiering, and parameter injection prevention.
7. **Scenario Simulation Tests**: Validate that all 10 OWASP ASI scenarios execute reliably and emit structured security events.

