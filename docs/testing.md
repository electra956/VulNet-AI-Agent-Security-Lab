# 🧪 VulNet AI Agent Security Lab — Testing Guide

The VulNet test suite provides comprehensive, deterministic unit and integration coverage across the entire Agentic AI pipeline and all 10 OWASP security scenarios.

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

The test runner will execute all 49 automated test cases across:
- Action Agent (`tests/test_action_agent.py`)
- Main Agent (`tests/test_main_agent.py`)
- MCP Server & Tools (`tests/test_mcp.py`)
- Agent Orchestrator (`tests/test_orchestrator.py`)
- OWASP Top 10 Scenarios (`tests/test_owasp_scenarios.py`)
- RAG Engine (`tests/test_rag_manual.py`)
- Research Agent (`tests/test_research_agent.py`)
- Security Controller (`tests/test_security_controller.py`)
- Security Pipeline (`tests/test_security_pipeline.py`)

---

## 2. Targeted Test Execution

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
python tests/test_security_pipeline.py
python tests/test_mcp.py
python tests/test_security_controller.py
python tests/test_orchestrator.py
```

---

## 3. Python Syntax Verification
To verify syntax across the entire repository without execution:
```bash
python -m py_compile agents/*.py chatbot/*.py mcp_server/*.py rag/*.py security/*.py vulnerabilities/**/*.py tests/*.py
```

---

## 4. Test Categories
1. **Perimeter Tests**: Validate that the Security Controller blocks malicious signatures in Secure Mode and permits simulation in Vulnerable Mode.
2. **Context & RAG Tests**: Validate TF-IDF relevance scoring, minimum score filtering, and indirect injection sanitization.
3. **Agent Goal Invariance Tests**: Validate that the Main Agent anchors the initial goal and detects goal drift.
4. **Tool Authorization & RBAC Tests**: Validate tool permission checking, risk tiering, and parameter injection prevention.
5. **Scenario Simulation Tests**: Validate that all 10 OWASP ASI scenarios execute reliably and emit structured security events.
