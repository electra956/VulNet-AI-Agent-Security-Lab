# 🏗️ VulNet AI Agent Security Lab — System Architecture

## 1. Overview
The **VulNet AI Agent Security Lab** is an educational and security research platform designed to model, demonstrate, and analyze vulnerabilities and defensive countermeasures in **Agentic AI systems**. It implements a complete end-to-end pipeline operating strictly within safe, local boundaries.

---

## 2. End-to-End Pipeline Architecture

```text
                     ┌───────────────────┐
                     │       USER        │
                     └─────────┬─────────┘
                               │ User Request / Prompt
                               ▼
                     ┌───────────────────┐
                     │    CHATBOT UI     │
                     │    (Streamlit)    │
                     └─────────┬─────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │      SECURITY CONTROLLER      │◄─────── Mode: Secure vs Vulnerable
               │  - Perimeter Regex & Signatures│
               │  - Direct Prompt Injection     │
               │  - Security Telemetry Logger   │
               └───────────────┬───────────────┘
                               │ (Allowed or Vulnerable Simulation)
                               ▼
               ┌───────────────────────────────┐
               │          RAG ENGINE           │
               │  - TF-IDF + Cosine Similarity │
               │  - Instruction/Data Separation│
               │  - Trust Classification       │
               │  - Indirect Injection Scanning│
               └───────────────┬───────────────┘
                               │ Context & Documents
                               ▼
               ┌───────────────────────────────┐
               │          MAIN AGENT           │
               │  - Objective Anchoring        │
               │  - Goal Drift Detection       │
               │  - Workflow Coordination      │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │        RESEARCH AGENT         │
               │  - Untrusted Evidence Boundary│
               │  - Factual Finding Extraction │
               │  - Command Neutralization     │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │         ACTION AGENT          │
               │  - Action Proposal Formulator │
               │  - Risk Tiering (L/M/H)       │
               │  - Human-in-the-Loop Gating   │
               └───────────────┬───────────────┘
                               │ Tool Call Request
                               ▼
               ┌───────────────────────────────┐
               │          MCP SERVER           │
               │  - Tool Whitelist Registry    │
               │  - RBAC (Guest/User/Admin)    │
               │  - Parameter Sanitization     │
               │  - High-Risk Authorization    │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │        SAFE DEMO TOOLS        │
               │  - get_security_status        │
               │  - check_tool_permission      │
               │  - create_audit_log           │
               │  - execute_data_export        │
               │  - modify_system_policy       │
               └───────────────────────────────┘
```

---

## 3. Component Deep Dive

### 3.1 Security Controller (`security/security_controller.py`)
- **First Line of Defense**: Intercepts requests at Step 0 before downstream propagation.
- **Operating Modes**:
  - **Secure Mode**: Halts malicious inputs (`THREAT_BLOCKED`), logs structured security telemetry events, and preserves system invariants.
  - **Vulnerable Mode**: Permits suspicious commands to proceed under labeled simulation tags for educational inspection.
- **Multi-Vector Detection**: Analyzes direct user inputs, indirect RAG document payloads, inter-agent messages, and tool parameters.
- **Telemetry Event Schema**:
  ```json
  {
    "timestamp": "2026-09-07T12:00:00.000000",
    "event_type": "THREAT_BLOCKED",
    "severity": "BLOCKED",
    "scenario": "ASI01 - Agent Goal Hijack",
    "component": "SECURITY_CONTROLLER",
    "message": "Protection blocked suspicious instruction: 'ignore previous instructions'",
    "decision": "BLOCK",
    "metadata": {}
  }
  ```

### 3.2 RAG Engine (`rag/rag_engine.py`)
- **TF-IDF & Cosine Similarity**: Local, in-memory knowledge retrieval with zero external network or database dependencies.
- **Instruction vs. Data Separation**: Encapsulates retrieved content in `<untrusted_knowledge_data source="..." trust_level="...">` blocks.
- **Trust Classification**: Labels documents as `TRUSTED_INTERNAL` vs `UNTRUSTED_EXTERNAL`.
- **Indirect Injection Scanning**: Neutralizes imperative override keywords in Secure Mode before passing context to agents.

### 3.3 Multi-Agent Collaboration (`agents/`)
- **Main Agent (`agents/main_agent.py`)**: Anchors the original user objective. Detects goal drift attempts embedded in context and neutralizes them in Secure Mode.
- **Research Agent (`agents/research_agent.py`)**: Treats external context strictly as untrusted evidence; extracts factual findings while stripping imperative commands.
- **Action Agent (`agents/action_agent.py`)**: Formulates safe action proposals and assigns risk tiers (`LOW`, `MEDIUM`, `HIGH`). Enforces authorization barriers for administrative actions in Secure Mode.
- **Orchestrator (`agents/orchestrator.py`)**: Coordinates pipeline execution, handles errors via circuit-breaking (ASI08 defense), and captures telemetry.

### 3.4 Model Context Protocol (MCP) Server (`mcp_server/`)
- **Tool Registry**: Maintains an explicit whitelist of registered tools and schemas.
- **Role-Based Access Control (RBAC)**: Enforces `GUEST`, `USER`, and `ADMIN` role hierarchies.
- **Input Validation**: Scans parameters for shell injection metacharacters (`;`, `|`, `&&`) and SQL injection keywords.
- **Safe Tools (`mcp_server/tools.py`)**: Pure deterministic mock tools with zero production reach.

---

## 4. Security Invariants
1. **No External Network Calls**: All operations execute locally in-memory.
2. **No Real Shell Commands**: The simulation never invokes `os.system` or `subprocess` against the host operating system.
3. **Deterministic Testing**: Every scenario produces predictable, repeatable security telemetry.
