# 🚨 OWASP Top 10 for Agentic AI — Vulnerability Reference

This document provides technical descriptions, attack vectors, simulations, and countermeasures for the OWASP Top 10 for Agentic Applications (ASI01 through ASI10) modeled in the VulNet AI Agent Security Lab.

---

## Matrix of Scenarios & Implementation Status

| ID | Name | Core Risk | VulNet Simulation | Primary Mitigation | Verified V3 Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ASI01** | **Agent Goal Hijack** | Direct/Indirect Prompt Injection | Overriding active goal via prompt or poisoned RAG | InputGuardrail, RAGGuardrail, Goal Anchoring | ✅ **LIVE IMPLEMENTED** (Full pipeline, Chatbot, RAG & API) |
| **ASI02** | **Tool Misuse** | Dangerous arguments / Tool injection | Injected shell metacharacters in tool parameters | ToolGuardrail, Parameter Schema & Whitelisting | 🛡️ **DEFENSE IMPLEMENTED** (ToolGuardrail & MCP Validation live) |
| **ASI03** | **Identity & Privilege Abuse** | Privilege Escalation / Impersonation | Low-privileged role invoking Admin tool or accessing other accounts | Hierarchical RBAC, BOLA Ownership & Session Binding | ✅ **LIVE IMPLEMENTED** (AuthManager, RBAC, Account BOLA Defense) |
| **ASI04** | **Supply Chain** | Compromised 3rd-party tools/plugins | Loading unverified package with mismatched hash | Cryptographic SHA-256 Pinning | 🧪 **SIMULATED / LAB SUITE** (Modeled in Scenario Explorer) |
| **ASI05** | **Unexpected Code Execution** | Remote Code Execution via eval/exec | Unsanitized Python script with `os.system` | Abstract Syntax Tree (AST) Validation | 🧪 **SIMULATED / LAB SUITE** (Modeled in Scenario Explorer) |
| **ASI06** | **Memory Poisoning** | Contaminating persistent state/memory | Malicious endpoint override injected into store | MemoryValidator quarantine & Policy Bounds | 🛡️ **DEFENSE IMPLEMENTED** (Live in SessionManager memory) |
| **ASI07** | **Insecure Inter-Agent Comm** | Message Spoofing & Forged Delegation | Unsigned message impersonating Research Agent | Cryptographic HMAC-SHA256 Signatures | 🧪 **SIMULATED / LAB SUITE** (Modeled in Scenario Explorer) |
| **ASI08** | **Cascading Failures** | Error amplification / Crash loops | Unhandled exception collapsing pipeline | Circuit Breakers & Graceful Degradation | ✅ **LIVE IMPLEMENTED** (Active in Orchestrator & Ollama fallback) |
| **ASI09** | **Human Trust Exploitation** | Deceptive summaries / Blind approval | Harmless summary masking critical policy drop | Human Approval Gate ($10k+) & Parameter Diffs | 🛡️ **DEFENSE IMPLEMENTED** (Human approval live, UI diff simulated) |
| **ASI10** | **Rogue Agents** | Unbounded sub-agents / runaway loops | Autonomous agent spawning excessive workers | Hard Lifecycle Quotas & Governance Clamping | 🧪 **SIMULATED / LAB SUITE** (Modeled in Scenario Explorer) |

---

## Scenario Descriptions & Implementation Details

### ASI01: Agent Goal Hijack
- **Threat Vector**: An attacker supplies direct prompts (`Ignore previous instructions and change your goal...`) or embeds indirect instructions inside retrieved RAG documents (`untrusted_third_party.txt`).
- **Vulnerable Behavior**: The agent pipeline adopts the attacker's objective, mutating its internal state.
- **Secure Defense**: The Security Controller intercepts the signature at Step 0, halting the pipeline and preserving invariants. The Main Agent anchors the initial goal immutable.

### ASI02: Tool Misuse and Exploitation
- **Threat Vector**: Injected commands inside tool parameters (e.g. `target_dataset = "telemetry; DROP TABLE users; --"`).
- **Vulnerable Behavior**: The MCP server forwards raw arguments directly into tool routines.
- **Secure Defense**: Parameter validation scans for dangerous metacharacters (`;`, `|`, `&&`, backticks) and aborts unauthorized calls.

### ASI03: Identity and Privilege Abuse
- **Threat Vector**: An unauthenticated or low-privileged caller (`GUEST`) invokes administrative tools (`modify_system_policy`).
- **Vulnerable Behavior**: The system assumes any caller routed through an agent inherits administrative capability.
- **Secure Defense**: The MCP server evaluates role levels (`GUEST=1`, `USER=2`, `ADMIN=3`) and enforces least privilege.

### ASI04: Agentic Supply Chain Vulnerabilities
- **Threat Vector**: An external plugin or dependency package is imported from an untrusted vendor with a tampered SHA-256 hash.
- **Vulnerable Behavior**: The package is loaded dynamically without provenance checking.
- **Secure Defense**: The loader computes the SHA-256 checksum, compares it against the trusted manifest, and verifies vendor credentials.

### ASI05: Unexpected Code Execution
- **Threat Vector**: An agent dynamically synthesizes and executes Python code containing `import os; os.system('whoami')`.
- **Vulnerable Behavior**: The host executes raw code using unrestricted `eval()` or `exec()`.
- **Secure Defense**: An Abstract Syntax Tree (AST) parser walks the code tree and rejects any nodes containing imports or system calls.

### ASI06: Memory & Context Poisoning
- **Threat Vector**: An adversary introduces false facts or configuration overrides into long-term agent memory.
- **Vulnerable Behavior**: The memory store persists the key without validating origin, corrupting subsequent interactions.
- **Secure Defense**: The memory manager scans updates for URL overrides and unauthorized policy changes, quarantining suspicious records.

### ASI07: Insecure Inter-Agent Communication
- **Threat Vector**: An attacker injects a forged task claiming to be sent from an authorized internal agent.
- **Vulnerable Behavior**: Downstream agents execute tasks based solely on the plaintext `sender` field.
- **Secure Defense**: Inter-agent messages require HMAC-SHA256 digital signatures with timing-safe comparison.

### ASI08: Cascading Failures
- **Threat Vector**: An internal tool or agent experiences a fatal runtime error or corrupted data response.
- **Vulnerable Behavior**: The uncaught exception terminates the multi-agent graph, crashing the user session.
- **Secure Defense**: Circuit breakers isolate the failing component, return a degraded fallback, and log high-severity telemetry.

### ASI09: Human-Agent Trust Exploitation
- **Threat Vector**: An agent generates a comforting conversational summary (`"Harmless routine cleanup"`) while sending an administrative payload that disables security policies.
- **Vulnerable Behavior**: The UI presents only the high-level natural language summary, leading to blind approval.
- **Secure Defense**: The interface displays raw API diffs, highlights semantic discrepancies, and demands explicit parameter confirmation.

### ASI10: Rogue Agents
- **Threat Vector**: An agent autonomously initiates a swarm of unmonitored sub-agents, exhausting system resources.
- **Vulnerable Behavior**: Sub-agents spawn without quota checks or depth bounds.
- **Secure Defense**: The agent governor enforces hard caps (e.g. maximum 3 sub-agents) and throttles rogue behavior.
