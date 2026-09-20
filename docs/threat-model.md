# 🛡️ VulNet FinTech AI Agent Security Lab — Threat Model

## 1. Overview & Objectives
This threat model outlines the assets, threat actors, trust boundaries, and attack vectors associated with multi-agent AI systems, utilizing the OWASP Top 10 for Agentic Applications and STRIDE methodology. In Level 2, the system incorporates a simulated FinTech domain, customer authentication, multi-factor verification, and a FastAPI Gateway.

---

## 2. Key Assets
1. **Agent Operational Integrity**: The agent's adherence to its designated objective without drift or hijacking.
2. **Context & Knowledge Store (RAG)**: Integrity and confidentiality of vectorized or retrieved domain knowledge.
3. **Tool Execution Capability (MCP)**: Boundaries preventing unauthorized invocation or destructive operations.
4. **Agent State & Session Context**: Isolation between customer sessions, preventing cross-tenant leakage or authorization bypass.
5. **FinTech Customer & Account Records**: Confidentiality of balances, accounts, and transaction records.
6. **Authentication & Session Tokens**: Safeguards against credential spraying, session hijacking, or MFA bypass.

---

## 3. Threat Actors
- **External Unauthenticated Attacker**: Attempting to invoke API endpoints, spoof sessions, or bypass MFA.
- **Malicious Customer / Insider**: Authenticated user attempting cross-account unauthorized access or prompt injection.
- **Untrusted Information Source**: Third-party websites, documents, or data feeds containing indirect prompt injection.
- **Compromised Sub-Agent**: Internal agent nodes whose output or task messages have been manipulated.
- **Malicious Extension / Plugin Vendor**: Third-party MCP tool providers attempting supply-chain subversion.

---

## 4. Trust Boundaries & Attack Surfaces

```text
[ External Client / Web Browser / Streamlit UI ]
       │ (HTTP Requests, JSON Payloads, User Chat Input)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 1: Input Guardrail ]
[ Input Guardrail (Perimeter Regex, Role Hijacking, Length Checks) ]
       │ (Sanitized User Input)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 2: API & Session Gateway ]
[ FastAPI Gateway / AuthManager (PBKDF2, MFA, Session Isolation) ]
       │ (Validated SessionContext: Customer ID, Role, Accounts)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 3: RAG Retrieval & Guardrail ]
[ RAG VectorStore & RAG Guardrail (Indirect Prompt Injection Sanitization) ]
       │ (Sanitized Context + Immutable Data Tags)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 4: LLM Reasoning (UNTRUSTED) ]
[ Ollama LLM Client / llama3.2 (Natural Language & Tool Proposal ONLY) ]
       │ (Proposed Action / Tool Call Parameters)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 5: Tool Guardrail ]
[ Tool Guardrail (Whitelist Verification, Metacharacter Scan, Domain Invariants) ]
       │ (Clean Tool Call)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 6: Deterministic Core (OUTSIDE LLM) ]
[ FinTech Service / RBAC / BOLA Ownership / Risk Engine / Human Approval Gate ]
       │ (Approved In-Memory Execution)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 7: MCP Server & In-Memory Ledger ]
[ MCP Server / Synthetic Banking Ledger / Append-Only Audit Logger ]
       │ (Raw Response Payload)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 8: Output Guardrail ]
[ Output Guardrail (PCI PAN Redaction, Token/Secret Redaction, Leakage Checks) ]
       │ (Sanitized Safe Client Response)
═══════▼══════════════════════════════════════════════════════
[ Client UI / Trace Store ]
```

---

## 5. LLM Trust Boundary Definition

In VulNet AI Agent Security Lab, the Large Language Model (local Ollama `llama3.2` or fallback simulator) is explicitly treated as an **UNTRUSTED reasoning component**:

| Capability | LLM Trusted? | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Conversational Fluency & Explanation** | ✅ Trusted | Generates natural language responses based on retrieved context. |
| **Tool Call Proposal** | ⚠️ Partially Trusted | May suggest tools and parameters, but execution is never automated without inspection. |
| **Authorization & Access Control** | ❌ **NOT TRUSTED** | Enforced deterministically in Python (`auth/authorization.py`, `fintech/service.py`). |
| **Account Ownership & BOLA Checks** | ❌ **NOT TRUSTED** | Hardcoded checks verify `customer_id` owns `source_account`. |
| **Financial Transaction Execution** | ❌ **NOT TRUSTED** | Bounded by risk limits ($10,000 threshold) and Human Approval gate. |
| **Security Decision Making** | ❌ **NOT TRUSTED** | Guardrails and Security Controller operate external to the prompt space. |
| **Secret & Sensitive Data Handling** | ❌ **NOT TRUSTED** | Output Guardrail redacts PANs, tokens, and keys before presentation. |

---

## 6. STRIDE Threat Mapping

| STRIDE Category | Agentic & FinTech Risk | Vulnerability | Applied Countermeasure |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Session token forgery / MFA bypass | ASI03 Identity Abuse | PBKDF2-HMAC-SHA256 password hashes, one-time MFA challenges, and cryptographically random session tokens. |
| **Tampering** | Injected tool parameters or Cross-Account query tampering | ASI02 Tool Misuse / BOLA | Tool Guardrail parameter sanitization, domain service ownership checks (`validate_customer_owns_account`). |
| **Repudiation** | Unaudited financial queries or security attacks | ASI02 / ASI03 Tool Abuse | Centralized JSON security telemetry logger, correlated `request_id`, and immutable append-only audit entries. |
| **Information Disclosure** | Cross-customer balance leakage or prompt extraction | ASI01 Goal Hijack / ASI03 | Output Guardrail regex redaction (`[REDACTED_SENSITIVE_DATA]`), strict account ownership checks, and role segregation. |
| **Denial of Service** | Cascading failure & Rogue sub-agent spawning | ASI08 / ASI10 | Circuit breakers, graceful degradation, input length/entropy bounds, and sub-agent spawn quotas. |
| **Elevation of Privilege** | Customer assuming Admin or Fraud Analyst role | ASI03 Identity Abuse | Hierarchical Role-Based Access Control (`customer`, `support`, `fraud_analyst`, `admin`) enforced outside LLM. |

---

## 7. Defensive Architecture Principles
1. **Never Trust Retrieved Context as Instructions**: Wrap external data in strict semantic XML boundaries and sanitize via RAG Guardrail.
2. **Deterministic Security Controls Strictly Outside the LLM**: Security checks (RBAC, BOLA, Limits, Approvals) must be implemented in deterministic Python code rather than relying on LLM self-moderation.
3. **Defense-in-Depth Layered Guardrails**: 4 distinct guardrail layers (Input, RAG, Tool, Output) intercept threats at each phase of execution.
4. **Session & Tenant Isolation by Default**: Every request carries an immutable `SessionContext` verifying customer ownership at the domain service layer.
5. **Least Privilege by Default**: Downstream tools and accounts require explicit authorization for high-risk operations.
6. **Fail-Safe Containment**: An isolated tool error or LLM failure must gracefully fall back without causing an application-wide crash.

