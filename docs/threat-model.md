# 🛡️ VulNet AI Agent Security Lab — Threat Model

## 1. Overview & Objectives
This threat model outlines the assets, threat actors, trust boundaries, and attack vectors associated with multi-agent AI systems, utilizing the OWASP Top 10 for Agentic Applications and STRIDE methodology.

---

## 2. Key Assets
1. **Agent Operational Integrity**: The agent's adherence to its designated objective without drift or hijacking.
2. **Context & Knowledge Store (RAG)**: Integrity and confidentiality of vectorized or retrieved domain knowledge.
3. **Tool Execution Capability (MCP)**: Boundaries preventing unauthorized invocation or destructive operations.
4. **Agent State & Memory**: Long-term preferences and session memory stores.
5. **System Governance**: Orchestration governance limiting compute usage and rogue behaviors.

---

## 3. Threat Actors
- **External End User**: Unauthenticated or authenticated users submitting direct prompt injections.
- **Untrusted Information Source**: Third-party websites, documents, or data feeds containing indirect prompt injection.
- **Compromised Sub-Agent**: Internal agent nodes whose output or task messages have been manipulated.
- **Malicious Extension / Plugin Vendor**: Third-party MCP tool providers attempting supply-chain subversion.

---

## 4. Trust Boundaries & Attack Surfaces

```text
[ External World ]
       │ (Untrusted User Prompts)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 1 ]
[ Chatbot Interface ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 2 ]
[ Security Controller ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 3 ]
[ RAG Engine / Knowledge Base ]
       │ (Untrusted External Documents)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 4 ]
[ Main Agent ◄──► Research Agent ◄──► Action Agent ] (Inter-Agent Bus)
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 5 ]
[ MCP Server ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 6 ]
[ Tools & Backend Environment ]
```

---

## 5. STRIDE Threat Mapping

| STRIDE Category | Agentic Risk | Vulnerability | Applied Countermeasure |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Inter-agent message forgery | ASI07 Insecure Communication | HMAC-SHA256 digital signatures on all message envelopes. |
| **Tampering** | Injected tool parameters | ASI02 Tool Misuse | Strict schema validation, regex sanitization of metacharacters. |
| **Repudiation** | Unaudited actions | ASI02 / ASI03 Tool Abuse | Centralized JSON security telemetry logger and audit logs. |
| **Information Disclosure** | System prompt leakage | ASI01 Goal Hijack | Perimeter signature detection blocking extraction phrases. |
| **Denial of Service** | Cascading failure & Rogue spawning | ASI08 / ASI10 | Circuit breakers, graceful degradation, and sub-agent spawn quotas. |
| **Elevation of Privilege** | Role impersonation in tools | ASI03 Identity Abuse | Hierarchical Role-Based Access Control (GUEST/USER/ADMIN). |

---

## 6. Defensive Architecture Principles
1. **Never Trust Retrieved Context as Instructions**: Wrap external data in strict semantic XML boundaries.
2. **Deterministic Security Controls Outside the LLM**: Security checks must be implemented in deterministic Python code rather than relying exclusively on LLM self-moderation.
3. **Least Privilege by Default**: Downstream tools require explicit authorization for high-risk operations.
4. **Fail-Safe Containment**: An isolated tool error must never cause an application-wide crash.
