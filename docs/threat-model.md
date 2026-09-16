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
[ External Client / Web Browser ]
       │ (HTTP Requests, JSON Payloads)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 1: API Gateway ]
[ FastAPI Gateway / Reverse Proxy ]
       │ (Authentication Verification, PBKDF2 + MFA Check)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 2: Identity & Session ]
[ Auth Manager & SessionContext Router ]
       │ (Validated SessionContext: Customer ID, Role, Accounts)
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 3: Security Controller ]
[ Security Controller (Heuristic Signatures & Mode Check) ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 4: FinTech Domain ]
[ FinTech Domain Service (Ownership Invariant Enforcement) ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 5: RAG Context ]
[ RAG Engine / Knowledge Base (TF-IDF Retrieval) ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 6: Multi-Agent Bus ]
[ Main Agent ◄──► Research Agent ◄──► Action Agent ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 7: MCP Server ]
[ MCP Server (RBAC & Parameter Sanitization) ]
       │
═══════▼══════════════════════════════════════════════════════ [ TRUST BOUNDARY 8: Backend Tools ]
[ Safe Demo Tools & Audit Logger ]
```

---

## 5. STRIDE Threat Mapping

| STRIDE Category | Agentic & FinTech Risk | Vulnerability | Applied Countermeasure |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Session token forgery / MFA bypass | ASI03 Identity Abuse | PBKDF2-HMAC-SHA256 password hashes, one-time MFA challenges, and cryptographically random session tokens. |
| **Tampering** | Injected tool parameters or Cross-Account query tampering | ASI02 Tool Misuse / BOLA | Strict Pydantic models, domain service ownership checks (`validate_customer_owns_account`). |
| **Repudiation** | Unaudited financial queries or security attacks | ASI02 / ASI03 Tool Abuse | Centralized JSON security telemetry logger, correlated `request_id`, and immutable audit entries. |
| **Information Disclosure** | Cross-customer balance leakage or prompt extraction | ASI01 Goal Hijack / ASI03 | Strict account ownership validation, perimeter signature filtering, and role segregation. |
| **Denial of Service** | Cascading failure & Rogue sub-agent spawning | ASI08 / ASI10 | Circuit breakers, graceful degradation, request size limits, and sub-agent spawn quotas. |
| **Elevation of Privilege** | Customer assuming Admin or Fraud Analyst role | ASI03 Identity Abuse | Hierarchical Role-Based Access Control (`customer`, `support`, `fraud_analyst`, `admin`). |

---

## 6. Defensive Architecture Principles
1. **Never Trust Retrieved Context as Instructions**: Wrap external data in strict semantic XML boundaries.
2. **Deterministic Security Controls Outside the LLM**: Security checks must be implemented in deterministic Python code rather than relying exclusively on LLM self-moderation.
3. **Session & Tenant Isolation by Default**: Every request carries an immutable `SessionContext` verifying customer ownership at the domain service layer.
4. **Least Privilege by Default**: Downstream tools and accounts require explicit authorization for high-risk operations.
5. **Fail-Safe Containment**: An isolated tool error must never cause an application-wide crash.

