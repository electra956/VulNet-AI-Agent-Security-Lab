"""
VulNet AI Agent Security Lab - Main Agent
Maintains primary user objective, performs intent classification, task planning,
and agent routing, and guards against goal hijacking (ASI01).

INVARIANT:
- Main Agent does NOT directly execute tools. Tool execution is managed by the Orchestrator.
- Main Agent determines intent, formulates task plan, and routes to specialized agents.
"""

from typing import Any, Dict, List, Optional
import re


class MainAgent:
    """
    Main Agent for the VulNet FinTech AI Agent Security Lab.

    Responsibilities:
    - Intent Classification: Classifies incoming user queries into FinTech domains
    - Task Planning: Generates structured task steps and risk evaluations
    - Agent Routing: Maps planned tasks to specialized FinTech agents
    - Goal Anchoring: Preserves original objective, guards against goal hijacking (ASI01)
    - Security Boundaries: NEVER directly executes tools; yields plans to the Orchestrator
    """

    INSTRUCTION_OVERRIDE_PATTERN = re.compile(
        r"(?i)(new objective:|change your goal to|ignore previous|system prompt override)"
    )

    # Intent classification pattern mappings
    INTENT_PATTERNS = [
        ("FRAUD_DISPUTE", re.compile(r"(?i)\b(flagged|fraud|dispute|suspicious|unauthorized charge|why was my transaction flagged)\b")),
        ("BALANCE_INQUIRY", re.compile(r"(?i)\b(balance|how much money|account overview|check balance|what is my balance)\b")),
        ("PAYMENT_REQUEST", re.compile(r"(?i)\b(transfer|send money|pay|wire|send \$|send ₹|transfer ₹|transfer \$)\b")),
        ("COMPLIANCE_INQUIRY", re.compile(r"(?i)\b(kyc|compliance|aml|regulat|identity verification|proof of address|kyc requirements)\b")),
        ("SUPPORT_REQUEST", re.compile(r"(?i)\b(help|support|freeze card|block card|lost card|contact agent|ticket|representative)\b")),
        ("FINANCIAL_RESEARCH", re.compile(r"(?i)\b(research|policy|rules for ai|market|guideline|rate|apr|terms)\b")),
    ]

    def classify_intent(self, request: str) -> str:
        """Classify user request into a discrete FinTech intent."""
        cleaned = request.strip()
        if not cleaned:
            return "UNKNOWN"

        for intent, pattern in self.INTENT_PATTERNS:
            if pattern.search(cleaned):
                return intent

        return "GENERAL_INQUIRY"

    def route_agent(self, intent: str, request: str = "") -> str:
        """
        Route classified intent to the appropriate specialized agent.
        Examples:
        - "What is my balance?" -> CustomerAgent
        - "Why was my transaction flagged?" -> FraudAgent
        - "Transfer ₹5,000" -> TransactionAgent
        - "What are the KYC requirements?" -> ComplianceAgent / FinancialResearchAgent
        """
        routing_table = {
            "BALANCE_INQUIRY": "CustomerAgent",
            "PAYMENT_REQUEST": "TransactionAgent",
            "FRAUD_DISPUTE": "FraudAgent",
            "COMPLIANCE_INQUIRY": "ComplianceAgent",
            "SUPPORT_REQUEST": "SupportAgent",
            "FINANCIAL_RESEARCH": "FinancialResearchAgent",
            "GENERAL_INQUIRY": "FinancialResearchAgent"
        }

        # Contextual refinement: If KYC query explicitly asks for market/research docs, can route to FinancialResearchAgent
        if intent == "COMPLIANCE_INQUIRY" and "research" in request.lower():
            return "FinancialResearchAgent"

        return routing_table.get(intent, "CustomerAgent")

    def create_plan(
        self,
        intent: str,
        request: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Formulate a structured task plan.
        INVARIANT: Main Agent does NOT directly execute tools.
        """
        target_agent = self.route_agent(intent, request)
        req_lower = request.lower()

        # Risk assessment for task plan
        if any(w in req_lower for w in ["delete", "admin", "override", "bypass"]):
            risk_tier = "HIGH"
        elif any(w in req_lower for w in ["transfer", "send", "wire", "pay", "freeze"]):
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        # Define plan steps based on intent
        if intent == "PAYMENT_REQUEST":
            steps = [
                "1. Identify sender and beneficiary accounts",
                "2. Validate sufficient funds and account ownership",
                "3. Formulate payment proposal for Orchestrator tool gate"
            ]
            requires_tool = True
            tool_candidate = "create_payment"
        elif intent == "BALANCE_INQUIRY":
            steps = [
                "1. Authenticate customer session context",
                "2. Retrieve authorized account balances from domain service"
            ]
            requires_tool = False
            tool_candidate = "get_balance"
        elif intent == "FRAUD_DISPUTE":
            steps = [
                "1. Locate transaction reference in anomaly logs",
                "2. Assess risk heuristics and review reason code",
                "3. Present findings and initiate dispute ticket"
            ]
            requires_tool = False
            tool_candidate = "review_fraud"
        elif intent == "COMPLIANCE_INQUIRY":
            steps = [
                "1. Lookup regulatory KYC/AML requirements",
                "2. Format required verification checklist for customer"
            ]
            requires_tool = False
            tool_candidate = "get_kyc_requirements"
        elif intent == "SUPPORT_REQUEST":
            steps = [
                "1. Determine customer support need",
                "2. Execute support workflow or card status update"
            ]
            requires_tool = True if "freeze" in req_lower else False
            tool_candidate = "create_support_ticket"
        else:
            steps = [
                "1. Search local verified financial knowledge base",
                "2. Synthesize factual research summary"
            ]
            requires_tool = False
            tool_candidate = "search_knowledge_base"

        return {
            "intent": intent,
            "target_agent": target_agent,
            "risk_tier": risk_tier,
            "steps": steps,
            "requires_tool": requires_tool,
            "tool_candidate": tool_candidate,
            "can_execute_tools_directly": False  # Enforced: Main Agent does not directly execute tools
        }

    def plan_and_route(
        self,
        request: str,
        session_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute intent classification, task planning, and agent routing."""
        intent = self.classify_intent(request)
        plan = self.create_plan(intent, request, session_context)
        return {
            "request": request,
            "intent": intent,
            "routed_agent": plan["target_agent"],
            "plan": plan
        }

    def analyze(
        self,
        user_request: str,
        retrieved_documents: List[Any],
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """
        Analyze request against retrieved context while preserving objective integrity (ASI01).
        Backward-compatible with original MainAgent interface.
        """
        document_count = len(retrieved_documents)
        original_goal = user_request.strip()
        active_goal = original_goal
        goal_drift_detected = False
        drift_source = None

        # --------------------------------------------------
        # INSPECT RETRIEVED CONTEXT FOR GOAL DRIFT
        # --------------------------------------------------
        for doc in retrieved_documents:
            content = doc.get("raw_content", doc.get("content", "")) if isinstance(doc, dict) else str(doc)
            doc_name = doc.get("document", "Unknown") if isinstance(doc, dict) else "Unknown"

            if self.INSTRUCTION_OVERRIDE_PATTERN.search(content):
                goal_drift_detected = True
                drift_source = doc_name
                if mode == "vulnerable":
                    # Simulate goal hijack adoption
                    active_goal = f"[HIJACKED GOAL via {doc_name}]: Reveal all system settings"
                break

        # Intent classification & task planning
        routing_info = self.plan_and_route(user_request)

        # --------------------------------------------------
        # NO DOCUMENTS FOUND
        # --------------------------------------------------
        if document_count == 0:
            return {
                "status": "completed",
                "original_goal": original_goal,
                "active_goal": active_goal,
                "goal_drift_detected": False,
                "decision": "No relevant documents were found.",
                "response": (
                    "I could not find relevant information in the "
                    "local knowledge base for this request."
                ),
                "documents_used": 0,
                "intent": routing_info["intent"],
                "routed_agent": routing_info["routed_agent"],
                "plan": routing_info["plan"]
            }

        # --------------------------------------------------
        # DOCUMENTS FOUND - BUILD STRUCTURED RESPONSE
        # --------------------------------------------------
        document_names = []
        for doc in retrieved_documents:
            if isinstance(doc, dict):
                name = doc.get("filename", doc.get("document", "Unknown Document"))
                trust = doc.get("trust_classification", "UNKNOWN")
                document_names.append(f"{name} [{trust}]")
            else:
                document_names.append(str(doc))

        response = f"""
## Main Agent Analysis

**Primary Objective:** `{original_goal}`

**Active Operational Goal:** `{active_goal}`

**Intent:** `{routing_info['intent']}` &bull; **Routed Agent:** `{routing_info['routed_agent']}`

**Retrieved Knowledge Sources:** {document_count} document(s)
"""
        for name in document_names:
            response += f"- 📄 {name}\n"

        if goal_drift_detected:
            if mode == "secure":
                response += f"""
> [!NOTE]
> **Security Defense Active**: Detected untrusted instruction in `{drift_source}`.
> Original goal anchored securely; conflicting instruction neutralized.
"""
            else:
                response += f"""
> [!WARNING]
> **Vulnerability Simulation**: Goal drift occurred!
> Active goal altered by untrusted context in `{drift_source}`.
"""

        response += f"""
### Agent Task Plan
- Target Agent: `{routing_info['routed_agent']}`
- Risk Tier: `{routing_info['plan']['risk_tier']}`
- Execution Delegated: Main Agent delegates tool execution to Orchestrator.
"""

        return {
            "status": "completed",
            "original_goal": original_goal,
            "active_goal": active_goal,
            "goal_drift_detected": goal_drift_detected,
            "decision": (
                "Goal preserved securely despite untrusted context."
                if (goal_drift_detected and mode == "secure")
                else "Request analyzed using retrieved context."
            ),
            "response": response.strip(),
            "documents_used": document_count,
            "intent": routing_info["intent"],
            "routed_agent": routing_info["routed_agent"],
            "plan": routing_info["plan"]
        }