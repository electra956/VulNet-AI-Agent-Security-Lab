"""
VulNet AI Agent Security Lab - Agent Orchestrator
Central coordinator for end-to-end FinTech Agentic AI workflow:
Request -> Security Gateway -> Main Agent (Intent Classification, Task Planning, Agent Routing)
-> Specialized FinTech Agent (Customer / Research / Transaction / Fraud / Compliance / Support)
-> Action Agent -> MCP Server -> Safe Tools.

INVARIANTS:
- Main Agent does NOT directly execute tools.
- Orchestrator controls execution and coordinates agent dispatch.
- Zero real financial actions or real infrastructure changes.
- Safe error containment prevents cascading pipeline failures (ASI08).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from rag.rag_engine import RAGEngine
from agents.main_agent import MainAgent
from agents.research_agent import ResearchAgent
from agents.action_agent import ActionAgent
from agents.specialized_agents import (
    BaseFinTechAgent,
    CustomerAgent,
    FinancialResearchAgent,
    TransactionAgent,
    FraudAgent,
    ComplianceAgent,
    SupportAgent,
)
from mcp_server.server import MCPServer
from security.security_controller import SecurityController


class AgentOrchestrator:
    """
    Central orchestrator for the VulNet FinTech AI Agent Security Lab.

    Features:
    - Centralized execution control across specialized domain agents
    - Intent classification, task planning, and routing via Main Agent
    - Security perimeter validation before processing begins
    - Fail-safe error containment (prevents cascading pipeline crashes)
    - Full telemetry trace logging
    """

    def __init__(self, mode: str = "secure"):
        self.security = SecurityController(mode=mode)
        self.rag = RAGEngine(security_controller=self.security)
        self.main_agent = MainAgent()
        self.research_agent = ResearchAgent()
        self.action_agent = ActionAgent()
        self.mcp = MCPServer(mode=mode, security_controller=self.security)

        # Specialized FinTech Domain Agents
        self.specialized_agents: Dict[str, BaseFinTechAgent] = {
            "CustomerAgent": CustomerAgent(),
            "FinancialResearchAgent": FinancialResearchAgent(),
            "TransactionAgent": TransactionAgent(),
            "FraudAgent": FraudAgent(),
            "ComplianceAgent": ComplianceAgent(),
            "SupportAgent": SupportAgent(),
        }
        self.customer_agent = self.specialized_agents["CustomerAgent"]
        self.financial_research_agent = self.specialized_agents["FinancialResearchAgent"]
        self.transaction_agent = self.specialized_agents["TransactionAgent"]
        self.fraud_agent = self.specialized_agents["FraudAgent"]
        self.compliance_agent = self.specialized_agents["ComplianceAgent"]
        self.support_agent = self.specialized_agents["SupportAgent"]

    def set_mode(self, mode: str) -> None:
        """Propagate security mode across all subsystems."""
        self.security.set_mode(mode)
        self.mcp.set_mode(mode)

    def get_mode(self) -> str:
        """Get the current security mode."""
        return self.security.get_mode()

    def execute_agent(
        self,
        target_agent_name: str,
        request: str,
        plan: Optional[Dict[str, Any]] = None,
        session_context: Optional[Dict[str, Any]] = None,
        retrieved_documents: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a specific specialized agent under Orchestrator control.
        Handles invalid / unknown agent requests gracefully with structured error output.
        """
        agent = self.specialized_agents.get(target_agent_name)
        if not agent:
            return {
                "agent": target_agent_name,
                "intent": plan.get("intent", "UNKNOWN") if plan else "UNKNOWN",
                "status": "invalid_request",
                "requested_action": "none",
                "response": (
                    f"### ❌ Execution Error: Unrecognized Agent\n\n"
                    f"The orchestrator cannot route to unknown agent `{target_agent_name}`.\n"
                    f"Available specialized agents: {', '.join(f'`{k}`' for k in self.specialized_agents.keys())}"
                ),
                "metadata": {
                    "error": "unrecognized_agent",
                    "requested_agent": target_agent_name,
                    "available_agents": list(self.specialized_agents.keys())
                }
            }

        return agent.process(
            request=request,
            plan=plan or {},
            session_context=session_context,
            retrieved_documents=retrieved_documents,
            mode=self.get_mode()
        )

    def process(
        self,
        user_request: str,
        user_authorized: bool = False,
        session_context: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete Agentic AI workflow with security boundaries,
        intent classification, task planning, and specialized agent routing.
        """
        start_time = datetime.now()
        mode = self.get_mode()
        stages_executed = []

        ctx_meta = (
            session_context.to_dict()
            if hasattr(session_context, "to_dict")
            else (session_context if isinstance(session_context, dict) else {})
        )

        try:
            # ------------------------------------------
            # STEP 0: PERIMETER SECURITY EVALUATION
            # ------------------------------------------
            stages_executed.append("🛡️ Security Controller: Request Evaluation")
            security_result = self.security.evaluate_request(user_request, session_context=ctx_meta)

            if security_result.get("blocked", False) or security_result.get("decision") == "BLOCK":
                stages_executed.append("🚫 Pipeline Halted: Security Rule Blocked")
                return {
                    "user_request": user_request,
                    "security": security_result,
                    "session_context": ctx_meta,
                    "retrieved_documents": [],
                    "main_agent": None,
                    "research_agent": None,
                    "action_agent": None,
                    "specialized_agent_result": None,
                    "intent": None,
                    "routed_agent": None,
                    "task_plan": None,
                    "final_response": security_result.get("message", "Request blocked by security perimeter."),
                    "mcp_security_status": None,
                    "mcp_audit_log": None,
                    "pipeline_status": "blocked",
                    "stages": stages_executed,
                    "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000)
                }

            # ------------------------------------------
            # STEP 1: RAG RETRIEVAL
            # ------------------------------------------
            stages_executed.append("📚 RAG: Document Retrieval & Threat Scan")
            retrieved_documents = self.rag.search(user_request)

            # ------------------------------------------
            # STEP 2: MAIN AGENT ANALYSIS & TASK PLANNING
            # ------------------------------------------
            stages_executed.append("🤖 Main Agent: Objective Anchoring, Intent Classification & Routing")
            main_result = self.main_agent.analyze(
                user_request=user_request,
                retrieved_documents=retrieved_documents,
                mode=mode
            )

            intent = main_result.get("intent", "GENERAL_INQUIRY")
            routed_agent = main_result.get("routed_agent", "CustomerAgent")
            task_plan = main_result.get("plan", {})

            # ------------------------------------------
            # STEP 3: SPECIALIZED FINTECH AGENT EXECUTION
            # ------------------------------------------
            stages_executed.append(f"🧭 Orchestrator: Dispatching to {routed_agent}")
            specialized_result = self.execute_agent(
                target_agent_name=routed_agent,
                request=user_request,
                plan=task_plan,
                session_context=ctx_meta,
                retrieved_documents=retrieved_documents
            )
            stages_executed.append(f"🎯 {routed_agent}: Execution Completed ({specialized_result.get('status')})")

            # ------------------------------------------
            # STEP 4: RESEARCH AGENT EXTRACTION
            # ------------------------------------------
            stages_executed.append("🔍 Research Agent: Findings Extraction")
            research_result = self.research_agent.research(
                user_request=user_request,
                retrieved_documents=retrieved_documents,
                mode=mode
            )

            # ------------------------------------------
            # STEP 5: ACTION AGENT PROPOSAL & RISK GATING
            # ------------------------------------------
            stages_executed.append("⚡ Action Agent: Action Proposal & Risk Gating")
            action_result = self.action_agent.execute(
                user_request=user_request,
                research_result=research_result,
                mode=mode,
                user_authorized=user_authorized
            )

            # ------------------------------------------
            # STEP 6: MCP TOOL EXECUTION (STATUS)
            # ------------------------------------------
            stages_executed.append("🔌 MCP: Security Status Tool Invocation")
            security_status = self.mcp.execute_tool("get_security_status")

            # ------------------------------------------
            # STEP 7: MCP AUDIT LOGGING
            # ------------------------------------------
            stages_executed.append("📝 MCP: Audit Log Tool Invocation")
            audit_log = self.mcp.execute_tool(
                "create_audit_log",
                message=f"Agent pipeline processed request for [{routed_agent}]: '{user_request[:50]}...'"
            )

            stages_executed.append("🟢 Pipeline Completed Safely")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            completed_meta = {
                "status": "completed",
                "output_reached": True,
                "stages_count": len(stages_executed),
                "routed_agent": routed_agent,
                "intent": intent,
                "agent_status": specialized_result.get("status")
            }
            completed_meta.update(ctx_meta)
            self.security.log_event(
                event_type="PIPELINE_EXECUTION_COMPLETED",
                message=f"Pipeline processed successfully by {routed_agent} ({exec_time}ms)",
                severity="INFO",
                scenario=None,
                component="ORCHESTRATOR",
                decision="ALLOW",
                metadata=completed_meta
            )

            return {
                "user_request": user_request,
                "security": security_result,
                "session_context": ctx_meta,
                "retrieved_documents": retrieved_documents,
                "main_agent": main_result,
                "research_agent": research_result,
                "action_agent": action_result,
                "specialized_agent_result": specialized_result,
                "intent": intent,
                "routed_agent": routed_agent,
                "task_plan": task_plan,
                "final_response": specialized_result.get("response", "Request processed successfully."),
                "mcp_security_status": security_status,
                "mcp_audit_log": audit_log,
                "pipeline_status": "completed",
                "stages": stages_executed,
                "execution_time_ms": exec_time
            }

        except Exception as exc:
            # Cascading Failure Protection (ASI08): Fail-safe containment
            fail_meta = {
                "error": str(exc),
                "stage": stages_executed[-1] if stages_executed else "INIT"
            }
            fail_meta.update(ctx_meta)
            self.security.log_event(
                event_type="PIPELINE_CASCADING_FAILURE_PREVENTED",
                message=f"Pipeline exception intercepted safely: {str(exc)}",
                severity="CRITICAL",
                scenario="ASI08 - Cascading Failures",
                component="ORCHESTRATOR",
                decision="MITIGATE",
                metadata=fail_meta
            )
            return {
                "user_request": user_request,
                "security": {"allowed": False, "blocked": True, "reason": f"Pipeline error contained: {str(exc)}"},
                "session_context": ctx_meta,
                "retrieved_documents": [],
                "main_agent": None,
                "research_agent": None,
                "action_agent": None,
                "specialized_agent_result": None,
                "intent": None,
                "routed_agent": None,
                "task_plan": None,
                "final_response": f"Pipeline error contained safely: {str(exc)}",
                "mcp_security_status": None,
                "mcp_audit_log": None,
                "pipeline_status": "error",
                "error": str(exc),
                "stages": stages_executed + [f"❌ Contained Error: {str(exc)}"],
                "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000)
            }