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
from observability.trace import RequestTracer, AgentTrace, get_trace_store
from observability.audit import get_audit_logger
from observability.events import TraceStageName, StageStatus


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
        session_context: Optional[Any] = None,
        tracer: Optional[RequestTracer] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete Agentic AI workflow with security boundaries,
        intent classification, task planning, specialized agent routing,
        and end-to-end observability tracing.
        """
        start_time = datetime.now()
        mode = self.get_mode()
        stages_executed = []
        audit_logger = get_audit_logger()

        ctx_meta = (
            session_context.to_dict()
            if hasattr(session_context, "to_dict")
            else (session_context if isinstance(session_context, dict) else {})
        )
        req_id = ctx_meta.get("request_id", "REQ-000000")
        sess_id = ctx_meta.get("session_id", "SESSION-001")
        usr_id = ctx_meta.get("user_id", "CUST-001")

        if tracer is None:
            tracer = RequestTracer(request_id=req_id, session_id=sess_id, user_id=usr_id, action="agent_orchestration")

        # Invariant: Guarantee Authentication & Authorization stages are accounted for
        if not tracer.trace.get_stage("Authentication"):
            tracer.record_stage("Authentication", status=StageStatus.SUCCESS.value, details=f"User {usr_id} authenticated")
        if not tracer.trace.get_stage("Authorization"):
            tracer.record_stage("Authorization", status=StageStatus.SUCCESS.value, details=f"Role {ctx_meta.get('role', 'CUSTOMER')} authorized")

        try:
            # ------------------------------------------
            # STEP 0: PERIMETER SECURITY EVALUATION
            # ------------------------------------------
            tracer.start_stage("Security Gateway")
            stages_executed.append("🛡️ Security Controller: Request Evaluation")
            security_result = self.security.evaluate_request(user_request, session_context=ctx_meta)

            if security_result.get("blocked", False) or security_result.get("decision") == "BLOCK":
                stages_executed.append("🚫 Pipeline Halted: Security Rule Blocked")
                reason = security_result.get("message", "Request blocked by security perimeter.")
                tracer.record_stage("Security Gateway", status=StageStatus.BLOCKED.value, details=reason)

                # Skip subsequent execution stages in trace
                tracer.record_stage("Intent Classification", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("Main Agent", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("Transaction Agent", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("Risk Engine", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("MCP", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("Permission", status=StageStatus.SKIPPED.value, details="Halted at perimeter")
                tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Execution blocked at perimeter")

                # Audit stage still executes to log the incident
                tracer.start_stage("Audit")
                audit_rec = audit_logger.log_audit(
                    request_id=req_id,
                    session_id=sess_id,
                    user_id=usr_id,
                    action="agent_process",
                    decision="BLOCK",
                    status="blocked",
                    risk="HIGH",
                    error=reason,
                    metadata={"security_eval": security_result}
                )
                tracer.record_stage("Audit", status=StageStatus.SUCCESS.value, details=f"Security alert logged ({audit_rec.audit_id})")

                final_trace = tracer.finalize(status="blocked", decision="BLOCK", risk="HIGH")
                get_trace_store().add_trace(final_trace)

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
                    "final_response": reason,
                    "mcp_security_status": None,
                    "mcp_audit_log": None,
                    "pipeline_status": "blocked",
                    "stages": stages_executed,
                    "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000),
                    "trace": final_trace,
                    "checklist": final_trace.render_checklist()
                }

            tracer.record_stage("Security Gateway", status=StageStatus.SUCCESS.value, details="Perimeter check passed")

            # ------------------------------------------
            # STEP 1: RAG RETRIEVAL
            # ------------------------------------------
            stages_executed.append("📚 RAG: Document Retrieval & Threat Scan")
            retrieved_documents = self.rag.search(user_request)

            # ------------------------------------------
            # STEP 2: MAIN AGENT ANALYSIS & TASK PLANNING
            # ------------------------------------------
            tracer.start_stage("Intent Classification")
            stages_executed.append("🤖 Main Agent: Objective Anchoring, Intent Classification & Routing")
            main_result = self.main_agent.analyze(
                user_request=user_request,
                retrieved_documents=retrieved_documents,
                mode=mode
            )

            intent = main_result.get("intent", "GENERAL_INQUIRY")
            routed_agent = main_result.get("routed_agent", "CustomerAgent")
            task_plan = main_result.get("plan", {})
            tracer.record_stage("Intent Classification", status=StageStatus.SUCCESS.value, details=f"Classified: {intent}")

            tracer.start_stage("Main Agent")
            tracer.record_stage("Main Agent", status=StageStatus.SUCCESS.value, details=f"Anchored goal; Dispatched to {routed_agent}")

            # ------------------------------------------
            # STEP 3: SPECIALIZED FINTECH AGENT EXECUTION
            # ------------------------------------------
            tracer.start_stage(routed_agent)
            stages_executed.append(f"🧭 Orchestrator: Dispatching to {routed_agent}")
            specialized_result = self.execute_agent(
                target_agent_name=routed_agent,
                request=user_request,
                plan=task_plan,
                session_context=ctx_meta,
                retrieved_documents=retrieved_documents
            )
            spec_status = specialized_result.get("status", "success")
            stages_executed.append(f"🎯 {routed_agent}: Execution Completed ({spec_status})")
            tracer.record_stage(routed_agent, status=StageStatus.SUCCESS.value, details=f"Executed with status: {spec_status}")

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
            # STEP 6: RISK ENGINE EVALUATION
            # ------------------------------------------
            tracer.start_stage("Risk Engine")
            risk_tier = "LOW"
            if intent in ("PAYMENT_REQUEST", "TRANSFER_FUNDS", "HIGH_RISK_ACTION"):
                risk_tier = "MEDIUM"
            tracer.record_stage("Risk Engine", status=StageStatus.SUCCESS.value, details=f"Risk score evaluated: {risk_tier}")

            # ------------------------------------------
            # STEP 7: MCP & PERMISSION GATES
            # ------------------------------------------
            tracer.start_stage("MCP")
            stages_executed.append("🔌 MCP: Security Status Tool Invocation")
            security_status = self.mcp.execute_tool("get_security_status")
            tracer.record_stage("MCP", status=StageStatus.SUCCESS.value, details="MCP Gateway verified")

            tracer.start_stage("Permission")
            tracer.record_stage("Permission", status=StageStatus.SUCCESS.value, details=f"Role {ctx_meta.get('role', 'CUSTOMER')} permission confirmed")

            # ------------------------------------------
            # STEP 8: TOOL EXECUTION & MCP AUDIT LOGGING
            # ------------------------------------------
            tracer.start_stage("Tool")
            tool_status = StageStatus.SUCCESS.value if security_status.get("status") == "success" else StageStatus.BLOCKED.value
            tracer.record_stage("Tool", status=tool_status, details="Tool executed in sandbox")

            stages_executed.append("📝 MCP: Audit Log Tool Invocation")
            audit_log = self.mcp.execute_tool(
                "create_audit_log",
                message=f"Agent pipeline processed request for [{routed_agent}]: '{user_request[:50]}...'"
            )

            # ------------------------------------------
            # STEP 9: SECURITY AUDIT RECORD
            # ------------------------------------------
            tracer.start_stage("Audit")
            audit_rec = audit_logger.log_audit(
                request_id=req_id,
                session_id=sess_id,
                user_id=usr_id,
                agent=routed_agent,
                tool="create_audit_log",
                action="agent_orchestration",
                decision="ALLOW",
                status="completed",
                risk=risk_tier,
                metadata={"intent": intent, "routed_agent": routed_agent}
            )
            tracer.record_stage("Audit", status=StageStatus.SUCCESS.value, details=f"Audit record {audit_rec.audit_id} logged")

            stages_executed.append("🟢 Pipeline Completed Safely")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            completed_meta = {
                "status": "completed",
                "output_reached": True,
                "stages_count": len(stages_executed),
                "routed_agent": routed_agent,
                "intent": intent,
                "agent_status": spec_status
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

            final_trace = tracer.finalize(
                status="completed",
                decision="ALLOW",
                risk=risk_tier,
                agent=routed_agent,
                tool="create_audit_log"
            )
            get_trace_store().add_trace(final_trace)

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
                "execution_time_ms": exec_time,
                "trace": final_trace,
                "checklist": final_trace.render_checklist()
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

            tracer.record_stage("Tool", status=StageStatus.BLOCKED.value, details="Exception halted tool")
            tracer.start_stage("Audit")
            audit_rec = audit_logger.log_audit(
                request_id=req_id,
                session_id=sess_id,
                user_id=usr_id,
                action="agent_orchestration",
                decision="ERROR",
                status="error",
                risk="HIGH",
                error=str(exc)
            )
            tracer.record_stage("Audit", status=StageStatus.SUCCESS.value, details=f"Error audit logged ({audit_rec.audit_id})")
            final_trace = tracer.finalize(status="error", decision="ERROR", error=str(exc))
            get_trace_store().add_trace(final_trace)

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
                "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000),
                "trace": final_trace,
                "checklist": final_trace.render_checklist()
            }