"""
VulNet AI Agent Security Lab - Agent Orchestrator
Central coordinator for end-to-end pipeline execution:
User -> Security Controller -> RAG -> Main Agent -> Research Agent -> Action Agent -> MCP Server -> Safe Tools.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from rag.rag_engine import RAGEngine
from agents.main_agent import MainAgent
from agents.research_agent import ResearchAgent
from agents.action_agent import ActionAgent
from mcp_server.server import MCPServer
from security.security_controller import SecurityController


class AgentOrchestrator:
    """
    Central orchestrator for the VulNet AI Agent Security Lab.

    Features:
    - End-to-end pipeline coordination
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

    def set_mode(self, mode: str) -> None:
        """Propagate security mode across all subsystems."""
        self.security.set_mode(mode)
        self.mcp.set_mode(mode)

    def get_mode(self) -> str:
        """Get the current security mode."""
        return self.security.get_mode()

    def process(self, user_request: str, user_authorized: bool = False) -> Dict[str, Any]:
        """
        Execute the complete Agentic AI workflow with security boundaries.
        """
        start_time = datetime.now()
        mode = self.get_mode()
        stages_executed = []

        try:
            # ------------------------------------------
            # STEP 0: PERIMETER SECURITY EVALUATION
            # ------------------------------------------
            stages_executed.append("🛡️ Security Controller: Request Evaluation")
            security_result = self.security.evaluate_request(user_request)

            if security_result.get("blocked", False):
                stages_executed.append("🚫 Pipeline Halted: Security Rule Blocked")
                return {
                    "user_request": user_request,
                    "security": security_result,
                    "retrieved_documents": [],
                    "main_agent": None,
                    "research_agent": None,
                    "action_agent": None,
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
            # STEP 2: MAIN AGENT ANALYSIS
            # ------------------------------------------
            stages_executed.append("🤖 Main Agent: Objective Anchoring & Analysis")
            main_result = self.main_agent.analyze(
                user_request=user_request,
                retrieved_documents=retrieved_documents,
                mode=mode
            )

            # ------------------------------------------
            # STEP 3: RESEARCH AGENT EXTRACTION
            # ------------------------------------------
            stages_executed.append("🔍 Research Agent: Findings Extraction")
            research_result = self.research_agent.research(
                user_request=user_request,
                retrieved_documents=retrieved_documents,
                mode=mode
            )

            # ------------------------------------------
            # STEP 4: ACTION AGENT PROPOSAL
            # ------------------------------------------
            stages_executed.append("⚡ Action Agent: Action Proposal & Risk Gating")
            action_result = self.action_agent.execute(
                user_request=user_request,
                research_result=research_result,
                mode=mode,
                user_authorized=user_authorized
            )

            # ------------------------------------------
            # STEP 5: MCP TOOL EXECUTION (STATUS)
            # ------------------------------------------
            stages_executed.append("🔌 MCP: Security Status Tool Invocation")
            security_status = self.mcp.execute_tool("get_security_status")

            # ------------------------------------------
            # STEP 6: MCP AUDIT LOGGING
            # ------------------------------------------
            stages_executed.append("📝 MCP: Audit Log Tool Invocation")
            audit_log = self.mcp.execute_tool(
                "create_audit_log",
                message=f"Agent pipeline processed request: '{user_request[:60]}...'"
            )

            stages_executed.append("🟢 Pipeline Completed Safely")

            return {
                "user_request": user_request,
                "security": security_result,
                "retrieved_documents": retrieved_documents,
                "main_agent": main_result,
                "research_agent": research_result,
                "action_agent": action_result,
                "mcp_security_status": security_status,
                "mcp_audit_log": audit_log,
                "pipeline_status": "completed",
                "stages": stages_executed,
                "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000)
            }

        except Exception as exc:
            # Cascading Failure Protection (ASI08): Fail-safe containment
            self.security.log_event(
                event_type="PIPELINE_CASCADING_FAILURE_PREVENTED",
                message=f"Pipeline exception intercepted safely: {str(exc)}",
                severity="CRITICAL",
                scenario="ASI08 - Cascading Failures",
                component="ORCHESTRATOR",
                decision="MITIGATE",
                metadata={"error": str(exc), "stage": stages_executed[-1] if stages_executed else "INIT"}
            )
            return {
                "user_request": user_request,
                "security": {"allowed": False, "blocked": True, "reason": f"Pipeline error contained: {str(exc)}"},
                "retrieved_documents": [],
                "main_agent": None,
                "research_agent": None,
                "action_agent": None,
                "mcp_security_status": None,
                "mcp_audit_log": None,
                "pipeline_status": "error",
                "error": str(exc),
                "stages": stages_executed + [f"❌ Contained Error: {str(exc)}"],
                "execution_time_ms": int((datetime.now() - start_time).total_seconds() * 1000)
            }