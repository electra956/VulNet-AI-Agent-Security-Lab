from rag.rag_engine import RAGEngine

from agents.main_agent import MainAgent
from agents.research_agent import ResearchAgent
from agents.action_agent import ActionAgent

from mcp_server.server import MCPServer

from security.security_controller import SecurityController


class AgentOrchestrator:
    """
    Central orchestrator for the VulNet AI Agent Security Lab.

    Pipeline:

        User
          ↓
        Security Controller
          ↓
        RAG
          ↓
        Main Agent
          ↓
        Research Agent
          ↓
        Action Agent
          ↓
        MCP Server
          ↓
        Safe Demo Tools

    The Security Controller is the first security
    boundary before agent processing begins.
    """

    def __init__(self, mode="secure"):

        # ------------------------------------------
        # SECURITY CONTROLLER
        # ------------------------------------------

        self.security = SecurityController(
            mode=mode
        )

        # ------------------------------------------
        # RAG
        # ------------------------------------------

        self.rag = RAGEngine()

        # ------------------------------------------
        # AGENTS
        # ------------------------------------------

        self.main_agent = MainAgent()

        self.research_agent = ResearchAgent()

        self.action_agent = ActionAgent()

        # ------------------------------------------
        # MCP
        # ------------------------------------------

        self.mcp = MCPServer()


    # ==================================================
    # SECURITY MODE
    # ==================================================

    def set_mode(self, mode):

        self.security.set_mode(mode)


    def get_mode(self):

        return self.security.get_mode()


    # ==================================================
    # MAIN PIPELINE
    # ==================================================

    def process(self, user_request):

        # ------------------------------------------
        # STEP 0: SECURITY VALIDATION
        # ------------------------------------------

        security_result = self.security.evaluate_request(
            user_request
        )


        # ------------------------------------------
        # BLOCKED REQUEST
        # ------------------------------------------

        if security_result["blocked"]:

            return {

                "user_request": user_request,

                "security": security_result,

                "retrieved_documents": [],

                "main_agent": None,

                "research_agent": None,

                "action_agent": None,

                "mcp_security_status": None,

                "mcp_audit_log": None,

                "pipeline_status": "blocked"

            }


        # ------------------------------------------
        # STEP 1: RAG
        # ------------------------------------------

        retrieved_documents = self.rag.search(
            user_request
        )


        # ------------------------------------------
        # STEP 2: MAIN AGENT
        # ------------------------------------------

        main_result = self.main_agent.analyze(
            user_request,
            retrieved_documents
        )


        # ------------------------------------------
        # STEP 3: RESEARCH AGENT
        # ------------------------------------------

        research_result = self.research_agent.research(
            user_request,
            retrieved_documents
        )


        # ------------------------------------------
        # STEP 4: ACTION AGENT
        # ------------------------------------------

        action_result = self.action_agent.execute(
            user_request,
            research_result
        )


        # ------------------------------------------
        # STEP 5: MCP SECURITY STATUS
        # ------------------------------------------

        security_status = self.mcp.execute_tool(
            "get_security_status"
        )


        # ------------------------------------------
        # STEP 6: MCP AUDIT LOG
        # ------------------------------------------

        audit_log = self.mcp.execute_tool(
            "create_audit_log",
            message=(
                "Agent pipeline completed for request: "
                f"{user_request}"
            )
        )


        # ------------------------------------------
        # COMPLETE RESULT
        # ------------------------------------------

        return {

            "user_request": user_request,

            "security": security_result,

            "retrieved_documents": retrieved_documents,

            "main_agent": main_result,

            "research_agent": research_result,

            "action_agent": action_result,

            "mcp_security_status": security_status,

            "mcp_audit_log": audit_log,

            "pipeline_status": "completed"

        }