from agents.orchestrator import AgentOrchestrator


# --------------------------------------------------
# CREATE ORCHESTRATOR
# --------------------------------------------------

orchestrator = AgentOrchestrator()


# --------------------------------------------------
# TEST REQUEST
# --------------------------------------------------

user_request = (
    "What are the rules for AI agent tools?"
)


# --------------------------------------------------
# RUN COMPLETE PIPELINE
# --------------------------------------------------

result = orchestrator.process(
    user_request
)


# --------------------------------------------------
# DISPLAY RESULT
# --------------------------------------------------

print("\n========== COMPLETE AGENT PIPELINE ==========\n")


# --------------------------------------------------
# USER REQUEST
# --------------------------------------------------

print("USER REQUEST:")

print(
    result["user_request"]
)


# --------------------------------------------------
# RAG
# --------------------------------------------------

print("\n========== RAG ==========")

print(
    f"Documents retrieved: "
    f"{len(result['retrieved_documents'])}"
)

for document in result["retrieved_documents"]:

    print(
        f"- {document['document']} "
        f"(Score: {document['score']})"
    )


# --------------------------------------------------
# MAIN AGENT
# --------------------------------------------------

print("\n========== MAIN AGENT ==========")

print(
    result["main_agent"]["decision"]
)


# --------------------------------------------------
# RESEARCH AGENT
# --------------------------------------------------

print("\n========== RESEARCH AGENT ==========")

print(
    result["research_agent"]["summary"]
)


# --------------------------------------------------
# ACTION AGENT
# --------------------------------------------------

print("\n========== ACTION AGENT ==========")

print(
    result["action_agent"]["decision"]
)


# --------------------------------------------------
# MCP SECURITY STATUS
# --------------------------------------------------

print("\n========== MCP SECURITY STATUS ==========")

mcp_security = result[
    "mcp_security_status"
]

print(mcp_security)


# --------------------------------------------------
# MCP AUDIT LOG
# --------------------------------------------------

print("\n========== MCP AUDIT LOG ==========")

mcp_audit = result[
    "mcp_audit_log"
]

print(mcp_audit)


# --------------------------------------------------
# PIPELINE COMPLETE
# --------------------------------------------------

print(
    "\n========== PIPELINE COMPLETED ==========\n"
)