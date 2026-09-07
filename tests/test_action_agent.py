from agents.action_agent import ActionAgent


# --------------------------------------------------
# CREATE ACTION AGENT
# --------------------------------------------------

agent = ActionAgent()


# --------------------------------------------------
# TEST DATA
# --------------------------------------------------

user_request = "What are the rules for AI agent tools?"

research_result = {
    "status": "completed",
    "summary": (
        "The Research Agent analyzed relevant security documents."
    ),
    "documents_analyzed": 2
}


# --------------------------------------------------
# RUN ACTION AGENT
# --------------------------------------------------

result = agent.execute(
    user_request,
    research_result
)


# --------------------------------------------------
# DISPLAY RESULT
# --------------------------------------------------

print("\n========== ACTION AGENT TEST ==========\n")

print("STATUS:")
print(result["status"])

print("\nDECISION:")
print(result["decision"])

print("\nDOCUMENTS ANALYZED:")
print(result.get("documents_analyzed", 0))

print("\nACTION:")
print(result["action"])
