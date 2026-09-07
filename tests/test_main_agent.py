from agents.main_agent import MainAgent


# --------------------------------------------------
# CREATE MAIN AGENT
# --------------------------------------------------

agent = MainAgent()


# --------------------------------------------------
# TEST DATA
# --------------------------------------------------

user_request = "What are the rules for AI agent tools?"

retrieved_documents = [

    {
        "filename": "company_policy.txt",
        "score": 0.265
    },

    {
        "filename": "test_context.txt",
        "score": 0.368
    }
]


# --------------------------------------------------
# RUN MAIN AGENT
# --------------------------------------------------

result = agent.analyze(
    user_request,
    retrieved_documents
)


# --------------------------------------------------
# DISPLAY RESULT
# --------------------------------------------------

print("\n========== MAIN AGENT TEST ==========\n")

print("STATUS:")
print(result["status"])

print("\nDECISION:")
print(result["decision"])

print("\nDOCUMENTS USED:")
print(result["documents_used"])

print("\nRESPONSE:")
print(result["response"])
