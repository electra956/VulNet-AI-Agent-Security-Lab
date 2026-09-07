from rag.rag_engine import RAGEngine
from agents.research_agent import ResearchAgent


# --------------------------------------------------
# INITIALIZE COMPONENTS
# --------------------------------------------------

rag_engine = RAGEngine()

research_agent = ResearchAgent()


# --------------------------------------------------
# TEST REQUEST
# --------------------------------------------------

user_request = (
    "What are the rules for AI agent tools?"
)


# --------------------------------------------------
# RETRIEVE DOCUMENTS
# --------------------------------------------------

retrieved_documents = rag_engine.search(
    user_request
)


# --------------------------------------------------
# RUN RESEARCH AGENT
# --------------------------------------------------

result = research_agent.research(
    user_request,
    retrieved_documents
)


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

print("\n========== RESEARCH AGENT TEST ==========\n")

print("STATUS:")
print(result["status"])

print("\nSUMMARY:")
print(result["summary"])

print("\nDOCUMENTS ANALYZED:")
print(result["documents_analyzed"])

print("\nFINDINGS:")

for finding in result["findings"]:

    print("\n------------------------------")

    print(
        f"DOCUMENT: "
        f"{finding['document']}"
    )

    print(
        f"SCORE: "
        f"{finding['score']}"
    )

    print("\nCONTENT PREVIEW:")

    print(
        finding["content_preview"]
    )
