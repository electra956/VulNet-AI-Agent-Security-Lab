from rag.rag_engine import RAGEngine


rag = RAGEngine()

query = "What are the rules for AI agent tools?"

results = rag.search(query)

print("\n========== RAG RESULTS ==========\n")

for result in results:

    print("=" * 50)

    print("DOCUMENT:", result["document"])

    print("SCORE:", result["score"])

    print("\nCONTENT:\n")

    print(result["content"])
