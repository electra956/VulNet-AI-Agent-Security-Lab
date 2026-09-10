from rag.rag_engine import RAGEngine
from security.security_controller import SecurityController


def test_rag_search_relevance():
    rag = RAGEngine()
    query = "What are the rules for AI agent tools?"
    results = rag.search(query)

    assert len(results) > 0
    top_doc = results[0]
    assert "document" in top_doc
    assert "content" in top_doc
    assert top_doc["score"] >= 0.05
    assert "trust_classification" in top_doc
    assert "wrapped_context" in top_doc


def test_rag_min_score_filter():
    rag = RAGEngine()
    # Nonsense query should yield 0 results with default min_score=0.05
    results = rag.search("xyzzyqwerty12345unrelatedgibberish", min_score=0.2)
    assert len(results) == 0


def test_rag_indirect_injection_sanitization_in_secure_mode():
    sec = SecurityController(mode="secure")
    rag = RAGEngine(security_controller=sec)

    # Search for something matching untrusted_third_party.txt
    results = rag.search("third party integration ignore previous instructions")
    untrusted_results = [r for r in results if "untrusted" in r["document"].lower()]

    if untrusted_results:
        doc = untrusted_results[0]
        assert doc["trust_classification"] == "UNTRUSTED_EXTERNAL"
        # In secure mode, the injection phrase should be neutralized
        assert "[NEUTRALIZED_UNTRUSTED_INSTRUCTION]" in doc["content"]


if __name__ == "__main__":
    test_rag_search_relevance()
    test_rag_min_score_filter()
    test_rag_indirect_injection_sanitization_in_secure_mode()
    print("RAG tests passed successfully!")
