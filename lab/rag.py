"""
VulNet Attack Lab - the RAG used by the lab scenarios.

This is the real `rag.rag_engine.RAGEngine` (chunking, metadata, hybrid Ollama-embedding + TF-IDF retrieval,
trust levels, injection scanning) with the lab's synthetic corpus ingested on top of `rag/knowledge/`,
including a deliberately POISONED external document. It uses its own vector-store file so lab runs never
touch the chatbot's `data/vector_store.json`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

from rag.rag_engine import RAGEngine

_ENGINE: Optional[RAGEngine] = None
_DOC_DIR = Path(__file__).parent / "data" / "rag_docs"


def get_lab_rag() -> RAGEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RAGEngine(knowledge_path="rag/knowledge", vector_store_path="data/lab_vector_store.json")
        for f in sorted(_DOC_DIR.glob("*.txt")):
            _ENGINE.ingest_document(f.name, f.read_text(encoding="utf-8"))
        _ENGINE._dense_attempt_at = 0.0          # a cold embedding model can miss the first attempt; retry once now
        _ENGINE._ensure_dense_matrix()
    return _ENGINE


def retrieve(query: str, security_controller: Any, top_k: int = 4) -> List[dict]:
    """Real retrieval; the engine sanitises untrusted chunks only when the attached controller is SECURE."""
    engine = get_lab_rag()
    engine.set_security_controller(security_controller)
    return engine.search(query, top_k=top_k, min_score=0.01)
