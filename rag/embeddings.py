"""
VulNet FinTech AI Agent Security Lab - Ollama Embedding Provider.

Thin adapter that produces REAL dense embeddings through the configured Ollama embedding model
(OLLAMA_EMBED_MODEL, default nomic-embed-text). It never fabricates vectors: when Ollama or the
model is unavailable, `is_available()` is False and callers must fall back to lexical retrieval.

nomic-embed-text expects task prefixes, so documents and queries are embedded differently.
"""

import logging
import time
from typing import List, Optional

logger = logging.getLogger("vulnet.rag.embeddings")


class OllamaEmbeddingProvider:
    DOC_PREFIX = "search_document: "
    QUERY_PREFIX = "search_query: "
    AVAILABILITY_TTL_SEC = 15.0

    def __init__(self, client=None):
        if client is None:
            from llm.ollama_client import get_ollama_client
            client = get_ollama_client()
        self.client = client
        self._avail: Optional[bool] = None
        self._checked_at = 0.0

    @property
    def model_name(self) -> str:
        return self.client.embed_model

    def is_available(self, force: bool = False) -> bool:
        now = time.time()
        if not force and self._avail is not None and now - self._checked_at < self.AVAILABILITY_TTL_SEC:
            return self._avail
        try:
            self._avail = bool(self.client.has_model(self.client.embed_model))
        except Exception:
            self._avail = False
        self._checked_at = now
        return self._avail

    def embed_documents(self, texts: List[str]) -> Optional[List[List[float]]]:
        if not texts or not self.is_available():
            return None
        vectors: List[List[float]] = []
        for i in range(0, len(texts), 16):  # keep individual requests small
            batch = self.client.embed_many([self.DOC_PREFIX + t for t in texts[i:i + 16]])
            if not batch:
                return None
            vectors.extend(batch)
        return vectors

    def embed_query(self, text: str) -> Optional[List[float]]:
        if not self.is_available():
            return None
        vectors = self.client.embed_many([self.QUERY_PREFIX + text])
        return vectors[0] if vectors else None
