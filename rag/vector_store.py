"""
VulNet FinTech AI Agent Security Lab - Persistent Local Vector Store
Lightweight, zero-bloat, persistent local vector database storing chunk embeddings,
rich provenance metadata, and performing cosine similarity search.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("vulnet.rag.vector_store")


def cosine_similarity_vectors(vec_a: List[float], vec_b: List[float]) -> float:
    """Compute cosine similarity between two float vectors."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for a, b in zip(vec_a, vec_b):
        dot += a * b
        norm_a += a * a
        norm_b += b * b
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


class LocalDenseEmbedder:
    """
    Deterministic 128-dimensional dense vector generator.
    Serves as an offline local fallback when Ollama embedding model is not yet loaded.
    Produces stable, normalized dense embeddings based on character/word n-grams.
    """

    DIM = 128

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.DIM
        tokens = text.lower().split()
        if not tokens:
            return vec

        for t in tokens:
            # Word hash
            h_word = int(hashlib.md5(t.encode("utf-8")).hexdigest(), 16)
            idx_word = h_word % self.DIM
            sign_word = 1.0 if (h_word % 2 == 0) else -1.0
            vec[idx_word] += sign_word

            # Char 3-grams
            for i in range(len(t) - 2):
                gram = t[i:i + 3]
                h_gram = int(hashlib.sha1(gram.encode("utf-8")).hexdigest(), 16)
                idx_gram = h_gram % self.DIM
                sign_gram = 1.0 if (h_gram % 2 == 0) else -1.0
                vec[idx_gram] += 0.5 * sign_gram

        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0.0:
            vec = [v / norm for v in vec]
        return vec


class PersistentVectorStore:
    """
    Persistent, completely local vector store.
    Stores chunk records, embeddings, and full security provenance metadata.
    Persists to disk in `data/vector_store.json`.
    """

    def __init__(
        self,
        persist_path: str = "data/vector_store.json",
        embedding_dimension: int = 128
    ):
        self.persist_path = Path(persist_path)
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        self.local_embedder = LocalDenseEmbedder()
        self.records: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Load persistent records from disk."""
        if self.persist_path.exists():
            try:
                with open(self.persist_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.records = data.get("records", {})
                    logger.info(f"Loaded {len(self.records)} records from {self.persist_path}")
            except Exception as exc:
                logger.warning(f"Could not load vector store from {self.persist_path}: {exc}")
                self.records = {}
        else:
            self.records = {}

    def save(self) -> None:
        """Persist in-memory records to disk."""
        try:
            with open(self.persist_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "version": "1.0",
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "count": len(self.records),
                        "records": self.records,
                    },
                    f,
                    indent=2,
                )
        except Exception as exc:
            logger.error(f"Failed to persist vector store to {self.persist_path}: {exc}")

    def add_record(
        self,
        chunk_id: str,
        content: str,
        metadata: Dict[str, Any],
        embedding: Optional[List[float]] = None
    ) -> None:
        """
        Add or update a vector record with chunk content and security metadata.
        """
        if embedding is None:
            embedding = self.local_embedder.embed(content)

        self.records[chunk_id] = {
            "chunk_id": chunk_id,
            "content": content,
            "metadata": metadata,
            "embedding": embedding,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def delete_record(self, chunk_id: str) -> bool:
        """Remove a record by chunk_id."""
        if chunk_id in self.records:
            del self.records[chunk_id]
            return True
        return False

    def clear(self) -> None:
        """Clear all records."""
        self.records = {}
        self.save()

    def search(
        self,
        query_vector: List[float],
        top_k: int = 3,
        min_score: float = 0.05,
        trust_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve top_k candidate chunks matching the query vector.
        Applies optional trust level filter (e.g. ['TRUSTED_INTERNAL']).
        """
        scored_candidates: List[Tuple[float, Dict[str, Any]]] = []

        for chunk_id, rec in self.records.items():
            emb = rec.get("embedding", [])
            meta = rec.get("metadata", {})

            # Trust policy filter
            if trust_filter:
                trust_level = meta.get("trust_level", "UNKNOWN")
                if trust_level not in trust_filter:
                    continue

            score = cosine_similarity_vectors(query_vector, emb)
            if score >= min_score:
                scored_candidates.append((score, rec))

        # Sort descending by score
        scored_candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, rec in scored_candidates[:top_k]:
            results.append({
                "chunk_id": rec["chunk_id"],
                "content": rec["content"],
                "score": round(score, 4),
                "metadata": rec.get("metadata", {})
            })

        return results
