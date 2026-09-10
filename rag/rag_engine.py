"""
VulNet AI Agent Security Lab - Hardened RAG Engine
Provides TF-IDF retrieval with instruction/data separation, trust classification,
and indirect prompt injection scanning.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class RAGEngine:
    """
    RAG Engine with security boundaries for Agentic AI.

    Security Capabilities:
    - Instruction vs Data separation (XML boundary wrapping)
    - Trust classification (TRUSTED_INTERNAL vs UNTRUSTED_EXTERNAL)
    - Suspicious context scanning (detecting embedded prompt overrides)
    - Relevance threshold filtering
    """

    SUSPICIOUS_PATTERNS = [
        r"ignore (?:all )?previous instructions",
        r"forget your instructions",
        r"override your (?:rules|goal)",
        r"reveal (?:system )?prompt",
        r"you are now",
        r"new objective:",
        r"new instructions:",
        r"execute this instruction",
        r"system prompt override"
    ]

    def __init__(self, knowledge_path: str = "rag/knowledge", security_controller: Optional[Any] = None):
        self.knowledge_path = Path(knowledge_path)
        self.security_controller = security_controller
        self.documents: List[str] = []
        self.document_names: List[str] = []
        self.trust_levels: List[str] = []

        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.vectors = None

        self.load_documents()

    def set_security_controller(self, controller: Any) -> None:
        """Attach or update the security controller reference."""
        self.security_controller = controller

    def _classify_trust(self, filename: str) -> str:
        """Classify document trust based on origin/naming convention."""
        lower_name = filename.lower()
        if "untrusted" in lower_name or "external" in lower_name or "third_party" in lower_name:
            return "UNTRUSTED_EXTERNAL"
        return "TRUSTED_INTERNAL"

    def load_documents(self) -> None:
        """Load all .txt files from the knowledge directory and compute vectors."""
        self.documents = []
        self.document_names = []
        self.trust_levels = []

        if not self.knowledge_path.exists():
            return

        for file_path in sorted(self.knowledge_path.glob("*.txt")):
            try:
                content = file_path.read_text(encoding="utf-8")
                self.documents.append(content)
                self.document_names.append(file_path.name)
                self.trust_levels.append(self._classify_trust(file_path.name))
            except Exception:
                continue

        if self.documents:
            self.vectors = self.vectorizer.fit_transform(self.documents)

    def scan_content_security(self, content: str) -> Dict[str, Any]:
        """Scan document content for embedded instruction hijacking."""
        content_lower = content.lower()
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, content_lower):
                return {
                    "is_safe": False,
                    "matched_pattern": pattern,
                    "risk": "INDIRECT_PROMPT_INJECTION"
                }
        return {
            "is_safe": True,
            "matched_pattern": None,
            "risk": "NONE"
        }

    def wrap_context_boundary(self, content: str, doc_name: str, trust: str) -> str:
        """
        Wrap retrieved data in clear data-only XML tags to prevent
        agents from misinterpreting data as instructions.
        """
        return (
            f'<untrusted_knowledge_data source="{doc_name}" trust_level="{trust}">\n'
            f"{content.strip()}\n"
            f"</untrusted_knowledge_data>"
        )

    def search(
        self,
        query: str,
        top_k: int = 3,
        min_score: float = 0.05
    ) -> List[Dict[str, Any]]:
        """
        Search the knowledge base and return hardened context representations.
        """
        if not self.documents or self.vectors is None:
            return []

        try:
            query_vector = self.vectorizer.transform([query])
            scores = cosine_similarity(query_vector, self.vectors)[0]
        except Exception:
            return []

        ranked_indexes = scores.argsort()[::-1]
        results: List[Dict[str, Any]] = []

        # Determine current security mode
        current_mode = "secure"
        if self.security_controller and hasattr(self.security_controller, "get_mode"):
            current_mode = self.security_controller.get_mode()

        for index in ranked_indexes:
            score = float(scores[index])
            if score < min_score:
                continue

            doc_name = self.document_names[index]
            raw_content = self.documents[index]
            trust = self.trust_levels[index]

            # Security scan of retrieved document
            sec_scan = self.scan_content_security(raw_content)
            is_safe = sec_scan["is_safe"]

            # Log telemetry if security controller is present
            if not is_safe and self.security_controller:
                if current_mode == "secure":
                    self.security_controller.log_event(
                        event_type="RAG_POISONING_MITIGATED",
                        message=f"Indirect injection detected in retrieved doc '{doc_name}': neutralized.",
                        severity="HIGH",
                        scenario="ASI01 - Agent Goal Hijack",
                        component="RAG",
                        decision="MITIGATE",
                        metadata={"document": doc_name, "score": round(score, 3)}
                    )
                else:
                    self.security_controller.log_event(
                        event_type="RAG_POISONING_ALLOWED",
                        message=f"Indirect injection detected in retrieved doc '{doc_name}': allowed in vulnerable mode.",
                        severity="WARNING",
                        scenario="ASI01 - Agent Goal Hijack",
                        component="RAG",
                        decision="ALLOW",
                        metadata={"document": doc_name, "score": round(score, 3)}
                    )

            # Sanitize content in Secure Mode if suspicious
            sanitized_content = raw_content
            if not is_safe and current_mode == "secure":
                # Neutralize prompt injection phrases
                sanitized_content = re.sub(
                    r"(?i)(ignore (?:all )?previous instructions|forget your instructions|override your rules|reveal system prompt)",
                    "[NEUTRALIZED_UNTRUSTED_INSTRUCTION]",
                    raw_content
                )

            wrapped = self.wrap_context_boundary(
                sanitized_content if current_mode == "secure" else raw_content,
                doc_name,
                trust
            )

            results.append({
                "document": doc_name,
                "content": sanitized_content if current_mode == "secure" else raw_content,
                "raw_content": raw_content,
                "score": round(score, 3),
                "trust_classification": trust,
                "is_safe": is_safe,
                "wrapped_context": wrapped
            })

            if len(results) >= top_k:
                break

        return results