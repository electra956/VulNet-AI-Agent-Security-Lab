"""
VulNet AI Agent Security Lab - Research Agent
Extracts research findings from retrieved RAG context while enforcing
an untrusted-data boundary (ASI06 / ASI01).
"""

from typing import Any, Dict, List, Optional
import re


class ResearchAgent:
    """
    Research Agent for the VulNet AI Agent Security Lab.

    Responsibilities:
    - Analyzes documents retrieved by the RAG system
    - Enforces data/instruction separation
    - Extracts structured findings with trust classifications
    - Isolates embedded prompts from propagating as trusted findings
    """

    def research(
        self,
        user_request: str,
        retrieved_documents: List[Any],
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """Extract structured findings from context."""
        if not retrieved_documents:
            return {
                "status": "completed",
                "findings": [],
                "summary": "No relevant documents were available for research.",
                "documents_analyzed": 0
            }

        findings = []
        for doc in retrieved_documents:
            if isinstance(doc, dict):
                doc_name = doc.get("document", "Unknown Document")
                doc_content = doc.get("content", "")
                doc_score = doc.get("score", 0)
                trust_class = doc.get("trust_classification", "UNKNOWN")
                is_safe = doc.get("is_safe", True)
            else:
                doc_name = str(doc)
                doc_content = str(doc)
                doc_score = 0
                trust_class = "UNKNOWN"
                is_safe = True

            # In Secure Mode, neutralize imperative commands so findings remain purely factual
            preview = doc_content[:300].strip()
            if mode == "secure" and not is_safe:
                preview = re.sub(
                    r"(?i)(ignore (?:all )?previous instructions|reveal system prompt|new objective:)",
                    "[ISOLATED_INSTRUCTION]",
                    preview
                )

            findings.append({
                "document": doc_name,
                "score": doc_score,
                "trust_classification": trust_class,
                "is_safe": is_safe,
                "content_preview": preview
            })

        summary = (
            f"The Research Agent analyzed {len(findings)} retrieved document(s) "
            f"for request: '{user_request}'. All external context treated as untrusted evidence."
        )

        return {
            "status": "completed",
            "findings": findings,
            "summary": summary,
            "documents_analyzed": len(findings)
        }
