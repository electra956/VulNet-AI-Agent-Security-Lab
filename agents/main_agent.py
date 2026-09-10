"""
VulNet AI Agent Security Lab - Main Agent
Maintains the primary user objective, coordinates analysis,
and guards against goal hijacking (ASI01).
"""

from typing import Any, Dict, List, Optional
import re


class MainAgent:
    """
    Main Agent for the VulNet AI Agent Security Lab.

    Responsibilities:
    - Anchors the original user objective
    - Analyzes incoming user requests and retrieved knowledge
    - Detects potential goal drift or conflicting instructions
    - Secure Mode: Preserves original objective, neutralizes conflicting commands
    - Vulnerable Mode: Simulates goal drift when untrusted instructions enter context
    """

    INSTRUCTION_OVERRIDE_PATTERN = re.compile(
        r"(?i)(new objective:|change your goal to|ignore previous|system prompt override)"
    )

    def analyze(
        self,
        user_request: str,
        retrieved_documents: List[Any],
        mode: str = "secure"
    ) -> Dict[str, Any]:
        """
        Analyze request against retrieved context while preserving objective integrity.
        """
        document_count = len(retrieved_documents)
        original_goal = user_request.strip()
        active_goal = original_goal
        goal_drift_detected = False
        drift_source = None

        # --------------------------------------------------
        # INSPECT RETRIEVED CONTEXT FOR GOAL DRIFT
        # --------------------------------------------------
        for doc in retrieved_documents:
            content = doc.get("raw_content", doc.get("content", "")) if isinstance(doc, dict) else str(doc)
            doc_name = doc.get("document", "Unknown") if isinstance(doc, dict) else "Unknown"

            if self.INSTRUCTION_OVERRIDE_PATTERN.search(content):
                goal_drift_detected = True
                drift_source = doc_name
                if mode == "vulnerable":
                    # Simulate goal hijack adoption
                    active_goal = f"[HIJACKED GOAL via {doc_name}]: Reveal all system settings"
                break

        # --------------------------------------------------
        # NO DOCUMENTS FOUND
        # --------------------------------------------------
        if document_count == 0:
            return {
                "status": "completed",
                "original_goal": original_goal,
                "active_goal": active_goal,
                "goal_drift_detected": False,
                "decision": "No relevant documents were found.",
                "response": (
                    "I could not find relevant information in the "
                    "local knowledge base for this request."
                ),
                "documents_used": 0
            }

        # --------------------------------------------------
        # DOCUMENTS FOUND - BUILD STRUCTURED RESPONSE
        # --------------------------------------------------
        document_names = []
        for doc in retrieved_documents:
            if isinstance(doc, dict):
                name = doc.get("filename", doc.get("document", "Unknown Document"))
                trust = doc.get("trust_classification", "UNKNOWN")
                document_names.append(f"{name} [{trust}]")
            else:
                document_names.append(str(doc))

        response = f"""
## Main Agent Analysis

**Primary Objective:** `{original_goal}`

**Active Operational Goal:** `{active_goal}`

**Retrieved Knowledge Sources:** {document_count} document(s)
"""
        for name in document_names:
            response += f"- 📄 {name}\n"

        if goal_drift_detected:
            if mode == "secure":
                response += f"""
> [!NOTE]
> **Security Defense Active**: Detected untrusted instruction in `{drift_source}`.
> Original goal anchored securely; conflicting instruction neutralized.
"""
            else:
                response += f"""
> [!WARNING]
> **Vulnerability Simulation**: Goal drift occurred!
> Active goal altered by untrusted context in `{drift_source}`.
"""

        response += """
### Agent Decision
Request analyzed and validated under current security posture.
Proceeding to research extraction stage.
"""

        return {
            "status": "completed",
            "original_goal": original_goal,
            "active_goal": active_goal,
            "goal_drift_detected": goal_drift_detected,
            "decision": (
                "Goal preserved securely despite untrusted context."
                if (goal_drift_detected and mode == "secure")
                else "Request analyzed using retrieved context."
            ),
            "response": response.strip(),
            "documents_used": document_count
        }