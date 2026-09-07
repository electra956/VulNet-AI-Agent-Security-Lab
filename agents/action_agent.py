class ActionAgent:
    """
    Action Agent for the VulNet AI Agent Security Lab.

    This agent receives:
    - User request
    - Research findings

    It decides what simulated action should happen next.

    No real external actions are performed.
    """

    def execute(self, user_request, research_result):

        # --------------------------------------------------
        # BASIC VALIDATION
        # --------------------------------------------------

        if not research_result:

            return {
                "status": "blocked",
                "decision": "No research result was provided.",
                "action": "No action performed."
            }

        # --------------------------------------------------
        # GET RESEARCH INFORMATION
        # --------------------------------------------------

        documents_analyzed = research_result.get(
            "documents_analyzed",
            0
        )

        # --------------------------------------------------
        # NO DOCUMENTS AVAILABLE
        # --------------------------------------------------

        if documents_analyzed == 0:

            return {
                "status": "completed",
                "decision": "No relevant context was available.",
                "action": (
                    "No simulated action was performed because "
                    "the Research Agent found no relevant documents."
                )
            }

        # --------------------------------------------------
        # SIMULATED ACTION
        # --------------------------------------------------

        action_message = f"""
## Action Agent Result

**User Request:**

{user_request}

### Research Validation

The Action Agent received research findings based on
**{documents_analyzed} document(s)**.

### Simulated Action

The Action Agent approved a **safe simulated action**.

No real systems, credentials, files, networks, or external
services were modified.

### Security Status

🟢 Simulation completed safely.
"""

        return {
            "status": "completed",
            "decision": "Safe simulated action approved.",
            "action": action_message,
            "documents_analyzed": documents_analyzed
        }
