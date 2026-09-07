class ResearchAgent:
    """
    Research Agent for the VulNet AI Agent Security Lab.

    This agent receives:
    - User request
    - Documents retrieved by the RAG system

    It extracts relevant findings from the available
    local knowledge-base context.
    """

    def research(self, user_request, retrieved_documents):

        # ----------------------------------------------
        # NO DOCUMENTS
        # ----------------------------------------------

        if not retrieved_documents:

            return {
                "status": "completed",
                "findings": [],
                "summary": (
                    "No relevant documents were available "
                    "for research."
                ),
                "documents_analyzed": 0
            }


        # ----------------------------------------------
        # ANALYZE DOCUMENTS
        # ----------------------------------------------

        findings = []

        for document in retrieved_documents:

            document_name = document.get(
                "document",
                "Unknown Document"
            )

            document_content = document.get(
                "content",
                ""
            )

            document_score = document.get(
                "score",
                0
            )

            finding = {
                "document": document_name,
                "score": document_score,
                "content_preview": (
                    document_content[:300]
                )
            }

            findings.append(finding)


        # ----------------------------------------------
        # CREATE SUMMARY
        # ----------------------------------------------

        summary = (
            f"The Research Agent analyzed "
            f"{len(findings)} retrieved document(s) "
            f"for the user request: '{user_request}'."
        )


        return {
            "status": "completed",
            "findings": findings,
            "summary": summary,
            "documents_analyzed": len(findings)
        }
