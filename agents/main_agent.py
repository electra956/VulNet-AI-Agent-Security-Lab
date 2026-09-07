class MainAgent:
    """
    Main Agent for the VulNet AI Agent Security Lab.

    This agent receives:
    - User request
    - Retrieved RAG documents

    It analyzes the available context and creates
    a structured response.
    """

    def analyze(self, user_request, retrieved_documents):

        document_count = len(retrieved_documents)

        # --------------------------------------------------
        # NO DOCUMENTS FOUND
        # --------------------------------------------------

        if document_count == 0:

            return {
                "status": "completed",
                "decision": "No relevant documents were found.",
                "response": (
                    "I could not find relevant information in the "
                    "local knowledge base for this request."
                ),
                "documents_used": 0
            }

        # --------------------------------------------------
        # DOCUMENTS FOUND
        # --------------------------------------------------

        document_names = []

        for document in retrieved_documents:

            # Handle dictionary-based RAG results
            if isinstance(document, dict):

                name = document.get(
                    "filename",
                    document.get(
                        "document",
                        "Unknown Document"
                    )
                )

                document_names.append(name)

            else:

                document_names.append(
                    str(document)
                )

        # --------------------------------------------------
        # CREATE RESPONSE
        # --------------------------------------------------

        response = f"""
## Main Agent Analysis

**User Request:**

{user_request}

The Main Agent received **{document_count} relevant document(s)** from the RAG system.

### Documents Considered

"""

        for name in document_names:

            response += f"- 📄 {name}\n"

        response += """

### Agent Decision

The request has been analyzed using the retrieved local knowledge-base context.

The Main Agent will use this information as context for the next stages of the Agentic AI pipeline.
"""

        return {
            "status": "completed",
            "decision": "Request analyzed using retrieved RAG context.",
            "response": response,
            "documents_used": document_count
        }