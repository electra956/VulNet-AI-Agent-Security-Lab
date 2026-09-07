from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class RAGEngine:

    def __init__(self, knowledge_path="rag/knowledge"):

        self.knowledge_path = Path(knowledge_path)

        self.documents = []
        self.document_names = []

        self.vectorizer = TfidfVectorizer(
            stop_words="english"
        )

        self.vectors = None

        self.load_documents()


    def load_documents(self):
        """Load all .txt files from the knowledge directory."""

        for file_path in self.knowledge_path.glob("*.txt"):

            content = file_path.read_text(
                encoding="utf-8"
            )

            self.documents.append(content)

            self.document_names.append(
                file_path.name
            )

        if self.documents:

            self.vectors = self.vectorizer.fit_transform(
                self.documents
            )


    def search(
        self,
        query,
        top_k=3,
        min_score=0.05
    ):
        """
        Search the knowledge base.

        Documents below min_score are ignored.
        """

        if not self.documents:
            return []

        query_vector = self.vectorizer.transform(
            [query]
        )

        scores = cosine_similarity(
            query_vector,
            self.vectors
        )[0]

        ranked_indexes = scores.argsort()[::-1]

        results = []

        for index in ranked_indexes:

            score = float(scores[index])

            # Stop when documents are no longer relevant
            if score < min_score:
                continue

            results.append(
                {
                    "document": self.document_names[index],
                    "content": self.documents[index],
                    "score": round(score, 3)
                }
            )

            if len(results) >= top_k:
                break

        return results