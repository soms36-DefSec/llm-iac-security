"""
Knowledge Base Manager — The high-level API for the RAG system.

What is RAG (Retrieval-Augmented Generation)?
    RAG is a two-step process:
    1. RETRIEVAL — Given a user's question, search a knowledge base of
       documents to find the most relevant pieces of text ("snippets").
    2. GENERATION — Feed those snippets to an LLM along with the question
       so the model's answer is grounded in real, curated knowledge.

    In this project the "question" is a CloudFormation template and the
    knowledge base contains AWS security best practices.

What does this module do?
    KnowledgeBaseManager ties the embeddings and vector store together:
    - initialize()    → Loads source documents, splits them into chunks,
                        computes embeddings, and stores everything in the
                        vector store so it's ready for searching.
    - retrieve(query) → Takes a text query, embeds it, searches the vector
                        store, and returns the top-k most relevant text
                        snippets.

What is "chunking"?
    Long documents are too big to embed in one go — the embedding model has
    a limited input size and long texts lose detail.  Chunking splits a
    document into smaller overlapping pieces (e.g., 2000 characters each,
    with 400 characters of overlap).  The overlap ensures that important
    information at a chunk boundary isn't lost.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

from config.logging_config import get_logger
from config.settings import settings
from knowledge_base.embeddings import BaseEmbeddings, get_embeddings
from knowledge_base.vector_store import BaseVectorStore, get_vector_store
from utils.file_utils import chunk_text, read_pdf, read_text

logger = get_logger(__name__)


class KnowledgeBaseManager:
    """
    High-level API for managing best-practice documents in the vector store.

    Usage:
        kb = KnowledgeBaseManager()
        kb.load_all_sources()           # one-time setup
        snippets = kb.retrieve("S3 encryption best practices")
    """

    def __init__(self) -> None:
        # Step 1 — Create the embedding backend (local or AWS) based on APP_MODE
        self._embeddings: BaseEmbeddings = get_embeddings()
        # Step 2 — Create the vector store backend, passing the embedding dimension
        #          so the index is sized correctly
        self._store: BaseVectorStore = get_vector_store(self._embeddings.dimension)
        # Step 3 — Ensure the underlying index exists
        self._store.ensure_index()

    # ------------------------------------------------------------------
    # Adding documents
    # ------------------------------------------------------------------

    def add_document(self, doc_id: str, text: str, metadata: dict[str, Any] | None = None) -> None:
        """
        Chunk a document, embed each chunk, and store it in the vector store.

        Args:
            doc_id:   A unique identifier for the document (e.g., its filename).
            text:     The full text content of the document.
            metadata: Optional dict of extra information to store alongside
                      each chunk (e.g., source filename, category).
        """
        if not text or len(text.strip()) < 10:
            return

        metadata = metadata or {}
        try:
            # Split the document into overlapping chunks
            chunks = chunk_text(text, chunk_size=2000, overlap=400)

            for i, chunk in enumerate(chunks):
                chunk_id = f"{doc_id}_chunk_{i}"
                chunk_metadata = {**metadata, "chunk_index": i}
                embedding = self._embeddings.embed(chunk)
                self._store.upsert(chunk_id, chunk, embedding, chunk_metadata)

            logger.info("document_added", doc_id=doc_id, chunks=len(chunks))
        except Exception as e:
            logger.error("failed_to_add_document", doc_id=doc_id, error=str(e))

    def add_from_file(self, path: Path, category: str) -> None:
        """
        Read a file (PDF, Markdown, or plain text) and add it to the knowledge base.

        Args:
            path:     Path to the file on disk.
            category: A label describing the type of document (e.g., "cis-benchmarks").
        """
        try:
            suffix = path.suffix.lower()
            if suffix == ".pdf":
                text = read_pdf(path)
            elif suffix in (".md", ".txt"):
                text = read_text(path)
            else:
                logger.warning("unsupported_file_type", file=path.name)
                return

            self.add_document(path.stem, text, {"source": path.name, "category": category})
        except Exception as e:
            logger.error("failed_to_process_file", file=path.name, error=str(e))

    # ------------------------------------------------------------------
    # Querying / Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, query: str, top_k: int | None = None) -> List[str]:
        """
        Search the knowledge base for text snippets relevant to the query.

        This is the core "Retrieval" step of RAG:
        1. Embed the query text into a vector.
        2. Search the vector store for the closest document chunks.
        3. Return the text content of those chunks.

        Args:
            query: The text to search for (e.g., a summary of CloudFormation resources).
            top_k: Override the default number of results to return.

        Returns:
            A list of text strings, each being a relevant chunk from the knowledge base.
        """
        query_embedding = self._embeddings.embed(query)
        results = self._store.search(query_embedding, top_k=top_k)
        return [doc.get("text", "") for doc in results]

    # ------------------------------------------------------------------
    # Bulk loading
    # ------------------------------------------------------------------

    def load_all_sources(self) -> None:
        """
        Load all documents from the default sources directory and any
        user-provided documents into the knowledge base.

        Source directories:
            - knowledge_base/sources/   — Built-in best-practice documents
            - user input/               — User-uploaded documents (optional)
        """
        # Load built-in source documents
        sources_dir = settings.app.knowledge_base_dir
        for doc_file in sources_dir.glob("*.*"):
            if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                self.add_from_file(doc_file, doc_file.stem.replace("_", "-"))
                logger.info("seeded", file=doc_file.name)

        # Load user-provided documents (if the directory exists)
        user_input_dir = sources_dir.parent / "user input"
        if user_input_dir.exists():
            for doc_file in user_input_dir.glob("*.*"):
                if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                    self.add_from_file(doc_file, "user-provided")
                    logger.info("user_input_loaded", file=doc_file.name)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all documents from the vector store (useful for re-initializing)."""
        self._store.clear()
