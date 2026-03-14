"""
Knowledge Base Manager — Ties embeddings + vector store into one simple API.

RAG Pipeline Overview:
    ┌─────────────┐   chunk    ┌───────────┐   embed    ┌─────────────┐
    │  .md / .pdf  │ ───────▶ │  Chunks    │ ───────▶  │ ChromaDB    │
    │  source docs │          │  (text)    │           │ (vectors)   │
    └─────────────┘           └───────────┘           └─────────────┘

    ┌──────────┐   embed    ┌───────────┐   search   ┌─────────────┐
    │  Query   │ ───────▶  │  Vector   │ ───────▶  │  Top-K      │
    │  (text)  │           │           │           │  Snippets   │
    └──────────┘           └───────────┘           └─────────────┘

Usage:
    from knowledge_base.kb_manager import KnowledgeBaseManager

    kb = KnowledgeBaseManager()
    kb.load_all_sources()                      # one-time setup
    snippets = kb.retrieve("S3 encryption")    # search
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

from config.logging_config import get_logger
from config.settings import settings
from knowledge_base.embeddings import EmbeddingModel
from knowledge_base.vector_store import VectorStore
from utils.file_utils import chunk_text, read_pdf, read_text

logger = get_logger(__name__)


class KnowledgeBaseManager:
    """
    High-level API that combines the embedding model and vector store
    so the rest of the codebase only needs to call two methods:

        load_all_sources()  — build the knowledge base (run once)
        retrieve(query)     — search the knowledge base (run per query)
    """

    def __init__(self) -> None:
        # Load the sentence-transformers embedding model
        self._embeddings = EmbeddingModel()
        # Create the ChromaDB-backed vector store
        self._store = VectorStore()
        self._store.initialize()

    # ------------------------------------------------------------------
    # Adding documents
    # ------------------------------------------------------------------

    def add_document(
        self,
        doc_id: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Split a document into chunks, embed each chunk, store in ChromaDB.

        What is chunking?
            Long documents are split into overlapping pieces (e.g., 2000 chars
            each with 400 chars of overlap).  Overlap ensures that important
            information at a chunk boundary isn't lost.

        Args:
            doc_id:   Unique identifier for the document (e.g., filename stem).
            text:     Full text content of the document.
            metadata: Extra info to store alongside each chunk.
        """
        if not text or len(text.strip()) < 10:
            return

        metadata = metadata or {}

        # Step 1 — Split the text into overlapping chunks
        chunks = chunk_text(text, chunk_size=2000, overlap=400)

        # Step 2 — Generate embeddings for all chunks in one batch (faster)
        embeddings = self._embeddings.generate_embeddings(chunks)

        # Step 3 — Build IDs and metadata for each chunk
        ids = [f"{doc_id}_chunk_{i}" for i in range(len(chunks))]
        metas = [{**metadata, "chunk_index": i} for i in range(len(chunks))]

        # Step 4 — Store in ChromaDB
        self._store.add_documents(
            ids=ids, texts=chunks, embeddings=embeddings, metadatas=metas
        )
        logger.info("document_added", doc_id=doc_id, chunks=len(chunks))

    def add_from_file(self, path: Path, category: str) -> None:
        """
        Read a file from disk and add it to the knowledge base.

        Supported formats: .md, .txt, .pdf
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

            self.add_document(
                path.stem, text, {"source": path.name, "category": category}
            )
        except Exception as e:
            logger.error("failed_to_process_file", file=path.name, error=str(e))

    # ------------------------------------------------------------------
    # Querying / Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, query: str, top_k: int = 5) -> List[str]:
        """
        Search the knowledge base for text snippets relevant to the query.

        This is the "Retrieval" step of RAG:
            1. Embed the query text.
            2. Search ChromaDB for the closest document chunks.
            3. Return the text content of those chunks.

        Args:
            query: Free-text search query.
            top_k: Number of results to return (default 5).

        Returns:
            A list of relevant text snippets from the knowledge base.
        """
        query_embedding = self._embeddings.generate_embedding(query)
        results = self._store.similarity_search(query_embedding, top_k=top_k)
        return [r["text"] for r in results if r.get("text")]

    # ------------------------------------------------------------------
    # Bulk loading
    # ------------------------------------------------------------------

    def load_all_sources(self) -> None:
        """
        Load every document from knowledge_base/sources/ (and user input/)
        into the vector store.  Run this once to set up the knowledge base.
        """
        sources_dir = settings.app.knowledge_base_dir
        loaded = 0

        for doc_file in sorted(sources_dir.glob("*.*")):
            if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                self.add_from_file(doc_file, doc_file.stem.replace("_", "-"))
                loaded += 1

        # Also load user-provided documents if the directory exists
        user_input_dir = sources_dir.parent / "user input"
        if user_input_dir.exists():
            for doc_file in sorted(user_input_dir.glob("*.*")):
                if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                    self.add_from_file(doc_file, "user-provided")
                    loaded += 1

        logger.info("all_sources_loaded", total_files=loaded, total_chunks=self._store.count())

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all documents from the vector store."""
        self._store.clear()
        # Re-initialize so the collection is ready for new data
        self._store.initialize()
