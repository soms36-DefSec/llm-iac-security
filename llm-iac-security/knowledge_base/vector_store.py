"""
Vector Store Module — Stores and searches document embeddings using ChromaDB.

What is a vector store?
    A vector store is a database optimized for storing embedding vectors and
    finding the ones most "similar" to a given query vector.  Similarity is
    measured using cosine distance — two vectors pointing in roughly the same
    direction are considered similar.

Why ChromaDB?
    ChromaDB is a free, open-source, embedded vector database that stores
    data locally on disk.  No API keys or cloud accounts needed.  It also
    handles embedding storage + metadata + similarity search in one package.

Usage:
    from knowledge_base.vector_store import VectorStore

    store = VectorStore()
    store.add_documents(
        ids=["doc1_chunk0"],
        texts=["S3 buckets should have encryption..."],
        embeddings=[[0.12, -0.34, ...]],
        metadatas=[{"source": "aws_well_architected.md"}],
    )
    results = store.similarity_search(query_embedding=[0.11, -0.33, ...], top_k=5)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from config.logging_config import get_logger
from config.settings import settings

logger = get_logger(__name__)

# ChromaDB collection name for the IaC security knowledge base
COLLECTION_NAME = "iac-security-kb"


class VectorStore:
    """
    ChromaDB-backed vector store for similarity search.

    Data is persisted to disk at  knowledge_base/.chromadb/  so you only need
    to run the setup script once.  Subsequent runs will reuse the stored data.
    """

    def __init__(self, persist_directory: str | Path | None = None):
        """
        Initialize the ChromaDB client and get (or create) the collection.

        Args:
            persist_directory: Where ChromaDB stores its data on disk.
                               Defaults to  knowledge_base/.chromadb/  inside the project.
        """
        try:
            import chromadb
        except ImportError:
            raise RuntimeError(
                "chromadb is required.  Install with:\n"
                "  pip install chromadb"
            )

        if persist_directory is None:
            persist_directory = str(
                Path(settings.app.knowledge_base_dir).parent / ".chromadb"
            )

        self._persist_dir = str(persist_directory)
        logger.info("initializing_chromadb", persist_dir=self._persist_dir)

        # PersistentClient saves data to disk automatically
        self._client = chromadb.PersistentClient(path=self._persist_dir)
        self._collection = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialize(self, collection_name: str = COLLECTION_NAME) -> None:
        """
        Get or create the ChromaDB collection.

        A "collection" in ChromaDB is like a table — it holds all vectors
        and their associated metadata under one name.
        """
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},  # use cosine similarity
        )
        logger.info(
            "collection_ready",
            name=collection_name,
            count=self._collection.count(),
        )

    def add_documents(
        self,
        ids: List[str],
        texts: List[str],
        embeddings: List[List[float]],
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        Add (or update) documents in the vector store.

        Args:
            ids:        Unique string IDs for each document chunk.
            texts:      The raw text content of each chunk (stored for retrieval).
            embeddings: Pre-computed embedding vectors for each chunk.
            metadatas:  Optional list of metadata dicts (source file, category, etc.).
        """
        if self._collection is None:
            raise RuntimeError("Call initialize() before adding documents.")

        self._collection.upsert(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metadatas,
        )
        logger.info("documents_added", count=len(ids))

    def similarity_search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Find the top-k most similar document chunks to a query embedding.

        Args:
            query_embedding: The embedding vector of the search query.
            top_k:           How many results to return (default 5).

        Returns:
            A list of dicts, each containing:
                - "text":     The chunk's raw text.
                - "metadata": The chunk's metadata dict.
                - "distance": The cosine distance (lower = more similar).
        """
        if self._collection is None:
            raise RuntimeError("Call initialize() before searching.")

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, max(self._collection.count(), 1)),
            include=["documents", "metadatas", "distances"],
        )

        # ChromaDB returns nested lists (one per query); we sent one query so unpack [0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        output = []
        for text, meta, dist in zip(documents, metadatas, distances):
            output.append({"text": text, "metadata": meta, "distance": dist})

        return output

    def clear(self) -> None:
        """Delete the entire collection (useful for re-initializing)."""
        if self._collection is not None:
            self._client.delete_collection(self._collection.name)
            self._collection = None
            logger.info("collection_cleared")

    def count(self) -> int:
        """Return the number of document chunks currently stored."""
        if self._collection is None:
            return 0
        return self._collection.count()
