"""
Vector Store Module — Stores and retrieves document embeddings by similarity.

What is a vector store?
    A vector store is a specialized database for storing embedding vectors.
    When you search, it finds the vectors that are most "similar" to your query
    vector.  Similarity is measured using *cosine similarity* — two vectors
    pointing in the same direction score close to 1.0 (very similar), while
    unrelated vectors score close to 0.0.

This module supports two backends:
    - LOCAL mode:  Uses FAISS (Facebook AI Similarity Search), an in-memory
                   vector index that runs on your machine.  Great for
                   development — no API keys or cloud services needed.
    - AWS mode:    Uses Pinecone, a managed cloud vector database.
                   Requires a Pinecone API key and internet access.

The mode is determined by APP_MODE in your .env file (default: "local").
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.logging_config import get_logger
from config.settings import settings
from utils.exceptions import VectorStoreError

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Abstract base — defines the interface every vector store must follow
# ---------------------------------------------------------------------------
class BaseVectorStore(ABC):
    """
    Base class for all vector store backends.

    Subclasses must implement:
        ensure_index()    — Create/connect to the index
        upsert(...)       — Add or update a document
        search(...)       — Find the most similar documents to a query
        clear()           — Remove all documents (useful for resetting)
    """

    @abstractmethod
    def ensure_index(self) -> None:
        """Create the index if it does not exist, or connect to an existing one."""
        ...

    @abstractmethod
    def upsert(self, doc_id: str, text: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        """Insert or update a document in the index."""
        ...

    @abstractmethod
    def search(self, query_embedding: List[float], top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return the top-k most similar documents to the query embedding."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Remove all documents from the index."""
        ...


# ---------------------------------------------------------------------------
# LOCAL backend — FAISS (Facebook AI Similarity Search)
# ---------------------------------------------------------------------------
class FAISSVectorStore(BaseVectorStore):
    """
    In-memory vector store using FAISS.

    Documents are stored in a Python dict alongside a FAISS index.
    The index can optionally be saved to / loaded from disk so you
    don't have to re-embed documents every time you restart.

    FAISS is very fast for similarity search, even on CPU, but keeps
    everything in RAM — fine for the small knowledge bases in this project.
    """

    def __init__(self, dimension: int):
        self._dimension = dimension
        self._top_k = settings.pinecone.top_k_results  # reuse the same setting
        self._index = None
        # We keep a parallel dict that maps integer position → document metadata
        self._documents: Dict[int, Dict[str, Any]] = {}
        # Maps doc_id string → integer position in the FAISS index
        self._id_map: Dict[str, int] = {}
        self._next_pos = 0
        # Persistence path (inside the project's data directory)
        self._persist_dir = Path(settings.app.knowledge_base_dir).parent / ".faiss_store"

    def ensure_index(self) -> None:
        """Create a new FAISS index (Inner Product type for cosine similarity on normalized vectors)."""
        try:
            import faiss

            # Inner Product on L2-normalized vectors is equivalent to cosine similarity
            self._index = faiss.IndexFlatIP(self._dimension)
            logger.info("faiss_index_created", dimension=self._dimension)

            # Try to load persisted data if available
            self._load_from_disk()
        except ImportError as e:
            raise VectorStoreError(
                "faiss-cpu is required for local mode. "
                "Install it with: pip install faiss-cpu"
            ) from e
        except Exception as e:
            raise VectorStoreError(f"Failed to create FAISS index: {e}") from e

    def upsert(self, doc_id: str, text: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        """Add a document to the FAISS index."""
        import numpy as np

        if self._index is None:
            raise VectorStoreError("Index not initialized. Call ensure_index() first.")

        # Convert embedding to numpy array (FAISS expects float32)
        vec = np.array([embedding], dtype=np.float32)

        # If this doc_id already exists, we cannot easily remove from FAISS FlatIndex,
        # so we just add it again (duplicates are acceptable for this use case).
        pos = self._next_pos
        self._index.add(vec)
        self._documents[pos] = {"text": text, **metadata}
        self._id_map[doc_id] = pos
        self._next_pos += 1

    def search(self, query_embedding: List[float], top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        """Find the top-k most similar documents to the query embedding."""
        import numpy as np

        if self._index is None or self._index.ntotal == 0:
            return []

        k = min(top_k or self._top_k, self._index.ntotal)
        query = np.array([query_embedding], dtype=np.float32)

        # FAISS returns (distances, indices) arrays
        distances, indices = self._index.search(query, k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:
                continue
            doc = self._documents.get(int(idx), {})
            if doc:
                results.append({**doc, "_score": float(dist)})
        return results

    def clear(self) -> None:
        """Remove all documents from the index."""
        if self._index is not None:
            self._index.reset()
        self._documents.clear()
        self._id_map.clear()
        self._next_pos = 0
        logger.info("faiss_index_cleared")

    def save_to_disk(self) -> None:
        """Persist the FAISS index and metadata to disk."""
        import json
        import faiss

        if self._index is None:
            return
        self._persist_dir.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self._index, str(self._persist_dir / "index.faiss"))
        with open(self._persist_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(
                {"documents": {str(k): v for k, v in self._documents.items()},
                 "id_map": self._id_map, "next_pos": self._next_pos},
                f, default=str,
            )
        logger.info("faiss_index_saved", path=str(self._persist_dir))

    def _load_from_disk(self) -> None:
        """Load a previously persisted FAISS index from disk if it exists."""
        import json

        index_path = self._persist_dir / "index.faiss"
        meta_path = self._persist_dir / "metadata.json"
        if not index_path.exists() or not meta_path.exists():
            return
        try:
            import faiss

            self._index = faiss.read_index(str(index_path))
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._documents = {int(k): v for k, v in data["documents"].items()}
            self._id_map = data["id_map"]
            self._next_pos = data["next_pos"]
            logger.info("faiss_index_loaded", total=self._index.ntotal)
        except Exception as e:
            logger.warning("faiss_load_failed", error=str(e))


# ---------------------------------------------------------------------------
# AWS backend — Pinecone managed vector database
# ---------------------------------------------------------------------------
class PineconeVectorStore(BaseVectorStore):
    """
    Cloud-hosted vector store using Pinecone.

    Pinecone stores your embeddings on managed servers so you don't have to
    worry about persistence or scalability.  Requires a Pinecone API key.
    """

    def __init__(self, dimension: int = 1024):
        self._dimension = dimension
        cfg = settings.pinecone
        self._index_name = cfg.index
        self._top_k = cfg.top_k_results
        try:
            from pinecone import Pinecone

            self._pc = Pinecone(api_key=cfg.api_key)
            self._index = None
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def ensure_index(self) -> None:
        """Create the Pinecone index if it doesn't exist, then connect to it."""
        try:
            from pinecone import ServerlessSpec

            existing_indexes = [idx.name for idx in self._pc.list_indexes()]
            if self._index_name not in existing_indexes:
                self._pc.create_index(
                    name=self._index_name,
                    dimension=self._dimension,
                    metric="cosine",
                    spec=ServerlessSpec(cloud="aws", region=settings.aws.region),
                )
                logger.info("pinecone_index_created", index=self._index_name)
            self._index = self._pc.Index(self._index_name)
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def upsert(self, doc_id: str, text: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        """Insert or update a document in Pinecone."""
        try:
            self._index.upsert(
                vectors=[{"id": doc_id, "values": embedding, "metadata": {"text": text, **metadata}}]
            )
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def search(self, query_embedding: List[float], top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        """Query Pinecone for the most similar documents."""
        try:
            resp = self._index.query(
                vector=query_embedding,
                top_k=top_k or self._top_k,
                include_metadata=True,
            )
            return [match["metadata"] for match in resp["matches"] if "metadata" in match]
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def clear(self) -> None:
        """Delete all vectors from the Pinecone index."""
        try:
            self._index.delete(delete_all=True)
            logger.info("pinecone_index_cleared")
        except Exception as e:
            raise VectorStoreError(str(e)) from e


# ---------------------------------------------------------------------------
# Factory function — returns the right backend based on APP_MODE
# ---------------------------------------------------------------------------
def get_vector_store(dimension: int) -> BaseVectorStore:
    """
    Create and return the vector store backend matching the current APP_MODE setting.

    Args:
        dimension: The dimensionality of the embedding vectors to be stored.
                   Must match the dimension produced by the embedding backend.
    """
    mode = settings.app.mode.lower()
    if mode == "local":
        logger.info("using_faiss_vector_store")
        return FAISSVectorStore(dimension=dimension)
    elif mode == "aws":
        logger.info("using_pinecone_vector_store")
        return PineconeVectorStore(dimension=dimension)
    else:
        raise VectorStoreError(f"Unknown APP_MODE '{mode}'. Use 'local' or 'aws'.")
