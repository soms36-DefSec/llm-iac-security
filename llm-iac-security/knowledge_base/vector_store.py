"""
Dual-mode vector store wrapper for LLM IaC Security Scanner.

Local mode: ChromaDB with on-disk persistence.
AWS mode:   Pinecone serverless (replaces OpenSearch Serverless).

Both backends expose the same four-method interface so callers are
completely decoupled from the underlying store.
"""
from __future__ import annotations
import logging
import uuid
from typing import Any, Optional

import config.settings as settings
from utils.exceptions import KnowledgeBaseError

logger = logging.getLogger(__name__)


class VectorStore:
    """Dual-mode vector store wrapper.

    Provides unified add_documents, search, clear, and document_count
    methods regardless of the active backend (ChromaDB or Pinecone).

    Args:
        mode: Override the mode from settings. Useful for testing.

    Raises:
        KnowledgeBaseError: If the backend cannot be initialised.
    """

    def __init__(self, mode: Optional[str] = None) -> None:
        """Initialise the appropriate vector store backend.

        Args:
            mode: 'local' or 'aws'. Defaults to settings.MODE.

        Raises:
            KnowledgeBaseError: If backend initialisation fails.
        """
        self._mode = mode or settings.MODE
        self._client = None     # ChromaDB client (local)
        self._collection = None  # ChromaDB collection (local)
        self._index = None       # Pinecone index (aws)
        self._pinecone = None    # Pinecone client (aws)

    # ------------------------------------------------------------------
    # Internal initialisation (lazy)
    # ------------------------------------------------------------------

    def _init_local(self) -> None:
        """Initialise ChromaDB with a persistent directory.

        Raises:
            KnowledgeBaseError: If ChromaDB cannot be opened.
        """
        try:
            import chromadb
            self._client = chromadb.PersistentClient(
                path=settings.CHROMA_PERSIST_DIR
            )
            self._collection = self._client.get_or_create_collection(
                name="iac_security_kb",
                metadata={"hnsw:space": "cosine"},
            )
            logger.info(
                "ChromaDB initialised at %s", settings.CHROMA_PERSIST_DIR
            )
        except Exception as exc:
            raise KnowledgeBaseError(
                f"ChromaDB initialisation failed: {exc}"
            ) from exc

    def _init_aws(self) -> None:
        """Initialise Pinecone serverless index.

        Raises:
            KnowledgeBaseError: If Pinecone cannot be connected.
        """
        try:
            from pinecone import Pinecone, ServerlessSpec
            self._pinecone = Pinecone(api_key=settings.PINECONE_API_KEY)
            index_name = settings.PINECONE_INDEX
            existing = [i.name for i in self._pinecone.list_indexes()]
            if index_name not in existing:
                self._pinecone.create_index(
                    name=index_name,
                    dimension=1024,
                    metric="cosine",
                    spec=ServerlessSpec(cloud="aws", region=settings.AWS_REGION),
                )
                logger.info("Pinecone index created: %s", index_name)
            self._index = self._pinecone.Index(index_name)
            logger.info("Pinecone index connected: %s", index_name)
        except Exception as exc:
            raise KnowledgeBaseError(
                f"Pinecone initialisation failed: {exc}"
            ) from exc

    def _ensure_init(self) -> None:
        """Ensure the backend is initialised before any operation.

        Raises:
            KnowledgeBaseError: If initialisation has not been done.
        """
        if self._mode == "local" and self._collection is None:
            self._init_local()
        elif self._mode == "aws" and self._index is None:
            self._init_aws()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_documents(
        self, texts: list[str], metadatas: list[dict]
    ) -> None:
        """Add a batch of text chunks with metadata to the vector store.

        The embeddings must already be computed; this method stores the
        raw text alongside metadata. For ChromaDB, embeddings are
        generated internally via the collection's default embedding
        function — callers must pass pre-computed vectors separately via
        the internal upsert helpers used by kb_manager.

        NOTE: This method stores text + metadata; call upsert() when you
        also want to supply pre-computed embeddings (AWS mode).

        Args:
            texts:     List of text chunks.
            metadatas: Parallel list of metadata dicts.

        Raises:
            KnowledgeBaseError: If the store operation fails.
        """
        try:
            self._ensure_init()
            if self._mode == "local":
                ids = [str(uuid.uuid4()) for _ in texts]
                self._collection.add(
                    documents=texts,
                    metadatas=metadatas,
                    ids=ids,
                )
            else:
                raise KnowledgeBaseError(
                    "Use upsert() for AWS mode (embeddings required)."
                )
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"add_documents failed (mode={self._mode}): {exc}"
            ) from exc

    def upsert(
        self,
        doc_id: str,
        text: str,
        embedding: list[float],
        metadata: dict,
    ) -> None:
        """Upsert a single document with its pre-computed embedding.

        Works for both modes. In local mode the embedding is stored via
        ChromaDB; in AWS mode via Pinecone.

        Args:
            doc_id:    Unique identifier for this chunk.
            text:      The text content of the chunk.
            embedding: Pre-computed float vector.
            metadata:  Arbitrary metadata dict (source, chunk_index, …).

        Raises:
            KnowledgeBaseError: If the upsert fails.
        """
        try:
            self._ensure_init()
            if self._mode == "local":
                self._collection.upsert(
                    ids=[doc_id],
                    embeddings=[embedding],
                    documents=[text],
                    metadatas=[metadata],
                )
            else:
                self._index.upsert(
                    vectors=[
                        {
                            "id": doc_id,
                            "values": embedding,
                            "metadata": {"text": text, **metadata},
                        }
                    ]
                )
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"upsert failed (mode={self._mode}, doc_id={doc_id}): {exc}"
            ) from exc

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Find the top-k most similar documents to a query embedding.

        Args:
            query_embedding: Float vector for the query.
            top_k:           Number of results to return.

        Returns:
            List of dicts, each containing:
                {"text": str, "metadata": dict, "score": float}
            Sorted by descending similarity score.
            Results with score < settings.SIMILARITY_THRESHOLD are
            filtered out.

        Raises:
            KnowledgeBaseError: If the search fails.
        """
        try:
            self._ensure_init()
            threshold = settings.SIMILARITY_THRESHOLD
            results: list[dict[str, Any]] = []

            if self._mode == "local":
                resp = self._collection.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                    include=["documents", "metadatas", "distances"],
                )
                docs = resp.get("documents", [[]])[0]
                metas = resp.get("metadatas", [[]])[0]
                dists = resp.get("distances", [[]])[0]
                for doc, meta, dist in zip(docs, metas, dists):
                    # ChromaDB returns L2 distance for cosine space; convert
                    score = 1.0 - dist
                    if score >= threshold:
                        results.append(
                            {"text": doc, "metadata": meta, "score": score}
                        )
            else:
                resp = self._index.query(
                    vector=query_embedding,
                    top_k=top_k,
                    include_metadata=True,
                )
                for match in resp.get("matches", []):
                    score = float(match.get("score", 0.0))
                    if score >= threshold:
                        meta = match.get("metadata", {})
                        text = meta.pop("text", "")
                        results.append(
                            {"text": text, "metadata": meta, "score": score}
                        )

            # Sort descending
            results.sort(key=lambda x: x["score"], reverse=True)
            return results
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"search failed (mode={self._mode}): {exc}"
            ) from exc

    def clear(self) -> None:
        """Remove all documents from the store.

        Raises:
            KnowledgeBaseError: If the clear operation fails.
        """
        try:
            self._ensure_init()
            if self._mode == "local":
                name = self._collection.name
                self._client.delete_collection(name)
                self._collection = self._client.get_or_create_collection(
                    name=name,
                    metadata={"hnsw:space": "cosine"},
                )
                logger.info("ChromaDB collection cleared: %s", name)
            else:
                # Pinecone: delete all vectors by namespace
                self._index.delete(delete_all=True)
                logger.info("Pinecone index cleared: %s", settings.PINECONE_INDEX)
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"clear failed (mode={self._mode}): {exc}"
            ) from exc

    def document_count(self) -> int:
        """Return the number of documents (chunks) currently stored.

        Returns:
            Integer count of stored documents.

        Raises:
            KnowledgeBaseError: If the count cannot be retrieved.
        """
        try:
            self._ensure_init()
            if self._mode == "local":
                return self._collection.count()
            else:
                stats = self._index.describe_index_stats()
                return int(stats.get("total_vector_count", 0))
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"document_count failed (mode={self._mode}): {exc}"
            ) from exc
