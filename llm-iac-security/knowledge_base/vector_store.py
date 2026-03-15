"""Vector store providers: Pinecone (AWS/paid) and ChromaDB (local/free)."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from config.settings import settings
from config.logging_config import get_logger
from utils.exceptions import VectorStoreError

logger = get_logger(__name__)


class BaseVectorStore(ABC):
    """Abstract interface for vector stores."""
    @abstractmethod
    def ensure_index(self) -> None: ...

    @abstractmethod
    def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None: ...

    @abstractmethod
    def search(self, query_embedding: list[float]) -> list[dict[str, Any]]: ...


class PineconeVectorStore(BaseVectorStore):
    """Pinecone vector store for similarity search (paid/AWS mode)."""
    def __init__(self):
        cfg = settings.pinecone
        self._index_name = cfg.index
        self._top_k = cfg.top_k_results
        try:
            from pinecone import Pinecone
            self._pc = Pinecone(api_key=cfg.api_key)
            self._index = None
        except ImportError:
            raise VectorStoreError(
                "pinecone package is required for AWS mode. "
                "Install it with: pip install pinecone"
            )
        except Exception as e:
            raise VectorStoreError(f"Pinecone init failed: {e}") from e

    def ensure_index(self) -> None:
        try:
            from pinecone import ServerlessSpec
            existing_indexes = [idx.name for idx in self._pc.list_indexes()]
            if self._index_name not in existing_indexes:
                self._pc.create_index(
                    name=self._index_name,
                    dimension=1024,
                    metric='cosine',
                    spec=ServerlessSpec(cloud='aws', region=settings.aws.region)
                )
                logger.info("pinecone_index_created", index=self._index_name)
            self._index = self._pc.Index(self._index_name)
        except Exception as e:
            raise VectorStoreError(f"Pinecone ensure_index failed: {e}") from e

    def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        try:
            self._index.upsert(vectors=[{
                "id": doc_id,
                "values": embedding,
                "metadata": {"text": text, **metadata}
            }])
        except Exception as e:
            raise VectorStoreError(f"Pinecone upsert failed: {e}") from e

    def search(self, query_embedding: list[float]) -> list[dict[str, Any]]:
        try:
            resp = self._index.query(
                vector=query_embedding,
                top_k=self._top_k,
                include_metadata=True
            )
            return [match["metadata"] for match in resp["matches"] if "metadata" in match]
        except Exception as e:
            raise VectorStoreError(f"Pinecone search failed: {e}") from e


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB vector store for similarity search (local/free mode)."""
    def __init__(self):
        cfg = settings.chroma
        self._collection_name = cfg.collection_name
        self._top_k = cfg.top_k_results
        self._persist_dir = cfg.persist_directory
        self._client = None
        self._collection = None

    def ensure_index(self) -> None:
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            logger.info("chroma_collection_ready", collection=self._collection_name)
        except ImportError:
            raise VectorStoreError(
                "chromadb is required for local mode. "
                "Install it with: pip install chromadb"
            )
        except Exception as e:
            raise VectorStoreError(f"ChromaDB init failed: {e}") from e

    def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict) -> None:
        try:
            self._collection.upsert(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[text],
                metadatas=[metadata]
            )
        except Exception as e:
            raise VectorStoreError(f"ChromaDB upsert failed: {e}") from e

    def search(self, query_embedding: list[float]) -> list[dict[str, Any]]:
        try:
            results = self._collection.query(
                query_embeddings=[query_embedding],
                n_results=self._top_k,
                include=["documents", "metadatas"]
            )
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            return [{"text": doc, **(meta or {})} for doc, meta in zip(docs, metas)]
        except Exception as e:
            raise VectorStoreError(f"ChromaDB search failed: {e}") from e


def get_vector_store() -> BaseVectorStore:
    """Factory: returns the correct vector store based on MODE setting."""
    if settings.is_local:
        return ChromaVectorStore()
    return PineconeVectorStore()
