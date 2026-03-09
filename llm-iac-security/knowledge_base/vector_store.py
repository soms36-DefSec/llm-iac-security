from __future__ import annotations
from typing import Any
from pinecone import Pinecone, ServerlessSpec
from config.settings import settings
from config.logging_config import get_logger
from utils.exceptions import VectorStoreError

logger = get_logger(__name__)

class VectorStore:
    """Pinecone vector store for similarity search."""
    def __init__(self):
        cfg = settings.pinecone
        self._index_name = cfg.index
        self._top_k = cfg.top_k_results
        try:
            self._pc = Pinecone(api_key=cfg.api_key)
            # Delay Index assignment until ensure_index
            self._index = None
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def ensure_index(self):
        try:
            existing_indexes = [idx.name for idx in self._pc.list_indexes()]
            if self._index_name not in existing_indexes:
                self._pc.create_index(
                    name=self._index_name,
                    dimension=1024, # Titan Text Embeddings V2 default is 1024
                    metric='cosine',
                    spec=ServerlessSpec(cloud='aws', region=settings.aws.region)
                )
                logger.info("index_created", index=self._index_name)
            
            # Now assign the index
            self._index = self._pc.Index(self._index_name)
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict):
        try:
            # Pinecone metadata must not contain nested dicts for some configurations,
            # but here it's flat. We add the text to metadata so search can return it.
            self._index.upsert(vectors=[{
                "id": doc_id,
                "values": embedding,
                "metadata": {"text": text, **metadata}
            }])
        except Exception as e:
            raise VectorStoreError(str(e)) from e

    def search(self, query_embedding: list[float]) -> list[dict[str, Any]]:
        try:
            resp = self._index.query(
                vector=query_embedding,
                top_k=self._top_k,
                include_metadata=True
            )
            return [match["metadata"] for match in resp["matches"] if "metadata" in match]
        except Exception as e:
            raise VectorStoreError(str(e)) from e
