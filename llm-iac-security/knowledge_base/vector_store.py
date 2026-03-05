from __future__ import annotations
from typing import Any
from opensearchpy import OpenSearch, RequestsHttpConnection
from config.settings import settings
from config.logging_config import get_logger
from utils.exceptions import VectorStoreError

logger = get_logger(__name__)

INDEX_BODY = {
    "settings": {"index": {"knn": True}},
    "mappings": {"properties": {
        "text": {"type": "text"}, "embedding": {"type": "knn_vector", "dimension": 512},
        "source": {"type": "keyword"}, "category": {"type": "keyword"},
    }},
}

class VectorStore:
    """Amazon OpenSearch vector store for k-NN similarity search."""
    def __init__(self):
        cfg = settings.opensearch
        self._index = cfg.index
        self._top_k = cfg.top_k_results
        try:
            self._client = OpenSearch(
                hosts=[{"host": cfg.endpoint.replace("https://", ""), "port": 443}],
                http_auth=(cfg.username, cfg.password), use_ssl=True, verify_certs=True,
                connection_class=RequestsHttpConnection)
        except Exception as e: raise VectorStoreError(str(e)) from e

    def ensure_index(self):
        if not self._client.indices.exists(index=self._index):
            self._client.indices.create(index=self._index, body=INDEX_BODY)

    def upsert(self, doc_id: str, text: str, embedding: list[float], metadata: dict):
        self._client.index(index=self._index, id=doc_id,
                           body={"text": text, "embedding": embedding, **metadata}, refresh=True)

    def search(self, query_embedding: list[float]) -> list[dict[str, Any]]:
        try:
            resp = self._client.search(index=self._index, body={
                "size": self._top_k,
                "query": {"knn": {"embedding": {"vector": query_embedding, "k": self._top_k}}}})
            return [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as e: raise VectorStoreError(str(e)) from e
