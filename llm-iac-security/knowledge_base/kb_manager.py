from __future__ import annotations
from pathlib import Path
from typing import Any
from config.settings import settings
from config.logging_config import get_logger
from knowledge_base.embeddings import TitanEmbeddings
from knowledge_base.vector_store import VectorStore
from utils.file_utils import read_text

logger = get_logger(__name__)

class KnowledgeBaseManager:
    """High-level API for managing best-practice documents in the vector store."""
    def __init__(self):
        self._embeddings = TitanEmbeddings()
        self._store = VectorStore()
        self._store.ensure_index()

    def add_document(self, doc_id: str, text: str, metadata: dict[str, Any]) -> None:
        self._store.upsert(doc_id, text, self._embeddings.embed(text), metadata)
        logger.info("document_added", doc_id=doc_id)

    def add_from_file(self, path: Path, category: str) -> None:
        self.add_document(path.stem, read_text(path), {"source": path.name, "category": category})

    def retrieve(self, query: str) -> list[str]:
        results = self._store.search(self._embeddings.embed(query))
        return [doc.get("text", "") for doc in results]

    def load_all_sources(self) -> None:
        for md_file in settings.app.knowledge_base_dir.glob("*.md"):
            self.add_from_file(md_file, md_file.stem.replace("_", "-"))
            logger.info("seeded", file=md_file.name)
