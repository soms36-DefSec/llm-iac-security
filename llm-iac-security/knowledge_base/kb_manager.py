"""High-level API for managing best-practice documents in the vector store."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from config.settings import settings
from config.logging_config import get_logger
from knowledge_base.embeddings import get_embeddings
from knowledge_base.vector_store import get_vector_store
from utils.file_utils import read_text, read_pdf, chunk_text

logger = get_logger(__name__)


class KnowledgeBaseManager:
    """Manages the full lifecycle of the knowledge base (add, retrieve, load)."""
    def __init__(self):
        self._embeddings = get_embeddings()
        self._store = get_vector_store()
        self._store.ensure_index()

    def add_document(self, doc_id: str, text: str, metadata: dict[str, Any]) -> None:
        if not text or len(text.strip()) < 10:
            return
        try:
            chunks = chunk_text(text, chunk_size=2000, overlap=400)
            for i, chunk in enumerate(chunks):
                chunk_id = f"{doc_id}_chunk_{i}"
                chunk_metadata = {**metadata, "chunk_index": i}
                self._store.upsert(chunk_id, chunk, self._embeddings.embed(chunk), chunk_metadata)
            logger.info("document_added", doc_id=doc_id, chunks=len(chunks))
        except Exception as e:
            logger.error("failed_to_add_document", doc_id=doc_id, error=str(e))

    def add_from_file(self, path: Path, category: str) -> None:
        try:
            if path.suffix.lower() == ".pdf":
                text = read_pdf(path)
            elif path.suffix.lower() in [".md", ".txt"]:
                text = read_text(path)
            else:
                logger.warning("unsupported_file_type", file=path.name)
                return
            self.add_document(path.stem, text, {"source": path.name, "category": category})
        except Exception as e:
            logger.error("failed_to_process_file", file=path.name, error=str(e))

    def retrieve(self, query: str) -> list[str]:
        results = self._store.search(self._embeddings.embed(query))
        return [doc.get("text", "") for doc in results]

    def load_all_sources(self) -> None:
        for doc_file in settings.app.knowledge_base_dir.glob("*.*"):
            if doc_file.suffix.lower() in [".md", ".pdf", ".txt"]:
                self.add_from_file(doc_file, doc_file.stem.replace("_", "-"))
                logger.info("seeded", file=doc_file.name)

        user_input_dir = settings.app.knowledge_base_dir.parent / "user input"
        if user_input_dir.exists():
            for doc_file in user_input_dir.glob("*.*"):
                if doc_file.suffix.lower() in [".md", ".pdf", ".txt"]:
                    self.add_from_file(doc_file, "user-provided")
                    logger.info("user_input_loaded", file=doc_file.name)
