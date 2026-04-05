"""
Knowledge base manager for LLM IaC Security Scanner.

Handles chunking, embedding, indexing, and querying of security
best-practice documents stored in knowledge_base/sources/.

Uses the dual-mode EmbeddingModel and VectorStore so it works in both
local (HuggingFace + ChromaDB) and AWS (Titan + Pinecone) modes.
"""
from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import Any, Optional

import config.settings as settings
from knowledge_base.embeddings import EmbeddingModel
from knowledge_base.vector_store import VectorStore
from utils.exceptions import KnowledgeBaseError

logger = logging.getLogger(__name__)


def _chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Split text into overlapping character-level chunks.

    Preserves heading context: if a chunk starts mid-section the nearest
    preceding ## heading is prepended to the chunk text.

    Discards chunks shorter than 100 characters.

    Args:
        text:       Full document text.
        chunk_size: Maximum characters per chunk.
        overlap:    Characters of overlap between consecutive chunks.

    Returns:
        List of text chunks.
    """
    # Build an index of (position, heading) for all ## headings
    heading_pattern = re.compile(r"^(## .+)$", re.MULTILINE)
    headings: list[tuple[int, str]] = [
        (m.start(), m.group(1)) for m in heading_pattern.finditer(text)
    ]

    chunks: list[str] = []
    start = 0
    step = max(1, chunk_size - overlap)

    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()

        if len(chunk) >= 100:
            # Find the most recent heading before this chunk
            context_heading = ""
            for pos, heading in headings:
                if pos <= start:
                    context_heading = heading
                else:
                    break
            if context_heading and not chunk.startswith("##"):
                chunk = f"{context_heading}\n\n{chunk}"
            chunks.append(chunk)

        start += step

    return chunks


class KnowledgeBaseManager:
    """High-level API for managing best-practice documents.

    Provides initialize(), query(), and load helpers that work with both
    local (ChromaDB) and AWS (Pinecone) backends.

    Args:
        mode: Override the mode from settings. Useful for testing.
    """

    def __init__(self, mode: Optional[str] = None) -> None:
        """Initialise embedding model and vector store.

        Args:
            mode: 'local' or 'aws'. Defaults to settings.MODE.
        """
        self._mode = mode or settings.MODE
        self._embeddings = EmbeddingModel(mode=self._mode)
        self._store = VectorStore(mode=self._mode)

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialize(self, force_rebuild: bool = False) -> None:
        """Load all KB source documents into the vector store.

        Skips loading if the store already has documents and
        force_rebuild is False.

        Args:
            force_rebuild: If True, clear existing data and reload.

        Raises:
            KnowledgeBaseError: If loading or embedding fails.
        """
        try:
            if not force_rebuild:
                count = self._store.document_count()
                if count > 0:
                    logger.info(
                        "KB already populated (%d chunks); skipping rebuild.", count
                    )
                    return

            if force_rebuild:
                self._store.clear()

            self.load_all_sources()
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"KB initialisation failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Document loading
    # ------------------------------------------------------------------

    def add_document(
        self,
        doc_id: str,
        text: str,
        metadata: dict[str, Any],
    ) -> None:
        """Chunk, embed, and store a single document.

        Args:
            doc_id:   Unique base identifier for the document.
            text:     Full document text.
            metadata: Base metadata dict (source, category, etc.).

        Raises:
            KnowledgeBaseError: If any step fails.
        """
        if not text or len(text.strip()) < 10:
            logger.warning("Skipping empty/short document: %s", doc_id)
            return

        try:
            chunks = _chunk_text(
                text,
                chunk_size=settings.CHUNK_SIZE,
                overlap=settings.CHUNK_OVERLAP,
            )
            texts_to_embed = [c for c in chunks]
            if not texts_to_embed:
                return

            vectors = self._embeddings.embed_batch(texts_to_embed)

            for i, (chunk, vector) in enumerate(zip(chunks, vectors)):
                chunk_id = f"{doc_id}_chunk_{i}"
                chunk_meta = {**metadata, "chunk_index": i}
                self._store.upsert(chunk_id, chunk, vector, chunk_meta)

            logger.info(
                "Document indexed: doc_id=%s chunks=%d", doc_id, len(chunks)
            )
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"add_document failed for '{doc_id}': {exc}"
            ) from exc

    def add_from_file(self, path: Path, category: str) -> None:
        """Read a file and add it to the knowledge base.

        Supports .md, .txt, and .pdf files.

        Args:
            path:     Path to the source file.
            category: Category label stored in chunk metadata.

        Raises:
            KnowledgeBaseError: If reading or indexing fails.
        """
        try:
            suffix = path.suffix.lower()
            if suffix in (".md", ".txt"):
                text = path.read_text(encoding="utf-8", errors="replace")
            elif suffix == ".pdf":
                from utils.file_utils import read_pdf
                text = read_pdf(path)
            else:
                logger.warning("Unsupported file type skipped: %s", path.name)
                return

            self.add_document(
                doc_id=path.stem,
                text=text,
                metadata={"source": path.name, "category": category},
            )
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"add_from_file failed for '{path}': {exc}"
            ) from exc

    def load_all_sources(self) -> int:
        """Load all .md / .txt / .pdf files from KB sources directories.

        Reads from settings.KB_SOURCES_DIR and also from the 'user input'
        directory if it exists.

        Returns:
            Count of files successfully loaded.

        Raises:
            KnowledgeBaseError: If any file fails to load.
        """
        count = 0
        sources_dir = Path(settings.KB_SOURCES_DIR)
        for doc_file in sorted(sources_dir.glob("*.*")):
            if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                self.add_from_file(doc_file, doc_file.stem.replace("_", "-"))
                count += 1

        user_input_dir = sources_dir.parent / "user input"
        if user_input_dir.exists():
            for doc_file in sorted(user_input_dir.glob("*.*")):
                if doc_file.suffix.lower() in (".md", ".pdf", ".txt"):
                    self.add_from_file(doc_file, "user-provided")
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query(
        self, question: str, top_k: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """Retrieve the top-k most relevant KB chunks for a query.

        Args:
            question: Natural language query string.
            top_k:    Number of results. Defaults to settings.TOP_K_RESULTS.

        Returns:
            List of result dicts:
                {"text": str, "metadata": dict, "score": float}

        Raises:
            KnowledgeBaseError: If the embedding or search fails.
        """
        if top_k is None:
            top_k = settings.TOP_K_RESULTS

        try:
            query_vector = self._embeddings.embed_text(question)
            results = self._store.search(query_vector, top_k=top_k)
            # Deduplicate: keep only the highest-scoring chunk per source
            seen_sources: dict[str, dict[str, Any]] = {}
            for result in results:
                source = result.get("metadata", {}).get("source", "unknown")
                if source not in seen_sources or result["score"] > seen_sources[source]["score"]:
                    seen_sources[source] = result
            deduped = sorted(
                seen_sources.values(), key=lambda x: x["score"], reverse=True
            )
            return deduped[:top_k]
        except KnowledgeBaseError:
            raise
        except Exception as exc:
            raise KnowledgeBaseError(
                f"query failed: {exc}"
            ) from exc

    def retrieve(self, query: str) -> list[str]:
        """Return just the text snippets for a query (convenience wrapper).

        Args:
            query: Natural language query string.

        Returns:
            List of text strings from the top-k results.

        Raises:
            KnowledgeBaseError: If the query fails.
        """
        results = self.query(query)
        return [r["text"] for r in results]
