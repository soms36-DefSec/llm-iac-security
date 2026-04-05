from __future__ import annotations
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from knowledge_base.embeddings import EmbeddingModel
from knowledge_base.kb_manager import KnowledgeBaseManager

@pytest.fixture
def temp_chroma_dir():
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    # On Windows, ChromaDB may hold file handles open after the test; ignore cleanup errors
    shutil.rmtree(tmpdir, ignore_errors=True)

@pytest.fixture
def mock_embeddings():
    with patch("knowledge_base.kb_manager.EmbeddingModel") as mock:
        instance = mock.return_value
        # Return a dummy vector of 1024 dimensions (Titan size)
        instance.embed_text.return_value = [0.1] * 1024
        instance.embed_batch.return_value = [[0.1] * 1024]
        yield instance

def test_kb_initialize_and_query(temp_chroma_dir, mock_embeddings):
    """GAP 12: Test KB initialization and query with real ChromaDB and mocked embeddings."""
    kb_sources = str(Path(__file__).resolve().parent.parent.parent / "knowledge_base" / "sources")
    with patch("config.settings.MODE", "local"), \
         patch("config.settings.CHROMA_PERSIST_DIR", temp_chroma_dir), \
         patch("config.settings.KB_SOURCES_DIR", kb_sources):
        
        kb = KnowledgeBaseManager(mode="local")
        
        # Test initialize (which calls load_all_sources)
        # We need to mock add_from_file to avoid reading many files if we want a fast test,
        # but the spec says "real ChromaDB", so let's let it read at least one file.
        
        kb.initialize(force_rebuild=True)
        
        count = kb._store.document_count()
        assert count > 0, "KB should have some documents after initialization"
        
        # Test query
        results = kb.query("security best practices")
        assert len(results) > 0
        assert "text" in results[0]
        assert "metadata" in results[0]
        assert "score" in results[0]
