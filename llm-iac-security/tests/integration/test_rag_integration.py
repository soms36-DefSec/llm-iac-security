"""Integration test for RAG pipeline — tests with local ChromaDB when available."""
import pytest
from unittest.mock import patch, MagicMock


def test_kb_retrieve_with_mock():
    """Test KB retrieval with mocked embeddings and vector store."""
    mock_embeddings = MagicMock()
    mock_embeddings.embed.return_value = [0.1] * 384

    mock_store = MagicMock()
    mock_store.search.return_value = [
        {"text": "Enable S3 encryption at rest using AES-256.", "source": "cis_benchmarks.md"},
        {"text": "Use IAM least-privilege policies.", "source": "iam_best_practices.md"},
    ]

    with patch("knowledge_base.kb_manager.get_embeddings", return_value=mock_embeddings), \
         patch("knowledge_base.kb_manager.get_vector_store", return_value=mock_store):
        from knowledge_base.kb_manager import KnowledgeBaseManager
        kb = KnowledgeBaseManager()
        results = kb.retrieve("S3 bucket encryption best practices")

    assert len(results) == 2
    assert all(isinstance(r, str) for r in results)


@pytest.mark.skip(reason="Requires live Pinecone + Bedrock (AWS mode)")
def test_kb_retrieve_aws():
    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    results = kb.retrieve("S3 bucket encryption best practices")
    assert all(isinstance(r, str) for r in results)


@pytest.mark.skip(reason="Requires Ollama + ChromaDB running locally")
def test_kb_retrieve_local():
    import os
    os.environ["MODE"] = "local"
    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    results = kb.retrieve("S3 bucket encryption best practices")
    assert all(isinstance(r, str) for r in results)
