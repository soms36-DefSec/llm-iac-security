"""Unit tests for the knowledge base RAG module (embeddings, vector store, kb_manager)."""

from unittest.mock import patch, MagicMock
import pytest


# ---- Embeddings tests ----

@patch("knowledge_base.embeddings.settings")
def test_get_embeddings_local(mock_settings):
    """get_embeddings returns LocalEmbeddings when mode is 'local'."""
    mock_settings.app.mode = "local"
    with patch("knowledge_base.embeddings.LocalEmbeddings") as MockLocal:
        MockLocal.return_value = MagicMock()
        from knowledge_base.embeddings import get_embeddings
        result = get_embeddings()
        MockLocal.assert_called_once()


@patch("knowledge_base.embeddings.settings")
def test_get_embeddings_aws(mock_settings):
    """get_embeddings returns TitanEmbeddings when mode is 'aws'."""
    mock_settings.app.mode = "aws"
    with patch("knowledge_base.embeddings.TitanEmbeddings") as MockTitan:
        MockTitan.return_value = MagicMock()
        from knowledge_base.embeddings import get_embeddings
        result = get_embeddings()
        MockTitan.assert_called_once()


@patch("knowledge_base.embeddings.settings")
def test_get_embeddings_invalid_mode(mock_settings):
    """get_embeddings raises EmbeddingError for unknown mode."""
    mock_settings.app.mode = "gcp"
    from knowledge_base.embeddings import get_embeddings
    from utils.exceptions import EmbeddingError
    with pytest.raises(EmbeddingError, match="Unknown APP_MODE"):
        get_embeddings()


# ---- Vector Store tests ----

@patch("knowledge_base.vector_store.settings")
def test_get_vector_store_local(mock_settings):
    """get_vector_store returns FAISSVectorStore when mode is 'local'."""
    mock_settings.app.mode = "local"
    mock_settings.pinecone.top_k_results = 5
    mock_settings.app.knowledge_base_dir = "/tmp/kb/sources"
    with patch("knowledge_base.vector_store.FAISSVectorStore") as MockFAISS:
        MockFAISS.return_value = MagicMock()
        from knowledge_base.vector_store import get_vector_store
        result = get_vector_store(dimension=384)
        MockFAISS.assert_called_once_with(dimension=384)


@patch("knowledge_base.vector_store.settings")
def test_get_vector_store_aws(mock_settings):
    """get_vector_store returns PineconeVectorStore when mode is 'aws'."""
    mock_settings.app.mode = "aws"
    with patch("knowledge_base.vector_store.PineconeVectorStore") as MockPinecone:
        MockPinecone.return_value = MagicMock()
        from knowledge_base.vector_store import get_vector_store
        result = get_vector_store(dimension=1024)
        MockPinecone.assert_called_once_with(dimension=1024)


# ---- KnowledgeBaseManager tests ----

@patch("knowledge_base.kb_manager.get_vector_store")
@patch("knowledge_base.kb_manager.get_embeddings")
def test_kb_manager_retrieve(mock_get_emb, mock_get_store):
    """KnowledgeBaseManager.retrieve embeds query and searches the store."""
    mock_emb = MagicMock()
    mock_emb.dimension = 384
    mock_emb.embed.return_value = [0.1] * 384
    mock_get_emb.return_value = mock_emb

    mock_store = MagicMock()
    mock_store.search.return_value = [{"text": "snippet1"}, {"text": "snippet2"}]
    mock_get_store.return_value = mock_store

    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    results = kb.retrieve("S3 encryption")

    mock_emb.embed.assert_called_once_with("S3 encryption")
    mock_store.search.assert_called_once()
    assert results == ["snippet1", "snippet2"]


@patch("knowledge_base.kb_manager.get_vector_store")
@patch("knowledge_base.kb_manager.get_embeddings")
def test_kb_manager_add_document_chunks(mock_get_emb, mock_get_store):
    """KnowledgeBaseManager.add_document chunks text and upserts each chunk."""
    mock_emb = MagicMock()
    mock_emb.dimension = 384
    mock_emb.embed.return_value = [0.1] * 384
    mock_get_emb.return_value = mock_emb

    mock_store = MagicMock()
    mock_get_store.return_value = mock_store

    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    # Short text = 1 chunk
    kb.add_document("test-doc", "A" * 100, {"category": "test"})

    assert mock_store.upsert.call_count == 1
    mock_emb.embed.assert_called_once()


@patch("knowledge_base.kb_manager.get_vector_store")
@patch("knowledge_base.kb_manager.get_embeddings")
def test_kb_manager_skips_empty_text(mock_get_emb, mock_get_store):
    """KnowledgeBaseManager.add_document skips empty text."""
    mock_emb = MagicMock()
    mock_emb.dimension = 384
    mock_get_emb.return_value = mock_emb
    mock_store = MagicMock()
    mock_get_store.return_value = mock_store

    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    kb.add_document("empty", "", {})

    mock_store.upsert.assert_not_called()
