"""Unit tests for the knowledge base RAG module (mocked — no real models loaded)."""

from unittest.mock import patch, MagicMock
import pytest


class TestEmbeddingModel:
    """Test the EmbeddingModel wrapper."""

    @patch("knowledge_base.embeddings.SentenceTransformer", create=True)
    def test_generate_embedding(self, MockST):
        """generate_embedding returns a list of floats."""
        import numpy as np
        mock_model = MagicMock()
        mock_model.encode.return_value = np.array([0.1, 0.2, 0.3])
        MockST.return_value = mock_model

        from knowledge_base.embeddings import EmbeddingModel
        model = EmbeddingModel.__new__(EmbeddingModel)
        model._model = mock_model
        model._dimension = 384

        result = model.generate_embedding("test")
        mock_model.encode.assert_called_once_with("test", normalize_embeddings=True)
        assert result == pytest.approx([0.1, 0.2, 0.3])

    @patch("knowledge_base.embeddings.SentenceTransformer", create=True)
    def test_generate_embeddings_batch(self, MockST):
        """generate_embeddings returns one vector per input."""
        import numpy as np
        mock_model = MagicMock()
        mock_model.encode.return_value = np.array([[0.1, 0.2], [0.3, 0.4]])
        MockST.return_value = mock_model

        from knowledge_base.embeddings import EmbeddingModel
        model = EmbeddingModel.__new__(EmbeddingModel)
        model._model = mock_model
        model._dimension = 384

        result = model.generate_embeddings(["a", "b"])
        assert len(result) == 2

    def test_dimension_property(self):
        """dimension returns 384."""
        from knowledge_base.embeddings import EmbeddingModel
        model = EmbeddingModel.__new__(EmbeddingModel)
        model._dimension = 384
        assert model.dimension == 384


class TestPromptBuilder:
    """Test prompt building functions."""

    def test_build_rag_query_with_context(self):
        """Prompt includes context and question."""
        from llm.prompt_builder import PromptBuilder

        prompt = PromptBuilder.build_rag_query("How to secure S3?", ["snippet1", "snippet2"])
        assert "Context:" in prompt
        assert "snippet1" in prompt
        assert "snippet2" in prompt
        assert "How to secure S3?" in prompt

    def test_build_rag_query_empty_context(self):
        """Empty context produces 'No context available' message."""
        from llm.prompt_builder import PromptBuilder

        prompt = PromptBuilder.build_rag_query("test?", [])
        assert "No context available." in prompt

    def test_build_vulnerability_detection(self):
        """Vulnerability detection prompt includes template summary and RAG context."""
        from llm.prompt_builder import PromptBuilder

        system, messages = PromptBuilder.build_vulnerability_detection(
            "S3 bucket with no encryption", ["Enable SSE-KMS"]
        )
        assert "security" in system.lower()
        assert len(messages) == 1
        assert "Enable SSE-KMS" in messages[0]["content"]


class TestKnowledgeBaseManager:
    """Test KnowledgeBaseManager with mocked dependencies."""

    @patch("knowledge_base.kb_manager.VectorStore")
    @patch("knowledge_base.kb_manager.EmbeddingModel")
    def test_retrieve(self, MockEmb, MockStore):
        """retrieve() embeds the query and searches the store."""
        mock_emb = MagicMock()
        mock_emb.generate_embedding.return_value = [0.1] * 384
        MockEmb.return_value = mock_emb

        mock_store = MagicMock()
        mock_store.similarity_search.return_value = [
            {"text": "snippet1", "metadata": {}},
            {"text": "snippet2", "metadata": {}},
        ]
        MockStore.return_value = mock_store

        from knowledge_base.kb_manager import KnowledgeBaseManager
        kb = KnowledgeBaseManager()
        results = kb.retrieve("S3 encryption")

        mock_emb.generate_embedding.assert_called_once_with("S3 encryption")
        assert results == ["snippet1", "snippet2"]

    @patch("knowledge_base.kb_manager.VectorStore")
    @patch("knowledge_base.kb_manager.EmbeddingModel")
    def test_add_document_chunks(self, MockEmb, MockStore):
        """add_document() chunks text and calls add_documents on store."""
        mock_emb = MagicMock()
        mock_emb.generate_embeddings.return_value = [[0.1] * 384]
        MockEmb.return_value = mock_emb

        mock_store = MagicMock()
        MockStore.return_value = mock_store

        from knowledge_base.kb_manager import KnowledgeBaseManager
        kb = KnowledgeBaseManager()
        kb.add_document("test-doc", "A" * 100, {"category": "test"})

        mock_store.add_documents.assert_called_once()

    @patch("knowledge_base.kb_manager.VectorStore")
    @patch("knowledge_base.kb_manager.EmbeddingModel")
    def test_skips_empty_text(self, MockEmb, MockStore):
        """add_document() skips empty text."""
        MockEmb.return_value = MagicMock()
        mock_store = MagicMock()
        MockStore.return_value = mock_store

        from knowledge_base.kb_manager import KnowledgeBaseManager
        kb = KnowledgeBaseManager()
        kb.add_document("empty", "", {})

        mock_store.add_documents.assert_not_called()


class TestOllamaClient:
    """Test OllamaClient with mocked HTTP requests."""

    @patch("llm.ollama_client.requests")
    def test_generate(self, mock_requests):
        """generate() sends POST and returns response text."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "Hello!", "total_duration": 1000000}
        mock_resp.status_code = 200
        mock_requests.post.return_value = mock_resp

        from llm.ollama_client import OllamaClient
        client = OllamaClient()
        result = client.generate("Say hello")

        assert result == "Hello!"
        mock_requests.post.assert_called_once()

    @patch("llm.ollama_client.requests")
    def test_is_available(self, mock_requests):
        """is_available() checks the Ollama API."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "llama3:latest"}]}
        mock_requests.get.return_value = mock_resp

        from llm.ollama_client import OllamaClient
        client = OllamaClient()
        assert client.is_available() is True

    @patch("llm.ollama_client.requests")
    def test_connection_error(self, mock_requests):
        """generate() raises ConnectionError when Ollama is not running."""
        import requests as real_requests
        mock_requests.ConnectionError = real_requests.ConnectionError
        mock_requests.HTTPError = real_requests.HTTPError
        mock_requests.post.side_effect = real_requests.ConnectionError("refused")

        from llm.ollama_client import OllamaClient
        client = OllamaClient()
        with pytest.raises(ConnectionError):
            client.generate("test")
