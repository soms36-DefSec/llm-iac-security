"""
Integration tests for the RAG pipeline.

These tests exercise the full stack:
    Embedding → ChromaDB → Retrieval → PromptBuilder → (optionally) Ollama

Usage:
    # Run retrieval-only tests (no Ollama needed):
    cd llm-iac-security
    python -m pytest tests/integration/test_rag_integration.py -v

    # Run full pipeline tests including Ollama:
    RUN_OLLAMA_TESTS=1 python -m pytest tests/integration/test_rag_integration.py -v
"""

import os
import sys
from pathlib import Path

import pytest

# Ensure the project root is on the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestRAGRetrieval:
    """Test the retrieval pipeline (embedding + ChromaDB) — no Ollama needed."""

    def test_embedding_model_loads(self):
        """The sentence-transformers model loads and produces 384-dim vectors."""
        from knowledge_base.embeddings import EmbeddingModel

        model = EmbeddingModel()
        vec = model.generate_embedding("test input")

        assert isinstance(vec, list)
        assert len(vec) == 384
        assert all(isinstance(v, float) for v in vec)

    def test_embedding_batch(self):
        """Batch embedding produces one vector per input."""
        from knowledge_base.embeddings import EmbeddingModel

        model = EmbeddingModel()
        vecs = model.generate_embeddings(["hello", "world"])

        assert len(vecs) == 2
        assert len(vecs[0]) == 384

    def test_chromadb_add_and_search(self, tmp_path):
        """ChromaDB can store documents and retrieve them by similarity."""
        from knowledge_base.embeddings import EmbeddingModel
        from knowledge_base.vector_store import VectorStore

        model = EmbeddingModel()
        store = VectorStore(persist_directory=str(tmp_path / "test_chroma"))
        store.initialize()

        # Add a test document
        text = "S3 buckets should always have server-side encryption enabled."
        embedding = model.generate_embedding(text)
        store.add_documents(
            ids=["doc1"],
            texts=[text],
            embeddings=[embedding],
            metadatas=[{"source": "test"}],
        )

        assert store.count() == 1

        # Search for a related query
        query_vec = model.generate_embedding("How to encrypt S3?")
        results = store.similarity_search(query_vec, top_k=1)

        assert len(results) == 1
        assert "encryption" in results[0]["text"].lower()

    def test_kb_manager_end_to_end(self, tmp_path):
        """KnowledgeBaseManager can add a document and retrieve relevant snippets."""
        import knowledge_base.vector_store as vs_module

        original_init = vs_module.VectorStore.__init__

        def patched_init(self, persist_directory=None):
            original_init(self, persist_directory=str(tmp_path / "kb_test"))

        vs_module.VectorStore.__init__ = patched_init

        try:
            from knowledge_base.kb_manager import KnowledgeBaseManager

            kb = KnowledgeBaseManager()
            kb.add_document(
                "s3-best-practices",
                "S3 buckets should have encryption enabled using AES-256 or AWS KMS. "
                "Versioning should be turned on to protect against accidental deletes. "
                "Public access should be blocked by default.",
                {"category": "s3"},
            )

            results = kb.retrieve("S3 encryption best practices")
            assert len(results) > 0
            assert any("encryption" in r.lower() for r in results)
        finally:
            vs_module.VectorStore.__init__ = original_init

    def test_retrieval_returns_relevant_results(self, tmp_path):
        """Retrieval ranks related content higher than unrelated content."""
        import knowledge_base.vector_store as vs_module

        original_init = vs_module.VectorStore.__init__

        def patched_init(self, persist_directory=None):
            original_init(self, persist_directory=str(tmp_path / "rank_test"))

        vs_module.VectorStore.__init__ = patched_init

        try:
            from knowledge_base.kb_manager import KnowledgeBaseManager

            kb = KnowledgeBaseManager()
            kb.add_document("iam", "IAM roles should follow least privilege principle.", {"category": "iam"})
            kb.add_document("s3", "S3 buckets must have encryption enabled with KMS.", {"category": "s3"})
            kb.add_document("rds", "RDS instances should not be publicly accessible.", {"category": "rds"})

            results = kb.retrieve("S3 encryption", top_k=1)
            assert len(results) == 1
            assert "s3" in results[0].lower() or "encryption" in results[0].lower()
        finally:
            vs_module.VectorStore.__init__ = original_init


class TestPromptBuilder:
    """Test prompt construction."""

    def test_build_rag_query(self):
        """build_rag_query combines context and query into a structured prompt."""
        from llm.prompt_builder import PromptBuilder

        prompt = PromptBuilder.build_rag_query(
            query="How to secure S3?",
            context_snippets=["Enable encryption.", "Block public access."],
        )

        assert "Context:" in prompt
        assert "Enable encryption." in prompt
        assert "Block public access." in prompt
        assert "How to secure S3?" in prompt
        assert "Answer with security analysis" in prompt

    def test_build_rag_query_no_context(self):
        """build_rag_query handles empty context gracefully."""
        from llm.prompt_builder import PromptBuilder

        prompt = PromptBuilder.build_rag_query(query="test?", context_snippets=[])
        assert "No context available." in prompt


class TestOllamaClient:
    """Test the Ollama client (requires Ollama running locally)."""

    @pytest.mark.skipif(
        os.getenv("RUN_OLLAMA_TESTS", "0") != "1",
        reason="Set RUN_OLLAMA_TESTS=1 to run Ollama integration tests",
    )
    def test_ollama_generate(self):
        """Ollama can generate a response for a simple prompt."""
        from llm.ollama_client import OllamaClient

        client = OllamaClient()
        assert client.is_available(), "Ollama is not running or llama3 is not pulled"

        response = client.generate("Say hello in one word.", max_tokens=50)
        assert len(response) > 0

    @pytest.mark.skipif(
        os.getenv("RUN_OLLAMA_TESTS", "0") != "1",
        reason="Set RUN_OLLAMA_TESTS=1 to run Ollama integration tests",
    )
    def test_full_rag_pipeline(self, tmp_path):
        """Full pipeline: Query → Retrieve → Prompt → Ollama → Response."""
        import knowledge_base.vector_store as vs_module

        original_init = vs_module.VectorStore.__init__

        def patched_init(self, persist_directory=None):
            original_init(self, persist_directory=str(tmp_path / "pipeline_test"))

        vs_module.VectorStore.__init__ = patched_init

        try:
            from knowledge_base.kb_manager import KnowledgeBaseManager
            from llm.prompt_builder import PromptBuilder
            from llm.ollama_client import OllamaClient

            # Build knowledge base
            kb = KnowledgeBaseManager()
            kb.add_document(
                "s3-security",
                "S3 buckets should have encryption enabled. Use SSE-S3 or SSE-KMS. "
                "Block public access. Enable versioning. Enable access logging.",
                {"category": "s3"},
            )

            # Retrieve
            query = "What are best practices to secure AWS S3 buckets?"
            snippets = kb.retrieve(query)
            assert len(snippets) > 0

            # Build prompt
            prompt = PromptBuilder.build_rag_query(query, snippets)
            assert len(prompt) > 0

            # Generate response
            client = OllamaClient()
            response = client.generate(prompt, max_tokens=500)
            assert len(response) > 0
            response_lower = response.lower()
            assert any(
                term in response_lower
                for term in ["encryption", "s3", "bucket", "security", "access"]
            )
        finally:
            vs_module.VectorStore.__init__ = original_init
