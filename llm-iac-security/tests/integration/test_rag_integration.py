"""Integration test stubs for RAG pipeline (requires live AWS)."""
import pytest

@pytest.mark.skip(reason="Requires live OpenSearch + Bedrock")
def test_kb_retrieve_returns_strings():
    from knowledge_base.kb_manager import KnowledgeBaseManager
    kb = KnowledgeBaseManager()
    results = kb.retrieve("S3 bucket encryption best practices")
    assert all(isinstance(r, str) for r in results)
