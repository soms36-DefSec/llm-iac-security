"""Integration tests for the RAG pipeline.

The local-mode test runs with FAISS + sentence-transformers (no cloud needed).
The AWS-mode test requires live Pinecone + Bedrock credentials.
"""

import os
import pytest


@pytest.mark.skipif(
    os.getenv("RUN_LOCAL_INTEGRATION", "0") != "1",
    reason="Set RUN_LOCAL_INTEGRATION=1 to run local RAG integration tests",
)
def test_local_rag_end_to_end(monkeypatch):
    """Full local RAG cycle: add a document, retrieve matching snippets."""
    monkeypatch.setenv("APP_MODE", "local")
    # Re-import to pick up the env change
    from importlib import reload
    import config.settings as cs
    reload(cs)

    from knowledge_base.kb_manager import KnowledgeBaseManager

    kb = KnowledgeBaseManager()
    kb.clear()
    kb.add_document(
        "test-s3-best-practice",
        "S3 buckets should always have encryption enabled using AES-256 or AWS KMS. "
        "Versioning should be turned on to protect against accidental deletes. "
        "Public access should be blocked by default using the S3 Block Public Access settings.",
        {"category": "s3-security"},
    )
    results = kb.retrieve("S3 encryption best practices")
    assert len(results) > 0
    assert any("encryption" in r.lower() for r in results)


@pytest.mark.skip(reason="Requires live Pinecone + Bedrock credentials")
def test_aws_kb_retrieve_returns_strings():
    from knowledge_base.kb_manager import KnowledgeBaseManager

    kb = KnowledgeBaseManager()
    results = kb.retrieve("S3 bucket encryption best practices")
    assert all(isinstance(r, str) for r in results)
