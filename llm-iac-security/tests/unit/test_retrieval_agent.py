from unittest.mock import patch, MagicMock
import pytest
from agents.retrieval_agent import RetrievalAgent
from utils.exceptions import RetrievalAgentError


def test_run_adds_snippets(sample_normalized_template):
    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = ["s1", "s2"]
    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb):
        r = RetrievalAgent().run({"normalized_template": sample_normalized_template})
    assert r["rag_snippets"] == ["s1", "s2"]


def test_missing_template():
    mock_kb = MagicMock()
    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb):
        with pytest.raises(RetrievalAgentError):
            RetrievalAgent().run({})
