from unittest.mock import patch
import pytest
from agents.retrieval_agent import RetrievalAgent
from utils.exceptions import RetrievalAgentError

def test_run_adds_snippets(sample_normalized_template):
    with patch("agents.retrieval_agent.KnowledgeBaseManager") as M:
        M.return_value.retrieve.return_value = ["s1","s2"]
        r = RetrievalAgent().run({"normalized_template": sample_normalized_template})
    assert r["rag_snippets"] == ["s1","s2"]

def test_missing_template():
    with patch("agents.retrieval_agent.KnowledgeBaseManager"):
        with pytest.raises(RetrievalAgentError): RetrievalAgent().run({})
