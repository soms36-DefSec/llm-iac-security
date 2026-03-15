import json, textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from orchestrator.pipeline import IaCSecurityPipeline

FINDINGS = json.dumps({"vulnerabilities":[{"resource_id":"B","resource_type":"AWS::S3::Bucket",
    "severity":"HIGH","title":"Unencrypted","description":"...","remediation":"Fix","reference":"CIS"}],
    "summary":"1 finding."})


@pytest.fixture
def cf_template(tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text(textwrap.dedent("""
        AWSTemplateFormatVersion: "2010-09-09"
        Resources:
          B: {Type: AWS::S3::Bucket, Properties: {BucketName: test}}
    """))
    return p


def test_pipeline(cf_template):
    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = ["Use encryption."]

    mock_llm = MagicMock()
    mock_llm.invoke.side_effect = [FINDINGS, "# Report\n\nDone."]

    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb), \
         patch("agents.vulnerability_detection_agent.get_llm_client", return_value=mock_llm), \
         patch("agents.report_generation_agent.get_llm_client", return_value=mock_llm):
        r = IaCSecurityPipeline().run(cf_template)
    assert "findings" in r and "report_markdown" in r


def test_pipeline_clean_template(cf_template):
    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = []

    clean_resp = json.dumps({"vulnerabilities": [], "summary": "No issues found."})
    mock_llm = MagicMock()
    mock_llm.invoke.side_effect = [clean_resp, "# Report\n\nNo vulnerabilities found."]

    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb), \
         patch("agents.vulnerability_detection_agent.get_llm_client", return_value=mock_llm), \
         patch("agents.report_generation_agent.get_llm_client", return_value=mock_llm):
        r = IaCSecurityPipeline().run(cf_template)
    assert len(r["findings"]["vulnerabilities"]) == 0
