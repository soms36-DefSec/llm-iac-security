import json, textwrap
from pathlib import Path
from unittest.mock import patch
import pytest
from orchestrator.pipeline import IaCSecurityPipeline

FINDINGS = json.dumps({"vulnerabilities":[{"resource_id":"B","resource_type":"AWS::S3::Bucket",
    "severity":"HIGH","title":"Unencrypted","description":"...","remediation":"Fix","reference":"CIS"}],
    "summary":"1 finding."})

@pytest.fixture
def cf_template(tmp_path):
    p = tmp_path/"t.yaml"
    p.write_text(textwrap.dedent("""
        AWSTemplateFormatVersion: "2010-09-09"
        Resources:
          B: {Type: AWS::S3::Bucket, Properties: {BucketName: test}}
    """))
    return p

@patch("knowledge_base.kb_manager.KnowledgeBaseManager")
@patch("llm.bedrock_client.BedrockClient")
def test_pipeline(MockLLM, MockKB, cf_template):
    MockKB.return_value.retrieve.return_value = ["Use encryption."]
    MockLLM.return_value.invoke.side_effect = [FINDINGS, "# Report\n\nDone."]
    r = IaCSecurityPipeline().run(cf_template)
    assert "findings" in r and "report_markdown" in r
