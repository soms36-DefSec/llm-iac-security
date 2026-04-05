"""End-to-end pipeline test with correctly scoped mock patches."""
import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.pipeline import IaCSecurityPipeline

FINDINGS = json.dumps(
    {
        "vulnerabilities": [
            {
                "resource_name": "B",
                "resource_type": "AWS::S3::Bucket",
                "vulnerability_type": "No encryption",
                "severity": "HIGH",
                "description": "Bucket has no server-side encryption.",
                "remediation": "Add BucketEncryption with aws:kms.",
                "best_practice_reference": "CIS 2.1.1",
            }
        ],
        "summary": "1 finding.",
    }
)


@pytest.fixture
def cf_template(tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text(
        textwrap.dedent(
            """
            AWSTemplateFormatVersion: "2010-09-09"
            Resources:
              B: {Type: AWS::S3::Bucket, Properties: {BucketName: test}}
            """
        )
    )
    return p


# Patches must target the module where the name is *imported* (bound),
# not the source module. Order: decorators apply bottom-up, args left-to-right.
@patch("agents.report_generation_agent.BedrockClient")
@patch("agents.vulnerability_detection_agent.BedrockClient")
@patch("agents.retrieval_agent.KnowledgeBaseManager")
def test_pipeline_runs_end_to_end(MockKB, MockDetectLLM, MockReportLLM, cf_template, tmp_path):
    """Full pipeline runs without hitting real services and produces findings + report."""
    # Configure KB mock
    MockKB.return_value.initialize.return_value = None
    MockKB.return_value.retrieve.return_value = ["Use encryption for all S3 buckets."]

    # Detection agent: return structured findings JSON
    MockDetectLLM.return_value.invoke.return_value = FINDINGS

    # Report agent: return empty string (formatter handles it deterministically)
    MockReportLLM.return_value.invoke.return_value = ""

    output = tmp_path / "report.md"
    r = IaCSecurityPipeline().run(cf_template, output_path=str(output))

    assert "findings" in r, "Pipeline must produce 'findings' in result context"
    assert "report_markdown" in r, "Pipeline must produce 'report_markdown' in result context"
    assert "report_path" in r, "Pipeline must produce 'report_path' in result context"

    vulns = r["findings"].get("vulnerabilities", [])
    assert len(vulns) == 1
    assert vulns[0]["resource_name"] == "B"
    assert vulns[0]["severity"] == "HIGH"
