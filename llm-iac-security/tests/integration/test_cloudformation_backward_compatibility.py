from pathlib import Path
from unittest.mock import patch

from orchestrator.pipeline import IaCSecurityPipeline
from parsers.cloudformation_parser import CloudFormationParser

ROOT = Path(__file__).resolve().parents[2]


def test_cloudformation_parser_keeps_legacy_resource_shape():
    fixture = ROOT / "tests/fixtures/templates/T1_basic_s3.yaml"
    parsed = CloudFormationParser().parse_and_normalize(fixture)
    assert parsed["iac_type"] == "cloudformation"
    assert parsed["resources"]["PublicBucket"]["type"] == "AWS::S3::Bucket"
    assert parsed["resources"]["PublicBucket"]["resource_type"] == "AWS::S3::Bucket"


def test_cloudformation_pipeline_static_only_still_scans():
    fixture = ROOT / "tests/fixtures/templates/T1_basic_s3.yaml"
    with patch("agents.vulnerability_detection_agent.get_llm_client", side_effect=AssertionError("LLM called")):
        result = IaCSecurityPipeline(static_only=True).run(fixture)
    assert result["normalized_template"]["iac_type"] == "cloudformation"
    assert result["static_findings"]
    assert "report_markdown" in result
