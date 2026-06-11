from pathlib import Path
from unittest.mock import patch

from orchestrator.pipeline import IaCSecurityPipeline

ROOT = Path(__file__).resolve().parents[2]


def test_terraform_pipeline_static_only_does_not_call_llm():
    fixture = ROOT / "tests/fixtures/terraform/vulnerable/aws_s3_public_unencrypted"
    with patch("agents.vulnerability_detection_agent.get_llm_client", side_effect=AssertionError("LLM called")), \
         patch("agents.report_generation_agent.get_llm_client", side_effect=AssertionError("LLM called")):
        result = IaCSecurityPipeline(static_only=True).run(fixture)
    assert result["scan_mode"] == "static-only"
    assert len(result["static_findings"]) == 2
    assert len(result["findings"]["findings"]) == 2
    assert "Security Scan Report" in result["report_markdown"]
