from unittest.mock import patch
import pytest
from agents.report_generation_agent import ReportGenerationAgent
from utils.exceptions import ReportGenerationError

def test_run(sample_findings):
    with patch("agents.report_generation_agent.BedrockClient") as M:
        M.return_value.invoke.return_value = "# Security Scan Report\n\nContent"
        r = ReportGenerationAgent().run({"findings": sample_findings, "template_name": "t1"})
    # MarkdownFormatter generates deterministic output starting with the report header
    assert "# Security Scan Report" in r["report_markdown"]
    assert "report_markdown" in r

def test_missing():
    with patch("agents.report_generation_agent.BedrockClient"):
        with pytest.raises(ReportGenerationError): ReportGenerationAgent().run({"template_name":"t1"})
