from unittest.mock import patch
import pytest
from agents.report_generation_agent import ReportGenerationAgent
from utils.exceptions import ReportGenerationError

def test_run(sample_findings):
    with patch("agents.report_generation_agent.BedrockClient") as M:
        M.return_value.invoke.return_value = "# Report\n\nContent"
        r = ReportGenerationAgent().run({"findings": sample_findings, "template_name": "t1"})
    assert "# Report" in r["report_markdown"]

def test_missing():
    with patch("agents.report_generation_agent.BedrockClient"):
        with pytest.raises(ReportGenerationError): ReportGenerationAgent().run({"template_name":"t1"})
