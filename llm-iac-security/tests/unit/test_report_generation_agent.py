from unittest.mock import patch, MagicMock
import pytest
from agents.report_generation_agent import ReportGenerationAgent
from utils.exceptions import ReportGenerationError


def test_run(sample_findings):
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = "# Report\n\nContent"
    with patch("agents.report_generation_agent.get_llm_client", return_value=mock_llm):
        r = ReportGenerationAgent().run({"findings": sample_findings, "template_name": "t1"})
    assert "# Report" in r["report_markdown"]


def test_missing():
    mock_llm = MagicMock()
    with patch("agents.report_generation_agent.get_llm_client", return_value=mock_llm):
        with pytest.raises(ReportGenerationError):
            ReportGenerationAgent().run({"template_name": "t1"})
