from __future__ import annotations
from pathlib import Path
from typing import Any
from agents.report_generation_agent import ReportGenerationAgent
from agents.retrieval_agent import RetrievalAgent
from agents.vulnerability_detection_agent import VulnerabilityDetectionAgent
from config.logging_config import get_logger
from orchestrator.workflow_manager import WorkflowManager
from parsers.cloudformation_parser import CloudFormationParser
from reporting.report_builder import ReportBuilder
from utils.validation import validate_template_path

logger = get_logger(__name__)

class IaCSecurityPipeline:
    """End-to-end pipeline: parse -> retrieve -> detect -> report -> save."""
    def __init__(self):
        self._parser = CloudFormationParser()
        self._workflow = WorkflowManager([RetrievalAgent(), VulnerabilityDetectionAgent(), ReportGenerationAgent()])
        self._report_builder = ReportBuilder()

    def run(self, template_path: str | Path) -> dict[str, Any]:
        path = validate_template_path(template_path)
        logger.info("pipeline_started", template=path.name)
        normalized = self._parser.parse_and_normalize(path)
        ctx = {"template_path": str(path), "template_name": path.stem, "normalized_template": normalized}
        ctx = self._workflow.execute(ctx)
        ctx["report_path"] = str(self._report_builder.save(ctx["report_markdown"], path.stem))
        logger.info("pipeline_completed", report=ctx["report_path"])
        return ctx
