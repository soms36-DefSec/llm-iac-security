from __future__ import annotations
from pathlib import Path
from typing import Any

import config.settings as settings
from agents.report_generation_agent import ReportGenerationAgent
from agents.retrieval_agent import RetrievalAgent
from agents.vulnerability_detection_agent import VulnerabilityDetectionAgent
from config.logging_config import get_logger
from orchestrator.workflow_manager import WorkflowManager
from parsers.cloudformation_parser import CloudFormationParser
from reporting.report_builder import ReportBuilder
from utils.exceptions import UnsupportedTemplateFormatError
from utils.validation import validate_template_path

logger = get_logger(__name__)

_CF_EXTENSIONS = {".yaml", ".yml", ".json"}
_TF_EXTENSIONS = {".tf"}


def _get_parser(path: Path):
    """Return the appropriate parser for the given file extension.

    Args:
        path: Path to the IaC template file.

    Returns:
        An instance of the appropriate BaseParser subclass.

    Raises:
        UnsupportedTemplateFormatError: If the file extension is not supported.
    """
    suffix = path.suffix.lower()
    if suffix in _CF_EXTENSIONS:
        return CloudFormationParser()
    if suffix in _TF_EXTENSIONS:
        from parsers.terraform_parser import TerraformParser
        return TerraformParser()
    raise UnsupportedTemplateFormatError(
        f"Unsupported template format '{suffix}'. "
        f"Supported: {sorted(_CF_EXTENSIONS | _TF_EXTENSIONS)}"
    )


class IaCSecurityPipeline:
    """End-to-end pipeline: parse -> retrieve -> detect -> report -> save."""

    def __init__(self):
        # Fail fast with a clear message if required env vars are missing (MISS-01)
        settings.validate_config()
        self._workflow = WorkflowManager(
            [RetrievalAgent(), VulnerabilityDetectionAgent(), ReportGenerationAgent()]
        )
        self._report_builder = ReportBuilder()

    def run(self, template_path: str | Path, output_path: str | Path = None) -> dict[str, Any]:
        path = validate_template_path(template_path)
        logger.info("pipeline_started", template=path.name)
        # Auto-detect format from extension (MISS-09)
        parser = _get_parser(path)
        normalized = parser.parse_and_normalize(path)
        ctx = {
            "template_path": str(path),
            "template_name": path.stem,
            "normalized_template": normalized,
        }
        ctx = self._workflow.execute(ctx)
        ctx["report_path"] = str(
            self._report_builder.save(ctx["report_markdown"], path.stem, output_path=output_path)
        )
        logger.info("pipeline_completed", report=ctx["report_path"])
        return ctx
