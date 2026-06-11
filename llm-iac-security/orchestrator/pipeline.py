from __future__ import annotations
import time
from pathlib import Path
from typing import Any
from agents.report_generation_agent import ReportGenerationAgent
from agents.retrieval_agent import RetrievalAgent
from agents.risk_explainer_agent import RiskExplainerAgent
from agents.vulnerability_detection_agent import VulnerabilityDetectionAgent
from config.logging_config import get_logger
from llm.response_parser import static_findings_to_hybrid_response
from parsers.parser_factory import ParserFactory
from reporting.report_builder import ReportBuilder
from static_analysis.engine import StaticAnalysisEngine
from utils.validation import validate_template_path

logger = get_logger(__name__)

class IaCSecurityPipeline:
    """End-to-end pipeline: parse -> static rules -> optional hybrid reasoning -> report."""

    def __init__(self, static_only: bool = False, hybrid: bool = True):
        self._static_only = static_only
        self._hybrid = hybrid
        self._static_engine = StaticAnalysisEngine()
        self._risk_explainer = RiskExplainerAgent()
        self._report_agent = ReportGenerationAgent()
        self._report_builder = ReportBuilder()

    def run(
        self,
        template_path: str | Path,
        static_only: bool | None = None,
        hybrid: bool | None = None,
    ) -> dict[str, Any]:
        """Run a scan and return a machine-readable context dictionary."""
        started = time.perf_counter()
        path = validate_template_path(template_path)
        logger.info("pipeline_started", template=path.name)
        parser = ParserFactory.get_parser(path)
        normalized = parser.parse_and_normalize(path)
        static_findings = [finding.to_dict() for finding in self._static_engine.scan(normalized)]

        effective_static_only = self._static_only if static_only is None else static_only
        effective_hybrid = self._hybrid if hybrid is None else hybrid
        if effective_static_only:
            effective_hybrid = False

        ctx = {
            "template_path": str(path),
            "template_name": path.stem if path.is_file() else path.name,
            "normalized_template": normalized,
            "static_findings": static_findings,
            "scan_mode": "static-only" if not effective_hybrid else "hybrid",
            "deterministic_report": True,
            "llm_enrichment_skipped": False,
        }

        if effective_hybrid:
            ctx = self._run_hybrid(ctx)
        else:
            ctx["findings"] = static_findings_to_hybrid_response(static_findings)

        ctx["scan_metadata"] = {
            "latency_seconds": time.perf_counter() - started,
            "static_findings_count": len(static_findings),
            "findings_count": len(ctx.get("findings", {}).get("findings", [])),
        }
        ctx = self._risk_explainer.run(ctx)
        ctx = self._report_agent.run(ctx)
        ctx["report_path"] = str(self._report_builder.save(ctx["report_markdown"], path.stem))
        logger.info("pipeline_completed", report=ctx["report_path"])
        return ctx

    def _run_hybrid(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Run RAG and LLM reasoning, falling back to static findings if needed."""
        try:
            ctx = RetrievalAgent().run(ctx)
        except Exception as exc:
            logger.warning("retrieval_skipped", error=str(exc))
            ctx = {**ctx, "rag_snippets": []}
        try:
            return VulnerabilityDetectionAgent().run({**ctx, "hybrid_reasoning": True})
        except Exception as exc:
            logger.warning("hybrid_reasoning_skipped_static_fallback", error=str(exc))
            return {
                **ctx,
                "findings": static_findings_to_hybrid_response(
                    ctx.get("static_findings", []),
                    summary_note="Hybrid reasoning unavailable; returned static findings.",
                ),
                "llm_enrichment_skipped": True,
            }
