"""Report Generation Agent — converts structured findings into Markdown via LLM."""
from __future__ import annotations
import json
from typing import Any
from agents.base_agent import BaseAgent
from llm.bedrock_client import get_llm_client
from llm.prompt_builder import PromptBuilder
from reporting.markdown_formatter import MarkdownFormatter
from utils.exceptions import ReportGenerationError


class ReportGenerationAgent(BaseAgent):
    """Converts structured findings into Markdown via LLM."""
    def __init__(self):
        super().__init__()
        self._llm = None

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        findings = context.get("findings")
        if findings is None:
            raise ReportGenerationError("'findings' missing from context.")
        template_name = context.get("template_name", "unknown-template")
        if context.get("deterministic_report"):
            report = MarkdownFormatter().format(findings, template_name, context)
            return {**context, "report_markdown": report}
        if self._llm is None:
            self._llm = get_llm_client()
        system, messages = PromptBuilder.build_report_generation(
            json.dumps(findings, indent=2), template_name)
        report = self._llm.invoke(messages=messages, system=system)
        return {**context, "report_markdown": report}
