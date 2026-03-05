from __future__ import annotations
import json
from typing import Any
from agents.base_agent import BaseAgent
from llm.bedrock_client import BedrockClient
from llm.prompt_builder import PromptBuilder
from utils.exceptions import ReportGenerationError

class ReportGenerationAgent(BaseAgent):
    """Converts structured findings into Markdown via LLM."""
    def __init__(self):
        super().__init__()
        self._llm = BedrockClient()

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        findings = context.get("findings")
        if findings is None: raise ReportGenerationError("'findings' missing from context.")
        template_name = context.get("template_name", "unknown-template")
        system, messages = PromptBuilder.build_report_generation(
            json.dumps(findings, indent=2), template_name)
        report = self._llm.invoke(messages=messages, system=system)
        return {**context, "report_markdown": report}
