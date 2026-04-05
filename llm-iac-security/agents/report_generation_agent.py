from __future__ import annotations
import json
from typing import Any
from agents.base_agent import BaseAgent
from llm.bedrock_client import BedrockClient
from llm.prompt_builder import PromptBuilder
from reporting.markdown_formatter import MarkdownFormatter
from utils.exceptions import ReportGenerationError

class ReportGenerationAgent(BaseAgent):
    """Converts structured findings into Markdown via deterministic formatter."""
    def __init__(self):
        super().__init__()
        self._llm = BedrockClient()
        self._formatter = MarkdownFormatter()

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        findings = context.get("findings")
        if findings is None: raise ReportGenerationError("'findings' missing from context.")
        
        template_name = context.get("template_name", "unknown-template")
        self._log_start(f"Generating report for template: {template_name}")

        # If summary is missing from findings, we could ask LLM to generate one,
        # but the prompt already asks for it in VulnerabilityDetectionAgent.
        # If it's still empty, let's try to get a summary if there are findings.
        if not findings.get("summary") and findings.get("vulnerabilities"):
            try:
                system, messages = PromptBuilder.build_report_generation(
                    json.dumps(findings, indent=2), template_name)
                # We reuse build_report_generation but only take the executive summary part if needed.
                # Actually, the original agent just returned the whole LLM output.
                # Let's use the LLM to generate the "Summary" section if it's missing.
                raw_report = self._llm.invoke(messages=messages, system=system)
                # Heuristic: try to extract summary from LLM output or just use it as summary
                findings["summary"] = raw_report
            except Exception as e:
                self.logger.warning(f"Failed to generate LLM summary: {e}")
                findings["summary"] = "Security scan completed. See findings below."

        try:
            # GAP 4 & 6: Use deterministic formatter (which sorts by severity)
            report = self._formatter.format(findings, template_name)
            self._log_end(f"Generated report ({len(report)} chars)")
            return {**context, "report_markdown": report}
        except Exception as e:
            self._log_end(f"Error: {e}")
            raise ReportGenerationError(f"Report generation failed: {e}") from e
