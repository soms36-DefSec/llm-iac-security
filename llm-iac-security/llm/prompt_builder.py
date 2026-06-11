from __future__ import annotations
from typing import Any
from llm.prompt_templates import (
    VULNERABILITY_DETECTION_SYSTEM, VULNERABILITY_DETECTION_USER,
    HYBRID_VULNERABILITY_REASONING_SYSTEM_PROMPT, HYBRID_VULNERABILITY_REASONING_USER_PROMPT,
    REPORT_GENERATION_SYSTEM, REPORT_GENERATION_USER,
)

class PromptBuilder:
    """Builds fully-formed prompts for each agent."""
    @staticmethod
    def build_vulnerability_detection(template_summary: str, rag_snippets: list[str]):
        ctx = "\n\n---\n\n".join(rag_snippets) if rag_snippets else "No context retrieved."
        user = VULNERABILITY_DETECTION_USER.format(template_summary=template_summary, rag_context=ctx)
        return VULNERABILITY_DETECTION_SYSTEM, [{"role": "user", "content": user}]

    @staticmethod
    def build_hybrid_vulnerability_reasoning(
        iac_summary: str,
        static_findings_json: str,
        rag_snippets: list[str],
    ):
        ctx = "\n\n---\n\n".join(rag_snippets) if rag_snippets else "No context retrieved."
        user = HYBRID_VULNERABILITY_REASONING_USER_PROMPT.format(
            iac_summary=iac_summary,
            static_findings_json=static_findings_json,
            rag_context=ctx,
        )
        return HYBRID_VULNERABILITY_REASONING_SYSTEM_PROMPT, [{"role": "user", "content": user}]

    @staticmethod
    def build_report_generation(findings_json: str, template_name: str):
        user = REPORT_GENERATION_USER.format(findings_json=findings_json, template_name=template_name)
        return REPORT_GENERATION_SYSTEM, [{"role": "user", "content": user}]
