from __future__ import annotations
from typing import Any
import config.settings as settings
from llm.prompt_templates import (
    VULNERABILITY_DETECTION_SYSTEM, VULNERABILITY_DETECTION_USER,
    REPORT_GENERATION_SYSTEM, REPORT_GENERATION_USER,
)

class PromptBuilder:
    """Builds fully-formed prompts for each agent."""
    @staticmethod
    def build_vulnerability_detection(template_summary: str, rag_snippets: list[str]):
        ctx = "\n\n---\n\n".join(rag_snippets) if rag_snippets else "No context retrieved."
        # Enforce RAG context length budget to avoid silent prompt truncation (MISS-06)
        if len(ctx) > settings.MAX_RAG_CONTEXT_CHARS:
            ctx = ctx[:settings.MAX_RAG_CONTEXT_CHARS] + "\n\n[...context truncated for length...]"
        user = VULNERABILITY_DETECTION_USER.format(template_summary=template_summary, rag_context=ctx)
        return VULNERABILITY_DETECTION_SYSTEM, [{"role": "user", "content": user}]

    @staticmethod
    def build_report_generation(findings_json: str, template_name: str):
        user = REPORT_GENERATION_USER.format(findings_json=findings_json, template_name=template_name)
        return REPORT_GENERATION_SYSTEM, [{"role": "user", "content": user}]
