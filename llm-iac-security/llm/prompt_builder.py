"""
Prompt Builder — Combines retrieved RAG context with user queries into
structured prompts suitable for the LLM (Ollama/Llama3 or Bedrock/Claude).

What is a prompt?
    A prompt is the text you send to the LLM.  A well-structured prompt
    contains:
    1. A system instruction telling the model its role and output format.
    2. Context (the RAG snippets from the knowledge base).
    3. The actual question or task.

This module provides two builder methods:
    - build_vulnerability_detection()  — for the security analysis agent
    - build_rag_query()                — for general RAG Q&A (e.g., test_rag.py)
"""

from __future__ import annotations

from typing import List

from llm.prompt_templates import (
    VULNERABILITY_DETECTION_SYSTEM,
    VULNERABILITY_DETECTION_USER,
    REPORT_GENERATION_SYSTEM,
    REPORT_GENERATION_USER,
)


class PromptBuilder:
    """Builds fully-formed prompts for each agent."""

    @staticmethod
    def build_vulnerability_detection(
        template_summary: str, rag_snippets: list[str]
    ) -> tuple[str, list[dict[str, str]]]:
        """
        Build the prompt for the Vulnerability Detection Agent.

        Args:
            template_summary: Text summary of the CloudFormation template.
            rag_snippets:     Best-practice snippets from the knowledge base.

        Returns:
            (system_prompt, messages)  where messages is a list of role/content dicts.
        """
        ctx = "\n\n---\n\n".join(rag_snippets) if rag_snippets else "No context retrieved."
        user = VULNERABILITY_DETECTION_USER.format(
            template_summary=template_summary, rag_context=ctx
        )
        return VULNERABILITY_DETECTION_SYSTEM, [{"role": "user", "content": user}]

    @staticmethod
    def build_report_generation(
        findings_json: str, template_name: str
    ) -> tuple[str, list[dict[str, str]]]:
        """Build the prompt for the Report Generation Agent."""
        user = REPORT_GENERATION_USER.format(
            findings_json=findings_json, template_name=template_name
        )
        return REPORT_GENERATION_SYSTEM, [{"role": "user", "content": user}]

    @staticmethod
    def build_rag_query(query: str, context_snippets: List[str]) -> str:
        """
        Build a simple RAG prompt for general security Q&A.

        This is used by test_rag.py and the integration tests.

        The prompt format:
            Context: {retrieved_security_docs}
            Question: {user_query}
            Answer with security analysis and best practices.

        Args:
            query:            The user's question.
            context_snippets: Relevant text chunks from the knowledge base.

        Returns:
            A single string prompt ready to send to the LLM.
        """
        context_text = "\n\n---\n\n".join(context_snippets) if context_snippets else "No context available."

        prompt = (
            f"Context:\n{context_text}\n\n"
            f"Question: {query}\n\n"
            f"Answer with security analysis and best practices."
        )
        return prompt
