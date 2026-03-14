"""
Retrieval Agent — "The Librarian"

This agent is the first step in the RAG pipeline.  It receives a parsed
CloudFormation template, extracts the resource types mentioned, and queries
the knowledge base for relevant security best practices.

Pipeline position:
    CloudFormation Template → [RetrievalAgent] → rag_snippets added to context
"""

from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent
from knowledge_base.kb_manager import KnowledgeBaseManager
from parsers.resource_extractor import ResourceExtractor
from utils.exceptions import RetrievalAgentError


class RetrievalAgent(BaseAgent):
    """Queries the vector KB and injects RAG snippets into the context dict."""

    def __init__(self):
        super().__init__()
        self._kb = KnowledgeBaseManager()

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        1. Extract resource types from the normalized CloudFormation template.
        2. Build a summary query from those resources.
        3. Retrieve top-k relevant best-practice snippets from the knowledge base.
        4. Attach them to the context as 'rag_snippets'.

        Args:
            context: Must contain 'normalized_template' (from the parser).

        Returns:
            The same context dict with an additional 'rag_snippets' key.
        """
        normalized = context.get("normalized_template")
        if not normalized:
            raise RetrievalAgentError("'normalized_template' missing from context.")

        # Convert the template resources into a text summary for the search query
        query = ResourceExtractor(normalized).to_summary_text()
        self.logger.info("retrieval_query_built", query_length=len(query))

        # Search the knowledge base
        snippets = self._kb.retrieve(query)
        self.logger.info("retrieved_snippets", count=len(snippets))

        return {**context, "rag_snippets": snippets}
