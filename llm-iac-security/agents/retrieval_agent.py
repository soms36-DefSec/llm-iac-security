from __future__ import annotations
from typing import Any
from agents.base_agent import BaseAgent
from knowledge_base.kb_manager import KnowledgeBaseManager
from parsers.resource_extractor import ResourceExtractor
from utils.exceptions import RetrievalAgentError

class RetrievalAgent(BaseAgent):
    """Queries the vector KB and injects RAG snippets into context."""
    def __init__(self):
        super().__init__()
        self._kb = KnowledgeBaseManager()

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        normalized = context.get("normalized_template")
        if not normalized: raise RetrievalAgentError("'normalized_template' missing from context.")
        query = ResourceExtractor(normalized).to_summary_text()
        snippets = self._kb.retrieve(query)
        self.logger.info("retrieved_snippets", count=len(snippets))
        return {**context, "rag_snippets": snippets}
