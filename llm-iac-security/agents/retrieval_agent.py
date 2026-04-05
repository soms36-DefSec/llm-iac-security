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
        # GAP 13: Initialise KB before querying
        try:
            self._kb.initialize()
        except Exception as e:
            self.logger.warning(f"Failed to initialize KnowledgeBase: {e}. Retrieval might be limited.")

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        normalized = context.get("normalized_template")
        if not normalized: raise RetrievalAgentError("'normalized_template' missing from context.")
        
        resource_summary = ResourceExtractor(normalized).to_summary_text()
        self._log_start(f"Querying KB with resource summary: {resource_summary[:50]}...")

        try:
            snippets = self._kb.retrieve(resource_summary)
            self.logger.info("retrieved_snippets", count=len(snippets))
            self._log_end(f"Retrieved {len(snippets)} snippets")
            # Store resource_summary in context so VulnerabilityDetectionAgent reuses it (BUG-04)
            return {**context, "rag_snippets": snippets, "resource_summary": resource_summary}
        except Exception as e:
            self._log_end(f"Error: {e}")
            raise RetrievalAgentError(f"Retrieval failed: {e}") from e
