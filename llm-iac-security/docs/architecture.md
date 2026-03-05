# System Architecture

## Overview
Three-agent pipeline orchestrated by WorkflowManager:
1. RetrievalAgent: RAG via OpenSearch + Titan Embeddings
2. VulnerabilityDetectionAgent: LLM (Claude Sonnet 3.5 V2) analysis
3. ReportGenerationAgent: Markdown report generation

## Design Decisions
- **Immutable context**: Agents return new dicts, never mutate in-place.
- **Retry logic**: All Bedrock calls use exponential backoff (tenacity).
- **Pydantic settings**: Type-safe config with .env support.
- **Structlog**: Structured, JSON-compatible logging for production observability.
