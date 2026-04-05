"""Custom exception hierarchy for LLM IaC Security Scanner.

All project exceptions inherit from IaCSecurityBaseError so callers can
catch broadly (IaCSecurityBaseError) or narrowly (specific subclass).
"""


class IaCSecurityBaseError(Exception):
    """Base class for all LLM IaC Security Scanner exceptions."""

class IaCSecurityError(IaCSecurityBaseError):
    """Alias for IaCSecurityBaseError for spec compliance."""


class TemplateParsingError(IaCSecurityBaseError):
    """Raised when a YAML/JSON CloudFormation template cannot be parsed."""


class ParsingError(TemplateParsingError):
    """Alias for TemplateParsingError for backward compatibility."""


class UnsupportedTemplateFormatError(ParsingError):
    """Raised when a template file has an unsupported format or extension."""


class LLMError(IaCSecurityBaseError):
    """Raised when an Ollama or Bedrock API call fails."""


class LLMConnectionError(LLMError):
    """Alias for LLMError — connection or timeout to LLM backend."""


class LLMRateLimitError(LLMError):
    """Raised when the LLM backend returns a rate-limit error."""


class LLMResponseParseError(LLMError):
    """Raised when the LLM response cannot be parsed into structured data."""


class KnowledgeBaseError(IaCSecurityBaseError):
    """Raised when ChromaDB, Pinecone, or the KB manager encounters issues."""


class EmbeddingError(KnowledgeBaseError):
    """Raised when an embedding call fails."""


class VectorStoreError(KnowledgeBaseError):
    """Raised when a vector store operation fails."""


class AgentError(IaCSecurityBaseError):
    """Base class for agent-level errors."""


class RetrievalAgentError(AgentError):
    """Raised when the RetrievalAgent fails to fetch KB snippets."""


class VulnerabilityDetectionError(AgentError):
    """Raised when the VulnerabilityDetectionAgent fails."""


class ReportGenerationError(AgentError):
    """Raised when the ReportGenerationAgent fails."""


class StorageError(IaCSecurityBaseError):
    """Raised when an S3 upload/download or local cache operation fails."""


class ValidationError(IaCSecurityBaseError):
    """Raised when template schema validation fails."""


class ConfigurationError(IaCSecurityBaseError):
    """Raised when required environment variables are missing or invalid."""
