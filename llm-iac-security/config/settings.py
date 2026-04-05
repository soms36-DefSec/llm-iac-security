"""
Configuration module for LLM IaC Security Scanner.

Loads all settings from environment variables via python-dotenv.
Supports two operating modes: 'local' (Ollama + ChromaDB + HuggingFace)
and 'aws' (Bedrock + Pinecone + Titan).
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

load_dotenv(override=True)

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Mode control
# ---------------------------------------------------------------------------
MODE: str = os.getenv("MODE", "local")  # "local" or "aws"

# ---------------------------------------------------------------------------
# AWS settings
# ---------------------------------------------------------------------------
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY_ID: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_PROFILE: Optional[str] = os.getenv("AWS_PROFILE")

# Bedrock model IDs
BEDROCK_MODEL_ID: str = os.getenv(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"
)
BEDROCK_EMBED_MODEL_ID: str = os.getenv(
    "BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0"
)

# OpenSearch Serverless (AWS vector store)
OPENSEARCH_ENDPOINT: str = os.getenv("OPENSEARCH_ENDPOINT", "")

# Pinecone (alternative AWS vector store)
PINECONE_API_KEY: str = os.getenv("PINECONE_API_KEY", "")
PINECONE_INDEX: str = os.getenv("PINECONE_INDEX", "iac-security-kb")

# ---------------------------------------------------------------------------
# Local mode settings
# ---------------------------------------------------------------------------
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
CHROMA_PERSIST_DIR: str = os.getenv(
    "CHROMA_PERSIST_DIR", str(BASE_DIR / "data" / "chroma_db")
)
LOCAL_EMBED_MODEL: str = os.getenv("LOCAL_EMBED_MODEL", "all-MiniLM-L6-v2")

# ---------------------------------------------------------------------------
# Shared tuning constants
# ---------------------------------------------------------------------------
KB_SOURCES_DIR: str = os.getenv(
    "KB_SOURCES_DIR", str(BASE_DIR / "knowledge_base" / "sources")
)
CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "512"))
CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "50"))
TOP_K_RESULTS: int = int(os.getenv("TOP_K_RESULTS", "5"))
MAX_LLM_RETRIES: int = int(os.getenv("MAX_LLM_RETRIES", "3"))
LLM_TIMEOUT_SECONDS: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "4096"))
# Maximum total characters of RAG context injected into prompts (MISS-06)
MAX_RAG_CONTEXT_CHARS: int = int(os.getenv("MAX_RAG_CONTEXT_CHARS", "2048"))

# ---------------------------------------------------------------------------
# Output settings
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: str = os.getenv("LOG_FILE", str(BASE_DIR / "logs" / "iac_scanner.log"))
REPORTS_OUTPUT_DIR: str = os.getenv(
    "REPORTS_OUTPUT_DIR", str(BASE_DIR / "data" / "reports" / "generated")
)

# ---------------------------------------------------------------------------
# S3 settings
# ---------------------------------------------------------------------------
S3_REPORTS_BUCKET: str = os.getenv("S3_REPORTS_BUCKET", "iac-security-reports")
S3_TEMPLATES_BUCKET: str = os.getenv("S3_TEMPLATES_BUCKET", "iac-security-templates")

# Minimum similarity score for RAG retrieval
SIMILARITY_THRESHOLD: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.3"))


def validate_config() -> None:
    """Validate all required environment variables are set for the active mode.

    Args: None

    Returns: None

    Raises:
        ConfigurationError: If any required variable is missing or invalid.
    """
    from utils.exceptions import ConfigurationError

    missing: list[str] = []

    if MODE not in ("local", "aws"):
        raise ConfigurationError(
            f"MODE must be 'local' or 'aws', got: '{MODE}'"
        )

    if MODE == "aws":
        if not OPENSEARCH_ENDPOINT and not PINECONE_API_KEY:
            missing.append("OPENSEARCH_ENDPOINT or PINECONE_API_KEY")
        if not BEDROCK_MODEL_ID:
            missing.append("BEDROCK_MODEL_ID")

    if MODE == "local":
        if not OLLAMA_HOST:
            missing.append("OLLAMA_HOST")
        if not OLLAMA_MODEL:
            missing.append("OLLAMA_MODEL")

    if missing:
        raise ConfigurationError(
            f"Missing required configuration for MODE='{MODE}': {', '.join(missing)}"
        )
