"""Global configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    def load_dotenv(*_: object, **__: object) -> bool:
        return False


load_dotenv(override=True)
BASE_DIR = Path(__file__).resolve().parent.parent


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(slots=True)
class AWSSettings:
    region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-west-2"))
    access_key_id: str | None = field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID"))
    secret_access_key: str | None = field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY"))
    profile: str | None = field(default_factory=lambda: os.getenv("AWS_PROFILE"))


@dataclass(slots=True)
class BedrockSettings:
    model_id: str = field(
        default_factory=lambda: os.getenv(
            "BEDROCK_MODEL_ID",
            "global.anthropic.claude-sonnet-4-20250514-v1:0",
        )
    )
    embedding_model_id: str = field(
        default_factory=lambda: os.getenv(
            "BEDROCK_EMBEDDING_MODEL_ID",
            "amazon.titan-embed-text-v2:0",
        )
    )
    max_tokens: int = field(default_factory=lambda: _get_int("BEDROCK_MAX_TOKENS", 4096))
    temperature: float = field(default_factory=lambda: _get_float("BEDROCK_TEMPERATURE", 0.0))


@dataclass(slots=True)
class PineconeSettings:
    api_key: str = field(default_factory=lambda: os.getenv("PINECONE_API_KEY", ""))
    index: str = field(default_factory=lambda: os.getenv("PINECONE_INDEX", "iac-security-kb"))
    top_k_results: int = field(default_factory=lambda: _get_int("MAX_RAG_RESULTS", 5))


@dataclass(slots=True)
class OllamaSettings:
    host: str = field(default_factory=lambda: os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3"))
    max_tokens: int = field(default_factory=lambda: _get_int("OLLAMA_MAX_TOKENS", 4096))
    temperature: float = field(default_factory=lambda: _get_float("OLLAMA_TEMPERATURE", 0.0))


@dataclass(slots=True)
class ChromaSettings:
    persist_directory: str = field(
        default_factory=lambda: os.getenv("CHROMA_PERSIST_DIR", str(BASE_DIR / ".chroma_db"))
    )
    collection_name: str = field(default_factory=lambda: os.getenv("CHROMA_COLLECTION", "iac-security-kb"))
    top_k_results: int = field(default_factory=lambda: _get_int("MAX_RAG_RESULTS", 5))


@dataclass(slots=True)
class LocalEmbeddingSettings:
    model_name: str = field(default_factory=lambda: os.getenv("LOCAL_EMBEDDING_MODEL", "all-MiniLM-L6-v2"))


@dataclass(slots=True)
class S3Settings:
    reports_bucket: str = field(default_factory=lambda: os.getenv("S3_REPORTS_BUCKET", "iac-security-reports"))
    templates_bucket: str = field(default_factory=lambda: os.getenv("S3_TEMPLATES_BUCKET", "iac-security-templates"))


@dataclass(slots=True)
class AppSettings:
    mode: str = field(default_factory=lambda: os.getenv("MODE", "local"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    confidence_threshold: float = field(
        default_factory=lambda: _get_float("VULNERABILITY_CONFIDENCE_THRESHOLD", 0.7)
    )
    report_output_dir: Path = field(
        default_factory=lambda: BASE_DIR / os.getenv("REPORT_OUTPUT_DIR", "data/reports/generated")
    )
    knowledge_base_dir: Path = BASE_DIR / "knowledge_base" / "sources"


@dataclass(slots=True)
class Settings:
    aws: AWSSettings = field(default_factory=AWSSettings)
    bedrock: BedrockSettings = field(default_factory=BedrockSettings)
    pinecone: PineconeSettings = field(default_factory=PineconeSettings)
    ollama: OllamaSettings = field(default_factory=OllamaSettings)
    chroma: ChromaSettings = field(default_factory=ChromaSettings)
    local_embedding: LocalEmbeddingSettings = field(default_factory=LocalEmbeddingSettings)
    s3: S3Settings = field(default_factory=S3Settings)
    app: AppSettings = field(default_factory=AppSettings)

    @property
    def is_local(self) -> bool:
        return self.app.mode.lower() == "local"


settings = Settings()
