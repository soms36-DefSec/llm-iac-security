"""Global configuration — loads from .env and supports two modes: local and aws."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv(override=True)
BASE_DIR = Path(__file__).resolve().parent.parent


class AWSSettings(BaseModel):
    region: str = Field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    access_key_id: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID"))
    secret_access_key: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY"))
    profile: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_PROFILE"))


class BedrockSettings(BaseModel):
    model_id: str = Field(default_factory=lambda: os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0"))
    embedding_model_id: str = Field(default_factory=lambda: os.getenv("BEDROCK_EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0"))
    max_tokens: int = 4096
    temperature: float = 0.0


class PineconeSettings(BaseModel):
    api_key: str = Field(default_factory=lambda: os.getenv("PINECONE_API_KEY", ""))
    index: str = Field(default_factory=lambda: os.getenv("PINECONE_INDEX", "iac-security-kb"))
    top_k_results: int = Field(default_factory=lambda: int(os.getenv("MAX_RAG_RESULTS", "5")))


class OllamaSettings(BaseModel):
    host: str = Field(default_factory=lambda: os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    model: str = Field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3"))
    max_tokens: int = Field(default_factory=lambda: int(os.getenv("OLLAMA_MAX_TOKENS", "4096")))
    temperature: float = Field(default_factory=lambda: float(os.getenv("OLLAMA_TEMPERATURE", "0.0")))


class ChromaSettings(BaseModel):
    persist_directory: str = Field(default_factory=lambda: os.getenv("CHROMA_PERSIST_DIR", str(BASE_DIR / ".chroma_db")))
    collection_name: str = Field(default_factory=lambda: os.getenv("CHROMA_COLLECTION", "iac-security-kb"))
    top_k_results: int = Field(default_factory=lambda: int(os.getenv("MAX_RAG_RESULTS", "5")))


class LocalEmbeddingSettings(BaseModel):
    model_name: str = Field(default_factory=lambda: os.getenv("LOCAL_EMBEDDING_MODEL", "all-MiniLM-L6-v2"))


class S3Settings(BaseModel):
    reports_bucket: str = Field(default_factory=lambda: os.getenv("S3_REPORTS_BUCKET", "iac-security-reports"))
    templates_bucket: str = Field(default_factory=lambda: os.getenv("S3_TEMPLATES_BUCKET", "iac-security-templates"))


class AppSettings(BaseModel):
    mode: str = Field(default_factory=lambda: os.getenv("MODE", "local"))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    confidence_threshold: float = Field(default_factory=lambda: float(os.getenv("VULNERABILITY_CONFIDENCE_THRESHOLD", "0.7")))
    report_output_dir: Path = Field(default_factory=lambda: BASE_DIR / os.getenv("REPORT_OUTPUT_DIR", "data/reports/generated"))
    knowledge_base_dir: Path = BASE_DIR / "knowledge_base" / "sources"


class Settings(BaseModel):
    aws: AWSSettings = Field(default_factory=AWSSettings)
    bedrock: BedrockSettings = Field(default_factory=BedrockSettings)
    pinecone: PineconeSettings = Field(default_factory=PineconeSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    chroma: ChromaSettings = Field(default_factory=ChromaSettings)
    local_embedding: LocalEmbeddingSettings = Field(default_factory=LocalEmbeddingSettings)
    s3: S3Settings = Field(default_factory=S3Settings)
    app: AppSettings = Field(default_factory=AppSettings)

    @property
    def is_local(self) -> bool:
        return self.app.mode.lower() == "local"


settings = Settings()
