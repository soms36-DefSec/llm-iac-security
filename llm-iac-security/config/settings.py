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

class S3Settings(BaseModel):
    reports_bucket: str = Field(default_factory=lambda: os.getenv("S3_REPORTS_BUCKET", "iac-security-reports"))
    templates_bucket: str = Field(default_factory=lambda: os.getenv("S3_TEMPLATES_BUCKET", "iac-security-templates"))

class AppSettings(BaseModel):
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    confidence_threshold: float = Field(default_factory=lambda: float(os.getenv("VULNERABILITY_CONFIDENCE_THRESHOLD", "0.7")))
    report_output_dir: Path = Field(default_factory=lambda: BASE_DIR / os.getenv("REPORT_OUTPUT_DIR", "data/reports/generated"))
    knowledge_base_dir: Path = BASE_DIR / "knowledge_base" / "sources"
    # Ollama settings for local LLM inference
    ollama_base_url: str = Field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
    ollama_model: str = Field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3"))

class Settings(BaseModel):
    aws: AWSSettings = Field(default_factory=AWSSettings)
    bedrock: BedrockSettings = Field(default_factory=BedrockSettings)
    pinecone: PineconeSettings = Field(default_factory=PineconeSettings)
    s3: S3Settings = Field(default_factory=S3Settings)
    app: AppSettings = Field(default_factory=AppSettings)

settings = Settings()
