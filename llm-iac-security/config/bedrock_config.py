from __future__ import annotations
from dataclasses import dataclass
from config.settings import settings

@dataclass(frozen=True)
class BedrockConfig:
    region: str
    model_id: str
    embedding_model_id: str
    max_tokens: int
    temperature: float

    @classmethod
    def from_settings(cls) -> "BedrockConfig":
        b = settings.bedrock
        return cls(region=settings.aws.region, model_id=b.model_id,
                   embedding_model_id=b.embedding_model_id,
                   max_tokens=b.max_tokens, temperature=b.temperature)

bedrock_config = BedrockConfig.from_settings()
