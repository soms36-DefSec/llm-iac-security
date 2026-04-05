"""Bedrock configuration dataclass built from module-level settings constants."""
from __future__ import annotations
from dataclasses import dataclass

import config.settings as settings


@dataclass(frozen=True)
class BedrockConfig:
    """Immutable snapshot of Bedrock-related configuration.

    Args:
        region:              AWS region for Bedrock calls.
        model_id:            Bedrock model identifier for generation.
        embedding_model_id:  Bedrock model identifier for embeddings.
        max_tokens:          Maximum tokens to generate.
        temperature:         Default sampling temperature.
    """

    region: str
    model_id: str
    embedding_model_id: str
    max_tokens: int
    temperature: float

    @classmethod
    def from_settings(cls) -> "BedrockConfig":
        """Build a BedrockConfig from the current settings constants.

        Returns:
            Populated BedrockConfig instance.
        """
        return cls(
            region=settings.AWS_REGION,
            model_id=settings.BEDROCK_MODEL_ID,
            embedding_model_id=settings.BEDROCK_EMBED_MODEL_ID,
            max_tokens=settings.MAX_TOKENS,
            temperature=0.0,
        )


# Note: instantiate on demand via BedrockConfig.from_settings() rather than at import time
# to avoid running settings reads during module import (MISS-04)
