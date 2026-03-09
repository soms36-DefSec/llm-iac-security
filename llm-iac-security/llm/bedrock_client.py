from __future__ import annotations
import json
from typing import Any
from tenacity import retry, stop_after_attempt, wait_exponential
from config.settings import settings
from config.logging_config import get_logger
from utils.aws_utils import get_client
from utils.exceptions import LLMError

logger = get_logger(__name__)

class BedrockClient:
    """Amazon Bedrock runtime client wrapper with retry logic."""
    def __init__(self): 
        self._client = get_client("bedrock-runtime")
        self._model_id = settings.bedrock.model_id
        logger.info("bedrock_client_initialized", model_id=self._model_id)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), reraise=True)
    def invoke(self, messages: list[dict[str, Any]], system: str = "",
               max_tokens: int = None, temperature: float = None) -> str:
        
        # Bedrock Converse API format
        inference_config = {
            "maxTokens": max_tokens or settings.bedrock.max_tokens,
            "temperature": temperature if temperature is not None else settings.bedrock.temperature,
        }
        
        # Prepare system prompt
        system_prompts = []
        if system:
            system_prompts.append({"text": system})
            
        # Standardize message format for Converse API
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                "role": msg["role"],
                "content": [{"text": msg["content"]}]
            })
            
        try:
            # Converse API handles multiple model types (Anthropic, Titan, etc.)
            response = self._client.converse(
                modelId=self._model_id,
                messages=formatted_messages,
                system=system_prompts,
                inferenceConfig=inference_config
            )
            return response["output"]["message"]["content"][0]["text"]
        except Exception as exc:
            raise LLMError(f"Bedrock invocation failed (model={self._model_id}): {exc}") from exc
