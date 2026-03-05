from __future__ import annotations
import json
from typing import Any
from tenacity import retry, stop_after_attempt, wait_exponential
from config.bedrock_config import bedrock_config
from config.logging_config import get_logger
from utils.aws_utils import get_client
from utils.exceptions import LLMError, LLMRateLimitError

logger = get_logger(__name__)

class BedrockClient:
    """Amazon Bedrock runtime client wrapper with retry logic."""
    def __init__(self): self._client = get_client("bedrock-runtime")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), reraise=True)
    def invoke(self, messages: list[dict[str, Any]], system: str = "",
               max_tokens: int = None, temperature: float = None) -> str:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens or bedrock_config.max_tokens,
            "temperature": temperature if temperature is not None else bedrock_config.temperature,
            "messages": messages,
        }
        if system: body["system"] = system
        try:
            resp = self._client.invoke_model(
                modelId=bedrock_config.model_id, contentType="application/json",
                accept="application/json", body=json.dumps(body))
            return json.loads(resp["body"].read())["content"][0]["text"]
        except Exception as exc:
            raise LLMError(f"Bedrock invocation failed: {exc}") from exc
