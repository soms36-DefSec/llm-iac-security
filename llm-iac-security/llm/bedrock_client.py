"""LLM client providers: Amazon Bedrock (AWS/paid) and Ollama (local/free)."""
from __future__ import annotations
import json
from abc import ABC, abstractmethod
from typing import Any
from tenacity import retry, stop_after_attempt, wait_exponential
from config.settings import settings
from config.logging_config import get_logger
from utils.exceptions import LLMError

logger = get_logger(__name__)


class BaseLLMClient(ABC):
    """Abstract interface for LLM providers."""
    @abstractmethod
    def invoke(self, messages: list[dict[str, Any]], system: str = "",
               max_tokens: int = None, temperature: float = None) -> str: ...


class BedrockClient(BaseLLMClient):
    """Amazon Bedrock runtime client wrapper with retry logic."""
    def __init__(self):
        from utils.aws_utils import get_client
        self._client = get_client("bedrock-runtime")
        self._model_id = settings.bedrock.model_id
        logger.info("bedrock_client_initialized", model_id=self._model_id)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), reraise=True)
    def invoke(self, messages: list[dict[str, Any]], system: str = "",
               max_tokens: int = None, temperature: float = None) -> str:
        inference_config = {
            "maxTokens": max_tokens or settings.bedrock.max_tokens,
            "temperature": temperature if temperature is not None else settings.bedrock.temperature,
        }
        system_prompts = [{"text": system}] if system else []
        formatted_messages = [
            {"role": msg["role"], "content": [{"text": msg["content"]}]}
            for msg in messages
        ]
        try:
            response = self._client.converse(
                modelId=self._model_id,
                messages=formatted_messages,
                system=system_prompts,
                inferenceConfig=inference_config
            )
            return response["output"]["message"]["content"][0]["text"]
        except Exception as exc:
            raise LLMError(f"Bedrock invocation failed (model={self._model_id}): {exc}") from exc


class OllamaClient(BaseLLMClient):
    """Ollama local LLM client with retry logic (free, runs on your machine)."""
    def __init__(self):
        self._host = settings.ollama.host
        self._model = settings.ollama.model
        logger.info("ollama_client_initialized", host=self._host, model=self._model)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), reraise=True)
    def invoke(self, messages: list[dict[str, Any]], system: str = "",
               max_tokens: int = None, temperature: float = None) -> str:
        import requests

        api_messages = []
        if system:
            api_messages.append({"role": "system", "content": system})
        for msg in messages:
            api_messages.append({"role": msg["role"], "content": msg["content"]})

        payload = {
            "model": self._model,
            "messages": api_messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens or settings.ollama.max_tokens,
                "temperature": temperature if temperature is not None else settings.ollama.temperature,
            },
        }
        try:
            resp = requests.post(
                f"{self._host}/api/chat",
                json=payload,
                timeout=300
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
        except requests.exceptions.ConnectionError:
            raise LLMError(
                f"Cannot connect to Ollama at {self._host}. "
                "Make sure Ollama is running: ollama serve"
            )
        except Exception as exc:
            raise LLMError(f"Ollama invocation failed (model={self._model}): {exc}") from exc


def get_llm_client() -> BaseLLMClient:
    """Factory: returns the correct LLM client based on MODE setting."""
    if settings.is_local:
        return OllamaClient()
    return BedrockClient()
