"""
Ollama Client — Sends prompts to a locally-running Ollama instance.

What is Ollama?
    Ollama is a free, open-source tool that lets you run large language models
    (like Llama3) entirely on your own computer.  No API keys, no cloud costs.

Prerequisites:
    1. Install Ollama:   https://ollama.com/download
    2. Pull a model:     ollama pull llama3
    3. Ollama runs a local API server at  http://localhost:11434

Usage:
    from llm.ollama_client import OllamaClient

    client = OllamaClient()
    response = client.generate("What is S3 encryption?")
    print(response)
"""

from __future__ import annotations

import json
from typing import Optional

import requests

from config.logging_config import get_logger

logger = get_logger(__name__)

# Default Ollama API settings
DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3"


class OllamaClient:
    """
    Client for the Ollama REST API.

    Sends prompts to a locally-running Ollama server and returns the
    generated text response.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
    ):
        """
        Args:
            base_url: Ollama API URL (default: http://localhost:11434).
            model:    Model name to use (default: llama3).
                      Must be pulled first with  ollama pull <model>.
        """
        self._base_url = base_url.rstrip("/")
        self._model = model
        logger.info("ollama_client_initialized", model=self._model, base_url=self._base_url)

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """
        Send a prompt to Ollama and return the generated text.

        Args:
            prompt:      The user prompt / question.
            system:      Optional system prompt (sets the model's role).
            temperature: Creativity control (0.0 = deterministic, 1.0 = creative).
            max_tokens:  Maximum number of tokens to generate.

        Returns:
            The model's text response as a string.

        Raises:
            ConnectionError: If Ollama is not running.
            RuntimeError:    If the API returns an error.
        """
        url = f"{self._base_url}/api/generate"

        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,  # get the full response at once (simpler)
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        # Add system prompt if provided
        if system:
            payload["system"] = system

        logger.info(
            "ollama_request",
            model=self._model,
            prompt_length=len(prompt),
            has_system=bool(system),
        )

        try:
            resp = requests.post(url, json=payload, timeout=120)
            resp.raise_for_status()
        except requests.ConnectionError:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self._base_url}.\n"
                "Make sure Ollama is running:  ollama serve"
            )
        except requests.HTTPError as e:
            raise RuntimeError(f"Ollama API error: {e}") from e

        data = resp.json()
        response_text = data.get("response", "")

        logger.info(
            "ollama_response",
            model=self._model,
            response_length=len(response_text),
            total_duration_ms=data.get("total_duration", 0) // 1_000_000,
        )

        return response_text

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is available."""
        try:
            resp = requests.get(f"{self._base_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False
            models = [m["name"] for m in resp.json().get("models", [])]
            # Check if our model is available (with or without :latest tag)
            return any(
                self._model in name for name in models
            )
        except (requests.ConnectionError, requests.Timeout):
            return False
