"""
Dual-mode LLM client for LLM IaC Security Scanner.

Local mode: sends requests to a running Ollama server.
AWS mode:   calls Amazon Bedrock via the Converse API (Claude Sonnet 3.5 V2).

Retry logic: up to MAX_LLM_RETRIES attempts with exponential back-off
(1 s, 2 s, 4 s). Raises LLMError if all attempts fail or if
the call exceeds LLM_TIMEOUT_SECONDS.
"""
from __future__ import annotations
import json
import logging
import time
from typing import Any, Optional

import config.settings as settings
from utils.exceptions import LLMError, LLMRateLimitError

logger = logging.getLogger(__name__)


class LLMClient:
    """Dual-mode LLM client wrapper.

    Provides a single generate() method that works with either Ollama
    (local) or Amazon Bedrock (aws) depending on settings.MODE.

    Args:
        mode: Override the mode from settings. Useful for testing.
    """

    def __init__(self, mode: Optional[str] = None) -> None:
        """Initialise the LLM client.

        Args:
            mode: 'local' or 'aws'. Defaults to settings.MODE.
        """
        self._mode = mode or settings.MODE
        self._bedrock_client = None  # lazy-init for AWS mode
        logger.info(
            "LLMClient initialised (mode=%s)", self._mode
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_bedrock_client(self):
        """Lazy-initialise Bedrock runtime client.

        Returns:
            boto3 bedrock-runtime client.

        Raises:
            LLMError: If Bedrock client cannot be created.
        """
        if self._bedrock_client is not None:
            return self._bedrock_client
        try:
            import boto3
            self._bedrock_client = boto3.client(
                "bedrock-runtime", region_name=settings.AWS_REGION
            )
            return self._bedrock_client
        except Exception as exc:
            raise LLMError(
                f"Failed to create Bedrock client: {exc}"
            ) from exc

    def _call_ollama(
        self,
        prompt: str,
        system_message: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> str:
        """Send a chat request to the local Ollama server via /api/chat.

        Uses the chat endpoint with proper role-separated messages so the
        model can distinguish system instructions from user content.

        Args:
            prompt:         User prompt text.
            system_message: Optional system instruction.
            max_tokens:     Maximum tokens to generate.
            temperature:    Sampling temperature.

        Returns:
            The generated text string.

        Raises:
            LLMError: If the Ollama server is unreachable or
                returns a non-200 status.
        """
        import requests

        messages: list[dict] = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        url = f"{settings.OLLAMA_HOST}/api/chat"
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=settings.LLM_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                raise LLMError(
                    f"Ollama returned HTTP {response.status_code}: {response.text}"
                )
            data = response.json()
            return data.get("message", {}).get("content", "")
        except requests.exceptions.Timeout as exc:
            raise LLMError(
                f"Ollama request timed out after {settings.LLM_TIMEOUT_SECONDS}s"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise LLMError(
                f"Cannot connect to Ollama at {settings.OLLAMA_HOST}. "
                "Ensure 'ollama serve' is running."
            ) from exc

    def _call_bedrock(
        self,
        prompt: str,
        system_message: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> str:
        """Send a generation request to Amazon Bedrock via Converse API.

        Args:
            prompt:         User prompt text.
            system_message: Optional system instruction.
            max_tokens:     Maximum tokens to generate.
            temperature:    Sampling temperature.

        Returns:
            The generated text string.

        Raises:
            LLMError: If the Bedrock call fails.
        """
        client = self._get_bedrock_client()

        system_prompts: list[dict[str, Any]] = []
        if system_message:
            system_prompts.append({"text": system_message})

        messages = [{"role": "user", "content": [{"text": prompt}]}]

        inference_config: dict[str, Any] = {
            "maxTokens": max_tokens,
            "temperature": temperature,
        }

        try:
            response = client.converse(
                modelId=settings.BEDROCK_MODEL_ID,
                messages=messages,
                system=system_prompts,
                inferenceConfig=inference_config,
            )
            return response["output"]["message"]["content"][0]["text"]
        except Exception as exc:
            # Catch Bedrock throttling separately so callers can retry appropriately
            try:
                from botocore.exceptions import ClientError
                if isinstance(exc, ClientError):
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code in ("ThrottlingException", "TooManyRequestsException"):
                        raise LLMRateLimitError(
                            f"Bedrock throttled (code={code}): {exc}"
                        ) from exc
            except (ImportError, AttributeError):
                pass
            raise LLMError(
                f"Bedrock invocation failed (model={settings.BEDROCK_MODEL_ID}): {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        max_tokens: int = 2000,
        temperature: float = 0.1,
    ) -> str:
        """Generate text from a prompt with retry logic.

        Attempts up to settings.MAX_LLM_RETRIES times with exponential
        back-off (1 s, 2 s, 4 s, …). Logs each attempt with model name,
        estimated prompt length, and response time.

        Args:
            prompt:         The user prompt to send to the LLM.
            system_message: Optional system / instruction prefix.
            max_tokens:     Maximum tokens in the generated response.
            temperature:    Sampling temperature (0.0 = deterministic).

        Returns:
            The generated text as a string.

        Raises:
            LLMError: If all retries are exhausted.
        """
        model_label = (
            settings.OLLAMA_MODEL
            if self._mode == "local"
            else settings.BEDROCK_MODEL_ID
        )
        prompt_len = len(prompt) + len(system_message or "")
        logger.debug(
            "LLM call: mode=%s model=%s prompt_chars=%d",
            self._mode,
            model_label,
            prompt_len,
        )

        last_error: Optional[Exception] = None
        for attempt in range(1, settings.MAX_LLM_RETRIES + 1):
            t_start = time.time()
            try:
                if self._mode == "local":
                    result = self._call_ollama(
                        prompt, system_message, max_tokens, temperature
                    )
                else:
                    result = self._call_bedrock(
                        prompt, system_message, max_tokens, temperature
                    )
                elapsed = time.time() - t_start
                logger.info(
                    "LLM response: attempt=%d model=%s elapsed=%.2fs",
                    attempt,
                    model_label,
                    elapsed,
                )
                return result
            except LLMError as exc:
                last_error = exc
                elapsed = time.time() - t_start
                delay = 2 ** (attempt - 1)  # 1 s, 2 s, 4 s …
                logger.warning(
                    "LLM attempt %d/%d failed (%.2fs): %s — retrying in %ds",
                    attempt,
                    settings.MAX_LLM_RETRIES,
                    elapsed,
                    exc,
                    delay,
                )
                if attempt < settings.MAX_LLM_RETRIES:
                    time.sleep(delay)

        raise LLMError(
            f"LLM call failed after {settings.MAX_LLM_RETRIES} attempts "
            f"(mode={self._mode}, model={model_label}). "
            f"Last error: {last_error}"
        )


class BedrockClient(LLMClient):
    """Backward-compatible alias for LLMClient.

    Provides the invoke() interface expected by the agents, delegating
    to LLMClient.generate() under the hood.
    """

    def invoke(
        self,
        messages: list[dict],
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> str:
        """Invoke the LLM with Bedrock Converse-style message format.

        Args:
            messages:   List of message dicts with 'role' and 'content'.
            system:     System prompt string.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Returns:
            Generated text string.

        Raises:
            LLMError: If the call fails.
        """
        # Extract the user message content from the messages list
        prompt = ""
        for msg in messages:
            if msg.get("role") == "user":
                prompt = msg.get("content", "")
                break
        return self.generate(
            prompt=prompt,
            system_message=system or None,
            max_tokens=max_tokens,
            temperature=temperature,
        )
