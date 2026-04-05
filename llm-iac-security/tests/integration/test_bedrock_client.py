"""Integration tests for LLMClient / BedrockClient with mocked HTTP and boto3."""
from __future__ import annotations
import json
from unittest.mock import MagicMock, patch

import pytest
import responses as resp_lib

from llm.bedrock_client import BedrockClient
from utils.exceptions import LLMError


@resp_lib.activate
def test_bedrock_client_ollama_mock():
    """LLMClient in local mode calls /api/chat and extracts message.content."""
    with patch("config.settings.MODE", "local"), \
         patch("config.settings.OLLAMA_HOST", "http://localhost:11434"), \
         patch("config.settings.OLLAMA_MODEL", "llama3"):

        client = BedrockClient(mode="local")

        # /api/chat response format: {"message": {"role": "assistant", "content": "..."}}
        resp_lib.add(
            resp_lib.POST,
            "http://localhost:11434/api/chat",
            json={"message": {"role": "assistant", "content": "Hello from Ollama"}},
            status=200,
        )

        result = client.invoke(messages=[{"role": "user", "content": "Say hello."}])
        assert result == "Hello from Ollama"


def test_bedrock_client_bedrock_mock():
    """LLMClient in aws mode calls Bedrock Converse API correctly."""
    with patch("config.settings.MODE", "aws"), \
         patch("config.settings.BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0"):

        with patch("boto3.client") as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client

            mock_client.converse.return_value = {
                "output": {
                    "message": {
                        "content": [{"text": "Hello from Bedrock"}]
                    }
                }
            }

            client = BedrockClient(mode="aws")
            result = client.invoke(messages=[{"role": "user", "content": "Say hello."}])

            assert result == "Hello from Bedrock"
            mock_client.converse.assert_called_once()


@resp_lib.activate
def test_bedrock_client_retry_logic():
    """LLMClient retries on HTTP 500 and succeeds on the next attempt."""
    with patch("config.settings.MODE", "local"), \
         patch("config.settings.OLLAMA_HOST", "http://localhost:11434"), \
         patch("config.settings.MAX_LLM_RETRIES", 2):

        client = BedrockClient(mode="local")

        # First call fails, second succeeds
        resp_lib.add(resp_lib.POST, "http://localhost:11434/api/chat", status=500)
        resp_lib.add(
            resp_lib.POST,
            "http://localhost:11434/api/chat",
            json={"message": {"role": "assistant", "content": "Finally worked"}},
            status=200,
        )

        with patch("time.sleep"):  # Skip sleep for fast test
            result = client.invoke(messages=[{"role": "user", "content": "Test retry"}])
            assert result == "Finally worked"
            assert len(resp_lib.calls) == 2


@resp_lib.activate
def test_bedrock_client_ollama_sends_system_message():
    """Ollama /api/chat request includes system role message when provided."""
    with patch("config.settings.MODE", "local"), \
         patch("config.settings.OLLAMA_HOST", "http://localhost:11434"), \
         patch("config.settings.OLLAMA_MODEL", "llama3"):

        client = BedrockClient(mode="local")

        resp_lib.add(
            resp_lib.POST,
            "http://localhost:11434/api/chat",
            json={"message": {"role": "assistant", "content": "OK"}},
            status=200,
        )

        client.invoke(
            messages=[{"role": "user", "content": "Analyze this."}],
            system="You are a security expert.",
        )

        # Verify the request body included a system message
        sent_body = json.loads(resp_lib.calls[0].request.body)
        roles = [m["role"] for m in sent_body["messages"]]
        assert "system" in roles, "System message should be sent as role=system to /api/chat"
        assert "user" in roles
